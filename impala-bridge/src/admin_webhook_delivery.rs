//! Background worker for the admin webhook event feed.
//!
//! Runs in-process (spawned from `run_server`, no SNS/SQS dependency). Each tick:
//!   1. **Fan-out**: turn undispatched `event_outbox` rows into per-webhook
//!      `admin_webhook_delivery` rows (respecting each webhook's `event_types`).
//!   2. **Deliver**: POST due pending deliveries with an HMAC-SHA256 signature,
//!      retrying with exponential backoff; mark `failed` after `max_attempts` and
//!      auto-disable a webhook after `disable_threshold` consecutive failures.
//!
//! The URL is re-validated against SSRF rules at delivery time (defense-in-depth).

use std::time::Duration;

use log::{error, info, warn};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS;
use crate::events::sign;

pub struct DeliveryConfig {
    pub poll_secs: u64,
    pub max_attempts: u32,
    pub disable_threshold: i64,
}

#[derive(sqlx::FromRow)]
struct DueDelivery {
    delivery_id: i64,
    attempt: i32,
    webhook_id: i64,
    url: String,
    secret: String,
    event_id: i64,
    event_type: String,
    account_id: String,
    payload: serde_json::Value,
    created_ts: i64,
}

/// Worker entry point. Loops until `cancel` fires.
pub async fn run(pool: PgPool, cfg: DeliveryConfig, cancel: CancellationToken) {
    // Webhook URLs are caller-supplied, so this client dials through the SSRF
    // egress guard (vets every resolved address) and refuses redirects — a
    // followed 302 would otherwise walk a validated URL straight to an
    // internal address with no DNS control needed.
    let client = match crate::ssrf::guarded_client(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS) {
        Ok(c) => c,
        Err(e) => {
            error!("admin_webhook_delivery: failed to build HTTP client: {}", e);
            return;
        }
    };

    info!(
        "admin_webhook_delivery: started (poll={}s, max_attempts={}, disable_threshold={})",
        cfg.poll_secs, cfg.max_attempts, cfg.disable_threshold
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("admin_webhook_delivery: shutdown signal received");
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(cfg.poll_secs)) => {
                if let Err(e) = fan_out(&pool).await {
                    error!("admin_webhook_delivery: fan-out error: {}", e);
                }
                if let Err(e) = deliver_due(&pool, &client, &cfg).await {
                    error!("admin_webhook_delivery: delivery error: {}", e);
                }
            }
        }
    }
}

/// Turn undispatched outbox events into pending per-webhook deliveries.
async fn fan_out(pool: &PgPool) -> Result<(), sqlx::Error> {
    let events: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, event_type FROM event_outbox WHERE dispatched = FALSE ORDER BY id LIMIT 200",
    )
    .fetch_all(pool)
    .await?;

    for (event_id, event_type) in events {
        // One pending delivery per enabled webhook subscribed to this type
        // (NULL/empty event_types = all). ON CONFLICT keeps fan-out idempotent.
        sqlx::query(
            "INSERT INTO admin_webhook_delivery (webhook_id, event_id, status, next_attempt_at) \
             SELECT w.id, $1, 'pending', CURRENT_TIMESTAMP FROM admin_webhook w \
             WHERE w.enabled = TRUE \
               AND (w.event_types IS NULL OR cardinality(w.event_types) = 0 OR $2 = ANY(w.event_types)) \
             ON CONFLICT (webhook_id, event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(&event_type)
        .execute(pool)
        .await?;

        sqlx::query("UPDATE event_outbox SET dispatched = TRUE WHERE id = $1")
            .bind(event_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Deliver due pending rows, signing each request and applying retry/backoff.
async fn deliver_due(
    pool: &PgPool,
    client: &reqwest::Client,
    cfg: &DeliveryConfig,
) -> Result<(), sqlx::Error> {
    let due: Vec<DueDelivery> = sqlx::query_as(
        "SELECT d.id AS delivery_id, d.attempt, w.id AS webhook_id, w.url, w.secret, \
                e.id AS event_id, e.event_type, e.account_id, e.payload, \
                EXTRACT(EPOCH FROM e.created_at)::bigint AS created_ts \
         FROM admin_webhook_delivery d \
         JOIN admin_webhook w ON w.id = d.webhook_id \
         JOIN event_outbox e ON e.id = d.event_id \
         WHERE d.status = 'pending' AND d.next_attempt_at <= CURRENT_TIMESTAMP AND w.enabled = TRUE \
         ORDER BY d.id LIMIT 50",
    )
    .fetch_all(pool)
    .await?;

    for row in due {
        // Re-validate the URL at delivery time (DNS-rebinding / SSRF defense).
        if let Err(e) = crate::validate::validate_callback_url(&row.url) {
            warn!(
                "admin_webhook_delivery: webhook {} url failed SSRF check: {:?}",
                row.webhook_id, e
            );
            mark_failure(pool, &row, cfg, None, "URL failed SSRF validation").await?;
            continue;
        }

        let body = serde_json::json!({
            "event_id": row.event_id,
            "type": row.event_type,
            "account_id": row.account_id,
            "occurred_at": row.created_ts,
            "data": row.payload,
        });
        let body_str = body.to_string();
        let ts = chrono::Utc::now().timestamp();
        let signature = sign(row.secret.as_bytes(), ts, &body_str);

        let resp = client
            .post(&row.url)
            .header("Content-Type", "application/json")
            .header("X-Impala-Webhook-Id", row.webhook_id.to_string())
            .header("X-Impala-Event-Id", row.event_id.to_string())
            .header("X-Impala-Timestamp", ts.to_string())
            .header("X-Impala-Signature", format!("sha256={}", signature))
            .body(body_str)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let code = r.status().as_u16() as i32;
                mark_delivered(pool, row.delivery_id, row.webhook_id, code).await?;
            }
            Ok(r) => {
                let code = r.status().as_u16() as i32;
                let snippet: String = r
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(500)
                    .collect();
                mark_failure(
                    pool,
                    &row,
                    cfg,
                    Some(code),
                    &format!("HTTP {}: {}", code, snippet),
                )
                .await?;
            }
            Err(e) => {
                mark_failure(pool, &row, cfg, None, &format!("request error: {}", e)).await?;
            }
        }
    }
    Ok(())
}

async fn mark_delivered(
    pool: &PgPool,
    delivery_id: i64,
    webhook_id: i64,
    code: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE admin_webhook_delivery \
         SET status = 'delivered', attempt = attempt + 1, response_code = $2, \
             delivered_at = CURRENT_TIMESTAMP WHERE id = $1",
    )
    .bind(delivery_id)
    .bind(code)
    .execute(pool)
    .await?;

    // Success resets the consecutive-failure counter.
    sqlx::query(
        "UPDATE admin_webhook \
         SET failure_count = 0, last_error = NULL, last_delivery_at = CURRENT_TIMESTAMP \
         WHERE id = $1",
    )
    .bind(webhook_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_failure(
    pool: &PgPool,
    row: &DueDelivery,
    cfg: &DeliveryConfig,
    code: Option<i32>,
    err: &str,
) -> Result<(), sqlx::Error> {
    let new_attempt = row.attempt + 1;

    if new_attempt >= cfg.max_attempts as i32 {
        // Terminal: mark the delivery failed and bump the webhook's failure count.
        sqlx::query(
            "UPDATE admin_webhook_delivery \
             SET status = 'failed', attempt = $2, response_code = $3, response_body = $4 \
             WHERE id = $1",
        )
        .bind(row.delivery_id)
        .bind(new_attempt)
        .bind(code)
        .bind(err)
        .execute(pool)
        .await?;

        let (failure_count,): (i32,) = sqlx::query_as(
            "UPDATE admin_webhook \
             SET failure_count = failure_count + 1, last_error = $2, \
                 last_delivery_at = CURRENT_TIMESTAMP \
             WHERE id = $1 RETURNING failure_count",
        )
        .bind(row.webhook_id)
        .bind(err)
        .fetch_one(pool)
        .await?;

        if failure_count as i64 >= cfg.disable_threshold {
            warn!(
                "admin_webhook_delivery: auto-disabling webhook {} after {} consecutive failures",
                row.webhook_id, failure_count
            );
            sqlx::query("UPDATE admin_webhook SET enabled = FALSE WHERE id = $1")
                .bind(row.webhook_id)
                .execute(pool)
                .await?;
        }
    } else {
        // Retry with exponential backoff (capped at 1 hour).
        let exp = (new_attempt as u32).min(16);
        let backoff_secs = (60i64 * 2i64.pow(exp)).min(3600);
        let next = chrono::Utc::now() + chrono::Duration::seconds(backoff_secs);
        sqlx::query(
            "UPDATE admin_webhook_delivery \
             SET attempt = $2, response_code = $3, response_body = $4, next_attempt_at = $5 \
             WHERE id = $1",
        )
        .bind(row.delivery_id)
        .bind(new_attempt)
        .bind(code)
        .bind(err)
        .bind(next)
        .execute(pool)
        .await?;
    }
    Ok(())
}

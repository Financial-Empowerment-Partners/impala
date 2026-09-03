//! Background worker for the admin webhook event feed.
//!
//! Runs in-process (spawned from `run_server`, no SNS/SQS dependency) — on
//! EVERY server task, so cross-task duplication is a design constraint, not
//! an accident. Each tick:
//!   1. **Fan-out**: turn undispatched `event_outbox` rows into per-webhook
//!      `admin_webhook_delivery` rows (respecting each webhook's
//!      `event_types`). Idempotent (`ON CONFLICT DO NOTHING`), so two tasks
//!      fanning out the same event is harmless.
//!   2. **Claim**: LEASE the due pending deliveries — one `UPDATE` that
//!      pushes `next_attempt_at` out by `ADMIN_WEBHOOK_DELIVERY_LEASE_SECS`
//!      for rows selected `FOR UPDATE ... SKIP LOCKED`, at most
//!      `ADMIN_WEBHOOK_MAX_PER_WEBHOOK_PER_TICK` per webhook. A row stays
//!      `pending` (no new status, no sweep, partial index intact): a holder
//!      that dies simply lets its lease lapse and the row is retried as if
//!      it had never been claimed. Before this, every task ran a plain
//!      SELECT and two workers produced four POSTs for two events.
//!   3. **Deliver**: POST with an HMAC-SHA256 signature — concurrently
//!      across webhooks, sequentially (id order) within one — each with its
//!      own timeout. The outcome marks are guarded (`status = 'pending'`,
//!      plus the attempt counter as a CAS) so a late duplicate can never
//!      double-mark. Retries use exponential backoff; `failed` after
//!      `max_attempts`; a webhook auto-disables after `disable_threshold`
//!      consecutive terminal failures.
//!   4. **Prune** (hourly, bounded): age out DISPATCHED outbox rows that have
//!      no pending delivery, and TERMINAL delivery rows. Never money tables.
//!
//! Receiver semantics are **at-least-once**: a response lost in transit, or a
//! lease that lapsed under a slow receiver, re-POSTs the same event. The
//! `X-Impala-Event-Id` header (and `event_id` in the body) is stable across
//! retries and is the dedup key — documented under openapi.yaml's webhook tag.
//!
//! The URL is re-validated against SSRF rules at delivery time (defense-in-depth).

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::constants::{
    ADMIN_WEBHOOK_CLAIM_LIMIT, ADMIN_WEBHOOK_DELIVERY_CONCURRENCY,
    ADMIN_WEBHOOK_DELIVERY_LEASE_SECS, ADMIN_WEBHOOK_DELIVERY_RETENTION_SECS,
    ADMIN_WEBHOOK_MAX_PER_WEBHOOK_PER_TICK, ADMIN_WEBHOOK_POST_TIMEOUT_SECS,
    EVENT_OUTBOX_PRUNE_BATCH, EVENT_OUTBOX_PRUNE_INTERVAL_SECS, EVENT_OUTBOX_PRUNE_MAX_ROUNDS,
    EVENT_OUTBOX_RETENTION_SECS,
};
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

/// The claim: lease due pending rows in one statement.
///
/// The LATERAL subquery takes up to `$2` rows per enabled webhook (so one
/// flooded receiver cannot starve the others of the `$3` global budget),
/// locking them `FOR UPDATE OF d SKIP LOCKED` — `OF d` because the query
/// joins `admin_webhook`, whose rows must NOT be locked (that would serialize
/// every task on the webhook row and block admin edits). The UPDATE then
/// pushes `next_attempt_at` out by the lease (`$1`, seconds) and RETURNs the
/// ids only; the payload is re-selected by id because RETURNING can yield
/// delivery columns alone. Status stays `pending`. Validated against
/// Postgres 16 with two concurrent sessions: disjoint per-webhook slices.
const CLAIM_DUE_SQL: &str = "UPDATE admin_webhook_delivery AS t \
     SET next_attempt_at = CURRENT_TIMESTAMP + make_interval(secs => $1) \
     FROM ( \
         SELECT due.id \
         FROM admin_webhook w \
         CROSS JOIN LATERAL ( \
             SELECT d.id \
             FROM admin_webhook_delivery d \
             WHERE d.webhook_id = w.id \
               AND d.status = 'pending' \
               AND d.next_attempt_at <= CURRENT_TIMESTAMP \
             ORDER BY d.id \
             LIMIT $2 \
             FOR UPDATE OF d SKIP LOCKED \
         ) due \
         WHERE w.enabled = TRUE \
         ORDER BY due.id \
         LIMIT $3 \
     ) claimed \
     WHERE t.id = claimed.id \
     RETURNING t.id";

/// Payloads for the rows this task just leased, by id.
const CLAIMED_PAYLOAD_SQL: &str = "SELECT d.id AS delivery_id, d.attempt, \
            w.id AS webhook_id, w.url, w.secret, \
            e.id AS event_id, e.event_type, e.account_id, e.payload, \
            EXTRACT(EPOCH FROM e.created_at)::bigint AS created_ts \
     FROM admin_webhook_delivery d \
     JOIN admin_webhook w ON w.id = d.webhook_id \
     JOIN event_outbox e ON e.id = d.event_id \
     WHERE d.id = ANY($1) \
     ORDER BY d.id";

/// Success mark. Guarded on `pending`: a late duplicate (another holder
/// already closed the row) matches nothing and must not touch the webhook's
/// failure counter either.
const MARK_DELIVERED_SQL: &str = "UPDATE admin_webhook_delivery \
     SET status = 'delivered', attempt = attempt + 1, response_code = $2, \
         delivered_at = CURRENT_TIMESTAMP \
     WHERE id = $1 AND status = 'pending'";

/// Terminal failure. Guarded on `pending` AND on the attempt counter the
/// holder claimed at (`$5`): only the holder whose claim is current can
/// advance it, so a stale holder cannot fail a row a fresh one is retrying.
const MARK_FAILED_SQL: &str = "UPDATE admin_webhook_delivery \
     SET status = 'failed', attempt = $2, response_code = $3, response_body = $4 \
     WHERE id = $1 AND status = 'pending' AND attempt = $5";

/// Retry scheduling, same CAS (`$6` = the claimed attempt counter).
const MARK_RETRY_SQL: &str = "UPDATE admin_webhook_delivery \
     SET attempt = $2, response_code = $3, response_body = $4, next_attempt_at = $5 \
     WHERE id = $1 AND status = 'pending' AND attempt = $6";

/// Age out terminal delivery rows, oldest first, `$2` per statement.
const PRUNE_DELIVERIES_SQL: &str = "DELETE FROM admin_webhook_delivery \
     WHERE id IN ( \
         SELECT id FROM admin_webhook_delivery \
         WHERE status IN ('delivered', 'failed') \
           AND created_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
         ORDER BY id LIMIT $2 \
     )";

/// Age out dispatched outbox rows, oldest first, `$2` per statement. An
/// event that still has a PENDING delivery is kept whatever its age: the
/// delivery FK cascades on delete, so pruning it would silently drop an
/// undelivered event.
const PRUNE_OUTBOX_SQL: &str = "DELETE FROM event_outbox \
     WHERE id IN ( \
         SELECT e.id FROM event_outbox e \
         WHERE e.dispatched = TRUE \
           AND e.created_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
           AND NOT EXISTS ( \
               SELECT 1 FROM admin_webhook_delivery d \
               WHERE d.event_id = e.id AND d.status = 'pending' \
           ) \
         ORDER BY e.id LIMIT $2 \
     )";

/// Worker entry point. Loops until `cancel` fires.
pub async fn run(pool: PgPool, cfg: DeliveryConfig, cancel: CancellationToken) {
    // Webhook URLs are caller-supplied, so this client dials through the SSRF
    // egress guard (vets every resolved address) and refuses redirects — a
    // followed 302 would otherwise walk a validated URL straight to an
    // internal address with no DNS control needed. The client timeout is the
    // per-POST budget; `deliver_one` also wraps each request in it.
    let client = match crate::ssrf::guarded_client(ADMIN_WEBHOOK_POST_TIMEOUT_SECS) {
        Ok(c) => c,
        Err(e) => {
            error!("admin_webhook_delivery: failed to build HTTP client: {}", e);
            return;
        }
    };

    info!(
        "admin_webhook_delivery: started (poll={}s, max_attempts={}, disable_threshold={}, \
         lease={}s, per_webhook={}, concurrency={})",
        cfg.poll_secs,
        cfg.max_attempts,
        cfg.disable_threshold,
        ADMIN_WEBHOOK_DELIVERY_LEASE_SECS,
        ADMIN_WEBHOOK_MAX_PER_WEBHOOK_PER_TICK,
        ADMIN_WEBHOOK_DELIVERY_CONCURRENCY
    );

    // First prune on the first tick, then hourly. Every task runs it; the
    // statements are bounded and idempotent, so overlap only costs work.
    let mut next_prune = Instant::now();
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
                if let Err(e) = deliver_due(&pool, &client, &cfg, &cancel).await {
                    error!("admin_webhook_delivery: delivery error: {}", e);
                }
                if Instant::now() >= next_prune {
                    next_prune = Instant::now()
                        + Duration::from_secs(EVENT_OUTBOX_PRUNE_INTERVAL_SECS);
                    if let Err(e) = prune(&pool).await {
                        error!("admin_webhook_delivery: prune error: {}", e);
                    }
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

/// Lease the due pending rows, then deliver them: concurrently across
/// webhooks, sequentially within each.
async fn deliver_due(
    pool: &PgPool,
    client: &reqwest::Client,
    cfg: &DeliveryConfig,
    cancel: &CancellationToken,
) -> Result<(), sqlx::Error> {
    let claimed_at = Instant::now();
    let ids: Vec<i64> = sqlx::query_scalar(CLAIM_DUE_SQL)
        .bind(ADMIN_WEBHOOK_DELIVERY_LEASE_SECS as f64)
        .bind(ADMIN_WEBHOOK_MAX_PER_WEBHOOK_PER_TICK)
        .bind(ADMIN_WEBHOOK_CLAIM_LIMIT)
        .fetch_all(pool)
        .await?;
    if ids.is_empty() {
        return Ok(());
    }
    // Measured from BEFORE the claim statement ran: the lease started no
    // later than that, so this deadline is conservative.
    let lease_ends = claimed_at + Duration::from_secs(ADMIN_WEBHOOK_DELIVERY_LEASE_SECS as u64);
    let claimed = ids.len();

    let rows: Vec<DueDelivery> = sqlx::query_as(CLAIMED_PAYLOAD_SQL)
        .bind(ids)
        .fetch_all(pool)
        .await?;
    // Group per webhook; id order within a group is the payload query's.
    let mut per_webhook: BTreeMap<i64, Vec<DueDelivery>> = BTreeMap::new();
    for row in rows {
        per_webhook.entry(row.webhook_id).or_default().push(row);
    }
    debug!(
        "admin_webhook_delivery: leased {} delivery(ies) across {} webhook(s)",
        claimed,
        per_webhook.len()
    );

    futures::stream::iter(per_webhook.into_values())
        .for_each_concurrent(ADMIN_WEBHOOK_DELIVERY_CONCURRENCY, |batch| async move {
            deliver_batch(pool, client, cfg, cancel, lease_ends, batch).await;
        })
        .await;
    Ok(())
}

/// What to do with the rest of a webhook's batch after one delivery.
enum Next {
    Continue,
    /// The receiver is unreachable or shedding load; the rest of its batch
    /// would only burn timeouts. Leased rows come back when the lease lapses.
    StopBatch,
}

/// One webhook's leased rows, in id order, each POST bounded by its own
/// timeout. Errors are per row and logged: one row's DB failure must not
/// take down the other webhooks' batches.
async fn deliver_batch(
    pool: &PgPool,
    client: &reqwest::Client,
    cfg: &DeliveryConfig,
    cancel: &CancellationToken,
    lease_ends: Instant,
    batch: Vec<DueDelivery>,
) {
    let post_budget = Duration::from_secs(ADMIN_WEBHOOK_POST_TIMEOUT_SECS);
    for (i, row) in batch.iter().enumerate() {
        // Shutdown: start nothing new. Leased rows retry after the lease.
        if cancel.is_cancelled() {
            return;
        }
        // Never START a request that could outlast the lease: a POST still in
        // flight when another task re-claims the row is exactly the duplicate
        // the lease exists to prevent. (The compile-time assert on the
        // constants makes this unreachable at nominal speed; it guards a
        // stalled database or scheduler.)
        if Instant::now() + post_budget >= lease_ends {
            warn!(
                "admin_webhook_delivery: webhook {} lease nearly lapsed; deferring {} row(s) \
                 to the next lease",
                row.webhook_id,
                batch.len() - i
            );
            return;
        }
        match deliver_one(pool, client, cfg, row).await {
            Ok(Next::Continue) => {}
            Ok(Next::StopBatch) => return,
            Err(e) => {
                error!(
                    "admin_webhook_delivery: webhook {} delivery {}: {}",
                    row.webhook_id, row.delivery_id, e
                );
                return;
            }
        }
    }
}

/// Sign and POST one delivery, then record the outcome.
async fn deliver_one(
    pool: &PgPool,
    client: &reqwest::Client,
    cfg: &DeliveryConfig,
    row: &DueDelivery,
) -> Result<Next, sqlx::Error> {
    // Re-validate the URL at delivery time (DNS-rebinding / SSRF defense).
    if let Err(e) = crate::validate::validate_callback_url(&row.url) {
        warn!(
            "admin_webhook_delivery: webhook {} url failed SSRF check: {:?}",
            row.webhook_id, e
        );
        mark_failure(pool, row, cfg, None, "URL failed SSRF validation").await?;
        return Ok(Next::Continue);
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

    let request = async {
        let resp = client
            .post(&row.url)
            .header("Content-Type", "application/json")
            .header("X-Impala-Webhook-Id", row.webhook_id.to_string())
            .header("X-Impala-Event-Id", row.event_id.to_string())
            .header("X-Impala-Timestamp", ts.to_string())
            .header("X-Impala-Signature", format!("sha256={}", signature))
            .body(body_str)
            .send()
            .await?;
        let status = resp.status();
        // Only a failure's body is kept — a 500-char snippet for the audit row.
        let snippet: String = if status.is_success() {
            String::new()
        } else {
            resp.text()
                .await
                .unwrap_or_default()
                .chars()
                .take(500)
                .collect()
        };
        Ok::<_, reqwest::Error>((status, snippet))
    };

    match tokio::time::timeout(
        Duration::from_secs(ADMIN_WEBHOOK_POST_TIMEOUT_SECS),
        request,
    )
    .await
    {
        Ok(Ok((status, _))) if status.is_success() => {
            mark_delivered(pool, row, status.as_u16() as i32).await?;
            Ok(Next::Continue)
        }
        Ok(Ok((status, snippet))) => {
            let code = status.as_u16() as i32;
            mark_failure(
                pool,
                row,
                cfg,
                Some(code),
                &format!("HTTP {}: {}", code, snippet),
            )
            .await?;
            // A receiver shedding load must not be hammered with the rest of
            // its batch; any other rejection is that one event's business.
            Ok(
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                {
                    Next::StopBatch
                } else {
                    Next::Continue
                },
            )
        }
        Ok(Err(e)) => {
            mark_failure(pool, row, cfg, None, &format!("request error: {}", e)).await?;
            Ok(Next::StopBatch)
        }
        Err(_elapsed) => {
            mark_failure(
                pool,
                row,
                cfg,
                None,
                &format!(
                    "request timed out after {}s",
                    ADMIN_WEBHOOK_POST_TIMEOUT_SECS
                ),
            )
            .await?;
            Ok(Next::StopBatch)
        }
    }
}

async fn mark_delivered(pool: &PgPool, row: &DueDelivery, code: i32) -> Result<(), sqlx::Error> {
    let updated = sqlx::query(MARK_DELIVERED_SQL)
        .bind(row.delivery_id)
        .bind(code)
        .execute(pool)
        .await?;
    if updated.rows_affected() == 0 {
        // A late duplicate: another holder already closed this row. The
        // receiver saw the event twice (at-least-once); nothing to record.
        debug!(
            "admin_webhook_delivery: delivery {} already closed; ignoring late success",
            row.delivery_id
        );
        return Ok(());
    }

    // Success resets the consecutive-failure counter.
    sqlx::query(
        "UPDATE admin_webhook \
         SET failure_count = 0, last_error = NULL, last_delivery_at = CURRENT_TIMESTAMP \
         WHERE id = $1",
    )
    .bind(row.webhook_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Retry delay after `new_attempt` failures: 60s doubling per attempt,
/// capped at one hour.
fn backoff_secs(new_attempt: i32) -> i64 {
    let exp = (new_attempt.max(0) as u32).min(16);
    (60i64 * 2i64.pow(exp)).min(3600)
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
        // Terminal: mark the delivery failed and bump the webhook's failure
        // count — but only for a REAL transition. A late duplicate must not
        // count a second failure against the receiver.
        let updated = sqlx::query(MARK_FAILED_SQL)
            .bind(row.delivery_id)
            .bind(new_attempt)
            .bind(code)
            .bind(err)
            .bind(row.attempt)
            .execute(pool)
            .await?;
        if updated.rows_affected() == 0 {
            debug!(
                "admin_webhook_delivery: delivery {} no longer pending at attempt {}; \
                 ignoring late failure",
                row.delivery_id, row.attempt
            );
            return Ok(());
        }

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
        let next = chrono::Utc::now() + chrono::Duration::seconds(backoff_secs(new_attempt));
        let updated = sqlx::query(MARK_RETRY_SQL)
            .bind(row.delivery_id)
            .bind(new_attempt)
            .bind(code)
            .bind(err)
            .bind(next)
            .bind(row.attempt)
            .execute(pool)
            .await?;
        if updated.rows_affected() == 0 {
            debug!(
                "admin_webhook_delivery: delivery {} no longer pending at attempt {}; \
                 ignoring late failure",
                row.delivery_id, row.attempt
            );
        }
    }
    Ok(())
}

/// Bounded, age-based housekeeping. Terminal deliveries first, then
/// dispatched outbox rows with nothing pending; at most
/// `EVENT_OUTBOX_PRUNE_MAX_ROUNDS` batches of `EVENT_OUTBOX_PRUNE_BATCH` per
/// table per run, so a backlog drains over a few hours instead of holding
/// one statement open. Never money tables.
async fn prune(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut deliveries = 0u64;
    let mut events = 0u64;
    for _ in 0..EVENT_OUTBOX_PRUNE_MAX_ROUNDS {
        let n = sqlx::query(PRUNE_DELIVERIES_SQL)
            .bind(ADMIN_WEBHOOK_DELIVERY_RETENTION_SECS as f64)
            .bind(EVENT_OUTBOX_PRUNE_BATCH)
            .execute(pool)
            .await?
            .rows_affected();
        deliveries += n;
        if n < EVENT_OUTBOX_PRUNE_BATCH as u64 {
            break;
        }
    }
    for _ in 0..EVENT_OUTBOX_PRUNE_MAX_ROUNDS {
        let n = sqlx::query(PRUNE_OUTBOX_SQL)
            .bind(EVENT_OUTBOX_RETENTION_SECS as f64)
            .bind(EVENT_OUTBOX_PRUNE_BATCH)
            .execute(pool)
            .await?
            .rows_affected();
        events += n;
        if n < EVENT_OUTBOX_PRUNE_BATCH as u64 {
            break;
        }
    }
    if deliveries > 0 || events > 0 {
        info!(
            "admin_webhook_delivery: pruned {} terminal delivery row(s) and {} dispatched \
             outbox row(s) past retention",
            deliveries, events
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_leases_under_skip_locked_and_keeps_rows_pending() {
        // The claim is ONE statement whose candidates are locked with SKIP
        // LOCKED — a second task skips rather than selects the same rows
        // (the two-workers-four-POSTs bug) — and it pushes the lease out
        // instead of introducing a status, so the partial due-index and the
        // lease-lapse retry both keep working with no sweep.
        assert!(CLAIM_DUE_SQL.starts_with("UPDATE admin_webhook_delivery"));
        assert!(CLAIM_DUE_SQL.contains("FOR UPDATE OF d SKIP LOCKED"));
        assert!(CLAIM_DUE_SQL
            .contains("SET next_attempt_at = CURRENT_TIMESTAMP + make_interval(secs => $1)"));
        assert!(!CLAIM_DUE_SQL.contains("SET status"));
        assert!(!CLAIM_DUE_SQL.contains("'claimed'"));
        assert!(CLAIM_DUE_SQL.contains("d.status = 'pending'"));
        assert!(CLAIM_DUE_SQL.contains("d.next_attempt_at <= CURRENT_TIMESTAMP"));
        assert!(CLAIM_DUE_SQL.contains("w.enabled = TRUE"));
        // Per-webhook cap ($2) inside the LATERAL, global cap ($3) outside,
        // exactly three binds.
        assert!(CLAIM_DUE_SQL.contains("CROSS JOIN LATERAL"));
        assert!(CLAIM_DUE_SQL.contains("LIMIT $2"));
        assert!(CLAIM_DUE_SQL.contains("LIMIT $3"));
        assert!(!CLAIM_DUE_SQL.contains("$4"));
        assert!(CLAIM_DUE_SQL.ends_with("RETURNING t.id"));
    }

    #[test]
    fn payloads_are_loaded_by_leased_id_only() {
        assert!(CLAIMED_PAYLOAD_SQL.contains("WHERE d.id = ANY($1)"));
        assert!(CLAIMED_PAYLOAD_SQL.ends_with("ORDER BY d.id"));
        assert!(!CLAIMED_PAYLOAD_SQL.contains("$2"));
        // Every DueDelivery column, by alias — sqlx maps FromRow by name at
        // runtime, so a missing alias is a runtime failure.
        for col in [
            "d.id AS delivery_id",
            "d.attempt",
            "w.id AS webhook_id",
            "w.url",
            "w.secret",
            "e.id AS event_id",
            "e.event_type",
            "e.account_id",
            "e.payload",
            "AS created_ts",
        ] {
            assert!(CLAIMED_PAYLOAD_SQL.contains(col), "missing {}", col);
        }
    }

    #[test]
    fn outcome_marks_are_guarded_against_late_duplicates() {
        // A holder whose lease lapsed under a slow receiver may report after
        // a fresh holder already did; the guards make that report a no-op
        // instead of a double-mark (and a double-counted failure).
        assert!(MARK_DELIVERED_SQL.ends_with("WHERE id = $1 AND status = 'pending'"));
        assert!(MARK_FAILED_SQL.ends_with("WHERE id = $1 AND status = 'pending' AND attempt = $5"));
        assert!(MARK_RETRY_SQL.ends_with("WHERE id = $1 AND status = 'pending' AND attempt = $6"));
        // Placeholder counts match the bind sites — sqlx will not check.
        assert!(!MARK_DELIVERED_SQL.contains("$3"));
        assert!(!MARK_FAILED_SQL.contains("$6"));
        assert!(!MARK_RETRY_SQL.contains("$7"));
    }

    #[test]
    fn prune_touches_only_terminal_deliveries_and_pending_free_dispatched_events() {
        assert!(PRUNE_DELIVERIES_SQL.starts_with("DELETE FROM admin_webhook_delivery"));
        assert!(PRUNE_DELIVERIES_SQL.contains("status IN ('delivered', 'failed')"));
        assert!(PRUNE_DELIVERIES_SQL.contains("make_interval(secs => $1)"));
        assert!(PRUNE_DELIVERIES_SQL.contains("LIMIT $2"));

        assert!(PRUNE_OUTBOX_SQL.starts_with("DELETE FROM event_outbox"));
        assert!(PRUNE_OUTBOX_SQL.contains("e.dispatched = TRUE"));
        // The delivery FK cascades: an event with a pending delivery must
        // never be pruned, or the undelivered event silently disappears.
        assert!(PRUNE_OUTBOX_SQL.contains("NOT EXISTS"));
        assert!(PRUNE_OUTBOX_SQL.contains("d.event_id = e.id AND d.status = 'pending'"));
        assert!(PRUNE_OUTBOX_SQL.contains("LIMIT $2"));

        // Never money tables.
        for sql in [PRUNE_DELIVERIES_SQL, PRUNE_OUTBOX_SQL] {
            for table in [
                "conversion_reserve",
                "exchange_order",
                "transaction",
                "managed_seed",
                "impala_account",
            ] {
                assert!(!sql.contains(table), "prune must not touch {}", table);
            }
        }
    }

    #[test]
    fn backoff_doubles_from_two_minutes_and_caps_at_an_hour() {
        assert_eq!(backoff_secs(1), 120);
        assert_eq!(backoff_secs(2), 240);
        assert_eq!(backoff_secs(5), 1920);
        assert_eq!(backoff_secs(6), 3600);
        assert_eq!(backoff_secs(40), 3600);
        assert_eq!(backoff_secs(-3), 60);
    }
}

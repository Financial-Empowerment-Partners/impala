//! Inbound exchange-provider webhooks (`POST /webhooks/*`).
//!
//! The first UNauthenticated raw-body endpoints in the codebase: each handler
//! extracts `HeaderMap` + `Bytes` (never `Json<T>` — re-serialization would
//! not byte-match the signed payload), verifies the provider's signature over
//! the RAW bytes BEFORE any semantic JSON parsing, and enforces its own
//! Redis rate limit since the auth extractor's per-account limit does not
//! apply here. All verification failures return a uniform 401 (no oracle).
//!
//! Providers retry on non-2xx (Changelly up to 23 times/hour), so an unknown
//! order is acknowledged with 200 — it may belong to another environment or
//! predate this deployment. Order updates run under the terminal-status SQL
//! guard: a replayed or late webhook can never regress a final state.

use axum::body::Bytes;
use axum::extract::Extension;
use axum::http::HeaderMap;
use axum::Json;
use log::{error, info, warn};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::client_source::ClientSource;
use crate::constants::{
    EXCHANGE_PROVIDER_CHANGELLY_FIAT, EXCHANGE_PROVIDER_OWLPAY, EXCHANGE_WEBHOOK_RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::exchange::changelly::ChangellyFiat;
use crate::exchange::owlpay::{map_owlpay_status, OwlPayProvider};
use crate::exchange::reconcile::{
    json_decimal_string, snapshot_from_fiat_order, terminal_statuses,
};
use crate::telemetry::AppMetrics;

/// OwlPay Harbor signature header (`t=<unix>,v1=<hex>`).
const OWLPAY_SIGNATURE_HEADER: &str = "harbor-signature";

/// Changelly Fiat callback headers.
const CHANGELLY_API_KEY_HEADER: &str = "x-callback-api-key";
const CHANGELLY_SIGNATURE_HEADER: &str = "x-callback-signature";

/// Per-source budget for requests that have NOT yet proven a signature.
/// Forged traffic must never be able to spend the verified bucket, so the two
/// are accounted separately: unverified requests are charged here (keyed by
/// client IP, tight) before any crypto work, and only signature-verified
/// requests touch the per-provider bucket below.
const WEBHOOK_UNVERIFIED_RATE_LIMIT_MAX: u64 = 20;

/// Rate-limit an unverified inbound webhook by client source, then (once the
/// signature checks out) charge the shared per-provider bucket.
///
/// Keying the pre-verification limit on the source means a flood from one
/// forger cannot lock out the real provider, while still bounding the
/// signature-verification work any single source can force. The source is
/// the shared `ClientSource` attribution (`client_source.rs`): the
/// `X-Forwarded-For` entry the trusted proxy appended, never the leftmost
/// one or `X-Real-Ip` — both are sender-written, and a sender-chosen key
/// would hand every forger its own fresh bucket.
async fn check_webhook_rate_limits(
    redis_pool: &Arc<deadpool_redis::Pool>,
    scope: &str,
    source: &str,
) -> Result<(), AppError> {
    crate::redis_helpers::check_rate_limit(
        redis_pool,
        scope,
        source,
        WEBHOOK_UNVERIFIED_RATE_LIMIT_MAX,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await
}

/// Order UPDATE applied by verified webhooks, lifted to a const so the test
/// below pins the SQL-side terminal guard (`$8` binds the terminal statuses)
/// — no webhook, however late or replayed, may regress a final state.
const WEBHOOK_ORDER_UPDATE_SQL: &str = "UPDATE exchange_order \
     SET status = $1, provider_status = $2, amount_to = COALESCE($3, amount_to), \
         transfer_instructions = COALESCE($4, transfer_instructions), \
         provider_payload = COALESCE($5, provider_payload), last_error = NULL \
     WHERE provider = $6 AND provider_order_id = $7 \
       AND NOT (status = ANY($8))";

/// Map a DB error from the webhook path to an AppError, logging the context.
fn webhook_db_error(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e| {
        error!("exchange_webhook: {} error: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

// ── Payload extraction (pure, unit-tested) ─────────────────────────────

/// A parsed (already signature-verified) OwlPay event envelope.
pub(crate) enum OwlPayEvent<'a> {
    /// `data.object == "transfer"` with the fields we track.
    Transfer {
        uuid: &'a str,
        status: &'a str,
        data: &'a serde_json::Value,
    },
    /// Any other event family (customer.*, wallet.*, ...) — acknowledged
    /// and skipped.
    Other,
}

/// Classify an OwlPay webhook envelope (`{data: {object, uuid, status, ...}}`).
/// A transfer object missing its uuid/status is malformed, not ignorable.
pub(crate) fn parse_owlpay_event(event: &serde_json::Value) -> Result<OwlPayEvent<'_>, AppError> {
    let data = &event["data"];
    if data["object"].as_str() != Some("transfer") {
        return Ok(OwlPayEvent::Other);
    }
    match (data["uuid"].as_str(), data["status"].as_str()) {
        (Some(uuid), Some(status)) => Ok(OwlPayEvent::Transfer { uuid, status, data }),
        _ => Err(AppError::BadRequest("Invalid webhook payload".to_string())),
    }
}

/// Destination amount from an OwlPay transfer event: `destination.amount`,
/// falling back to `receipt.final_amount` once settlement details exist.
pub(crate) fn owlpay_destination_amount(data: &serde_json::Value) -> Option<String> {
    json_decimal_string(&data["destination"]["amount"])
        .or_else(|| json_decimal_string(&data["receipt"]["final_amount"]))
}

/// Extract `orderId` from a Changelly callback body. The callback signature
/// covers ONLY the compact string `{"orderId":"<id>"}`, so this is the one
/// field read before verification (and the only one used afterwards).
pub(crate) fn changelly_callback_order_id(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("orderId")?.as_str().map(str::to_owned)
}

// ── Shared guarded update ──────────────────────────────────────────────

/// A verified provider state change to apply to the local order row.
struct WebhookOrderUpdate<'a> {
    provider: &'static str,
    provider_order_id: &'a str,
    status: &'static str,
    provider_status: &'a str,
    amount_to: Option<String>,
    transfer_instructions: Option<serde_json::Value>,
    provider_payload: Option<serde_json::Value>,
}

/// Apply a webhook update: lock the row, UPDATE under the terminal guard,
/// emit `ExchangeOrderUpdated` on a real status change, commit, metrics
/// after. Unknown orders return `Ok` (the handler acks with 200 — providers
/// retry on non-2xx and the order may not be ours to know).
async fn apply_webhook_update(
    pool: &PgPool,
    metrics: &AppMetrics,
    upd: WebhookOrderUpdate<'_>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(webhook_db_error("begin"))?;

    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT order_id, payala_account_id, status FROM exchange_order \
         WHERE provider = $1 AND provider_order_id = $2 FOR UPDATE",
    )
    .bind(upd.provider)
    .bind(upd.provider_order_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(webhook_db_error("order lookup"))?;

    let Some((order_id, account_id, old_status)) = row else {
        info!(
            "exchange_webhook: unknown {} order {} — acknowledged",
            upd.provider, upd.provider_order_id
        );
        return Ok(());
    };

    let res = sqlx::query(WEBHOOK_ORDER_UPDATE_SQL)
        .bind(upd.status)
        .bind(upd.provider_status)
        .bind(&upd.amount_to)
        .bind(&upd.transfer_instructions)
        .bind(&upd.provider_payload)
        .bind(upd.provider)
        .bind(upd.provider_order_id)
        .bind(terminal_statuses())
        .execute(&mut *tx)
        .await
        .map_err(webhook_db_error("order update"))?;
    if res.rows_affected() == 0 {
        // Already terminal — the guard refused the write. Ack and move on.
        info!(
            "exchange_webhook: order {} already terminal ({}); update to '{}' ignored",
            order_id, old_status, upd.status
        );
        return Ok(());
    }

    let changed = old_status != upd.status;
    if changed {
        crate::events::emit_event(
            &mut tx,
            &crate::events::AccountEvent::ExchangeOrderUpdated {
                account_id,
                order_id: order_id.to_string(),
                provider: upd.provider.to_string(),
                status: upd.status.to_string(),
                provider_status: upd.provider_status.to_string(),
            },
        )
        .await?;
    }

    tx.commit().await.map_err(webhook_db_error("commit"))?;

    // Metrics only after commit — nothing may claim state that didn't land.
    if changed {
        metrics.record_exchange_order_update(upd.provider, upd.status, "webhook");
        info!(
            "exchange_webhook: order {} {} -> {} (provider_status={})",
            order_id, old_status, upd.status, upd.provider_status
        );
    }
    Ok(())
}

// ── Handlers ───────────────────────────────────────────────────────────

/// OwlPay Harbor webhook (`POST /webhooks/owlpay`). Unauthenticated;
/// trust derives entirely from the `harbor-signature` HMAC over the raw body
/// (timestamped, replay-windowed — verified before any parsing).
pub async fn owlpay_webhook(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    owlpay: Option<Extension<Arc<OwlPayProvider>>>,
    ClientSource(source): ClientSource,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("POST /webhooks/owlpay: {} bytes", body.len());

    let provider = owlpay
        .as_ref()
        .map(|Extension(p)| p)
        .ok_or_else(|| AppError::BadRequest("owlpay is not configured".to_string()))?;

    // Charged to the caller's own bucket, before any crypto work.
    check_webhook_rate_limits(&redis_pool, "webhook_owlpay_unverified", &source).await?;

    let signature = headers
        .get(OWLPAY_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!("owlpay_webhook: missing {} header", OWLPAY_SIGNATURE_HEADER);
            AppError::Unauthorized
        })?;

    // Verify over the RAW bytes before any parsing (constant-time compare +
    // replay window inside verify_webhook). Uniform 401 on any failure.
    provider.verify_webhook(signature, &body, chrono::Utc::now().timestamp())?;

    // Signature proven: only now may this request spend the shared
    // per-provider budget, so forged traffic can never exhaust it.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "webhook_owlpay",
        "global",
        EXCHANGE_WEBHOOK_RATE_LIMIT_MAX,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Signature verified — the payload is now trusted; parse it.
    let event: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        warn!("owlpay_webhook: signed payload is not valid JSON: {}", e);
        AppError::BadRequest("Invalid webhook payload".to_string())
    })?;

    let (uuid, status_raw, data) = match parse_owlpay_event(&event)? {
        OwlPayEvent::Other => {
            info!(
                "owlpay_webhook: ignoring non-transfer event (object={:?})",
                event["data"]["object"].as_str()
            );
            return Ok(Json(json!({"status": "success"})));
        }
        OwlPayEvent::Transfer { uuid, status, data } => (uuid, status, data),
    };

    apply_webhook_update(
        &pool,
        &metrics,
        WebhookOrderUpdate {
            provider: EXCHANGE_PROVIDER_OWLPAY,
            provider_order_id: uuid,
            status: map_owlpay_status(status_raw),
            provider_status: status_raw,
            amount_to: owlpay_destination_amount(data),
            transfer_instructions: data
                .get("transfer_instructions")
                .filter(|v| !v.is_null())
                .cloned(),
            provider_payload: Some(data.clone()),
        },
    )
    .await?;

    Ok(Json(json!({"status": "success"})))
}

/// Changelly Fiat callback (`POST /webhooks/changelly`).
/// Unauthenticated; gated by a constant-time `x-callback-api-key` compare
/// plus the RSA `x-callback-signature`.
///
/// The signature covers ONLY `{"orderId":"..."}` — the rest of the payload
/// is cryptographically UNTRUSTED by design (doc-confirmed). After
/// verification the order state is re-fetched from the Fiat API and the DB
/// is updated exclusively from that fetched state.
pub async fn changelly_webhook(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    changelly_fiat: Option<Extension<Arc<ChangellyFiat>>>,
    ClientSource(source): ClientSource,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("POST /webhooks/changelly: {} bytes", body.len());

    let provider = changelly_fiat
        .as_ref()
        .map(|Extension(p)| p)
        .ok_or_else(|| AppError::BadRequest("changelly_fiat is not configured".to_string()))?;

    check_webhook_rate_limits(&redis_pool, "webhook_changelly_unverified", &source).await?;

    let presented_key = headers
        .get(CHANGELLY_API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!(
                "changelly_webhook: missing {} header",
                CHANGELLY_API_KEY_HEADER
            );
            AppError::Unauthorized
        })?;
    if !bool::from(
        presented_key
            .as_bytes()
            .ct_eq(provider.api_key().as_bytes()),
    ) {
        warn!("changelly_webhook: {} mismatch", CHANGELLY_API_KEY_HEADER);
        return Err(AppError::Unauthorized);
    }

    let signature = headers
        .get(CHANGELLY_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            warn!(
                "changelly_webhook: missing {} header",
                CHANGELLY_SIGNATURE_HEADER
            );
            AppError::Unauthorized
        })?;

    // The one field read pre-verification: the signature is computed over
    // the compact {"orderId":"..."} string, which verify_callback rebuilds.
    let Some(order_id) = changelly_callback_order_id(&body) else {
        warn!("changelly_webhook: payload has no orderId");
        return Err(AppError::BadRequest("Invalid webhook payload".to_string()));
    };
    provider.verify_callback(&order_id, signature)?;

    // Signature proven: only now spend the shared per-provider budget.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "webhook_changelly",
        "global",
        EXCHANGE_WEBHOOK_RATE_LIMIT_MAX,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Discard the untrusted payload; re-fetch the authoritative order state.
    let Some(order) = provider.get_order_by_id(&order_id).await? else {
        info!(
            "changelly_webhook: order {} not found at provider — acknowledged",
            order_id
        );
        return Ok(Json(json!({"status": "success"})));
    };
    let Some(snapshot) = snapshot_from_fiat_order(&order) else {
        warn!(
            "changelly_webhook: fetched order {} has no status field",
            order_id
        );
        return Err(AppError::InternalError(
            "Exchange provider error".to_string(),
        ));
    };

    apply_webhook_update(
        &pool,
        &metrics,
        WebhookOrderUpdate {
            provider: EXCHANGE_PROVIDER_CHANGELLY_FIAT,
            provider_order_id: &order_id,
            status: snapshot.status,
            provider_status: &snapshot.status_raw,
            amount_to: snapshot.amount_to.clone(),
            transfer_instructions: None,
            provider_payload: snapshot.payload.clone(),
        },
    )
    .await?;

    Ok(Json(json!({"status": "success"})))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unverified-webhook bucket is keyed by the shared source
    /// attribution: the `X-Forwarded-For` entry the trusted proxy (one hop,
    /// the ALB) APPENDED — the rightmost — never the leftmost, which is
    /// whatever the sender wrote and would give every forger a fresh bucket.
    #[test]
    fn test_webhook_source_is_the_rightmost_trusted_hop() {
        use crate::client_source::client_source;

        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "203.0.113.7, 70.41.3.18".parse().unwrap(),
        );
        assert_eq!(client_source(&h, None, 1), "70.41.3.18");

        // `X-Real-Ip` is sender-written on our path and is never consulted.
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(client_source(&h, None, 1), "unknown");
    }

    #[test]
    fn test_webhook_source_falls_back_for_unusable_headers() {
        use crate::client_source::client_source;
        let peer: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();

        // No proxy headers at all: the TCP peer, or the narrow shared
        // `unknown` bucket without one.
        assert_eq!(client_source(&HeaderMap::new(), Some(peer), 1), "10.0.0.1");
        assert_eq!(client_source(&HeaderMap::new(), None, 1), "unknown");

        // A forged/garbage value must not become its own rate-limit bucket —
        // otherwise an attacker mints unlimited quota by varying the header.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_source(&h, None, 1), "unknown");

        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "".parse().unwrap());
        h.insert("x-real-ip", "10.0.0.1".parse().unwrap());
        assert_eq!(client_source(&h, Some(peer), 1), "10.0.0.1");
    }

    /// A representative Harbor transfer event (transfer.status.* family).
    fn transfer_event() -> serde_json::Value {
        json!({
            "data": {
                "object": "transfer",
                "uuid": "transfer_9f3c",
                "status": "pending_harbor",
                "type": "on-ramp",
                "transfer_instructions": {
                    "account_number": "123456789",
                    "narrative": "HARBOR-REF-1"
                },
                "destination": {"asset": "USDC", "amount": "99.50", "chain": "stellar"},
                "receipt": {"final_amount": "99.10", "exchange_rate": "1.0"}
            }
        })
    }

    // ── OwlPay envelope parsing ────────────────────────────────────────

    #[test]
    fn test_parse_owlpay_event_transfer() {
        let event = transfer_event();
        match parse_owlpay_event(&event).unwrap() {
            OwlPayEvent::Transfer { uuid, status, data } => {
                assert_eq!(uuid, "transfer_9f3c");
                assert_eq!(status, "pending_harbor");
                assert_eq!(data["type"], "on-ramp");
            }
            OwlPayEvent::Other => panic!("expected a transfer event"),
        }
    }

    #[test]
    fn test_parse_owlpay_event_non_transfer_ignored() {
        // customer.* / wallet.* events (and a missing data.object) are
        // acknowledged, never an error.
        for event in [
            json!({"data": {"object": "customer", "uuid": "cus_1", "status": "verified"}}),
            json!({"data": {"object": "reconciliation"}}),
            json!({"data": {}}),
            json!({}),
        ] {
            assert!(matches!(
                parse_owlpay_event(&event).unwrap(),
                OwlPayEvent::Other
            ));
        }
    }

    #[test]
    fn test_parse_owlpay_event_malformed_transfer_rejected() {
        // A transfer object without uuid/status is malformed — 400, not 200.
        for event in [
            json!({"data": {"object": "transfer", "status": "completed"}}),
            json!({"data": {"object": "transfer", "uuid": "transfer_1"}}),
            json!({"data": {"object": "transfer", "uuid": 42, "status": "completed"}}),
        ] {
            assert!(parse_owlpay_event(&event).is_err());
        }
    }

    #[test]
    fn test_owlpay_destination_amount_prefers_destination() {
        let event = transfer_event();
        assert_eq!(
            owlpay_destination_amount(&event["data"]).as_deref(),
            Some("99.50")
        );
    }

    #[test]
    fn test_owlpay_destination_amount_receipt_fallback() {
        let data = json!({
            "object": "transfer",
            "receipt": {"final_amount": 42.5}
        });
        assert_eq!(owlpay_destination_amount(&data).as_deref(), Some("42.5"));
        assert!(owlpay_destination_amount(&json!({"object": "transfer"})).is_none());
    }

    // ── Changelly callback parsing ─────────────────────────────────────

    #[test]
    fn test_changelly_callback_order_id() {
        let body = br#"{"orderId":"b3f7e8c2","status":"complete","payoutAmount":"97.30"}"#;
        assert_eq!(
            changelly_callback_order_id(body).as_deref(),
            Some("b3f7e8c2")
        );
    }

    #[test]
    fn test_changelly_callback_order_id_rejects_malformed() {
        assert!(changelly_callback_order_id(br#"{"status":"complete"}"#).is_none());
        assert!(changelly_callback_order_id(br#"{"orderId":42}"#).is_none());
        assert!(changelly_callback_order_id(b"not json at all").is_none());
        assert!(changelly_callback_order_id(b"").is_none());
    }

    // ── SQL shape pins ─────────────────────────────────────────────────

    /// Pins the SQL-side terminal guard and the update key: no webhook may
    /// regress a terminal status, and rows are addressed by
    /// (provider, provider_order_id) — never by client-supplied ids.
    #[test]
    fn test_webhook_update_sql_shape() {
        assert!(WEBHOOK_ORDER_UPDATE_SQL.contains("AND NOT (status = ANY($8))"));
        assert!(WEBHOOK_ORDER_UPDATE_SQL.contains("provider = $6 AND provider_order_id = $7"));
        assert!(WEBHOOK_ORDER_UPDATE_SQL.contains("amount_to = COALESCE($3, amount_to)"));
        assert!(WEBHOOK_ORDER_UPDATE_SQL
            .contains("transfer_instructions = COALESCE($4, transfer_instructions)"));
        assert!(
            WEBHOOK_ORDER_UPDATE_SQL.contains("provider_payload = COALESCE($5, provider_payload)")
        );
        assert!(WEBHOOK_ORDER_UPDATE_SQL.contains("last_error = NULL"));
    }
}

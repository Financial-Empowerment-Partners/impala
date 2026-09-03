//! Background reconcile loop for exchange orders.
//!
//! Runs in-process (spawned from `run_server`, no SNS/SQS dependency — the
//! admin_webhook_delivery shape). Each tick claims due non-terminal orders
//! (`next_poll_at <= now`) and refreshes each one against its provider via
//! [`refresh_order_once`], the single source of truth for provider→row
//! updates (also used by `GET /exchange/orders/{id}?refresh=true`).
//!
//! Terminal statuses never regress: every status UPDATE carries the
//! `AND NOT (status = ANY(<terminal>))` guard in its WHERE clause, so a late
//! poll result can never un-complete an order a webhook already finished.
//! Provider errors still push `next_poll_at` forward — a failing provider
//! must never turn the due-order scan into a hot loop.

use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::constants::{
    EXCHANGE_POLL_BATCH_LIMIT, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
    EXCHANGE_PROVIDER_CHANGELLY_FIAT, EXCHANGE_PROVIDER_OWLPAY, TERMINAL_EXCHANGE_STATUSES,
    VALID_EXCHANGE_STATUSES,
};
use crate::error::AppError;
use crate::exchange::changelly::{
    map_changelly_crypto_status, map_changelly_fiat_status, ChangellyCrypto, ChangellyFiat,
};
use crate::exchange::owlpay::{map_owlpay_status, OwlPayProvider, OwlPayTransfer};
use crate::telemetry::AppMetrics;

/// Reconcile-loop tuning. Also layered as an axum Extension so the
/// user-initiated `?refresh=true` path schedules its next poll on the same
/// configured cadence as the background loop.
#[derive(Debug, Clone)]
pub struct ReconcileConfig {
    /// Loop tick AND the base of the per-order exponential backoff.
    pub poll_secs: u64,
}

/// Due-order claim shape, lifted to a const so the test below pins the
/// batched, index-friendly scan (idx_exchange_order_pending) and the
/// `ORDER BY next_poll_at LIMIT` bound.
/// `provider <> 'reserve'`: reserve-diverted rows share the table and the
/// pending index but are driven by the reserve watcher — this poller has no
/// provider to ask about them and its unknown-provider arm would defer them
/// forever.
const DUE_ORDERS_SQL: &str = "SELECT order_id, provider, provider_order_id, poll_count \
     FROM exchange_order \
     WHERE status = ANY($1) AND provider <> 'reserve' \
       AND next_poll_at <= CURRENT_TIMESTAMP \
     ORDER BY next_poll_at LIMIT $2";

/// Provider→row refresh UPDATE. `$8` binds the terminal statuses — the
/// never-regress guard lives in the SQL itself, not in application logic.
const REFRESH_ORDER_UPDATE_SQL: &str = "UPDATE exchange_order \
     SET status = $2, provider_status = $3, amount_to = COALESCE($4, amount_to), \
         transfer_instructions = COALESCE($5, transfer_instructions), \
         provider_payload = COALESCE($6, provider_payload), \
         last_error = NULL, poll_count = poll_count + 1, next_poll_at = $7 \
     WHERE order_id = $1 AND NOT (status = ANY($8))";

/// Poll bookkeeping when no provider state landed (unconfigured provider or
/// provider error): push the next poll forward without touching order state.
const DEFER_ORDER_SQL: &str = "UPDATE exchange_order \
     SET poll_count = poll_count + 1, next_poll_at = $2, \
         last_error = COALESCE($3, last_error) \
     WHERE order_id = $1";

/// True when `status` is one of the four terminal exchange statuses.
pub fn is_terminal_exchange_status(status: &str) -> bool {
    TERMINAL_EXCHANGE_STATUSES.contains(&status)
}

/// Terminal statuses as owned strings for `= ANY($n)` binds (the SQL-side
/// never-regress guard on every order UPDATE).
pub(crate) fn terminal_statuses() -> Vec<String> {
    TERMINAL_EXCHANGE_STATUSES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The four non-terminal statuses, as owned strings for `= ANY($n)` binds.
pub(crate) fn non_terminal_statuses() -> Vec<String> {
    VALID_EXCHANGE_STATUSES
        .iter()
        .filter(|s| !TERMINAL_EXCHANGE_STATUSES.contains(s))
        .map(|s| s.to_string())
        .collect()
}

/// House backoff shape (admin_webhook_delivery.rs): cap the exponent BEFORE
/// pow to avoid overflow, then cap the result at one hour. Floors at 1s so a
/// zero base interval can never schedule an immediate re-poll (hot loop).
pub(crate) fn poll_backoff_secs(poll_secs: u64, poll_count: i32) -> u64 {
    let exp = (poll_count.max(0) as u32).min(16);
    poll_secs.saturating_mul(1u64 << exp).clamp(1, 3600)
}

/// First N chars of a string (error snippets for `last_error` / responses).
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Extract a decimal amount that providers serialize as either a JSON string
/// or a bare number. Amounts stay strings on our side — never f64.
pub(crate) fn json_decimal_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Map a DB error from the reconcile path to an AppError, logging the context.
fn reconcile_db_error(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e| {
        error!("exchange_reconcile: {} error: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

// ── Provider snapshots (pure normalization, unit-tested) ───────────────

/// Provider-neutral view of an order's upstream state. `payload = None`
/// keeps the stored `provider_payload` untouched (COALESCE in the UPDATE).
pub(crate) struct ProviderSnapshot {
    pub status_raw: String,
    pub status: &'static str,
    pub amount_to: Option<String>,
    pub transfer_instructions: Option<serde_json::Value>,
    pub payload: Option<serde_json::Value>,
}

/// Snapshot from a Changelly `getTransactions` result (rich detail: amountTo
/// plus payin/payout hashes preserved inside the raw payload). Accepts the
/// bare result array or a single tx object; `None` when no usable entry.
pub(crate) fn snapshot_from_changelly_tx_detail(
    result: &serde_json::Value,
) -> Option<ProviderSnapshot> {
    let item = match result.as_array() {
        Some(arr) => arr.first()?,
        None => result,
    };
    let status_raw = item.get("status")?.as_str()?.to_string();
    Some(ProviderSnapshot {
        status: map_changelly_crypto_status(&status_raw),
        status_raw,
        amount_to: json_decimal_string(&item["amountTo"]),
        transfer_instructions: None,
        payload: Some(item.clone()),
    })
}

/// Snapshot from a bare Changelly `getStatus` string (fallback path — keeps
/// the stored provider_payload untouched).
pub(crate) fn snapshot_from_changelly_status(status: &str) -> ProviderSnapshot {
    ProviderSnapshot {
        status: map_changelly_crypto_status(status),
        status_raw: status.to_string(),
        amount_to: None,
        transfer_instructions: None,
        payload: None,
    }
}

/// Snapshot from an OwlPay transfer object.
pub(crate) fn snapshot_from_owlpay_transfer(t: &OwlPayTransfer) -> ProviderSnapshot {
    ProviderSnapshot {
        status: map_owlpay_status(&t.status),
        status_raw: t.status.clone(),
        amount_to: t.destination_amount.clone(),
        transfer_instructions: t.transfer_instructions.clone(),
        payload: Some(t.raw.clone()),
    }
}

/// Snapshot from a Changelly Fiat order object (also tolerates the raw
/// `{orders: [...]}` list envelope). `None` when the object has no status.
pub(crate) fn snapshot_from_fiat_order(order: &serde_json::Value) -> Option<ProviderSnapshot> {
    let order = order
        .get("orders")
        .and_then(|o| o.as_array())
        .and_then(|a| a.first())
        .unwrap_or(order);
    let status_raw = order.get("status")?.as_str()?.to_string();
    Some(ProviderSnapshot {
        status: map_changelly_fiat_status(&status_raw),
        status_raw,
        amount_to: json_decimal_string(&order["payoutAmount"]),
        transfer_instructions: None,
        payload: Some(order.clone()),
    })
}

// ── Poll loop ──────────────────────────────────────────────────────────

/// Worker entry point. Loops until `cancel` fires; every error is logged,
/// never fatal.
pub async fn run(
    pool: PgPool,
    owlpay: Option<Arc<OwlPayProvider>>,
    changelly_crypto: Option<Arc<ChangellyCrypto>>,
    changelly_fiat: Option<Arc<ChangellyFiat>>,
    metrics: Arc<AppMetrics>,
    cfg: ReconcileConfig,
    cancel: CancellationToken,
) {
    info!(
        "exchange_reconcile: started (poll={}s, batch_limit={})",
        cfg.poll_secs, EXCHANGE_POLL_BATCH_LIMIT
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("exchange_reconcile: shutdown signal received");
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(cfg.poll_secs)) => {
                if let Err(e) = tick(
                    &pool,
                    owlpay.as_ref(),
                    changelly_crypto.as_ref(),
                    changelly_fiat.as_ref(),
                    &metrics,
                    cfg.poll_secs,
                )
                .await
                {
                    error!("exchange_reconcile: tick error: {}", e);
                }
            }
        }
    }
}

/// One poll tick: claim due non-terminal orders and refresh each in turn.
/// Sequential on purpose — Changelly enforces tight request-per-second
/// limits, and per-order failures must not poison the batch.
async fn tick(
    pool: &PgPool,
    owlpay: Option<&Arc<OwlPayProvider>>,
    changelly_crypto: Option<&Arc<ChangellyCrypto>>,
    changelly_fiat: Option<&Arc<ChangellyFiat>>,
    metrics: &AppMetrics,
    poll_secs: u64,
) -> Result<(), sqlx::Error> {
    // One instance polls per tick. Every task used to run this loop against
    // the same due set: N× the providers' request budgets (Changelly's is
    // tight enough to 429 user-facing calls), backoff growing by N per
    // round, and a hung provider stalling every instance at once. The lock
    // is cancellation-safe (reserve_watch::AdvisoryLock) and is NOT held
    // per row — provider calls never run under a row lock.
    let lock = crate::exchange::reserve_watch::AdvisoryLock::new(
        crate::constants::EXCHANGE_RECONCILE_LOCK_KEY,
    );
    let Some(guard) = lock.try_acquire(pool).await? else {
        return Ok(());
    };
    let result = tick_locked(
        pool,
        owlpay,
        changelly_crypto,
        changelly_fiat,
        metrics,
        poll_secs,
    )
    .await;
    if let Err(e) = guard.release_now().await {
        error!(
            "exchange_reconcile: advisory unlock failed ({}); guard drop releases it",
            e
        );
    }
    result
}

async fn tick_locked(
    pool: &PgPool,
    owlpay: Option<&Arc<OwlPayProvider>>,
    changelly_crypto: Option<&Arc<ChangellyCrypto>>,
    changelly_fiat: Option<&Arc<ChangellyFiat>>,
    metrics: &AppMetrics,
    poll_secs: u64,
) -> Result<(), sqlx::Error> {
    let due: Vec<(Uuid, String, String, i32)> = sqlx::query_as(DUE_ORDERS_SQL)
        .bind(non_terminal_statuses())
        .bind(EXCHANGE_POLL_BATCH_LIMIT)
        .fetch_all(pool)
        .await?;

    for (order_id, provider, provider_order_id, poll_count) in due {
        if let Err(e) = refresh_order_with_source(
            pool,
            owlpay,
            changelly_crypto,
            changelly_fiat,
            metrics,
            order_id,
            poll_secs,
            "poll",
        )
        .await
        {
            error!(
                "exchange_reconcile: refresh of order {} ({} {}) failed: {} (poll_count={})",
                order_id, provider, provider_order_id, e, poll_count
            );
        }
    }
    Ok(())
}

/// Refresh one order from its provider — shared by the poll loop and
/// `GET /exchange/orders/{id}?refresh=true`.
///
/// Fetches provider state, applies it under the terminal-status SQL guard,
/// bumps `poll_count`, and schedules `next_poll_at` with the house
/// exponential backoff. Provider errors are absorbed (recorded in
/// `last_error`, poll pushed forward) — only DB errors and a missing order
/// surface as `Err`. Emits `ExchangeOrderUpdated` on a real status change.
pub async fn refresh_order_once(
    pool: &PgPool,
    owlpay: Option<&Arc<OwlPayProvider>>,
    changelly_crypto: Option<&Arc<ChangellyCrypto>>,
    changelly_fiat: Option<&Arc<ChangellyFiat>>,
    metrics: &AppMetrics,
    order_id: Uuid,
    poll_secs: u64,
) -> Result<(), AppError> {
    refresh_order_with_source(
        pool,
        owlpay,
        changelly_crypto,
        changelly_fiat,
        metrics,
        order_id,
        poll_secs,
        "refresh",
    )
    .await
}

#[allow(clippy::too_many_arguments)] // provider set + scheduling context
async fn refresh_order_with_source(
    pool: &PgPool,
    owlpay: Option<&Arc<OwlPayProvider>>,
    changelly_crypto: Option<&Arc<ChangellyCrypto>>,
    changelly_fiat: Option<&Arc<ChangellyFiat>>,
    metrics: &AppMetrics,
    order_id: Uuid,
    poll_secs: u64,
    source: &'static str,
) -> Result<(), AppError> {
    let row: Option<(String, String, String, i32)> = sqlx::query_as(
        "SELECT provider, provider_order_id, status, poll_count \
         FROM exchange_order WHERE order_id = $1",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await
    .map_err(reconcile_db_error("order read"))?;

    let Some((provider, provider_order_id, status, poll_count)) = row else {
        return Err(AppError::NotFound("Exchange order not found".to_string()));
    };
    if is_terminal_exchange_status(&status) {
        return Ok(());
    }

    let backoff_secs = poll_backoff_secs(poll_secs, poll_count);

    let snapshot = match fetch_provider_snapshot(
        owlpay,
        changelly_crypto,
        changelly_fiat,
        &provider,
        &provider_order_id,
    )
    .await
    {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            // Unconfigured provider or order unknown upstream (already
            // logged) — just push the poll forward.
            return defer_order(
                pool,
                order_id,
                backoff_secs,
                Some("provider state unavailable"),
            )
            .await;
        }
        Err(e) => {
            warn!(
                "exchange_reconcile: provider fetch for order {} ({}) failed: {}",
                order_id, provider, e
            );
            let msg = truncate_chars(&e.to_string(), 500);
            return defer_order(pool, order_id, backoff_secs, Some(&msg)).await;
        }
    };

    apply_snapshot(
        pool,
        metrics,
        order_id,
        &provider,
        snapshot,
        backoff_secs,
        source,
    )
    .await
}

/// Fetch the provider's view of an order. `Ok(None)` = no state available
/// without it being an error worth surfacing (unconfigured provider, order
/// unknown upstream); the caller defers the next poll.
async fn fetch_provider_snapshot(
    owlpay: Option<&Arc<OwlPayProvider>>,
    changelly_crypto: Option<&Arc<ChangellyCrypto>>,
    changelly_fiat: Option<&Arc<ChangellyFiat>>,
    provider: &str,
    provider_order_id: &str,
) -> Result<Option<ProviderSnapshot>, AppError> {
    match provider {
        EXCHANGE_PROVIDER_OWLPAY => {
            let Some(p) = owlpay else {
                warn!("exchange_reconcile: owlpay is not configured; deferring order poll");
                return Ok(None);
            };
            let transfer = p.get_transfer(provider_order_id).await?;
            Ok(Some(snapshot_from_owlpay_transfer(&transfer)))
        }
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => {
            let Some(p) = changelly_crypto else {
                warn!(
                    "exchange_reconcile: changelly_crypto is not configured; deferring order poll"
                );
                return Ok(None);
            };
            // Rich detail first (amountTo + payin/payout hashes land in the
            // raw payload); getStatus as fallback when detail is missing or
            // lagging a fresh transaction.
            match p.get_transactions_by_id(provider_order_id).await {
                Ok(detail) => {
                    if let Some(snapshot) = snapshot_from_changelly_tx_detail(&detail) {
                        return Ok(Some(snapshot));
                    }
                    let status = p.get_status(provider_order_id).await?;
                    Ok(Some(snapshot_from_changelly_status(&status)))
                }
                Err(e) => {
                    warn!(
                        "exchange_reconcile: getTransactions for {} failed ({}); \
                         falling back to getStatus",
                        provider_order_id, e
                    );
                    let status = p.get_status(provider_order_id).await?;
                    Ok(Some(snapshot_from_changelly_status(&status)))
                }
            }
        }
        EXCHANGE_PROVIDER_CHANGELLY_FIAT => {
            let Some(p) = changelly_fiat else {
                warn!("exchange_reconcile: changelly_fiat is not configured; deferring order poll");
                return Ok(None);
            };
            match p.get_order_by_id(provider_order_id).await? {
                // None also covers a fetched order without a status field.
                Some(order) => Ok(snapshot_from_fiat_order(&order)),
                None => {
                    warn!(
                        "exchange_reconcile: changelly_fiat has no order {}",
                        provider_order_id
                    );
                    Ok(None)
                }
            }
        }
        other => {
            // 'reserve' rows are excluded by DUE_ORDERS_SQL and the refresh
            // handler; anything else is a DB-CHECK-constrained value this
            // match forgot. Defensive only.
            error!("exchange_reconcile: unknown provider '{}'", other);
            Ok(None)
        }
    }
}

/// Push `next_poll_at` forward without touching order state — used when the
/// provider is unconfigured or errored so the poll loop never spins hot.
async fn defer_order(
    pool: &PgPool,
    order_id: Uuid,
    backoff_secs: u64,
    last_error: Option<&str>,
) -> Result<(), AppError> {
    let next_poll_at = chrono::Utc::now() + chrono::Duration::seconds(backoff_secs as i64);
    sqlx::query(DEFER_ORDER_SQL)
        .bind(order_id)
        .bind(next_poll_at)
        .bind(last_error)
        .execute(pool)
        .await
        .map_err(reconcile_db_error("defer update"))?;
    Ok(())
}

/// Apply a provider snapshot to the order row: guarded UPDATE + event +
/// commit, metrics after. The row is re-read (and locked) inside the
/// transaction so the old status used for change detection cannot be stale.
async fn apply_snapshot(
    pool: &PgPool,
    metrics: &AppMetrics,
    order_id: Uuid,
    provider: &str,
    snapshot: ProviderSnapshot,
    backoff_secs: u64,
    source: &'static str,
) -> Result<(), AppError> {
    let next_poll_at = chrono::Utc::now() + chrono::Duration::seconds(backoff_secs as i64);

    let mut tx = pool.begin().await.map_err(reconcile_db_error("begin"))?;

    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT payala_account_id, status FROM exchange_order WHERE order_id = $1 FOR UPDATE",
    )
    .bind(order_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(reconcile_db_error("order lock"))?;
    let Some((account_id, old_status)) = row else {
        return Err(AppError::NotFound("Exchange order not found".to_string()));
    };

    let res = sqlx::query(REFRESH_ORDER_UPDATE_SQL)
        .bind(order_id)
        .bind(snapshot.status)
        .bind(&snapshot.status_raw)
        .bind(&snapshot.amount_to)
        .bind(&snapshot.transfer_instructions)
        .bind(&snapshot.payload)
        .bind(next_poll_at)
        .bind(terminal_statuses())
        .execute(&mut *tx)
        .await
        .map_err(reconcile_db_error("order update"))?;
    if res.rows_affected() == 0 {
        // The order reached a terminal status concurrently (e.g. a webhook
        // landed between our read and this update) — the guard refused the
        // write. Nothing to record.
        info!(
            "exchange_reconcile: order {} already terminal; {} update skipped",
            order_id, source
        );
        return Ok(());
    }

    let changed = old_status != snapshot.status;
    if changed {
        crate::events::emit_event(
            &mut tx,
            &crate::events::AccountEvent::ExchangeOrderUpdated {
                account_id,
                order_id: order_id.to_string(),
                provider: provider.to_string(),
                status: snapshot.status.to_string(),
                provider_status: snapshot.status_raw.clone(),
            },
        )
        .await?;
    }

    tx.commit().await.map_err(reconcile_db_error("commit"))?;

    // Metrics only after commit — nothing may claim state that didn't land.
    if changed {
        metrics.record_exchange_order_update(provider, snapshot.status, source);
        info!(
            "exchange_reconcile: order {} {} -> {} (provider_status={}, source={})",
            order_id, old_status, snapshot.status, snapshot.status_raw, source
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── backoff ────────────────────────────────────────────────────────

    #[test]
    fn test_poll_backoff_progression() {
        assert_eq!(poll_backoff_secs(60, 0), 60);
        assert_eq!(poll_backoff_secs(60, 1), 120);
        assert_eq!(poll_backoff_secs(60, 5), 1920);
        // 60 * 2^6 = 3840 caps at one hour.
        assert_eq!(poll_backoff_secs(60, 6), 3600);
        assert_eq!(poll_backoff_secs(60, 16), 3600);
    }

    #[test]
    fn test_poll_backoff_exponent_capped_before_pow() {
        // Would overflow without the .min(16) exponent cap.
        assert_eq!(poll_backoff_secs(60, i32::MAX), 3600);
        assert_eq!(poll_backoff_secs(u64::MAX, 16), 3600);
    }

    #[test]
    fn test_poll_backoff_defensive_edges() {
        // Negative counts are treated as zero...
        assert_eq!(poll_backoff_secs(60, -3), 60);
        // ...and a zero base interval still floors at 1s (never a hot loop).
        assert_eq!(poll_backoff_secs(0, 0), 1);
    }

    // ── status vocabulary helpers ──────────────────────────────────────

    #[test]
    fn test_terminal_and_non_terminal_partition_valid() {
        let terminal = terminal_statuses();
        let non_terminal = non_terminal_statuses();
        assert_eq!(terminal.len(), 4);
        assert_eq!(non_terminal.len(), 4);
        for s in &terminal {
            assert!(!non_terminal.contains(s));
            assert!(VALID_EXCHANGE_STATUSES.contains(&s.as_str()));
        }
        assert_eq!(
            terminal.len() + non_terminal.len(),
            VALID_EXCHANGE_STATUSES.len()
        );
    }

    #[test]
    fn test_is_terminal_exchange_status() {
        for s in ["completed", "failed", "refunded", "expired"] {
            assert!(is_terminal_exchange_status(s));
        }
        for s in ["created", "awaiting_deposit", "processing", "on_hold", ""] {
            assert!(!is_terminal_exchange_status(s));
        }
    }

    // ── json helpers ───────────────────────────────────────────────────

    #[test]
    fn test_json_decimal_string() {
        assert_eq!(
            json_decimal_string(&json!("12.5")),
            Some("12.5".to_string())
        );
        assert_eq!(json_decimal_string(&json!(0.1)), Some("0.1".to_string()));
        assert_eq!(json_decimal_string(&json!(42)), Some("42".to_string()));
        assert_eq!(json_decimal_string(&json!("")), None);
        assert_eq!(json_decimal_string(&json!(null)), None);
        assert_eq!(json_decimal_string(&json!(true)), None);
        assert_eq!(json_decimal_string(&json!({})), None);
    }

    #[test]
    fn test_truncate_chars() {
        assert_eq!(truncate_chars("abcdef", 3), "abc");
        assert_eq!(truncate_chars("ab", 3), "ab");
        // Char-boundary safe (a byte-indexed slice would panic here).
        assert_eq!(truncate_chars("ééé", 2), "éé");
    }

    // ── provider snapshots ─────────────────────────────────────────────

    #[test]
    fn test_snapshot_from_changelly_tx_detail_array() {
        let detail = json!([{
            "id": "tx1", "status": "waiting", "amountTo": "98.7",
            "payinHash": null, "payoutHash": null
        }]);
        let s = snapshot_from_changelly_tx_detail(&detail).unwrap();
        assert_eq!(s.status_raw, "waiting");
        assert_eq!(s.status, "awaiting_deposit"); // contract-pinned mapping
        assert_eq!(s.amount_to.as_deref(), Some("98.7"));
        assert!(s.transfer_instructions.is_none());
        // The full tx object (incl. hashes) is preserved as the payload.
        assert_eq!(s.payload, Some(detail[0].clone()));
    }

    #[test]
    fn test_snapshot_from_changelly_tx_detail_object_form() {
        let s = snapshot_from_changelly_tx_detail(&json!({"status": "finished"})).unwrap();
        assert_eq!(s.status, "completed");
        assert!(s.amount_to.is_none());
    }

    #[test]
    fn test_snapshot_from_changelly_tx_detail_unusable() {
        // Empty array (getTransactions lagging a fresh tx) and missing status.
        assert!(snapshot_from_changelly_tx_detail(&json!([])).is_none());
        assert!(snapshot_from_changelly_tx_detail(&json!([{"id": "tx1"}])).is_none());
        assert!(snapshot_from_changelly_tx_detail(&json!({"status": 7})).is_none());
    }

    #[test]
    fn test_snapshot_from_changelly_status_keeps_payload() {
        let s = snapshot_from_changelly_status("exchanging");
        assert_eq!(s.status, "processing");
        assert_eq!(s.status_raw, "exchanging");
        // None => COALESCE keeps the stored provider_payload untouched.
        assert!(s.payload.is_none());
        assert!(s.amount_to.is_none());
    }

    #[test]
    fn test_snapshot_from_owlpay_transfer() {
        let raw = json!({"uuid": "transfer_1", "status": "completed"});
        let t = OwlPayTransfer {
            uuid: "transfer_1".to_string(),
            status: "completed".to_string(),
            transfer_type: Some("off-ramp".to_string()),
            transfer_instructions: Some(json!({"instruction_address": "GABC"})),
            destination_amount: Some("101.25".to_string()),
            raw: raw.clone(),
        };
        let s = snapshot_from_owlpay_transfer(&t);
        assert_eq!(s.status, "completed");
        assert_eq!(s.status_raw, "completed");
        assert_eq!(s.amount_to.as_deref(), Some("101.25"));
        assert_eq!(
            s.transfer_instructions,
            Some(json!({"instruction_address": "GABC"}))
        );
        assert_eq!(s.payload, Some(raw));
    }

    #[test]
    fn test_snapshot_from_fiat_order_object() {
        let order = json!({
            "orderId": "ord-1", "status": "complete",
            "payoutAmount": "97.30", "transactionHash": "abc123"
        });
        let s = snapshot_from_fiat_order(&order).unwrap();
        assert_eq!(s.status_raw, "complete");
        assert_eq!(s.status, "completed"); // contract-pinned fiat mapping
        assert_eq!(s.amount_to.as_deref(), Some("97.30"));
        // transactionHash rides along inside the stored payload.
        assert_eq!(s.payload.as_ref().unwrap()["transactionHash"], "abc123");
    }

    #[test]
    fn test_snapshot_from_fiat_order_envelope_form() {
        let envelope = json!({"orders": [{"status": "hold", "payoutAmount": 12.5}], "total": 1});
        let s = snapshot_from_fiat_order(&envelope).unwrap();
        assert_eq!(s.status, "on_hold");
        assert_eq!(s.amount_to.as_deref(), Some("12.5"));
    }

    #[test]
    fn test_snapshot_from_fiat_order_missing_status() {
        assert!(snapshot_from_fiat_order(&json!({"orderId": "ord-1"})).is_none());
        assert!(snapshot_from_fiat_order(&json!({"orders": []})).is_none());
    }

    // ── SQL shape pins ─────────────────────────────────────────────────

    /// Pins the batched due-order scan: one bounded, ordered claim per tick,
    /// and — load-bearing — the reserve exclusion: without it every
    /// non-terminal reserve order lands in the unknown-provider defer path,
    /// stamping last_error and pushing the watcher's own schedule column.
    #[test]
    fn test_due_orders_sql_shape() {
        assert!(DUE_ORDERS_SQL.contains("status = ANY($1)"));
        assert!(DUE_ORDERS_SQL.contains("provider <> 'reserve'"));
        assert!(DUE_ORDERS_SQL.contains("next_poll_at <= CURRENT_TIMESTAMP"));
        assert!(DUE_ORDERS_SQL.contains("ORDER BY next_poll_at LIMIT $2"));
    }

    /// Pins the terminal-status guard: it must live in the UPDATE's WHERE,
    /// not in application logic, so no code path can regress a final state.
    #[test]
    fn test_refresh_update_sql_has_terminal_guard() {
        assert!(REFRESH_ORDER_UPDATE_SQL.contains("AND NOT (status = ANY($8))"));
        assert!(REFRESH_ORDER_UPDATE_SQL.contains("amount_to = COALESCE($4, amount_to)"));
        assert!(
            REFRESH_ORDER_UPDATE_SQL.contains("provider_payload = COALESCE($6, provider_payload)")
        );
        assert!(REFRESH_ORDER_UPDATE_SQL.contains("poll_count = poll_count + 1"));
    }

    /// Pins the defer path: bookkeeping only — it must never touch `status`.
    #[test]
    fn test_defer_sql_shape() {
        assert!(DEFER_ORDER_SQL.contains("poll_count = poll_count + 1"));
        assert!(DEFER_ORDER_SQL.contains("last_error = COALESCE($3, last_error)"));
        assert!(!DEFER_ORDER_SQL.contains("SET status"));
        assert!(!DEFER_ORDER_SQL.contains("status ="));
    }
}

//! Crash recovery for custodial payment intents.
//!
//! Every `CUSTODIAL_SWEEP_INTERVAL_SECS`, one pass under the
//! `CUSTODIAL_SWEEP_LOCK_KEY` advisory lock:
//!
//! 1. **Abandon** `prepared` rows older than `CUSTODIAL_INTENT_ABANDON_SECS`
//!    that carry no hash. Sound because no hash ⇒ no submit ever happened,
//!    and a late arm fails its compare-and-swap.
//! 2. **Resolve by hash** `submitted`/`ambiguous` rows armed more than
//!    `CUSTODIAL_STALE_INTENT_SECS` ago (longer than the 300s transaction
//!    validity window): Horizon either shows the hash settled (record it),
//!    failed (reject it), or — on a FRESH head — absent (expired, reject it).
//!    A lagging Horizon proves nothing and the row is left alone.
//!
//! Every write is a CAS on `(status, stellar_hash)`, so correctness never
//! depends on the lock; the lock only stops N instances doing N× the Horizon
//! reads. The sweep runs whether or not a conversion reserve is configured:
//! intents exist on every deployment that signs.

use futures::FutureExt;
use log::{debug, error, info, warn};
use opentelemetry::KeyValue;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;

use crate::constants::{
    CUSTODIAL_INTENT_ABANDON_SECS, CUSTODIAL_STALE_INTENT_SECS, CUSTODIAL_SWEEP_BATCH,
    CUSTODIAL_SWEEP_INTERVAL_SECS, CUSTODIAL_SWEEP_LOCK_KEY, HORIZON_MAX_LAG_SECS,
};
use crate::custody::intent::{record_settlement, reject_by_hash, OpenIntentRow, SettleOutcome};
use crate::error::AppError;
use crate::exchange::reserve_watch::AdvisoryLock;
use crate::stellar::horizon::{
    fetch_head_closed_at, fetch_transaction_payments, head_is_fresh, settles,
};
use crate::telemetry::AppMetrics;

/// Rows claimed but never armed, past the abandon age. Guarded on
/// `stellar_hash IS NULL`: an armed row is never touched here.
pub(crate) const ABANDON_SQL: &str = "UPDATE custodial_payment_intent \
     SET status = 'rejected', resolution = 'sweep_abandoned', \
         last_error = 'abandoned before submit', resolved_at = CURRENT_TIMESTAMP \
     WHERE status = 'prepared' AND stellar_hash IS NULL \
       AND created_at < CURRENT_TIMESTAMP - make_interval(secs => $1)";

/// Armed, unresolved rows past the stale age (oldest first, bounded).
pub(crate) const STALE_SQL: &str = "SELECT intent_id, payala_account_id, origin, \
        source_account, destination, asset_code, asset_issuer, amount_minor, memo, \
        stellar_hash, status, armed_at \
     FROM custodial_payment_intent \
     WHERE status IN ('submitted', 'ambiguous') \
       AND armed_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
     ORDER BY armed_at LIMIT $2";

/// Open-row gauge feed.
pub(crate) const OPEN_COUNTS_SQL: &str = "SELECT status, COUNT(*) \
     FROM custodial_payment_intent \
     WHERE status IN ('prepared', 'submitted', 'ambiguous') GROUP BY status";

pub(crate) struct SweepDeps {
    pub pool: PgPool,
    pub http: Arc<reqwest::Client>,
    pub horizon_url: String,
    pub metrics: Arc<AppMetrics>,
}

/// What Horizon said about one hash.
#[derive(Debug, PartialEq)]
pub(crate) enum HashLookup {
    /// Horizon unreachable or errored: nothing is known.
    Error,
    /// Horizon has no such transaction.
    NotFound,
    /// The transaction exists; `settles` = a successful matching payment is
    /// among its operations, `any_failed` = the transaction failed.
    Found { settles: bool, any_failed: bool },
}

#[derive(Debug, PartialEq)]
pub(crate) enum SweepVerdict {
    Settle,
    RejectFailedOnChain,
    RejectExpired,
    Leave,
}

/// The pure decision. `head_fresh` is `Some(true)` only when Horizon's head
/// was read this pass and is within `HORIZON_MAX_LAG_SECS` — absence on a
/// lagging or unread head is not evidence.
pub(crate) fn sweep_verdict(lookup: HashLookup, head_fresh: Option<bool>) -> SweepVerdict {
    match lookup {
        HashLookup::Found { settles: true, .. } => SweepVerdict::Settle,
        HashLookup::Found {
            settles: false,
            any_failed: true,
        } => SweepVerdict::RejectFailedOnChain,
        HashLookup::Found { .. } => SweepVerdict::Leave,
        HashLookup::NotFound if head_fresh == Some(true) => SweepVerdict::RejectExpired,
        HashLookup::NotFound | HashLookup::Error => SweepVerdict::Leave,
    }
}

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("custodial sweep: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

pub(crate) async fn run(deps: SweepDeps, cancel: CancellationToken) {
    info!(
        "custodial intent sweep started: cadence={}s stale={}s abandon={}s",
        CUSTODIAL_SWEEP_INTERVAL_SECS, CUSTODIAL_STALE_INTENT_SECS, CUSTODIAL_INTENT_ABANDON_SECS
    );
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("custodial intent sweep stopped");
                return;
            }
            _ = sleep(Duration::from_secs(CUSTODIAL_SWEEP_INTERVAL_SECS)) => {
                match std::panic::AssertUnwindSafe(tick(&deps)).catch_unwind().await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => error!("custodial sweep pass failed: {:?}", e),
                    Err(_) => error!("custodial sweep PANICKED; continuing on the next pass"),
                }
            }
        }
    }
}

async fn tick(deps: &SweepDeps) -> Result<(), AppError> {
    let lock = AdvisoryLock::new(CUSTODIAL_SWEEP_LOCK_KEY);
    let Some(guard) = lock
        .try_acquire(&deps.pool)
        .await
        .map_err(db_err("try lock"))?
    else {
        debug!("custodial sweep: another instance holds the lock; skipping this pass");
        return Ok(());
    };
    let result = pass(deps).await;
    if let Err(e) = guard.release_now().await {
        warn!(
            "custodial sweep: advisory unlock failed ({}); the guard's drop will release it",
            e
        );
    }
    result
}

/// One pass. Returns the number of rows it moved (for tests and logs).
pub(crate) async fn pass(deps: &SweepDeps) -> Result<(), AppError> {
    let abandoned = sqlx::query(ABANDON_SQL)
        .bind(CUSTODIAL_INTENT_ABANDON_SECS as f64)
        .execute(&deps.pool)
        .await
        .map_err(db_err("abandon"))?
        .rows_affected();
    if abandoned > 0 {
        warn!(
            "custodial sweep: abandoned {} unarmed intent(s) (nothing was signed for them)",
            abandoned
        );
        deps.metrics.record_custodial_sweep("abandoned", abandoned);
    }

    let stale: Vec<OpenIntentRow> = sqlx::query_as(STALE_SQL)
        .bind(CUSTODIAL_STALE_INTENT_SECS as f64)
        .bind(CUSTODIAL_SWEEP_BATCH)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("stale scan"))?;

    if !stale.is_empty() {
        let head_fresh = match fetch_head_closed_at(&deps.http, &deps.horizon_url).await {
            Ok(head) => Some(head_is_fresh(
                head,
                chrono::Utc::now(),
                HORIZON_MAX_LAG_SECS,
            )),
            Err(_) => None,
        };
        for row in &stale {
            resolve_row(deps, row, head_fresh).await;
        }
    }

    let counts: Vec<(String, i64)> = sqlx::query_as(OPEN_COUNTS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("open counts"))?;
    for status in crate::constants::CUSTODIAL_INTENT_OPEN_STATUSES {
        let n = counts
            .iter()
            .find(|(s, _)| s == status)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        deps.metrics.record_custodial_open(status, n.max(0) as u64);
    }
    Ok(())
}

/// Look one hash up and act on the verdict.
async fn resolve_row(deps: &SweepDeps, row: &OpenIntentRow, head_fresh: Option<bool>) {
    let Some(hash) = row.stellar_hash.as_deref() else {
        // Unreachable under chk_cpi_hash_state; never treat as evidence.
        error!(
            "custodial sweep: open intent {} has no hash; leaving it for an admin",
            row.intent_id
        );
        return;
    };
    let asset = row.asset();
    let lookup = match fetch_transaction_payments(&deps.http, &deps.horizon_url, hash).await {
        Err(_) => HashLookup::Error,
        Ok(None) => HashLookup::NotFound,
        Ok(Some(payments)) => HashLookup::Found {
            settles: payments.iter().any(|p| {
                settles(
                    p,
                    &row.source_account,
                    &row.destination,
                    row.amount_minor,
                    Some(&asset),
                )
            }),
            any_failed: payments
                .iter()
                .any(|p| p.transaction_successful == Some(false)),
        },
    };
    match sweep_verdict(lookup, head_fresh) {
        SweepVerdict::Settle => {
            match record_settlement(&deps.pool, &row.settlement(hash, "sweep_settled"), None).await
            {
                Ok(SettleOutcome::Settled { btxid }) => {
                    info!(
                        "custodial sweep: intent {} settled by hash (btxid {})",
                        row.intent_id, btxid
                    );
                    deps.metrics.record_custodial_sweep("settled", 1);
                }
                Ok(SettleOutcome::AlreadySettled) => {
                    debug!("custodial sweep: intent {} already resolved", row.intent_id)
                }
                Err(e) => error!(
                    "custodial sweep: intent {} settle failed: {:?}",
                    row.intent_id, e
                ),
            }
        }
        SweepVerdict::RejectFailedOnChain => {
            match reject_by_hash(
                &deps.pool,
                row.intent_id,
                hash,
                "sweep_failed",
                "transaction failed on-chain",
                None,
            )
            .await
            {
                Ok(true) => {
                    info!(
                        "custodial sweep: intent {} failed on-chain; rejected",
                        row.intent_id
                    );
                    deps.metrics.record_custodial_sweep("failed", 1);
                }
                Ok(false) => {}
                Err(e) => error!(
                    "custodial sweep: intent {} reject failed: {:?}",
                    row.intent_id, e
                ),
            }
        }
        SweepVerdict::RejectExpired => {
            match reject_by_hash(
                &deps.pool,
                row.intent_id,
                hash,
                "sweep_expired",
                "transaction absent from a fresh Horizon after its validity window",
                None,
            )
            .await
            {
                Ok(true) => {
                    info!(
                        "custodial sweep: intent {} never landed (fresh Horizon, {}s past arm); rejected",
                        row.intent_id, CUSTODIAL_STALE_INTENT_SECS
                    );
                    deps.metrics.record_custodial_sweep("expired", 1);
                }
                Ok(false) => {}
                Err(e) => error!(
                    "custodial sweep: intent {} reject failed: {:?}",
                    row.intent_id, e
                ),
            }
        }
        SweepVerdict::Leave => {
            if head_fresh == Some(true) {
                error!(
                    "custodial sweep: intent {} (hash {}) exists on-chain but is not the expected \
                     payment; an admin must resolve it (POST /admin/custody/intents/{}/resolve)",
                    row.intent_id, hash, row.intent_id
                );
            } else {
                warn!(
                    "custodial sweep: intent {} left unresolved (Horizon unreachable or lagging)",
                    row.intent_id
                );
            }
            deps.metrics.record_custodial_sweep("left", 1);
        }
    }
}

impl AppMetrics {
    /// `custodial.intents_swept{outcome}`.
    pub fn record_custodial_sweep(&self, outcome: &'static str, n: u64) {
        self.custodial_intents_swept
            .add(n, &[KeyValue::new("outcome", outcome)]);
    }

    /// `custodial.intents_open{status}` gauge.
    pub fn record_custodial_open(&self, status: &'static str, n: u64) {
        self.custodial_intents_open
            .record(n, &[KeyValue::new("status", status)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_verdict_table() {
        let found = |settles, any_failed| HashLookup::Found {
            settles,
            any_failed,
        };
        for fresh in [Some(true), Some(false), None] {
            assert_eq!(
                sweep_verdict(found(true, false), fresh),
                SweepVerdict::Settle
            );
            // A settling payment inside a transaction Horizon also flags as
            // failed cannot happen; settle wins so the row is never lost.
            assert_eq!(
                sweep_verdict(found(true, true), fresh),
                SweepVerdict::Settle
            );
            assert_eq!(
                sweep_verdict(found(false, true), fresh),
                SweepVerdict::RejectFailedOnChain
            );
            assert_eq!(
                sweep_verdict(found(false, false), fresh),
                SweepVerdict::Leave
            );
            assert_eq!(sweep_verdict(HashLookup::Error, fresh), SweepVerdict::Leave);
        }
        assert_eq!(
            sweep_verdict(HashLookup::NotFound, Some(true)),
            SweepVerdict::RejectExpired
        );
    }

    #[test]
    fn stale_head_is_inconclusive() {
        // Absence on a lagging or unread Horizon is lag, not proof.
        assert_eq!(
            sweep_verdict(HashLookup::NotFound, Some(false)),
            SweepVerdict::Leave
        );
        assert_eq!(
            sweep_verdict(HashLookup::NotFound, None),
            SweepVerdict::Leave
        );
    }

    #[test]
    fn unreadable_chain_yields_leave_not_reject() {
        assert_eq!(
            sweep_verdict(HashLookup::Error, Some(true)),
            SweepVerdict::Leave
        );
    }

    #[test]
    fn abandon_sql_never_touches_armed_rows() {
        assert!(ABANDON_SQL.contains("WHERE status = 'prepared' AND stellar_hash IS NULL"));
        assert!(ABANDON_SQL.contains("resolution = 'sweep_abandoned'"));
        assert!(ABANDON_SQL.contains("make_interval(secs => $1)"));
        assert!(!ABANDON_SQL.contains("'submitted'"));
        assert!(!ABANDON_SQL.contains("'ambiguous'"));
    }

    #[test]
    fn stale_sql_selects_only_armed_open_rows() {
        assert!(STALE_SQL.contains("WHERE status IN ('submitted', 'ambiguous')"));
        assert!(STALE_SQL.contains("armed_at < CURRENT_TIMESTAMP - make_interval(secs => $1)"));
        assert!(STALE_SQL.contains("ORDER BY armed_at LIMIT $2"));
        assert!(!STALE_SQL.contains("'prepared'"));
        for col in crate::custody::intent::OPEN_INTENT_COLUMNS
            .split(',')
            .map(str::trim)
        {
            assert!(STALE_SQL.contains(col), "STALE_SQL lacks {}", col);
        }
    }

    #[test]
    fn open_counts_cover_every_non_terminal_status() {
        for s in crate::constants::CUSTODIAL_INTENT_OPEN_STATUSES {
            assert!(OPEN_COUNTS_SQL.contains(&format!("'{}'", s)));
        }
    }
}

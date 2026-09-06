//! Daily reconciliation snapshot job.
//!
//! Every `RECONCILIATION_JOB_INTERVAL_SECS`: if the configured UTC hour has
//! passed and no `daily` row exists for today's UTC date, take the
//! `RECONCILIATION_LOCK_KEY` advisory lock (skip the pass if held), compute
//! the full report (every custodial address, under the account and time
//! budgets) and record it. The partial unique index on
//! `(snapshot_date) WHERE kind = 'daily'` is the idempotency anchor: two
//! instances racing past the lock still produce exactly one row per date.
//!
//! A Horizon-lagging day is still recorded (`horizon_fresh = false`,
//! `invariants_ok = false`, warning `horizon_lagging`) with its drift alerts
//! suppressed — durable evidence of an unverifiable day beats a missing one.

use futures::FutureExt;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;

use crate::constants::{
    RECONCILIATION_JOB_INTERVAL_SECS, RECONCILIATION_LOCK_KEY, RECONCILIATION_SNAPSHOT_DAILY,
};
use crate::error::AppError;
use crate::exchange::reserve_watch::AdvisoryLock;

use super::compute::next_snapshot_due;
use super::{build_positions, record_snapshot, CustodialScope, ReconcileDeps};

/// The most recent daily snapshot date (cheap existence probe).
const LAST_DAILY_SQL: &str = "SELECT MAX(snapshot_date) FROM reconciliation_snapshot \
     WHERE kind = 'daily'";

pub async fn run(deps: Arc<ReconcileDeps>, utc_hour: u32, cancel: CancellationToken) {
    info!(
        "reconciliation snapshot job started: utc_hour={} max_accounts={} deadline={}s",
        utc_hour, deps.max_accounts, deps.deadline_secs
    );
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("reconciliation snapshot job stopped");
                return;
            }
            _ = sleep(Duration::from_secs(RECONCILIATION_JOB_INTERVAL_SECS)) => {
                match std::panic::AssertUnwindSafe(tick(&deps, utc_hour)).catch_unwind().await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => error!("reconciliation snapshot pass failed: {:?}", e),
                    Err(_) => error!("reconciliation snapshot job PANICKED; continuing"),
                }
            }
        }
    }
}

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("reconciliation job: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

async fn tick(deps: &ReconcileDeps, utc_hour: u32) -> Result<(), AppError> {
    let last_daily: Option<chrono::NaiveDate> = sqlx::query_scalar(LAST_DAILY_SQL)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("last daily"))?;
    if !next_snapshot_due(last_daily, chrono::Utc::now(), utc_hour) {
        return Ok(());
    }
    let lock = AdvisoryLock::new(RECONCILIATION_LOCK_KEY);
    let Some(guard) = lock
        .try_acquire(&deps.pool)
        .await
        .map_err(db_err("try lock"))?
    else {
        debug!("reconciliation job: another instance holds the lock; skipping this pass");
        return Ok(());
    };
    let result = snapshot_today(deps).await;
    if let Err(e) = guard.release_now().await {
        warn!(
            "reconciliation job: advisory unlock failed ({}); the guard's drop will release it",
            e
        );
    }
    result
}

async fn snapshot_today(deps: &ReconcileDeps) -> Result<(), AppError> {
    let report = build_positions(deps, CustodialScope::All).await?;
    match record_snapshot(deps, RECONCILIATION_SNAPSHOT_DAILY, None, &report).await? {
        Some(id) => info!(
            "reconciliation: daily snapshot {} recorded (complete={} fresh={} invariants_ok={} drift={})",
            id,
            report.response.complete,
            report.response.horizon.fresh,
            report.invariants_ok(),
            report.drift_detected()
        ),
        None => debug!("reconciliation: another instance recorded today's snapshot first"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_daily_probe_reads_the_date_column() {
        assert!(LAST_DAILY_SQL.contains("MAX(snapshot_date)"));
        assert!(LAST_DAILY_SQL.contains("kind = 'daily'"));
    }
}

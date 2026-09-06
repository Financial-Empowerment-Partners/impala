//! Reconciliation: the positions report (`GET /admin/reconciliation/
//! positions`) and its durable snapshots (037 part C).
//!
//! [`compute`] holds the schema and the pure arithmetic; this module gathers
//! the inputs (ledger, journal, obligations, custodial addresses, Horizon)
//! and [`job`] records one attributable daily snapshot per UTC date.
//!
//! Honesty rules baked into the report: the chain is authoritative for
//! Stellar; `conversion_reserve` is a mirror obligated to
//! `available + held == on-chain` per chain-legged bucket; Payala balances
//! are self-reported and unverified; on-card balances never reach the
//! bridge. An unverifiable state (Horizon lagging or unreachable) reads as
//! `null`, never as clean.

pub mod compute;
pub mod job;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use log::{error, warn};
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::constants::{
    CUSTODIAL_STALE_INTENT_SECS, HORIZON_MAX_LAG_SECS, RECONCILIATION_HORIZON_CONCURRENCY,
    RECONCILIATION_SNAPSHOT_DAILY, RESERVE_CURRENCY_XLM, RESERVE_SCALE_STELLAR,
};
use crate::custody::policy::PolicyRow;
use crate::error::AppError;
use crate::events::{emit_event, AccountEvent};
use crate::exchange::reserve::{parse_decimal_to_minor, ConversionReserve};
use crate::stellar::horizon::{fetch_head_closed_at, head_is_fresh};
use crate::stellar::OnchainAccount;
use crate::telemetry::AppMetrics;
use compute::*;

/// Shared by the admin endpoint and the daily job.
pub struct ReconcileDeps {
    pub pool: PgPool,
    pub http: Arc<reqwest::Client>,
    pub horizon_url: String,
    pub reserve: Option<Arc<ConversionReserve>>,
    pub metrics: Arc<AppMetrics>,
    /// Budget for a full custodial walk (`RECONCILIATION_MAX_ACCOUNTS`).
    pub max_accounts: i64,
    /// Wall-clock budget for a full walk (`RECONCILIATION_DEADLINE_SECS`).
    pub deadline_secs: u64,
}

/// Which custodial addresses a report covers.
#[derive(Debug, Clone, Copy)]
pub enum CustodialScope {
    /// One page (the interactive endpoint).
    Page { page: u64, per_page: u64 },
    /// Every address, under the account and time budgets (snapshots).
    All,
}

// ── SQL ────────────────────────────────────────────────────────────────

const BUCKETS_SQL: &str = "SELECT currency, minor_scale, available, held, drift_tolerance_minor \
     FROM conversion_reserve ORDER BY currency";
const JOURNAL_SQL: &str = "SELECT currency, COALESCE(SUM(delta), 0)::bigint, \
        COALESCE(SUM(held_delta), 0)::bigint \
     FROM conversion_reserve_entry GROUP BY currency";
const REFUNDS_SQL: &str = "SELECT currency, status, COALESCE(SUM(refund_minor), 0)::bigint \
     FROM conversion_reserve_refund \
     WHERE status IN ('queued', 'needs_review', 'frozen', 'inflight') GROUP BY 1, 2";
const PAYOUT_INTENTS_OPEN_SQL: &str = "SELECT COUNT(*) FROM conversion_reserve_entry e \
     WHERE e.kind = 'payout_attempt' AND NOT EXISTS \
       (SELECT 1 FROM conversion_reserve_entry f \
         WHERE f.order_id = e.order_id AND f.kind = 'fulfillment')";
const CYCLES_IN_FLIGHT_SQL: &str = "SELECT COUNT(*) FROM conversion_reserve_replenishment \
     WHERE state NOT IN ('completed', 'failed', 'refunded')";
/// Net `held` attributable to replenishment cycles, from the journal.
const CYCLE_HOLDS_SQL: &str = "SELECT currency, COALESCE(SUM(held_delta), 0)::bigint \
     FROM conversion_reserve_entry WHERE cycle_id IS NOT NULL GROUP BY currency";
const FIAT_IN_TRANSIT_SQL: &str = "SELECT COALESCE(SUM(fiat_minor), 0)::bigint \
     FROM conversion_reserve_replenishment WHERE state = 'in_transit'";
/// Holds of open reserve orders, from whichever anchor took them
/// (ORDER_HOLD_SQL semantics, aggregated).
const ORDER_HOLDS_SQL: &str = "SELECT COALESCE(e.currency, q.hold_currency) AS currency, \
        COALESCE(SUM(COALESCE(-e.delta, q.hold_minor)), 0)::bigint \
     FROM exchange_order o \
     LEFT JOIN conversion_reserve_entry e ON e.order_id = o.order_id AND e.kind = 'hold' \
     LEFT JOIN conversion_reserve_quote q ON q.order_id = o.order_id AND q.status = 'consumed' \
     WHERE o.provider = 'reserve' \
       AND o.status IN ('created', 'awaiting_deposit', 'processing', 'on_hold') \
       AND (e.entry_id IS NOT NULL OR q.quote_id IS NOT NULL) \
     GROUP BY 1";
const QUOTE_HOLDS_SQL: &str = "SELECT hold_currency, COALESCE(SUM(hold_minor), 0)::bigint \
     FROM conversion_reserve_quote WHERE status = 'open' GROUP BY 1";
const CUSTODIAL_COUNT_SQL: &str = "SELECT COUNT(*) FROM managed_seed \
     WHERE ($1::text IS NULL OR payala_account_id <> $1)";
const CUSTODIAL_PAGE_SQL: &str = "SELECT payala_account_id, stellar_account_id, origin, \
        format_version \
     FROM managed_seed WHERE ($1::text IS NULL OR payala_account_id <> $1) \
     ORDER BY id LIMIT $2 OFFSET $3";
const OPEN_INTENTS_BY_ACCOUNT_SQL: &str = "SELECT payala_account_id, COUNT(*), \
        COALESCE(SUM(amount_minor), 0)::bigint \
     FROM custodial_payment_intent \
     WHERE status IN ('prepared', 'submitted', 'ambiguous') AND payala_account_id = ANY($1) \
     GROUP BY 1";
const INTENT_COUNTS_SQL: &str = "SELECT status, COUNT(*) FROM custodial_payment_intent \
     WHERE status IN ('prepared', 'submitted', 'ambiguous') GROUP BY status";
const INTENT_STALE_SQL: &str = "SELECT COUNT(*) FROM custodial_payment_intent \
     WHERE status IN ('submitted', 'ambiguous') \
       AND armed_at < CURRENT_TIMESTAMP - make_interval(secs => $1)";
const INTENTS_SETTLED_24H_SQL: &str = "SELECT COALESCE(SUM(amount_minor), 0)::bigint \
     FROM custodial_payment_intent \
     WHERE status = 'settled' AND resolved_at >= CURRENT_TIMESTAMP - interval '24 hours'";
const CUSTODIAL_POLICY_SQL: &str = "SELECT paused, per_tx_max_stroops, \
        per_account_daily_max_stroops, require_idempotency_key FROM custodial_policy WHERE id";
const PAYALA_ACCOUNTS_SQL: &str = "SELECT COUNT(DISTINCT payala_account_id) FROM payala_reserve";
const PAYALA_NET_SQL: &str = "SELECT currency, COALESCE(SUM(balance), 0)::bigint \
     FROM payala_reserve GROUP BY currency";
const PAYALA_LAST_BATCH_SQL: &str = "SELECT to_char(MAX(created_at) AT TIME ZONE 'UTC', \
        'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM payala_sync_batch";
/// 11 binds; `ON CONFLICT DO NOTHING` is the daily anchor
/// (`uq_reconciliation_snapshot_daily`).
pub(crate) const SNAPSHOT_INSERT_SQL: &str = "INSERT INTO reconciliation_snapshot \
     (snapshot_date, kind, schema_version, as_of, horizon_head_closed_at, horizon_fresh, \
      complete, drift_detected, invariants_ok, payload, created_by) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
     ON CONFLICT DO NOTHING RETURNING snapshot_id";

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("reconciliation: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A gathered report plus the raw facts the snapshot row stores alongside
/// the payload.
pub struct Report {
    pub as_of: DateTime<Utc>,
    pub horizon_head: Option<DateTime<Utc>>,
    pub response: PositionsResponse,
}

impl Report {
    pub fn invariants_ok(&self) -> bool {
        invariants_ok(&self.response.invariants)
    }
    pub fn drift_detected(&self) -> bool {
        drift_detected(&self.response.reserve.buckets)
    }
}

/// The reserve account's chain state (best-effort; the caller decides what
/// an error means). Shared with `admin_reserve::get_status`.
pub(crate) async fn reserve_chain_snapshot(
    http: &reqwest::Client,
    horizon_url: &str,
    reserve: &ConversionReserve,
) -> Result<OnchainAccount, AppError> {
    crate::stellar::fetch_account_details(http, horizon_url, &reserve.stellar_address).await
}

#[derive(sqlx::FromRow)]
struct BucketRow {
    currency: String,
    minor_scale: i16,
    available: i64,
    held: i64,
    drift_tolerance_minor: i64,
}

#[derive(sqlx::FromRow)]
struct SeedRow {
    payala_account_id: String,
    stellar_account_id: String,
    origin: String,
    format_version: i16,
}

/// Gather the whole report.
pub async fn build_positions(
    deps: &ReconcileDeps,
    scope: CustodialScope,
) -> Result<Report, AppError> {
    let started = Instant::now();
    let as_of = Utc::now();
    let mut warnings: Vec<String> = Vec::new();

    // ── Horizon head ──────────────────────────────────────────────────
    let horizon_head = match fetch_head_closed_at(&deps.http, &deps.horizon_url).await {
        Ok(h) => Some(h),
        Err(_) => {
            warnings.push("horizon_unreachable".to_string());
            None
        }
    };
    let fresh = horizon_head.is_some_and(|h| head_is_fresh(h, as_of, HORIZON_MAX_LAG_SECS));
    if horizon_head.is_some() && !fresh {
        warnings.push("horizon_lagging".to_string());
    }
    let horizon = HorizonView {
        url: deps.horizon_url.clone(),
        head_closed_at: horizon_head.map(ts),
        lag_secs: horizon_head.map(|h| as_of.signed_duration_since(h).num_seconds()),
        fresh,
    };

    // ── Reserve: ledger, journal, chain ───────────────────────────────
    let bucket_rows: Vec<BucketRow> = sqlx::query_as(BUCKETS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("buckets"))?;
    let journal: BTreeMap<String, (i64, i64)> =
        sqlx::query_as::<_, (String, i64, i64)>(JOURNAL_SQL)
            .fetch_all(&deps.pool)
            .await
            .map_err(db_err("journal"))?
            .into_iter()
            .map(|(c, a, h)| (c, (a, h)))
            .collect();

    let chain = match &deps.reserve {
        Some(r) => match reserve_chain_snapshot(&deps.http, &deps.horizon_url, r).await {
            Ok(acct) => Some(acct),
            Err(_) => {
                warnings.push("reserve_chain_unreachable".to_string());
                None
            }
        },
        None => None,
    };
    let chain_readable = chain.is_some();
    let mut buckets = Vec::with_capacity(bucket_rows.len());
    for b in &bucket_rows {
        let (asset, chain_leg) = match &deps.reserve {
            Some(r) if b.currency == RESERVE_CURRENCY_XLM => (None, true),
            Some(r) => match r.stablecoin(&b.currency) {
                Some((code, issuer)) => (Some(format!("{}:{}", code, issuer)), true),
                None => (None, false),
            },
            None => (None, false),
        };
        let (onchain_raw, trustline) = match (&chain, &deps.reserve) {
            (Some(acct), Some(r)) if acct.exists => {
                if b.currency == RESERVE_CURRENCY_XLM {
                    (acct.native_balance.clone(), None)
                } else if let Some((code, issuer)) = r.stablecoin(&b.currency) {
                    let line = acct.balances.iter().find(|bal| {
                        bal.asset_code.as_deref() == Some(code)
                            && bal.asset_issuer.as_deref() == Some(issuer)
                    });
                    (line.map(|l| l.balance.clone()), Some(line.is_some()))
                } else {
                    (None, None)
                }
            }
            _ => (None, None),
        };
        let (a, h) = journal.get(&b.currency).copied().unwrap_or((0, 0));
        let (pos, w) = bucket_position(
            &BucketInput {
                currency: b.currency.clone(),
                minor_scale: b.minor_scale,
                available: b.available,
                held: b.held,
                drift_tolerance: b.drift_tolerance_minor,
                journal_available: a,
                journal_held: h,
                asset,
                chain_leg,
                onchain_raw,
                trustline,
                offline_held: 0,
            },
            chain_readable && chain.as_ref().is_some_and(|c| c.exists),
        );
        warnings.extend(w);
        buckets.push(pos);
    }

    // ── Obligations ───────────────────────────────────────────────────
    let mut obligations = Obligations::default();
    for (currency, status, minor) in sqlx::query_as::<_, (String, String, i64)>(REFUNDS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("refunds"))?
    {
        let map = match status.as_str() {
            "queued" => &mut obligations.refunds_minor.queued,
            "needs_review" => &mut obligations.refunds_minor.needs_review,
            "frozen" => &mut obligations.refunds_minor.frozen,
            "inflight" => &mut obligations.refunds_minor.inflight,
            _ => continue,
        };
        map.insert(currency, minor);
    }
    obligations.order_holds_minor = sqlx::query_as::<_, (String, i64)>(ORDER_HOLDS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("order holds"))?
        .into_iter()
        .collect();
    obligations.quote_holds_minor = sqlx::query_as::<_, (String, i64)>(QUOTE_HOLDS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("quote holds"))?
        .into_iter()
        .collect();
    obligations.payout_intents_open = sqlx::query_scalar(PAYOUT_INTENTS_OPEN_SQL)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("payout intents"))?;
    obligations.cycles_in_flight = sqlx::query_scalar(CYCLES_IN_FLIGHT_SQL)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("cycles"))?;
    obligations.cycle_holds_minor = sqlx::query_as::<_, (String, i64)>(CYCLE_HOLDS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("cycle holds"))?
        .into_iter()
        .filter(|(_, m)| *m != 0)
        .collect();
    obligations.fiat_in_transit_cents = sqlx::query_scalar(FIAT_IN_TRANSIT_SQL)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("fiat in transit"))?;
    // Offline issuance/redemption (038) does not exist yet: zero liabilities.
    for b in &buckets {
        obligations
            .offline_outstanding_minor
            .insert(b.currency.clone(), 0);
    }

    // ── Custodial addresses ───────────────────────────────────────────
    let reserve_id = deps.reserve.as_ref().map(|r| r.reserve_account_id.clone());
    let accounts_total: i64 = sqlx::query_scalar(CUSTODIAL_COUNT_SQL)
        .bind(&reserve_id)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("custodial count"))?;
    let (page, per_page, mut offset, limit_pages) = match scope {
        CustodialScope::Page { page, per_page } => {
            let (pp, off) = crate::models::PaginationParams { page, per_page }.clamped();
            (page.max(1), pp as u64, off, Some(1usize))
        }
        CustodialScope::All => (1, 100, 0, None),
    };
    let deadline = Duration::from_secs(deps.deadline_secs);
    let mut seeds: Vec<SeedRow> = Vec::new();
    let mut truncated = false;
    let mut pages_read = 0usize;
    loop {
        if limit_pages.is_some_and(|n| pages_read >= n) {
            break;
        }
        if matches!(scope, CustodialScope::All)
            && (seeds.len() as i64 >= deps.max_accounts || started.elapsed() > deadline)
        {
            truncated = true;
            break;
        }
        let rows: Vec<SeedRow> = sqlx::query_as(CUSTODIAL_PAGE_SQL)
            .bind(&reserve_id)
            .bind(per_page as i64)
            .bind(offset)
            .fetch_all(&deps.pool)
            .await
            .map_err(db_err("custodial page"))?;
        let n = rows.len();
        seeds.extend(rows);
        pages_read += 1;
        offset += per_page as i64;
        if n < per_page as usize {
            break;
        }
    }
    if matches!(scope, CustodialScope::All) && (seeds.len() as i64) < accounts_total && !truncated {
        truncated = true;
    }
    if truncated {
        warnings.push(format!(
            "custodial_walk_truncated: {} of {} addresses read",
            seeds.len(),
            accounts_total
        ));
    }

    let ids: Vec<String> = seeds.iter().map(|s| s.payala_account_id.clone()).collect();
    let open_by_account: BTreeMap<String, (i64, i64)> =
        sqlx::query_as::<_, (String, i64, i64)>(OPEN_INTENTS_BY_ACCOUNT_SQL)
            .bind(&ids)
            .fetch_all(&deps.pool)
            .await
            .map_err(db_err("open intents by account"))?
            .into_iter()
            .map(|(a, n, m)| (a, (n, m)))
            .collect();

    let mut positions: Vec<CustodialPosition> = seeds
        .iter()
        .map(|s| {
            let (n, m) = open_by_account
                .get(&s.payala_account_id)
                .copied()
                .unwrap_or((0, 0));
            CustodialPosition {
                payala_account_id: s.payala_account_id.clone(),
                stellar_account_id: s.stellar_account_id.clone(),
                origin: s.origin.clone(),
                format_version: s.format_version,
                onchain: None,
                unreachable: false,
                open_intents: n,
                open_intents_minor: m,
            }
        })
        .collect();

    let addresses: Vec<(usize, String)> = positions
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p.stellar_account_id.clone()))
        .collect();
    let lookups = futures::stream::iter(addresses.into_iter().map(|(i, address)| {
        let http = deps.http.clone();
        let horizon_url = deps.horizon_url.clone();
        async move {
            (
                i,
                crate::stellar::fetch_account_details(&http, &horizon_url, &address).await,
            )
        }
    }))
    .buffer_unordered(RECONCILIATION_HORIZON_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    let mut totals = CustodialTotals::default();
    for (i, result) in lookups {
        match result {
            Ok(acct) => {
                let xlm = acct
                    .native_balance
                    .as_deref()
                    .and_then(|b| parse_decimal_to_minor(b, RESERVE_SCALE_STELLAR));
                if let Some(x) = xlm {
                    totals.xlm_stroops = totals.xlm_stroops.saturating_add(x);
                }
                let balances = acct
                    .balances
                    .iter()
                    .filter(|b| b.asset_type != "native")
                    .map(|b| CustodialBalance {
                        asset_code: b.asset_code.clone().unwrap_or_default(),
                        asset_issuer: b.asset_issuer.clone(),
                        minor: parse_decimal_to_minor(&b.balance, RESERVE_SCALE_STELLAR),
                    })
                    .collect();
                positions[i].onchain = Some(CustodialOnchain {
                    exists: acct.exists,
                    xlm_stroops: xlm,
                    balances,
                });
            }
            Err(_) => {
                positions[i].unreachable = true;
                totals.addresses_unreachable += 1;
            }
        }
    }
    totals.addresses_checked = positions.len();
    totals.truncated = truncated;
    for (status, n) in sqlx::query_as::<_, (String, i64)>(INTENT_COUNTS_SQL)
        .fetch_all(&deps.pool)
        .await
        .map_err(db_err("intent counts"))?
    {
        match status.as_str() {
            "prepared" => totals.intents_prepared = n,
            "submitted" => totals.intents_submitted = n,
            "ambiguous" => totals.intents_ambiguous = n,
            _ => {}
        }
    }
    totals.intents_stale = sqlx::query_scalar(INTENT_STALE_SQL)
        .bind(CUSTODIAL_STALE_INTENT_SECS as f64)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("stale intents"))?;
    totals.intents_settled_24h_minor = sqlx::query_scalar(INTENTS_SETTLED_24H_SQL)
        .fetch_one(&deps.pool)
        .await
        .map_err(db_err("settled 24h"))?;
    let policy: Option<PolicyRow> = sqlx::query_as(CUSTODIAL_POLICY_SQL)
        .fetch_optional(&deps.pool)
        .await
        .map_err(db_err("custodial policy"))?;
    let policy_summary = match policy {
        Some(p) => CustodialPolicySummary {
            paused: p.paused,
            configured: p.is_configured(),
        },
        None => {
            warnings.push("custodial_policy_row_missing".to_string());
            CustodialPolicySummary {
                paused: false,
                configured: false,
            }
        }
    };

    // ── Payala (self-reported, unverified) ────────────────────────────
    let payala = PayalaView {
        source: PAYALA_SOURCE,
        accounts_with_reserve: sqlx::query_scalar(PAYALA_ACCOUNTS_SQL)
            .fetch_one(&deps.pool)
            .await
            .map_err(db_err("payala accounts"))?,
        net_minor_by_currency: sqlx::query_as::<_, (String, i64)>(PAYALA_NET_SQL)
            .fetch_all(&deps.pool)
            .await
            .map_err(db_err("payala net"))?
            .into_iter()
            .collect(),
        last_batch_at: sqlx::query_scalar::<_, Option<String>>(PAYALA_LAST_BATCH_SQL)
            .fetch_one(&deps.pool)
            .await
            .map_err(db_err("payala last batch"))?,
    };

    let chain_verifiable = fresh
        && deps.reserve.is_some()
        && chain_readable
        && chain.as_ref().is_some_and(|c| c.exists);
    if deps.reserve.is_some() && chain.as_ref().is_some_and(|c| !c.exists) {
        warnings.push("reserve_account_not_found_on_chain".to_string());
    }
    let invariants = invariants(&buckets, &obligations, &totals, chain_verifiable, fresh);

    let response = PositionsResponse {
        schema_version: schema_version(),
        as_of: ts(as_of),
        complete: !truncated,
        horizon,
        reserve: ReserveView {
            configured: deps.reserve.is_some(),
            stellar_address: deps.reserve.as_ref().map(|r| r.stellar_address.clone()),
            buckets,
            obligations,
        },
        custodial: CustodialView {
            source: CUSTODIAL_SOURCE,
            accounts_total,
            page,
            per_page,
            checked: positions.len(),
            positions,
            totals,
            policy: policy_summary,
        },
        payala,
        card: CardView {
            source: CARD_SOURCE,
            note: CARD_NOTE,
        },
        invariants,
        warnings,
    };
    Ok(Report {
        as_of,
        horizon_head,
        response,
    })
}

/// Persist a report as a snapshot row with its events, in one transaction.
/// `Ok(None)` = the daily anchor already held a row for the date (another
/// instance won); nothing was written.
pub async fn record_snapshot(
    deps: &ReconcileDeps,
    kind: &str,
    created_by: Option<&str>,
    report: &Report,
) -> Result<Option<Uuid>, AppError> {
    let payload = serde_json::to_value(&report.response).map_err(|e| {
        error!("reconciliation: payload serialization failed: {}", e);
        AppError::InternalError("snapshot serialization failed".to_string())
    })?;
    let invariants_ok = report.invariants_ok();
    let drift_detected = report.drift_detected();
    let fresh = report.response.horizon.fresh;
    let mut tx = deps.pool.begin().await.map_err(db_err("snapshot begin"))?;
    let inserted: Option<Uuid> = sqlx::query_scalar(SNAPSHOT_INSERT_SQL)
        .bind(report.as_of.date_naive())
        .bind(kind)
        .bind(report.response.schema_version)
        .bind(report.as_of)
        .bind(report.horizon_head)
        .bind(fresh)
        .bind(report.response.complete)
        .bind(drift_detected)
        .bind(invariants_ok)
        .bind(&payload)
        .bind(created_by)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("snapshot insert"))?;
    let Some(snapshot_id) = inserted else {
        drop(tx);
        return Ok(None);
    };
    let actor = deps
        .reserve
        .as_ref()
        .map(|r| r.reserve_account_id.clone())
        .unwrap_or_else(|| "bridge".to_string());
    // Drift alerts only from a fresh Horizon: a lagging day is recorded
    // (unattested) with its alerts suppressed.
    if fresh {
        for b in &report.response.reserve.buckets {
            if b.chain_leg && b.drift_ok == Some(false) {
                if let (Some(onchain), Some(ledger), Some(drift)) =
                    (b.onchain_minor, b.ledger_total_minor, b.drift_minor)
                {
                    emit_event(
                        &mut tx,
                        &AccountEvent::ReserveDrift {
                            account_id: actor.clone(),
                            currency: b.currency.clone(),
                            ledger_total_minor: ledger,
                            onchain_minor: onchain,
                            drift_minor: drift,
                            tolerance_minor: b.drift_tolerance_minor,
                            snapshot_id: snapshot_id.to_string(),
                        },
                    )
                    .await?;
                }
            }
        }
    }
    emit_event(
        &mut tx,
        &AccountEvent::ReconciliationSnapshotRecorded {
            account_id: actor,
            snapshot_id: snapshot_id.to_string(),
            kind: kind.to_string(),
            complete: report.response.complete,
            drift_detected,
            invariants_ok,
            horizon_fresh: fresh,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("snapshot commit"))?;

    deps.metrics
        .record_reconciliation_snapshot(kind, report.response.complete, invariants_ok);
    for b in &report.response.reserve.buckets {
        if let Some(d) = b.drift_minor {
            deps.metrics.record_reconciliation_drift(&b.currency, d);
        }
    }
    if drift_detected {
        warn!(
            "reconciliation snapshot {} ({}): DRIFT detected; see reserve.drift events",
            snapshot_id, kind
        );
    }
    if kind == RECONCILIATION_SNAPSHOT_DAILY && !invariants_ok {
        warn!(
            "reconciliation snapshot {} (daily) is UNATTESTED: invariants_ok=false fresh={} complete={}",
            snapshot_id, fresh, report.response.complete
        );
    }
    Ok(Some(snapshot_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_insert_binds_eleven() {
        let cols = &SNAPSHOT_INSERT_SQL
            [SNAPSHOT_INSERT_SQL.find('(').unwrap() + 1..SNAPSHOT_INSERT_SQL.find(')').unwrap()];
        assert_eq!(cols.split(',').count(), 11);
        assert!(SNAPSHOT_INSERT_SQL.contains("$11)"));
        assert!(!SNAPSHOT_INSERT_SQL.contains("$12"));
        assert!(SNAPSHOT_INSERT_SQL.contains("ON CONFLICT DO NOTHING RETURNING snapshot_id"));
    }

    #[test]
    fn obligation_queries_name_their_states() {
        assert!(REFUNDS_SQL.contains("('queued', 'needs_review', 'frozen', 'inflight')"));
        assert!(CYCLES_IN_FLIGHT_SQL.contains("NOT IN ('completed', 'failed', 'refunded')"));
        for s in crate::constants::RESERVE_TERMINAL_CYCLE_STATES {
            assert!(CYCLES_IN_FLIGHT_SQL.contains(&format!("'{}'", s)));
        }
        assert!(FIAT_IN_TRANSIT_SQL.contains("state = 'in_transit'"));
        assert!(ORDER_HOLDS_SQL.contains("e.kind = 'hold'"));
        assert!(ORDER_HOLDS_SQL.contains("q.status = 'consumed'"));
        assert!(QUOTE_HOLDS_SQL.contains("status = 'open'"));
        assert!(PAYOUT_INTENTS_OPEN_SQL.contains("'payout_attempt'"));
        assert!(PAYOUT_INTENTS_OPEN_SQL.contains("'fulfillment'"));
        for s in crate::constants::CUSTODIAL_INTENT_OPEN_STATUSES {
            assert!(OPEN_INTENTS_BY_ACCOUNT_SQL.contains(&format!("'{}'", s)));
            assert!(INTENT_COUNTS_SQL.contains(&format!("'{}'", s)));
        }
        assert!(
            INTENT_STALE_SQL.contains("armed_at < CURRENT_TIMESTAMP - make_interval(secs => $1)")
        );
    }

    /// The custodial walk always excludes the reserve account: its custody is
    /// reported under `reserve`, and counting it twice would double the
    /// XLM total.
    #[test]
    fn custodial_walk_excludes_the_reserve_account() {
        assert!(CUSTODIAL_COUNT_SQL.contains("payala_account_id <> $1"));
        assert!(CUSTODIAL_PAGE_SQL.contains("payala_account_id <> $1"));
        assert!(CUSTODIAL_PAGE_SQL.contains("ORDER BY id LIMIT $2 OFFSET $3"));
    }
}

//! Conversion-reserve background driver: deposit detection, on-chain USDC
//! payouts, stale-payout freezing, and pay-in-window expiry.
//!
//! One tick (see [`tick`]) runs the phases in a fixed order — deposits first
//! so a pay-in landing near its deadline is matched before the expiry pass
//! can release its hold, and expiry ONLY after a fully successful page drain
//! (a Horizon outage must delay expiry, not race it):
//!
//! 1. **Deposits** — page `GET /accounts/{reserve}/payments` forward from the
//!    stored cursor, match incoming payments by text memo against
//!    `awaiting_deposit` reserve orders, and record every stray inflow in
//!    `conversion_reserve_unmatched` (custodial money is never tracked in
//!    log lines only). The cursor advances only after a page's transactions
//!    commit — misses are forbidden; replays are no-ops via the per-payment
//!    paging_token anchor (a credited payment's token lands in exactly one
//!    of conversion_reserve_entry / conversion_reserve_unmatched, and the
//!    pre-check + unique indexes catch it even when its CLASSIFICATION
//!    changes between passes), backstopped by `UNIQUE(order_id, kind)`.
//! 2. **Payouts** — for `processing` auto-swap orders: write the
//!    `payout_attempt` intent entry FIRST (write-ahead; the partial unique
//!    index makes exactly one writer win), then submit the USDC payment,
//!    then record completion. A definitive Horizon rejection (400 with
//!    result codes — the tx provably did not land) schedules a bounded
//!    retry; an ambiguous outcome (timeout/5xx) freezes the order `on_hold`
//!    for admin resolution and is NEVER resubmitted automatically.
//! 3. **Stale sweep** — `processing` orders whose intent is old but whose
//!    submit outcome was never recorded (crash mid-flight) freeze `on_hold`.
//! 4. **Expiry** — `awaiting_deposit` orders past the deposit TTL expire and
//!    release their hold.
//!
//! Multi-instance: every tick takes `pg_try_advisory_lock` and skips when
//! another instance holds it. Money-correctness (no double payout, no
//! double credit) never depends on the lock — the intent unique index, the
//! paging_token anchor, and guarded status transitions carry it; only work
//! dedup and retry PACING (backoff/poll_count bookkeeping) assume a single
//! ticker, so a lock that fails open degrades to noise, not loss.

use std::sync::Arc;

use log::{error, info, warn};
use sqlx::PgPool;
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::constants::{
    RESERVE_CURRENCY_USDC, RESERVE_CURRENCY_XLM, RESERVE_MAX_PAYOUT_ATTEMPTS,
    RESERVE_SCALE_STELLAR, RESERVE_WATCHER_LOCK_KEY, RESERVE_WATCH_PAGE_LIMIT,
};
use crate::error::AppError;
use crate::events::AccountEvent;
use crate::exchange::reconcile::poll_backoff_secs;
use crate::exchange::reserve::{
    memo_matches_ref, minor_to_decimal_string, parse_decimal_to_minor, ConversionReserve,
    RESERVE_BUCKET_APPLY_SQL, RESERVE_ENTRY_INSERT_SQL,
};
use crate::seed_protect::SeedProtector;
use crate::stellar::horizon::{fetch_latest_cursor, fetch_payments_page, HorizonPayment};
use crate::stellar::{Asset, PaymentParams, StellarSigner};
use crate::telemetry::AppMetrics;

/// Intent age after which a `processing` order with no recorded submit
/// outcome is frozen for admin review. Longer than the signed transaction's
/// 300s validity window so "still in flight" and "crashed" can't be confused.
const STALE_INTENT_SECS: i64 = 600;
// Compile-time guard: the freeze threshold must never undercut the payment's
// validity window (signer TX_TIMEOUT_SECS = 300) or a freeze could race a
// transaction that still lands.
const _: () = assert!(STALE_INTENT_SECS >= 2 * 300);

/// `provider_status` markers on reserve rows (raw-provider-status column is
/// unused for an internal provider, so it carries the payout sub-state).
const PS_RETRY: &str = "payout_retry";
const PS_INFLIGHT: &str = "payout_inflight";
const PS_PAID: &str = "paid";
const PS_AWAITING_DISBURSEMENT: &str = "awaiting_disbursement";

/// Auto-swap orders due for a payout attempt: fresh ones with no intent yet,
/// plus definitively-rejected ones scheduled for retry. Orders with an
/// intent and any other marker are in flight or frozen — never selected.
const DUE_PAYOUTS_SQL: &str = "SELECT o.order_id, o.payala_account_id, \
        o.amount_to, o.payout_address, o.payout_extra_id, o.provider_order_id, \
        o.provider_status, o.poll_count \
     FROM exchange_order o \
     LEFT JOIN conversion_reserve_entry e \
       ON e.order_id = o.order_id AND e.kind = 'payout_attempt' \
     WHERE o.provider = 'reserve' AND o.status = 'processing' \
       AND o.provider_payload->>'shape' = 'auto_swap' \
       AND o.next_poll_at <= CURRENT_TIMESTAMP \
       AND (e.entry_id IS NULL OR o.provider_status = 'payout_retry') \
     ORDER BY o.next_poll_at LIMIT 25";

/// Crashed-in-flight orders: an intent exists, it is old, and no outcome was
/// recorded (fresh-claim NULL or an orphaned in-flight marker).
const STALE_INTENT_SQL: &str = "SELECT o.order_id, o.payala_account_id \
     FROM exchange_order o \
     JOIN conversion_reserve_entry e \
       ON e.order_id = o.order_id AND e.kind = 'payout_attempt' \
     WHERE o.provider = 'reserve' AND o.status = 'processing' \
       AND (o.provider_status IS NULL OR o.provider_status = 'payout_inflight') \
       AND e.created_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
     LIMIT 25";

/// Deposit-window expiry scan.
const EXPIRABLE_SQL: &str = "SELECT order_id, payala_account_id FROM exchange_order \
     WHERE provider = 'reserve' AND status = 'awaiting_deposit' \
       AND created_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
     LIMIT 50";

/// Everything the watcher needs; built once in `run_server`.
pub struct ReserveWatchDeps {
    pub pool: PgPool,
    pub http: Arc<reqwest::Client>,
    pub horizon_url: String,
    pub reserve: Arc<ConversionReserve>,
    pub signer: Arc<dyn StellarSigner>,
    pub protector: Arc<dyn SeedProtector>,
    pub metrics: Arc<AppMetrics>,
}

/// Watcher entrypoint (reconcile-loop shape): tick every `watch_secs`,
/// absorb all errors, exit on cancellation.
pub async fn run(deps: ReserveWatchDeps, cancel: CancellationToken) {
    info!(
        "conversion-reserve watcher started: account={} address={} cadence={}s ttl={}s",
        deps.reserve.reserve_account_id,
        deps.reserve.stellar_address,
        deps.reserve.watch_secs,
        deps.reserve.deposit_ttl_secs
    );
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("conversion-reserve watcher stopped");
                return;
            }
            _ = sleep(Duration::from_secs(deps.reserve.watch_secs)) => {
                if let Err(e) = tick(&deps).await {
                    error!("reserve watcher tick failed: {:?}", e);
                }
            }
        }
    }
}

/// One watcher pass under the cross-instance advisory lock.
async fn tick(deps: &ReserveWatchDeps) -> Result<(), AppError> {
    let mut lock_conn = deps.pool.acquire().await.map_err(db_err("acquire"))?;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(RESERVE_WATCHER_LOCK_KEY)
        .fetch_one(&mut *lock_conn)
        .await
        .map_err(db_err("try lock"))?;
    if !got {
        return Ok(());
    }

    let result = tick_inner(deps).await;

    // Unlock, and if that fails CLOSE the connection instead of returning it
    // to the pool — a pooled connection still holding the session lock would
    // silently stall every instance's watcher until the pool recycles it.
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(RESERVE_WATCHER_LOCK_KEY)
        .fetch_one(&mut *lock_conn)
        .await;
    if unlocked.is_err() {
        warn!("reserve watcher: advisory unlock failed; closing the lock connection");
        drop(lock_conn.detach());
    }
    result
}

async fn tick_inner(deps: &ReserveWatchDeps) -> Result<(), AppError> {
    let deposits_drained = drain_deposits(deps).await;
    drive_payouts(deps).await;
    freeze_stale_intents(deps).await;
    // Expiry only when this tick saw the chain up to now: a Horizon outage
    // must delay expiry rather than race a deposit that already landed.
    if deposits_drained.is_ok() {
        expire_stale_orders(deps).await;
    }
    deposits_drained
}

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("reserve watcher: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

// ── Phase 1: deposits ──────────────────────────────────────────────────

async fn drain_deposits(deps: &ReserveWatchDeps) -> Result<(), AppError> {
    let mut cursor: Option<String> =
        sqlx::query_scalar("SELECT horizon_cursor FROM conversion_reserve_state WHERE id")
            .fetch_one(&deps.pool)
            .await
            .map_err(db_err("cursor read"))?;

    // First enablement: initialize to the feed's latest token so history
    // predating the reserve is never scanned into the unmatched queue.
    if cursor.is_none() {
        if let Some(latest) =
            fetch_latest_cursor(&deps.http, &deps.horizon_url, &deps.reserve.stellar_address)
                .await?
        {
            advance_cursor(&deps.pool, &latest).await?;
            cursor = Some(latest);
        }
    }

    loop {
        let page = fetch_payments_page(
            &deps.http,
            &deps.horizon_url,
            &deps.reserve.stellar_address,
            cursor.as_deref(),
            RESERVE_WATCH_PAGE_LIMIT,
        )
        .await?;
        if page.raw_count == 0 {
            return Ok(());
        }
        // RAW accounting on purpose: fullness and the cursor must cover
        // records the parser skips (account_merge etc. appear on the
        // /payments feed) or a run of them stalls the scan forever.
        let full = page.raw_count as u32 == RESERVE_WATCH_PAGE_LIMIT;
        for payment in &page.records {
            process_payment(deps, payment).await?;
        }
        // Only after every record's transaction committed.
        let last_token = match page.last_token {
            Some(t) => t,
            None => return Ok(()), // malformed tail record: retry next tick
        };
        advance_cursor(&deps.pool, &last_token).await?;
        cursor = Some(last_token);
        if !full {
            return Ok(());
        }
    }
}

/// Monotonic cursor write: paging tokens are numeric strings; never regress.
async fn advance_cursor(pool: &PgPool, token: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE conversion_reserve_state SET horizon_cursor = $1 \
         WHERE id AND (horizon_cursor IS NULL OR $1::numeric > horizon_cursor::numeric)",
    )
    .bind(token)
    .execute(pool)
    .await
    .map_err(db_err("cursor advance"))?;
    Ok(())
}

/// Order fields deposit matching needs.
#[derive(sqlx::FromRow)]
struct MatchOrderRow {
    order_id: Uuid,
    payala_account_id: String,
    status: String,
    amount_from: String,
    shape: Option<String>,
    hold_minor: Option<i64>,
}

/// What to do with one incoming payment. Pure decision, unit-tested.
#[derive(Debug, PartialEq)]
enum DepositAction {
    /// Not addressed to the reserve (outgoing/foreign) — ignore silently.
    Ignore,
    /// Credit the order and start fulfillment/disbursement.
    Match {
        currency: &'static str,
        amount_minor: i64,
        overpaid: bool,
    },
    /// Record in the unmatched queue (`reason` from the 031 vocabulary).
    Unmatched {
        reason: &'static str,
        currency: Option<&'static str>,
        amount_minor: Option<i64>,
    },
}

/// The expected pay-in asset per shape: auto-swap orders deposit native XLM,
/// disburse orders deposit the configured USDC.
fn expected_currency(shape: Option<&str>) -> &'static str {
    match shape {
        Some("disburse") => RESERVE_CURRENCY_USDC,
        _ => RESERVE_CURRENCY_XLM,
    }
}

/// Map a payment's asset onto a reserve bucket, if it is one we track.
fn payment_currency(p: &HorizonPayment, reserve: &ConversionReserve) -> Option<&'static str> {
    if p.asset_type == "native" {
        return Some(RESERVE_CURRENCY_XLM);
    }
    if p.asset_code.as_deref() == Some(reserve.usdc_code.as_str())
        && p.asset_issuer.as_deref() == Some(reserve.usdc_issuer.as_str())
    {
        return Some(RESERVE_CURRENCY_USDC);
    }
    None
}

fn classify_deposit(
    p: &HorizonPayment,
    reserve: &ConversionReserve,
    order: Option<&MatchOrderRow>,
) -> DepositAction {
    if p.to != reserve.stellar_address {
        return DepositAction::Ignore;
    }
    let currency = payment_currency(p, reserve);
    let amount_minor = parse_decimal_to_minor(&p.amount, RESERVE_SCALE_STELLAR);
    let order = match order {
        Some(o) => o,
        None => {
            return DepositAction::Unmatched {
                reason: "no_match",
                currency,
                amount_minor,
            }
        }
    };
    if order.status != crate::constants::EXCHANGE_STATUS_AWAITING_DEPOSIT {
        return DepositAction::Unmatched {
            reason: "late",
            currency,
            amount_minor,
        };
    }
    let expected = expected_currency(order.shape.as_deref());
    match (currency, amount_minor) {
        (Some(c), Some(amount)) if c == expected => {
            match parse_decimal_to_minor(&order.amount_from, RESERVE_SCALE_STELLAR) {
                Some(need) if amount >= need => DepositAction::Match {
                    currency: c,
                    amount_minor: amount,
                    overpaid: amount > need,
                },
                Some(_) => DepositAction::Unmatched {
                    reason: "underpaid",
                    currency,
                    amount_minor,
                },
                None => DepositAction::Unmatched {
                    reason: "wrong_asset",
                    currency,
                    amount_minor,
                },
            }
        }
        _ => DepositAction::Unmatched {
            reason: "wrong_asset",
            currency,
            amount_minor,
        },
    }
}

async fn process_payment(deps: &ReserveWatchDeps, p: &HorizonPayment) -> Result<(), AppError> {
    // Payment-level idempotency FIRST: a replayed page must be a no-op even
    // when the payment's classification changed between passes (matched on
    // pass one, "late" on replay because its order already left
    // awaiting_deposit — the order-keyed and unmatched-keyed anchors each
    // cover only their own side of that crossover). Every credited payment
    // records its paging_token in exactly one of these two tables, and the
    // unique indexes make this check race-safe belt-and-braces.
    let seen: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversion_reserve_entry WHERE paging_token = $1) \
             OR EXISTS(SELECT 1 FROM conversion_reserve_unmatched WHERE paging_token = $1)",
    )
    .bind(&p.paging_token)
    .fetch_one(&deps.pool)
    .await
    .map_err(db_err("seen check"))?;
    if seen {
        return Ok(());
    }

    // Look the memo up among reserve orders (refs are uppercase; compare
    // normalized so wallets that lowercase memos still match).
    let order: Option<MatchOrderRow> = match &p.memo_text {
        Some(memo) if !memo.trim().is_empty() => sqlx::query_as(
            "SELECT order_id, payala_account_id, status, amount_from, \
                    provider_payload->>'shape' AS shape, \
                    (provider_payload->>'hold_minor')::bigint AS hold_minor \
             FROM exchange_order \
             WHERE provider = 'reserve' AND provider_order_id = UPPER(TRIM($1))",
        )
        .bind(memo)
        .fetch_optional(&deps.pool)
        .await
        .map_err(db_err("memo lookup"))?,
        _ => None,
    };
    if let (Some(o), Some(m)) = (&order, &p.memo_text) {
        // Sanity: the SQL normalization and the pure matcher must agree.
        debug_assert!(memo_matches_ref(
            m,
            &crate::exchange::reserve::base32_order_ref(&o.order_id)
        ));
    }

    match classify_deposit(p, &deps.reserve, order.as_ref()) {
        DepositAction::Ignore => Ok(()),
        DepositAction::Match {
            currency,
            amount_minor,
            overpaid,
        } => {
            let o = order.expect("Match requires an order");
            apply_deposit(deps, p, &o, currency, amount_minor, overpaid).await
        }
        DepositAction::Unmatched {
            reason,
            currency,
            amount_minor,
        } => {
            record_unmatched(
                deps,
                p,
                reason,
                currency,
                amount_minor,
                order.as_ref().map(|o| o.order_id),
            )
            .await
        }
    }
}

async fn apply_deposit(
    deps: &ReserveWatchDeps,
    p: &HorizonPayment,
    order: &MatchOrderRow,
    currency: &'static str,
    amount_minor: i64,
    overpaid: bool,
) -> Result<(), AppError> {
    let disburse = order.shape.as_deref() == Some("disburse");
    let mut tx = deps.pool.begin().await.map_err(db_err("deposit begin"))?;

    // Guarded claim out of awaiting_deposit: a second payment with the same
    // memo (or a replayed page) finds rows_affected == 0 and falls through
    // to the unmatched queue as "late".
    let claimed = sqlx::query(
        "UPDATE exchange_order \
         SET status = 'processing', provider_status = $2, last_error = NULL, \
             next_poll_at = CASE WHEN $3 THEN CURRENT_TIMESTAMP + interval '10 years' \
                                 ELSE CURRENT_TIMESTAMP END \
         WHERE order_id = $1 AND status = 'awaiting_deposit'",
    )
    .bind(order.order_id)
    .bind(if disburse {
        Some(PS_AWAITING_DISBURSEMENT)
    } else {
        None
    })
    .bind(disburse)
    .execute(&mut *tx)
    .await
    .map_err(db_err("deposit claim"))?;
    if claimed.rows_affected() == 0 {
        drop(tx);
        return record_unmatched(
            deps,
            p,
            "late",
            Some(currency),
            Some(amount_minor),
            Some(order.order_id),
        )
        .await;
    }

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(currency)
        .bind(amount_minor)
        .bind(0i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("deposit credit"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!("reserve deposit: bucket {} missing", currency);
        AppError::InternalError("Database error".to_string())
    })?;

    let note = if overpaid {
        Some(format!(
            "overpaid: expected {} received {}",
            order.amount_from,
            minor_to_decimal_string(amount_minor, RESERVE_SCALE_STELLAR)
        ))
    } else {
        None
    };
    let entry = sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(currency)
        .bind("deposit")
        .bind(amount_minor)
        .bind(0i64)
        .bind(bal_after)
        .bind(held_after)
        .bind(order.order_id)
        .bind(Option::<String>::None)
        .bind(Some(p.tx_hash.clone()))
        .bind(Some(p.paging_token.clone()))
        .bind(Option::<String>::None)
        .bind(&note)
        .execute(&mut *tx)
        .await;
    match entry {
        Ok(_) => {}
        // Payment already credited by a racing pass (paging_token or
        // (order_id, kind) unique): the whole claim rolls back — a no-op.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Ok(());
        }
        Err(e) => return Err(db_err("deposit entry")(e)),
    }

    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReserveDepositMatched {
            account_id: order.payala_account_id.clone(),
            order_id: order.order_id.to_string(),
            currency: currency.to_string(),
            amount_minor,
        },
    )
    .await?;
    if disburse {
        crate::events::emit_event(
            &mut tx,
            &AccountEvent::ReserveDisbursementPending {
                account_id: order.payala_account_id.clone(),
                order_id: order.order_id.to_string(),
                amount_usd_cents: order.hold_minor.unwrap_or(0),
            },
        )
        .await?;
    }
    tx.commit().await.map_err(db_err("deposit commit"))?;

    deps.metrics.reserve_deposits_matched.add(1, &[]);
    deps.metrics.record_exchange_order_update(
        "reserve",
        crate::constants::EXCHANGE_STATUS_PROCESSING,
        "reserve_watch",
    );
    info!(
        "reserve deposit matched: order={} {} {} tx={}{}",
        order.order_id,
        minor_to_decimal_string(amount_minor, RESERVE_SCALE_STELLAR),
        currency,
        p.tx_hash,
        if overpaid { " (overpaid)" } else { "" }
    );
    Ok(())
}

async fn record_unmatched(
    deps: &ReserveWatchDeps,
    p: &HorizonPayment,
    reason: &'static str,
    currency: Option<&'static str>,
    amount_minor: Option<i64>,
    matched_order_id: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("unmatched begin"))?;
    let inserted = sqlx::query(
        "INSERT INTO conversion_reserve_unmatched \
             (paging_token, tx_hash, op_type, asset_code, asset_issuer, amount, \
              amount_minor, memo, matched_order_id, reason) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (paging_token) DO NOTHING",
    )
    .bind(&p.paging_token)
    .bind(&p.tx_hash)
    .bind(&p.op_type)
    .bind(&p.asset_code)
    .bind(&p.asset_issuer)
    .bind(&p.amount)
    .bind(amount_minor)
    .bind(&p.memo_text)
    .bind(matched_order_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(db_err("unmatched insert"))?;
    if inserted.rows_affected() == 0 {
        // Replayed page — already recorded (and credited, if applicable).
        return Ok(());
    }

    // Keep ledger == chain: credit the bucket for assets we track. Unknown
    // assets stay entry-less and surface as on-chain drift in the admin view.
    if let (Some(c), Some(amount)) = (currency, amount_minor) {
        let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
            .bind(c)
            .bind(amount)
            .bind(0i64)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err("unmatched credit"))?;
        if let Some((bal_after, held_after, _)) = bucket {
            let entry = sqlx::query(RESERVE_ENTRY_INSERT_SQL)
                .bind(c)
                .bind("unmatched_deposit")
                .bind(amount)
                .bind(0i64)
                .bind(bal_after)
                .bind(held_after)
                // order_id stays NULL: two late payments to one order must
                // both record, and UNIQUE(order_id, kind) would forbid that.
                // The paging_token unique is the per-payment anchor instead.
                .bind(Option::<Uuid>::None)
                .bind(Option::<String>::None)
                .bind(Some(p.tx_hash.clone()))
                .bind(Some(p.paging_token.clone()))
                .bind(Option::<String>::None)
                .bind(matched_order_id.map(|o| format!("order {}", o)))
                .execute(&mut *tx)
                .await;
            match entry {
                Ok(_) => {}
                // Already credited under this paging_token (e.g. it was
                // MATCHED on a prior pass and the order has since left
                // awaiting_deposit): roll the whole insert back — a no-op.
                Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                    return Ok(());
                }
                Err(e) => return Err(db_err("unmatched entry")(e)),
            }
        }
        crate::events::emit_event(
            &mut tx,
            &AccountEvent::ReserveUnmatchedDeposit {
                account_id: deps.reserve.reserve_account_id.clone(),
                currency: c.to_string(),
                amount_minor: amount,
                reason: reason.to_string(),
            },
        )
        .await?;
    }
    tx.commit().await.map_err(db_err("unmatched commit"))?;
    deps.metrics.reserve_unmatched_deposits.add(1, &[]);
    warn!(
        "reserve unmatched deposit: reason={} tx={} amount={} asset={:?} memo={:?}",
        reason, p.tx_hash, p.amount, p.asset_code, p.memo_text
    );
    Ok(())
}

// ── Phase 2: payouts ───────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct PayoutOrderRow {
    order_id: Uuid,
    payala_account_id: String,
    amount_to: Option<String>,
    payout_address: Option<String>,
    payout_extra_id: Option<String>,
    provider_order_id: String,
    provider_status: Option<String>,
    poll_count: i32,
}

async fn drive_payouts(deps: &ReserveWatchDeps) {
    let due: Vec<PayoutOrderRow> = match sqlx::query_as(DUE_PAYOUTS_SQL).fetch_all(&deps.pool).await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("reserve payouts: due scan failed: {}", e);
            return;
        }
    };
    for order in due {
        if let Err(e) = drive_one_payout(deps, &order).await {
            error!("reserve payout {}: {:?}", order.order_id, e);
        }
    }
}

async fn drive_one_payout(deps: &ReserveWatchDeps, order: &PayoutOrderRow) -> Result<(), AppError> {
    // Claim. Fresh order: the write-ahead intent INSERT is the claim — the
    // partial unique index admits exactly one winner ever. Retry order: CAS
    // the provider_status marker so concurrent watchers cannot both submit.
    if order.provider_status.as_deref() == Some(PS_RETRY) {
        let claimed = sqlx::query(
            "UPDATE exchange_order SET provider_status = $2 \
             WHERE order_id = $1 AND provider_status = $3",
        )
        .bind(order.order_id)
        .bind(PS_INFLIGHT)
        .bind(PS_RETRY)
        .execute(&deps.pool)
        .await
        .map_err(db_err("retry claim"))?;
        if claimed.rows_affected() == 0 {
            return Ok(());
        }
    } else {
        let mut tx = deps.pool.begin().await.map_err(db_err("intent begin"))?;
        // FOR UPDATE: the 0/0 intent entry still snapshots balance_after/
        // held_after, and an unlocked read could capture values no journal
        // replay reproduces.
        let (bal, held): (i64, i64) = sqlx::query_as(
            "SELECT available, held FROM conversion_reserve WHERE currency = $1 FOR UPDATE",
        )
        .bind(RESERVE_CURRENCY_USDC)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("intent bucket read"))?;
        let inserted = sqlx::query(RESERVE_ENTRY_INSERT_SQL)
            .bind(RESERVE_CURRENCY_USDC)
            .bind("payout_attempt")
            .bind(0i64)
            .bind(0i64)
            .bind(bal)
            .bind(held)
            .bind(order.order_id)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .execute(&mut *tx)
            .await;
        match inserted {
            Ok(_) => {
                sqlx::query("UPDATE exchange_order SET provider_status = $2 WHERE order_id = $1")
                    .bind(order.order_id)
                    .bind(PS_INFLIGHT)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err("intent mark"))?;
                tx.commit().await.map_err(db_err("intent commit"))?;
            }
            // Unique violation: another worker owns this payout (or a prior
            // attempt's outcome is unrecorded). Never submit, never flip
            // on_hold here — the stale sweep decides.
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                return Ok(());
            }
            Err(e) => return Err(db_err("intent insert")(e)),
        }
    }

    // Everything needed to pay, or freeze immediately (funds are committed).
    let (amount_to, payout_address) = match (&order.amount_to, &order.payout_address) {
        (Some(a), Some(p)) => (a.clone(), p.clone()),
        _ => {
            error!(
                "reserve payout {}: missing amount_to/payout_address",
                order.order_id
            );
            return freeze_on_hold(
                deps,
                order.order_id,
                &order.payala_account_id,
                "submit_failed",
            )
            .await;
        }
    };
    let amount_to_minor = match parse_decimal_to_minor(&amount_to, RESERVE_SCALE_STELLAR) {
        Some(v) if v > 0 => v,
        _ => {
            error!("reserve payout {}: bad amount_to", order.order_id);
            return freeze_on_hold(
                deps,
                order.order_id,
                &order.payala_account_id,
                "submit_failed",
            )
            .await;
        }
    };

    let seed = crate::handlers::managed_seed::load_protected_seed(
        &deps.pool,
        &deps.protector,
        &deps.reserve.reserve_account_id,
    )
    .await?;
    let params = PaymentParams {
        destination: payout_address,
        amount: amount_to.clone(),
        asset: Asset::Credit {
            code: deps.reserve.usdc_code.clone(),
            issuer: deps.reserve.usdc_issuer.clone(),
        },
        // The receiver's required memo wins; otherwise tag the payment with
        // the order ref so on-chain audit ties it back.
        memo: Some(
            order
                .payout_extra_id
                .clone()
                .unwrap_or_else(|| order.provider_order_id.clone()),
        ),
        fee: None,
    };
    let submitted = deps
        .signer
        .sign_and_submit_payment(seed.as_slice(), &params)
        .await;
    // `seed` zeroizes on drop.

    match submitted {
        Ok(tx_result) => {
            record_fulfillment(
                deps,
                order,
                amount_to_minor,
                &tx_result.stellar_hash,
                tx_result.stellar_tx_id.as_deref(),
            )
            .await
        }
        // Definitive rejection: Horizon 400 with result codes — the tx
        // provably did not land, a bounded retry is double-payout-safe.
        Err(AppError::BadRequest(msg)) => {
            deps.metrics.record_reserve_payout_failure("rejected");
            let permanent = msg.contains("op_no_trust") || msg.contains("op_no_destination");
            let attempts = order.poll_count + 1;
            if permanent || attempts >= RESERVE_MAX_PAYOUT_ATTEMPTS {
                let reason = if permanent {
                    "payout_rejected"
                } else {
                    "max_attempts"
                };
                sqlx::query(
                    "UPDATE exchange_order SET last_error = $2, poll_count = $3 \
                     WHERE order_id = $1",
                )
                .bind(order.order_id)
                .bind(crate::exchange::reconcile::truncate_chars(&msg, 200))
                .bind(attempts)
                .execute(&deps.pool)
                .await
                .map_err(db_err("reject record"))?;
                freeze_on_hold(deps, order.order_id, &order.payala_account_id, reason).await
            } else {
                let backoff = poll_backoff_secs(deps.reserve.watch_secs, attempts) as i64;
                sqlx::query(
                    "UPDATE exchange_order \
                     SET provider_status = $2, last_error = $3, poll_count = $4, \
                         next_poll_at = CURRENT_TIMESTAMP + make_interval(secs => $5) \
                     WHERE order_id = $1",
                )
                .bind(order.order_id)
                .bind(PS_RETRY)
                .bind(crate::exchange::reconcile::truncate_chars(&msg, 200))
                .bind(attempts)
                .bind(backoff as f64)
                .execute(&deps.pool)
                .await
                .map_err(db_err("retry schedule"))?;
                warn!(
                    "reserve payout {} rejected (attempt {}), retrying in {}s",
                    order.order_id, attempts, backoff
                );
                Ok(())
            }
        }
        // Ambiguous outcome (timeout/5xx/transport): the payment MAY land
        // within its 300s validity. Freeze; never auto-resubmit. The intent
        // entry stays as the marker that a submission may exist on-chain.
        Err(_) => {
            deps.metrics.record_reserve_payout_failure("submit_unknown");
            freeze_on_hold(
                deps,
                order.order_id,
                &order.payala_account_id,
                "submit_unknown",
            )
            .await
        }
    }
}

async fn record_fulfillment(
    deps: &ReserveWatchDeps,
    order: &PayoutOrderRow,
    amount_to_minor: i64,
    stellar_hash: &str,
    stellar_tx_id: Option<&str>,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("fulfill begin"))?;

    let updated = sqlx::query(
        "UPDATE exchange_order \
         SET status = 'completed', provider_status = $2, last_error = NULL \
         WHERE order_id = $1 AND status IN ('processing', 'on_hold')",
    )
    .bind(order.order_id)
    .bind(PS_PAID)
    .execute(&mut *tx)
    .await
    .map_err(db_err("fulfill update"))?;
    if updated.rows_affected() == 0 {
        // The payment SETTLED but the order left the completable states —
        // e.g. an admin resolve raced the submit. Refuse to guess: keep the
        // journal honest and shout for reconciliation.
        error!(
            "RESERVE PAYOUT SETTLED BUT ORDER NOT COMPLETABLE — order={} hash={} amount={}: \
             record the fulfillment manually (held_adjustment) and reconcile the on_hold ledger",
            order.order_id, stellar_hash, amount_to_minor
        );
        deps.metrics.record_reserve_payout_failure("unrecordable");
        return Ok(());
    }

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(RESERVE_CURRENCY_USDC)
        .bind(0i64)
        .bind(-amount_to_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("fulfill held release"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!(
            "reserve fulfillment {}: held underflow (drift) — manual held_adjustment needed",
            order.order_id
        );
        AppError::InternalError("Database error".to_string())
    })?;

    sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(RESERVE_CURRENCY_USDC)
        .bind("fulfillment")
        .bind(0i64)
        .bind(-amount_to_minor)
        .bind(bal_after)
        .bind(held_after)
        .bind(order.order_id)
        .bind(Option::<String>::None)
        .bind(Some(stellar_hash.to_string()))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(&mut *tx)
        .await
        .map_err(db_err("fulfill entry"))?;

    // Settlement row in the transaction table, linked via btxid.
    let btxid: Uuid = sqlx::query_scalar(
        "INSERT INTO transaction \
             (stellar_tx_id, stellar_hash, source_account, memo, account_id, origin) \
         VALUES ($1, $2, $3, $4, $5, 'conversion_reserve') \
         RETURNING btxid",
    )
    .bind(stellar_tx_id.unwrap_or(stellar_hash))
    .bind(stellar_hash)
    .bind(&deps.reserve.stellar_address)
    .bind(&order.provider_order_id)
    .bind(&order.payala_account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("fulfill transaction row"))?;
    sqlx::query("UPDATE exchange_order SET btxid = $2 WHERE order_id = $1")
        .bind(order.order_id)
        .bind(btxid)
        .execute(&mut *tx)
        .await
        .map_err(db_err("fulfill btxid link"))?;

    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReserveFulfilled {
            account_id: order.payala_account_id.clone(),
            order_id: order.order_id.to_string(),
            currency: RESERVE_CURRENCY_USDC.to_string(),
            amount_minor: amount_to_minor,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("fulfill commit"))?;

    deps.metrics.reserve_fulfillments.add(1, &[]);
    deps.metrics.record_exchange_order_update(
        "reserve",
        crate::constants::EXCHANGE_STATUS_COMPLETED,
        "reserve_watch",
    );
    info!(
        "reserve payout completed: order={} amount={} hash={} btxid={}",
        order.order_id,
        minor_to_decimal_string(amount_to_minor, RESERVE_SCALE_STELLAR),
        stellar_hash,
        btxid
    );
    Ok(())
}

/// Freeze a processing order for admin resolution. The hold stays; the
/// guarded transition fires the event/metric exactly once even when two
/// watchers race.
async fn freeze_on_hold(
    deps: &ReserveWatchDeps,
    order_id: Uuid,
    payala_account_id: &str,
    reason: &'static str,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("hold begin"))?;
    let updated = sqlx::query(
        "UPDATE exchange_order \
         SET status = 'on_hold', last_error = COALESCE(last_error, $2), \
             next_poll_at = CURRENT_TIMESTAMP + interval '10 years' \
         WHERE order_id = $1 AND status = 'processing'",
    )
    .bind(order_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(db_err("hold update"))?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReservePayoutPending {
            account_id: payala_account_id.to_string(),
            order_id: order_id.to_string(),
            reason: reason.to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("hold commit"))?;
    deps.metrics.record_exchange_order_update(
        "reserve",
        crate::constants::EXCHANGE_STATUS_ON_HOLD,
        "reserve_watch",
    );
    warn!("reserve order {} frozen on_hold: {}", order_id, reason);
    Ok(())
}

// ── Phase 3: stale intents ─────────────────────────────────────────────

async fn freeze_stale_intents(deps: &ReserveWatchDeps) {
    let stale: Vec<(Uuid, String)> = match sqlx::query_as(STALE_INTENT_SQL)
        .bind(STALE_INTENT_SECS as f64)
        .fetch_all(&deps.pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("reserve stale sweep failed: {}", e);
            return;
        }
    };
    for (order_id, account_id) in stale {
        deps.metrics.record_reserve_payout_failure("stale_intent");
        if let Err(e) = freeze_on_hold(deps, order_id, &account_id, "stale_intent").await {
            error!("reserve stale freeze {}: {:?}", order_id, e);
        }
    }
}

// ── Phase 4: expiry ────────────────────────────────────────────────────

async fn expire_stale_orders(deps: &ReserveWatchDeps) {
    let expirable: Vec<(Uuid, String)> = match sqlx::query_as(EXPIRABLE_SQL)
        .bind(deps.reserve.deposit_ttl_secs as f64)
        .fetch_all(&deps.pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("reserve expiry scan failed: {}", e);
            return;
        }
    };
    for (order_id, account_id) in expirable {
        if let Err(e) = expire_one(deps, order_id, &account_id).await {
            error!("reserve expiry {}: {:?}", order_id, e);
        }
    }
}

async fn expire_one(
    deps: &ReserveWatchDeps,
    order_id: Uuid,
    payala_account_id: &str,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("expire begin"))?;

    // The guarded transition serializes against a concurrent deposit match:
    // exactly one of them leaves awaiting_deposit.
    let updated = sqlx::query(
        "UPDATE exchange_order SET status = 'expired', \
             next_poll_at = CURRENT_TIMESTAMP + interval '10 years' \
         WHERE order_id = $1 AND status = 'awaiting_deposit'",
    )
    .bind(order_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err("expire update"))?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }

    // Release exactly what the creation hold took.
    let hold: Option<(String, i64)> = sqlx::query_as(
        "SELECT currency, -delta FROM conversion_reserve_entry \
         WHERE order_id = $1 AND kind = 'hold'",
    )
    .bind(order_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err("expire hold lookup"))?;
    let (currency, hold_minor) = hold.ok_or_else(|| {
        error!("reserve expiry {}: hold entry missing", order_id);
        AppError::InternalError("Database error".to_string())
    })?;

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&currency)
        .bind(hold_minor)
        .bind(-hold_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("expire release"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!("reserve expiry {}: held underflow (drift)", order_id);
        AppError::InternalError("Database error".to_string())
    })?;

    sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(&currency)
        .bind("hold_release")
        .bind(hold_minor)
        .bind(-hold_minor)
        .bind(bal_after)
        .bind(held_after)
        .bind(order_id)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Some("deposit window expired".to_string()))
        .execute(&mut *tx)
        .await
        .map_err(db_err("expire entry"))?;

    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReserveOrderExpired {
            account_id: payala_account_id.to_string(),
            order_id: order_id.to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("expire commit"))?;

    deps.metrics.reserve_expiries.add(1, &[]);
    deps.metrics.record_exchange_order_update(
        "reserve",
        crate::constants::EXCHANGE_STATUS_EXPIRED,
        "reserve_watch",
    );
    info!("reserve order {} expired; hold released", order_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserve() -> ConversionReserve {
        ConversionReserve {
            reserve_account_id: "svc-reserve".to_string(),
            stellar_address: "GRESERVE".to_string(),
            usdc_code: "USDC".to_string(),
            usdc_issuer: "GISSUER".to_string(),
            deposit_ttl_secs: 1800,
            watch_secs: 30,
        }
    }

    fn xlm_payment(to: &str, amount: &str) -> HorizonPayment {
        HorizonPayment {
            paging_token: "1".to_string(),
            tx_hash: "h1".to_string(),
            op_type: "payment".to_string(),
            to: to.to_string(),
            asset_type: "native".to_string(),
            asset_code: None,
            asset_issuer: None,
            amount: amount.to_string(),
            memo_text: Some("REF".to_string()),
        }
    }

    fn awaiting_order(amount_from: &str, shape: &str) -> MatchOrderRow {
        MatchOrderRow {
            order_id: Uuid::new_v4(),
            payala_account_id: "acct".to_string(),
            status: "awaiting_deposit".to_string(),
            amount_from: amount_from.to_string(),
            shape: Some(shape.to_string()),
            hold_minor: Some(2000),
        }
    }

    #[test]
    fn outgoing_and_foreign_payments_are_ignored() {
        let r = reserve();
        let p = xlm_payment("GSOMEONE_ELSE", "10.0000000");
        assert_eq!(classify_deposit(&p, &r, None), DepositAction::Ignore);
    }

    #[test]
    fn exact_and_over_payment_match() {
        let r = reserve();
        let o = awaiting_order("10", "auto_swap");
        let p = xlm_payment("GRESERVE", "10.0000000");
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Match {
                currency: RESERVE_CURRENCY_XLM,
                amount_minor: 100_000_000,
                overpaid: false
            }
        );
        let p = xlm_payment("GRESERVE", "10.0000001");
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Match {
                currency: RESERVE_CURRENCY_XLM,
                amount_minor: 100_000_001,
                overpaid: true
            }
        );
    }

    #[test]
    fn underpayment_is_unmatched_not_matched() {
        let r = reserve();
        let o = awaiting_order("10", "auto_swap");
        let p = xlm_payment("GRESERVE", "9.9999999");
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Unmatched {
                reason: "underpaid",
                currency: Some(RESERVE_CURRENCY_XLM),
                amount_minor: Some(99_999_999)
            }
        );
    }

    #[test]
    fn late_deposit_after_expiry_is_recorded_not_credited_to_order() {
        let r = reserve();
        let mut o = awaiting_order("10", "auto_swap");
        o.status = "expired".to_string();
        let p = xlm_payment("GRESERVE", "10.0000000");
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Unmatched {
                reason: "late",
                currency: Some(RESERVE_CURRENCY_XLM),
                amount_minor: Some(100_000_000)
            }
        );
    }

    #[test]
    fn wrong_asset_for_shape_is_unmatched() {
        let r = reserve();
        // auto_swap expects XLM; USDC arrives.
        let o = awaiting_order("10", "auto_swap");
        let p = HorizonPayment {
            asset_type: "credit_alphanum4".to_string(),
            asset_code: Some("USDC".to_string()),
            asset_issuer: Some("GISSUER".to_string()),
            ..xlm_payment("GRESERVE", "10.0000000")
        };
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Unmatched {
                reason: "wrong_asset",
                currency: Some(RESERVE_CURRENCY_USDC),
                amount_minor: Some(100_000_000)
            }
        );
        // disburse expects the configured USDC; wrong issuer is foreign.
        let o = awaiting_order("10", "disburse");
        let p = HorizonPayment {
            asset_type: "credit_alphanum4".to_string(),
            asset_code: Some("USDC".to_string()),
            asset_issuer: Some("GOTHER".to_string()),
            ..xlm_payment("GRESERVE", "10.0000000")
        };
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Unmatched {
                reason: "wrong_asset",
                currency: None,
                amount_minor: Some(100_000_000)
            }
        );
    }

    #[test]
    fn disburse_orders_match_on_configured_usdc() {
        let r = reserve();
        let o = awaiting_order("20", "disburse");
        let p = HorizonPayment {
            asset_type: "credit_alphanum4".to_string(),
            asset_code: Some("USDC".to_string()),
            asset_issuer: Some("GISSUER".to_string()),
            ..xlm_payment("GRESERVE", "20.0000000")
        };
        assert_eq!(
            classify_deposit(&p, &r, Some(&o)),
            DepositAction::Match {
                currency: RESERVE_CURRENCY_USDC,
                amount_minor: 200_000_000,
                overpaid: false
            }
        );
    }

    #[test]
    fn no_order_is_no_match() {
        let r = reserve();
        let p = xlm_payment("GRESERVE", "5.0000000");
        assert_eq!(
            classify_deposit(&p, &r, None),
            DepositAction::Unmatched {
                reason: "no_match",
                currency: Some(RESERVE_CURRENCY_XLM),
                amount_minor: Some(50_000_000)
            }
        );
    }

    #[test]
    fn expected_currency_by_shape() {
        assert_eq!(expected_currency(Some("auto_swap")), RESERVE_CURRENCY_XLM);
        assert_eq!(expected_currency(Some("disburse")), RESERVE_CURRENCY_USDC);
        assert_eq!(expected_currency(None), RESERVE_CURRENCY_XLM);
    }

    // ── SQL shape pins ─────────────────────────────────────────────────

    #[test]
    fn due_payouts_sql_selects_only_claimable_auto_swaps() {
        assert!(DUE_PAYOUTS_SQL.contains("o.provider = 'reserve'"));
        assert!(DUE_PAYOUTS_SQL.contains("o.status = 'processing'"));
        assert!(DUE_PAYOUTS_SQL.contains("provider_payload->>'shape' = 'auto_swap'"));
        assert!(
            DUE_PAYOUTS_SQL.contains("e.entry_id IS NULL OR o.provider_status = 'payout_retry'")
        );
        assert!(DUE_PAYOUTS_SQL.contains("kind = 'payout_attempt'"));
    }

    #[test]
    fn stale_intent_sql_only_covers_unrecorded_outcomes() {
        assert!(STALE_INTENT_SQL.contains("o.status = 'processing'"));
        assert!(STALE_INTENT_SQL
            .contains("o.provider_status IS NULL OR o.provider_status = 'payout_inflight'"));
        assert!(STALE_INTENT_SQL.contains("kind = 'payout_attempt'"));
    }

    #[test]
    fn expiry_sql_only_touches_awaiting_deposit() {
        assert!(EXPIRABLE_SQL.contains("status = 'awaiting_deposit'"));
        assert!(EXPIRABLE_SQL.contains("provider = 'reserve'"));
    }
}

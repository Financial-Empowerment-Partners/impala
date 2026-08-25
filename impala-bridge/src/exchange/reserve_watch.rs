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
    RESERVE_AUTO_REFUND_REASONS, RESERVE_CURRENCY_USD, RESERVE_CURRENCY_USDC, RESERVE_CURRENCY_XLM,
    RESERVE_MAX_PAYOUT_ATTEMPTS, RESERVE_REFUND_COOLDOWN_SECS, RESERVE_REFUND_MAX_ATTEMPTS,
    RESERVE_REFUND_MAX_PER_TICK, RESERVE_REFUND_MEMO_PREFIX, RESERVE_REFUND_MIN_MINOR,
    RESERVE_SCALE_STELLAR, RESERVE_WATCHER_LOCK_KEY, RESERVE_WATCH_PAGE_LIMIT,
};
use crate::error::AppError;
use crate::events::AccountEvent;
use crate::exchange::reconcile::poll_backoff_secs;
use crate::exchange::reserve::{
    journal_insert, memo_matches_ref, minor_to_decimal_string, parse_decimal_to_minor,
    ConversionReserve, JournalEntry, ORDER_HOLD_SQL, RESERVE_BUCKET_APPLY_SQL,
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

/// What an on-chain submission actually proved.
///
/// Shared by every driver that signs from the reserve account (payouts,
/// refunds, replenishment) so the definitive-vs-ambiguous rule lives in one
/// tested place. The distinction is the whole basis of double-spend safety:
/// only a DEFINITIVE rejection may be retried.
#[derive(Debug, PartialEq)]
pub(crate) enum SubmitOutcome {
    /// Landed. `stellar_hash` is authoritative.
    Settled,
    /// Horizon 400 WITH result codes: the transaction provably did not and
    /// cannot land, so re-signing it is double-spend-safe. `permanent` marks
    /// rejections that retrying cannot fix.
    Rejected { msg: String, permanent: bool },
    /// Anything else — 429/503/504, transport error, unparseable response.
    /// The transaction MAY still land inside its validity window, so it must
    /// never be resubmitted; the caller freezes for a human instead.
    Ambiguous,
}

/// Result codes that a retry cannot fix: the destination cannot receive this
/// asset at all.
const PERMANENT_RESULT_CODES: &[&str] = &[
    "op_no_trust",
    "op_no_destination",
    "op_line_full",
    "op_not_authorized",
];

/// Classify a signer result. `Err(BadRequest)` is the signer's encoding of
/// "Horizon 400 with parsed result codes" (see stellar/signer.rs); every
/// other error variant is ambiguous by construction.
pub(crate) fn classify_submit<T>(result: &Result<T, AppError>) -> SubmitOutcome {
    match result {
        Ok(_) => SubmitOutcome::Settled,
        Err(AppError::BadRequest(msg)) => SubmitOutcome::Rejected {
            msg: msg.clone(),
            permanent: PERMANENT_RESULT_CODES.iter().any(|c| msg.contains(c)),
        },
        Err(_) => SubmitOutcome::Ambiguous,
    }
}

// ── Refund decisions (pure) ────────────────────────────────────────────

/// Memo carried by an outgoing refund.
///
/// MUST NOT equal an order ref: `find_onchain_payout` reads an outgoing
/// payment carrying the order ref as proof the payout landed, so a refund
/// wearing that memo would make `resolve fail` refuse and `resolve complete`
/// record the refund's hash as the fulfillment. The prefix plus a short
/// suffix is both distinct from the 26-char ref and inside MEMO_TEXT's 28
/// bytes.
pub(crate) fn refund_memo(order_ref: &str) -> String {
    let tail: String = order_ref
        .chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{}{}", RESERVE_REFUND_MEMO_PREFIX, tail)
}

/// What to do with money the reserve cannot use.
#[derive(Debug, PartialEq)]
pub(crate) enum RefundDecision {
    /// Auto-refundable: queue it for the driver.
    Queue {
        destination: String,
        refund_minor: i64,
    },
    /// Queued but parked for a human (over cap, or dust).
    Review {
        destination: String,
        refund_minor: i64,
        why: &'static str,
    },
    /// No obligation. `why` is recorded on the source row so the manual
    /// queue explains itself instead of going silent.
    Skip(&'static str),
}

/// Inputs to [`refund_decision`], gathered from the payment and its context.
pub(crate) struct RefundContext<'a> {
    pub enabled: bool,
    pub reason: &'a str,
    pub op_type: &'a str,
    /// Bucket the funds landed in; `None` for assets the reserve cannot send.
    pub currency: Option<&'a str>,
    pub amount_minor: Option<i64>,
    /// The order's declared refund address, when one was supplied. Preferred
    /// over the inferred sender: it is a user-stated intent rather than an
    /// inference from an omnibus-capable address.
    pub declared_refund_address: Option<&'a str>,
    pub sender_address: Option<&'a str>,
    pub sender_muxed: Option<&'a str>,
    pub reserve_address: &'a str,
    pub usdc_issuer: &'a str,
    /// Per-currency cap; 0 disables refunds for that bucket entirely.
    pub max_minor: i64,
}

/// Every exclusion in one tested place, first match wins.
///
/// The residual risk this cannot remove: a self-custodial sender is safe to
/// refund, but an exchange withdrawal arrives from an omnibus address where a
/// refund is generally lost, and there is no reliable programmatic test for
/// the difference. `from_muxed` is the only machine-detectable custodian
/// signal. That is why refunds ship flag-off, capped, and cancellable.
pub(crate) fn refund_decision(ctx: &RefundContext<'_>) -> RefundDecision {
    if !ctx.enabled {
        return RefundDecision::Skip("disabled");
    }
    if !RESERVE_AUTO_REFUND_REASONS.contains(&ctx.reason) {
        // `no_match` and `wrong_asset` land here: an unmemoed inflow is
        // exactly how ops tops the pool up, so auto-refunding one would wire
        // the float straight back to ops.
        return RefundDecision::Skip("reason_manual");
    }
    match ctx.op_type {
        // The starting balance IS the account's base reserve, and the funder
        // is ops — refunding it would unfund the reserve account.
        "create_account" => return RefundDecision::Skip("create_account"),
        // The sender parted with a DIFFERENT asset than the one that
        // arrived; returning what arrived changes the asset mid-flight.
        "path_payment_strict_send" | "path_payment_strict_receive" => {
            return RefundDecision::Skip("path_payment")
        }
        "payment" => {}
        _ => return RefundDecision::Skip("unsupported_op"),
    }
    // A muxed sender means the address we can see is a SHARED base account;
    // the signer has no muxed support, so returning funds there strands them
    // a second time.
    if ctx.sender_muxed.is_some() && ctx.declared_refund_address.is_none() {
        return RefundDecision::Skip("muxed_sender");
    }
    let destination = match ctx.declared_refund_address.or(ctx.sender_address) {
        Some(d) if crate::validate::validate_stellar_account_id(d).is_ok() => d.to_string(),
        Some(_) => return RefundDecision::Skip("bad_destination"),
        None => return RefundDecision::Skip("no_sender"),
    };
    if destination == ctx.reserve_address {
        // Paying ourselves would debit the ledger for a no-op.
        return RefundDecision::Skip("self_refund");
    }
    if destination == ctx.usdc_issuer {
        // Sending an issued asset back to its issuer BURNS it.
        return RefundDecision::Skip("issuer_destination");
    }
    let (currency, refund_minor) = match (ctx.currency, ctx.amount_minor) {
        (Some(c), Some(a)) if a > 0 => (c, a),
        _ => return RefundDecision::Skip("unsupported_asset"),
    };
    // The USD float is a bank balance; there is nothing to send on-chain.
    if currency == RESERVE_CURRENCY_USD {
        return RefundDecision::Skip("unsupported_asset");
    }
    if ctx.max_minor <= 0 {
        return RefundDecision::Skip("disabled");
    }
    if refund_minor < RESERVE_REFUND_MIN_MINOR {
        // Dust is never silently absorbed — the point of the feature is that
        // customer money stops living in a log line.
        return RefundDecision::Review {
            destination,
            refund_minor,
            why: "dust",
        };
    }
    if refund_minor > ctx.max_minor {
        return RefundDecision::Review {
            destination,
            refund_minor,
            why: "over_cap",
        };
    }
    RefundDecision::Queue {
        destination,
        refund_minor,
    }
}

/// Grace before a queued refund may be sent.
///
/// `underpaid` waits out the deposit window as well: refunding immediately
/// would race a user topping the order up.
pub(crate) fn refund_cooldown_secs(reason: &str, deposit_ttl_secs: u64) -> i64 {
    match reason {
        "underpaid" => deposit_ttl_secs as i64 + RESERVE_REFUND_COOLDOWN_SECS,
        _ => RESERVE_REFUND_COOLDOWN_SECS,
    }
}

/// Everything the watcher needs; built once in `run_server`.
pub struct ReserveWatchDeps {
    pub pool: PgPool,
    pub http: Arc<reqwest::Client>,
    pub horizon_url: String,
    pub reserve: Arc<ConversionReserve>,
    pub signer: Arc<dyn StellarSigner>,
    pub protector: Arc<dyn SeedProtector>,
    pub metrics: Arc<AppMetrics>,
    /// Needed by the replenishment leg that sells accumulated XLM. Absent
    /// when the provider is unconfigured, which simply means no cycles run.
    pub changelly_crypto: Option<Arc<crate::exchange::changelly::ChangellyCrypto>>,
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
    // Refunds are chain-dependent: the signer fetches a sequence number
    // before signing, so during a Horizon outage every submit would classify
    // as ambiguous and freeze — turning a transient outage into a fully
    // frozen queue needing per-row manual work.
    if deposits_drained.is_ok() {
        drive_refunds(deps).await;
    }
    freeze_stale_intents(deps).await;
    freeze_stale_refunds(deps).await;
    // Expiry only when this tick saw the chain up to now: a Horizon outage
    // must delay expiry rather than race a deposit that already landed.
    if deposits_drained.is_ok() {
        expire_stale_orders(deps).await;
    }
    // Quote expiry is deliberately NOT gated: a price lock has no on-chain
    // leg, so nothing can race it but create_order — which the row lock
    // settles — and gating would keep its capacity locked through every
    // Horizon outage for no benefit.
    expire_stale_quotes(deps).await;
    // Replenishment runs LAST and only on a healthy chain view: it spends
    // the pool's own float, so it must size itself against XLM that nobody
    // is owed (refunds ran earlier) and must never spend blind.
    if deposits_drained.is_ok() {
        crate::exchange::replenish::drive_replenishment(deps).await;
    }
    crate::exchange::replenish::freeze_stale_cycles(deps).await;
    deposits_drained
}

/// Release capacity held by price locks that were never used.
async fn expire_stale_quotes(deps: &ReserveWatchDeps) {
    let expirable: Vec<(Uuid,)> =
        match sqlx::query_as(crate::exchange::reserve_quote::QUOTE_EXPIRABLE_SQL)
            .bind(crate::constants::RESERVE_QUOTE_EXPIRE_BATCH)
            .fetch_all(&deps.pool)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("reserve quote expiry scan failed: {}", e);
                return;
            }
        };
    for (quote_id,) in expirable {
        match crate::exchange::reserve_quote::expire_quote_now(&deps.pool, quote_id).await {
            // False means a concurrent create consumed it first — expected.
            Ok(true) => {
                deps.metrics.reserve_quote_expiries.add(1, &[]);
                info!("reserve quote {} expired; capacity released", quote_id);
            }
            Ok(false) => {}
            Err(e) => error!("reserve quote expiry {}: {:?}", quote_id, e),
        }
    }
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

    // A replenishment cycle's payout and refund both carry its cycle ref, so
    // check that namespace first. Which direction an arrival represents is
    // decided by ASSET, not by the memo — see classify_cycle_arrival.
    //
    // Gated on the payment being INBOUND: the bridge's own outgoing pay-in to
    // the provider carries the same ref, and must never be read as an
    // arrival crediting the pool.
    let inbound = p.to == deps.reserve.stellar_address;
    if inbound {
        if let Some(memo) = p.memo_text.as_deref().filter(|m| !m.trim().is_empty()) {
            let cycle: Option<(Uuid, String, String, String)> = sqlx::query_as(
                "SELECT cycle_id, kind, spend_currency, recv_currency \
             FROM conversion_reserve_replenishment WHERE cycle_ref = UPPER(TRIM($1))",
            )
            .bind(memo)
            .fetch_optional(&deps.pool)
            .await
            .map_err(db_err("cycle memo lookup"))?;
            if let Some((cycle_id, kind, spend_currency, recv_currency)) = cycle {
                let currency = payment_currency(p, &deps.reserve);
                let amount_minor = parse_decimal_to_minor(&p.amount, RESERVE_SCALE_STELLAR);
                let arrival = crate::exchange::replenish::classify_cycle_arrival(
                    currency,
                    amount_minor,
                    &spend_currency,
                    &recv_currency,
                );
                if arrival != crate::exchange::replenish::CycleArrival::Unmatched {
                    let credited_currency = currency.expect("classified arrivals carry a currency");
                    let booked = crate::exchange::replenish::credit_cycle_arrival(
                        deps,
                        cycle_id,
                        &kind,
                        &arrival,
                        credited_currency,
                        &p.paging_token,
                        &p.tx_hash,
                    )
                    .await?;
                    // Only stop here when the cycle actually booked it. A closed
                    // cycle declines, and the money must still reach the ledger
                    // and the queue through the ordinary path below.
                    if booked {
                        return Ok(());
                    }
                }
            }
        }
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
    let entry = journal_insert(JournalEntry {
        currency: currency.to_string(),
        kind: "deposit".to_string(),
        delta: amount_minor,
        balance_after: bal_after,
        held_after,
        order_id: Some(order.order_id),
        stellar_tx_hash: Some(p.tx_hash.clone()),
        paging_token: Some(p.paging_token.clone()),
        note,
        // Where a refund would go back to, captured at credit time — the
        // only moment the payer is known.
        sender_address: p.from.clone(),
        sender_muxed: p.from_muxed.clone(),
        ..Default::default()
    })
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
    let inserted = sqlx::query(UNMATCHED_INSERT_SQL)
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
        // Without the payer there is nothing to refund TO, and the manual queue
        // cannot tell an admin who to pay.
        .bind(&p.from)
        .bind(&p.from_muxed)
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
            let entry = journal_insert(JournalEntry {
                currency: c.to_string(),
                kind: "unmatched_deposit".to_string(),
                delta: amount,
                balance_after: bal_after,
                held_after,
                // order_id stays NULL: two late payments to one order must
                // both record, and UNIQUE(order_id, kind) would forbid that.
                // The paging_token unique is the per-payment anchor instead.
                stellar_tx_hash: Some(p.tx_hash.clone()),
                paging_token: Some(p.paging_token.clone()),
                note: matched_order_id.map(|o| format!("order {}", o)),
                sender_address: p.from.clone(),
                sender_muxed: p.from_muxed.clone(),
                ..Default::default()
            })
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

        // Queue the return in the SAME transaction as the credit, so an
        // obligation exists iff the money was booked.
        queue_refund(
            &deps.reserve,
            &deps.metrics,
            &mut tx,
            QueueRefundInput {
                source_paging_token: &p.paging_token,
                source_tx_hash: &p.tx_hash,
                order_id: matched_order_id,
                currency: c,
                amount_minor: amount,
                reason,
                op_type: &p.op_type,
                declared_refund_address: None,
                sender_address: p.from.as_deref(),
                sender_muxed: p.from_muxed.as_deref(),
                order_ref: None,
                account_id: None,
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
        let inserted = journal_insert(JournalEntry {
            currency: RESERVE_CURRENCY_USDC.to_string(),
            kind: "payout_attempt".to_string(),
            balance_after: bal,
            held_after: held,
            order_id: Some(order.order_id),
            ..Default::default()
        })
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
        &deps.signer,
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

    match classify_submit(&submitted) {
        SubmitOutcome::Settled => {
            let tx_result = submitted.expect("Settled implies Ok");
            record_fulfillment(
                deps,
                order,
                amount_to_minor,
                &tx_result.stellar_hash,
                tx_result.stellar_tx_id.as_deref(),
            )
            .await
        }
        // Definitive rejection: the tx provably did not land, so a bounded
        // retry is double-payout-safe.
        SubmitOutcome::Rejected { msg, permanent } => {
            deps.metrics.record_reserve_payout_failure("rejected");
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
        SubmitOutcome::Ambiguous => {
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

    journal_insert(JournalEntry {
        currency: RESERVE_CURRENCY_USDC.to_string(),
        kind: "fulfillment".to_string(),
        held_delta: -amount_to_minor,
        balance_after: bal_after,
        held_after,
        order_id: Some(order.order_id),
        stellar_tx_hash: Some(stellar_hash.to_string()),
        ..Default::default()
    })
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

// ── Phase 2b: refunds ──────────────────────────────────────────────────

/// Everything needed to mint a refund obligation.
pub(crate) struct QueueRefundInput<'a> {
    /// The on-chain payment being returned. `UNIQUE` on the refund table, so
    /// one inflow can never mint two obligations — across BOTH queueing
    /// sites, because a payment is either matched (a `deposit` entry) or
    /// stray (an unmatched row), never both.
    pub source_paging_token: &'a str,
    pub source_tx_hash: &'a str,
    pub order_id: Option<Uuid>,
    pub currency: &'a str,
    pub amount_minor: i64,
    pub reason: &'a str,
    pub op_type: &'a str,
    pub declared_refund_address: Option<&'a str>,
    pub sender_address: Option<&'a str>,
    pub sender_muxed: Option<&'a str>,
    /// The order ref the refund memo is derived from, when there is an order.
    pub order_ref: Option<&'a str>,
    pub account_id: Option<&'a str>,
}

/// Mint a refund obligation inside the caller's transaction, or record why
/// not. Returns the decision so the caller can shape its response.
pub(crate) async fn queue_refund(
    reserve: &ConversionReserve,
    metrics: &AppMetrics,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: QueueRefundInput<'_>,
) -> Result<RefundDecision, AppError> {
    let settings: (bool,) =
        sqlx::query_as("SELECT refunds_enabled FROM conversion_reserve_state WHERE id")
            .fetch_one(&mut **tx)
            .await
            .map_err(db_err("refund settings"))?;
    let max_minor: i64 =
        sqlx::query_scalar("SELECT refund_max_minor FROM conversion_reserve WHERE currency = $1")
            .bind(input.currency)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_err("refund cap"))?
            .unwrap_or(0);

    let decision = refund_decision(&RefundContext {
        enabled: settings.0,
        reason: input.reason,
        op_type: input.op_type,
        currency: Some(input.currency),
        amount_minor: Some(input.amount_minor),
        declared_refund_address: input.declared_refund_address,
        sender_address: input.sender_address,
        sender_muxed: input.sender_muxed,
        reserve_address: &reserve.stellar_address,
        usdc_issuer: &reserve.usdc_issuer,
        max_minor,
    });

    let (destination, refund_minor, status, skip_reason) = match &decision {
        RefundDecision::Queue {
            destination,
            refund_minor,
        } => (destination.clone(), *refund_minor, "queued", None),
        RefundDecision::Review {
            destination,
            refund_minor,
            why,
        } => (
            destination.clone(),
            *refund_minor,
            "needs_review",
            Some(*why),
        ),
        RefundDecision::Skip(why) => {
            // No obligation, but the queue must still explain itself.
            sqlx::query(
                "UPDATE conversion_reserve_unmatched SET refund_skip_reason = $2 \
                 WHERE paging_token = $1",
            )
            .bind(input.source_paging_token)
            .bind(why)
            .execute(&mut **tx)
            .await
            .map_err(db_err("refund skip reason"))?;
            return Ok(decision);
        }
    };

    let memo = input.order_ref.map(refund_memo);
    let cooldown = refund_cooldown_secs(input.reason, reserve.deposit_ttl_secs);
    let refund_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO conversion_reserve_refund \
             (source_paging_token, source_tx_hash, order_id, currency, amount_minor, \
              refund_minor, destination, memo, reason, status, skip_reason, \
              next_attempt_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                 CURRENT_TIMESTAMP + make_interval(secs => $12)) \
         ON CONFLICT (source_paging_token) DO NOTHING \
         RETURNING refund_id",
    )
    .bind(input.source_paging_token)
    .bind(input.source_tx_hash)
    .bind(input.order_id)
    .bind(input.currency)
    .bind(input.amount_minor)
    .bind(refund_minor)
    .bind(&destination)
    .bind(&memo)
    .bind(input.reason)
    .bind(status)
    .bind(skip_reason)
    .bind(cooldown as f64)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_err("refund insert"))?;

    let refund_id = match refund_id {
        Some(id) => id,
        // Already minted for this payment — a replay, by construction.
        None => return Ok(decision),
    };
    sqlx::query("UPDATE conversion_reserve_unmatched SET refund_id = $2 WHERE paging_token = $1")
        .bind(input.source_paging_token)
        .bind(refund_id)
        .execute(&mut **tx)
        .await
        .map_err(db_err("refund link"))?;

    crate::events::emit_event(
        tx,
        &AccountEvent::ReserveRefundQueued {
            account_id: input
                .account_id
                .unwrap_or(&reserve.reserve_account_id)
                .to_string(),
            refund_id: refund_id.to_string(),
            currency: input.currency.to_string(),
            amount_minor: refund_minor,
            reason: input.reason.to_string(),
        },
    )
    .await?;
    metrics.record_reserve_refund_queued(input.reason);
    info!(
        "reserve refund {} queued ({}): {} {} -> {}",
        refund_id,
        status,
        minor_to_decimal_string(refund_minor, RESERVE_SCALE_STELLAR),
        input.currency,
        destination
    );
    Ok(decision)
}

/// Obligations eligible for an on-chain send. Only `queued` is reachable:
/// `needs_review` waits for an admin, `inflight` is owned by a worker, and
/// every other state is terminal or frozen.
const DUE_REFUNDS_SQL: &str = "SELECT r.refund_id, r.currency, r.refund_minor, \
        r.destination, r.memo, r.order_id, r.attempts, r.reason, r.source_tx_hash, \
        o.payala_account_id \
     FROM conversion_reserve_refund r \
     LEFT JOIN exchange_order o ON o.order_id = r.order_id \
     WHERE r.status = 'queued' AND r.next_attempt_at <= CURRENT_TIMESTAMP \
     ORDER BY r.next_attempt_at LIMIT $1";

/// The claim. Exactly one worker wins; anything not `queued` is unreachable.
const CLAIM_REFUND_SQL: &str = "UPDATE conversion_reserve_refund \
     SET status = 'inflight', attempts = attempts + 1, \
         claimed_at = CURRENT_TIMESTAMP, last_error = NULL \
     WHERE refund_id = $1 AND status = 'queued' \
       AND next_attempt_at <= CURRENT_TIMESTAMP";

/// 24h refund spend for a bucket, netting reversals so a provably-unsent
/// refund does not consume the cap. Read under the bucket's row lock.
const DAILY_REFUND_SPEND_SQL: &str = "SELECT COALESCE(SUM(-delta), 0)::bigint \
     FROM conversion_reserve_entry \
     WHERE kind IN ('refund_intent', 'refund_reversal') AND currency = $1 \
       AND created_at >= CURRENT_TIMESTAMP - interval '24 hours'";

/// Record a stray inflow. The sender columns are what make a refund
/// possible at all — an inflow with no recorded payer can only be returned
/// by hand, from an explorer.
const UNMATCHED_INSERT_SQL: &str = "INSERT INTO conversion_reserve_unmatched \
     (paging_token, tx_hash, op_type, asset_code, asset_issuer, amount, \
      amount_minor, memo, matched_order_id, reason, sender_address, sender_muxed) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     ON CONFLICT (paging_token) DO NOTHING";

/// Push a refund's next attempt out. Targets `queued`, because the caller
/// rolled its claim back before getting here.
const DEFER_REFUND_SQL: &str = "UPDATE conversion_reserve_refund \
     SET last_error = $2, \
         next_attempt_at = CURRENT_TIMESTAMP + make_interval(secs => $3) \
     WHERE refund_id = $1 AND status = 'queued'";

/// Crashed mid-submit: claimed long enough ago that the signed transaction
/// can no longer land, with no outcome recorded.
const STALE_REFUND_SQL: &str = "SELECT refund_id FROM conversion_reserve_refund \
     WHERE status = 'inflight' \
       AND claimed_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
     LIMIT 25";

#[derive(sqlx::FromRow)]
struct DueRefundRow {
    refund_id: Uuid,
    currency: String,
    refund_minor: i64,
    destination: String,
    memo: Option<String>,
    order_id: Option<Uuid>,
    attempts: i32,
    #[allow(dead_code)]
    reason: String,
    #[allow(dead_code)]
    source_tx_hash: String,
    payala_account_id: Option<String>,
}

async fn drive_refunds(deps: &ReserveWatchDeps) {
    // Master switch, re-read every tick: flipping it off must stop payments
    // that are already queued, not just new queueing.
    let enabled: bool =
        match sqlx::query_scalar("SELECT refunds_enabled FROM conversion_reserve_state WHERE id")
            .fetch_one(&deps.pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("reserve refunds: settings read failed: {}", e);
                return;
            }
        };
    if !enabled {
        return;
    }

    let due: Vec<DueRefundRow> = match sqlx::query_as(DUE_REFUNDS_SQL)
        .bind(RESERVE_REFUND_MAX_PER_TICK)
        .fetch_all(&deps.pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("reserve refunds: due scan failed: {}", e);
            return;
        }
    };
    for r in due {
        if let Err(e) = drive_one_refund(deps, &r).await {
            error!("reserve refund {}: {:?}", r.refund_id, e);
        }
    }
}

async fn drive_one_refund(deps: &ReserveWatchDeps, r: &DueRefundRow) -> Result<(), AppError> {
    // ── Claim + write-ahead debit, one transaction ────────────────────
    //
    // The debit is written BEFORE the submit on purpose. The failure that
    // matters is "submitted, then crashed": with a write-ahead debit that
    // leaves the ledger CORRECT and only the metadata missing, whereas a
    // post-submit debit would overstate `available` by the refunded amount
    // with no marker that a submission exists at all.
    let mut tx = deps.pool.begin().await.map_err(db_err("refund begin"))?;
    let claimed = sqlx::query(CLAIM_REFUND_SQL)
        .bind(r.refund_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("refund claim"))?;
    if claimed.rows_affected() == 0 {
        // Another worker owns it, or an admin cancelled it between the scan
        // and now.
        return Ok(());
    }

    // Takes the bucket row lock, which is also what makes the daily cap
    // below exact against concurrent refunds of the same currency.
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&r.currency)
        .bind(-r.refund_minor)
        .bind(0i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("refund debit"))?;
    let (bal_after, held_after, _) = match bucket {
        Some(b) => b,
        None => {
            drop(tx);
            return defer_refund(deps, r, "insufficient").await;
        }
    };

    let spent: i64 = sqlx::query_scalar(DAILY_REFUND_SPEND_SQL)
        .bind(&r.currency)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("refund daily spend"))?;
    let daily_cap: i64 = sqlx::query_scalar(
        "SELECT refund_daily_max_minor FROM conversion_reserve WHERE currency = $1",
    )
    .bind(&r.currency)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("refund daily cap"))?;
    // `spent` already includes this refund's own intent? No — the intent is
    // written below, so compare the running total plus this one.
    if daily_cap <= 0 || spent + r.refund_minor > daily_cap {
        drop(tx);
        return defer_refund(deps, r, "cap_daily").await;
    }

    journal_insert(JournalEntry {
        currency: r.currency.clone(),
        kind: "refund_intent".to_string(),
        delta: -r.refund_minor,
        balance_after: bal_after,
        held_after,
        // order_id stays NULL: two late payments against one order each earn
        // a refund, and a retry writes intent/reversal/intent — both would
        // collide with UNIQUE(order_id, kind). refund_id is the link.
        refund_id: Some(r.refund_id),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("refund intent"))?;
    tx.commit().await.map_err(db_err("refund claim commit"))?;

    // ── Submit ────────────────────────────────────────────────────────
    let asset = match r.currency.as_str() {
        RESERVE_CURRENCY_XLM => Asset::Native,
        RESERVE_CURRENCY_USDC => Asset::Credit {
            code: deps.reserve.usdc_code.clone(),
            issuer: deps.reserve.usdc_issuer.clone(),
        },
        other => {
            error!(
                "reserve refund {}: unsupported asset {}",
                r.refund_id, other
            );
            return freeze_refund(deps, r.refund_id, "unsupported_asset").await;
        }
    };
    let seed = crate::handlers::managed_seed::load_protected_seed(
        &deps.pool,
        &deps.protector,
        &deps.signer,
        &deps.reserve.reserve_account_id,
    )
    .await?;
    let params = PaymentParams {
        destination: r.destination.clone(),
        amount: minor_to_decimal_string(r.refund_minor, RESERVE_SCALE_STELLAR),
        asset,
        memo: r.memo.clone(),
        fee: None,
    };
    let submitted = deps
        .signer
        .sign_and_submit_payment(seed.as_slice(), &params)
        .await;
    // `seed` zeroizes on drop.

    match classify_submit(&submitted) {
        SubmitOutcome::Settled => {
            let tx_result = submitted.expect("Settled implies Ok");
            record_refund_sent(deps, r, &tx_result.stellar_hash).await
        }
        SubmitOutcome::Rejected { msg, permanent } => {
            deps.metrics.record_reserve_refund_failure("rejected");
            let exhausted = permanent || r.attempts + 1 >= RESERVE_REFUND_MAX_ATTEMPTS;
            reverse_refund(deps, r, &msg, exhausted).await
        }
        // The payment MAY still land. Freeze WITHOUT reversing: the debit
        // stands because the money may genuinely be gone.
        SubmitOutcome::Ambiguous => {
            deps.metrics.record_reserve_refund_failure("submit_unknown");
            freeze_refund(deps, r.refund_id, "submit_unknown").await
        }
    }
}

/// Roll a claim back to `queued` with backoff (nothing was submitted).
async fn defer_refund(
    deps: &ReserveWatchDeps,
    r: &DueRefundRow,
    reason: &'static str,
) -> Result<(), AppError> {
    deps.metrics.record_reserve_refund_failure(reason);
    let backoff = poll_backoff_secs(deps.reserve.watch_secs, r.attempts).max(3600) as f64;
    // The caller rolled its claim transaction back before calling this, so
    // the row is still `queued` with attempts un-incremented — CASing on
    // `inflight` would match zero rows, losing the backoff and spinning the
    // driver on the same row every tick.
    sqlx::query(DEFER_REFUND_SQL)
        .bind(r.refund_id)
        .bind(reason)
        .bind(backoff)
        .execute(&deps.pool)
        .await
        .map_err(db_err("refund defer"))?;
    Ok(())
}

/// A definitive rejection: restore the ledger, then retry or give up.
async fn reverse_refund(
    deps: &ReserveWatchDeps,
    r: &DueRefundRow,
    msg: &str,
    exhausted: bool,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("reverse begin"))?;
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&r.currency)
        .bind(r.refund_minor)
        .bind(0i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("reverse credit"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!("reserve refund {}: reversal underflow (drift)", r.refund_id);
        AppError::InternalError("Database error".to_string())
    })?;
    journal_insert(JournalEntry {
        currency: r.currency.clone(),
        kind: "refund_reversal".to_string(),
        delta: r.refund_minor,
        balance_after: bal_after,
        held_after,
        refund_id: Some(r.refund_id),
        note: Some(crate::exchange::reconcile::truncate_chars(msg, 200)),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("reverse entry"))?;

    if exhausted {
        sqlx::query(
            "UPDATE conversion_reserve_refund \
             SET status = 'failed', last_error = $2, resolved_at = CURRENT_TIMESTAMP \
             WHERE refund_id = $1 AND status = 'inflight'",
        )
        .bind(r.refund_id)
        .bind(crate::exchange::reconcile::truncate_chars(msg, 200))
        .execute(&mut *tx)
        .await
        .map_err(db_err("reverse fail"))?;
    } else {
        let backoff = poll_backoff_secs(deps.reserve.watch_secs, r.attempts) as f64;
        sqlx::query(
            "UPDATE conversion_reserve_refund \
             SET status = 'queued', claimed_at = NULL, last_error = $2, \
                 next_attempt_at = CURRENT_TIMESTAMP + make_interval(secs => $3) \
             WHERE refund_id = $1 AND status = 'inflight'",
        )
        .bind(r.refund_id)
        .bind(crate::exchange::reconcile::truncate_chars(msg, 200))
        .bind(backoff)
        .execute(&mut *tx)
        .await
        .map_err(db_err("reverse requeue"))?;
    }
    tx.commit().await.map_err(db_err("reverse commit"))?;
    warn!(
        "reserve refund {} rejected ({}): {}",
        r.refund_id,
        if exhausted { "failed" } else { "will retry" },
        crate::exchange::reconcile::truncate_chars(msg, 120)
    );
    Ok(())
}

/// Freeze for a human. The debit is NOT reversed — the money may be gone.
async fn freeze_refund(
    deps: &ReserveWatchDeps,
    refund_id: Uuid,
    reason: &'static str,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("freeze begin"))?;
    let updated = sqlx::query(
        "UPDATE conversion_reserve_refund \
         SET status = 'frozen', last_error = COALESCE(last_error, $2) \
         WHERE refund_id = $1 AND status = 'inflight'",
    )
    .bind(refund_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(db_err("refund freeze"))?;
    // Guarded, so the event fires exactly once per real transition.
    if updated.rows_affected() == 1 {
        crate::events::emit_event(
            &mut tx,
            &AccountEvent::ReserveRefundFailed {
                account_id: deps.reserve.reserve_account_id.clone(),
                refund_id: refund_id.to_string(),
                reason: reason.to_string(),
            },
        )
        .await?;
        tx.commit().await.map_err(db_err("freeze commit"))?;
        warn!("reserve refund {} frozen: {}", refund_id, reason);
    }
    Ok(())
}

/// The refund landed: close the obligation and record the settlement.
async fn record_refund_sent(
    deps: &ReserveWatchDeps,
    r: &DueRefundRow,
    stellar_hash: &str,
) -> Result<(), AppError> {
    let mut tx = deps
        .pool
        .begin()
        .await
        .map_err(db_err("refund sent begin"))?;
    let updated = sqlx::query(
        "UPDATE conversion_reserve_refund \
         SET status = 'sent', stellar_tx_hash = $2, resolved_at = CURRENT_TIMESTAMP, \
             last_error = NULL \
         WHERE refund_id = $1 AND status = 'inflight'",
    )
    .bind(r.refund_id)
    .bind(stellar_hash)
    .execute(&mut *tx)
    .await
    .map_err(db_err("refund sent update"))?;
    if updated.rows_affected() == 0 {
        // Settled on-chain but the row left `inflight` (an admin resolved it
        // concurrently). Refuse to guess — shout for reconciliation.
        error!(
            "RESERVE REFUND SETTLED BUT ROW NOT RECORDABLE — refund={} hash={} amount={} {}: \
             reconcile the ledger against the chain",
            r.refund_id, stellar_hash, r.refund_minor, r.currency
        );
        deps.metrics.record_reserve_refund_failure("unrecordable");
        return Ok(());
    }

    // The value already left `available` at intent time; this entry records
    // that it actually landed.
    let (bal, held): (i64, i64) = sqlx::query_as(
        "SELECT available, held FROM conversion_reserve WHERE currency = $1 FOR UPDATE",
    )
    .bind(&r.currency)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("refund sent bucket"))?;
    journal_insert(JournalEntry {
        currency: r.currency.clone(),
        kind: "refund_sent".to_string(),
        balance_after: bal,
        held_after: held,
        refund_id: Some(r.refund_id),
        stellar_tx_hash: Some(stellar_hash.to_string()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("refund sent entry"))?;

    let btxid: Uuid = sqlx::query_scalar(
        "INSERT INTO transaction \
             (stellar_tx_id, stellar_hash, source_account, memo, account_id, origin) \
         VALUES ($1, $2, $3, $4, $5, 'conversion_reserve') \
         RETURNING btxid",
    )
    .bind(stellar_hash)
    .bind(stellar_hash)
    .bind(&deps.reserve.stellar_address)
    .bind(&r.memo)
    .bind(&r.payala_account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("refund transaction row"))?;
    sqlx::query("UPDATE conversion_reserve_refund SET btxid = $2 WHERE refund_id = $1")
        .bind(r.refund_id)
        .bind(btxid)
        .execute(&mut *tx)
        .await
        .map_err(db_err("refund btxid"))?;

    // An order whose deposit is now returned is terminally refunded. Guarded
    // to the resolve-failed state ONLY: an `underpaid` refund leaves its
    // order in awaiting_deposit, and flipping that would make expire_one's
    // guarded transition match zero rows, stranding the hold forever.
    if let Some(order_id) = r.order_id {
        sqlx::query(
            "UPDATE exchange_order SET status = 'refunded', provider_status = 'refunded' \
             WHERE order_id = $1 AND status = 'failed' AND provider_status = 'resolved_failed'",
        )
        .bind(order_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("refund order status"))?;
    }

    if let Some(ref account_id) = r.payala_account_id {
        crate::events::emit_event(
            &mut tx,
            &AccountEvent::ReserveRefundSent {
                account_id: account_id.clone(),
                refund_id: r.refund_id.to_string(),
                currency: r.currency.clone(),
                amount_minor: r.refund_minor,
            },
        )
        .await?;
    }
    tx.commit().await.map_err(db_err("refund sent commit"))?;

    deps.metrics.reserve_refunds_sent.add(1, &[]);
    info!(
        "reserve refund {} sent: {} {} to {} hash={}",
        r.refund_id,
        minor_to_decimal_string(r.refund_minor, RESERVE_SCALE_STELLAR),
        r.currency,
        r.destination,
        stellar_hash
    );
    Ok(())
}

/// Freeze refunds whose submit outcome was never recorded.
async fn freeze_stale_refunds(deps: &ReserveWatchDeps) {
    let stale: Vec<(Uuid,)> = match sqlx::query_as(STALE_REFUND_SQL)
        .bind(STALE_INTENT_SECS as f64)
        .fetch_all(&deps.pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("reserve refund stale sweep failed: {}", e);
            return;
        }
    };
    for (refund_id,) in stale {
        deps.metrics.record_reserve_refund_failure("stale_claim");
        if let Err(e) = freeze_refund(deps, refund_id, "stale_claim").await {
            error!("reserve refund stale freeze {}: {:?}", refund_id, e);
        }
    }
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

    // Release exactly what the creation hold took — from whichever anchor
    // took it (the order's own entry, or a consumed quote's).
    let hold: Option<(String, i64)> = sqlx::query_as(ORDER_HOLD_SQL)
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

    journal_insert(JournalEntry {
        currency: currency.clone(),
        kind: "hold_release".to_string(),
        delta: hold_minor,
        held_delta: -hold_minor,
        balance_after: bal_after,
        held_after,
        order_id: Some(order_id),
        note: Some("deposit window expired".to_string()),
        ..Default::default()
    })
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
            quote_ttl_secs: 300,
        }
    }

    fn xlm_payment(to: &str, amount: &str) -> HorizonPayment {
        HorizonPayment {
            paging_token: "1".to_string(),
            tx_hash: "h1".to_string(),
            op_type: "payment".to_string(),
            to: to.to_string(),
            from: Some("GSENDER".to_string()),
            from_muxed: None,
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

    // ── Refund decisions ───────────────────────────────────────────────

    // Structurally valid 56-char base32 test addresses (validate_stellar_
    // account_id is a format gate, not a checksum check).
    const T_SENDER: &str = "GSENDERABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
    const T_RESERVE: &str = "GRESERVEABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOP";
    const T_ISSUER: &str = "GISSUERABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
    const T_DECLARED: &str = "GDECLAREDABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNO";

    fn refund_ctx<'a>(reason: &'a str, sender: Option<&'a str>) -> RefundContext<'a> {
        RefundContext {
            enabled: true,
            reason,
            op_type: "payment",
            currency: Some(RESERVE_CURRENCY_XLM),
            // 5 XLM, comfortably over the dust floor.
            amount_minor: Some(50_000_000),
            declared_refund_address: None,
            sender_address: sender,
            sender_muxed: None,
            reserve_address: T_RESERVE,
            usdc_issuer: T_ISSUER,
            max_minor: 1_000_000_000,
        }
    }

    #[test]
    fn refund_memo_can_never_be_mistaken_for_an_order_ref() {
        // THE regression pin. find_onchain_payout reads an outgoing payment
        // carrying the order ref as proof the payout landed; a refund memo
        // that matched would make resolve-fail refuse and resolve-complete
        // record the refund's hash as the fulfillment.
        for _ in 0..64 {
            let order_ref = crate::exchange::reserve::base32_order_ref(&Uuid::new_v4());
            let memo = refund_memo(&order_ref);
            assert!(
                !memo_matches_ref(&memo, &order_ref),
                "refund memo {} collided with order ref {}",
                memo,
                order_ref
            );
            assert!(memo.len() <= 28, "memo must fit Stellar MEMO_TEXT");
            assert!(memo.starts_with(RESERVE_REFUND_MEMO_PREFIX));
        }
    }

    #[test]
    fn refunds_are_skipped_when_disabled_or_not_auto_eligible() {
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.enabled = false;
        assert_eq!(refund_decision(&c), RefundDecision::Skip("disabled"));

        // An unmemoed inflow is how ops tops the pool up — auto-refunding it
        // would wire the float straight back to ops.
        for manual in ["no_match", "wrong_asset", "manual"] {
            let c = refund_ctx(manual, Some(T_SENDER));
            assert_eq!(refund_decision(&c), RefundDecision::Skip("reason_manual"));
        }
    }

    #[test]
    fn refunds_exclude_unrefundable_operation_shapes() {
        // The starting balance IS the base reserve, and the funder is ops.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.op_type = "create_account";
        assert_eq!(refund_decision(&c), RefundDecision::Skip("create_account"));

        // The payer parted with a different asset than the one that arrived.
        for pp in ["path_payment_strict_send", "path_payment_strict_receive"] {
            let mut c = refund_ctx("late", Some(T_SENDER));
            c.op_type = pp;
            assert_eq!(refund_decision(&c), RefundDecision::Skip("path_payment"));
        }
    }

    #[test]
    fn refunds_refuse_unsafe_destinations() {
        // Muxed: the visible address is a SHARED base account.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.sender_muxed = Some("MSENDERXXXX");
        assert_eq!(refund_decision(&c), RefundDecision::Skip("muxed_sender"));

        // No payer at all (pre-032 rows, or a feed without `from`).
        let c = refund_ctx("late", None);
        assert_eq!(refund_decision(&c), RefundDecision::Skip("no_sender"));

        // Paying ourselves debits the ledger for a no-op.
        let c = refund_ctx("late", Some(T_RESERVE));
        assert_eq!(refund_decision(&c), RefundDecision::Skip("self_refund"));

        // Returning an issued asset to its issuer BURNS it.
        let c = refund_ctx("late", Some(T_ISSUER));
        assert_eq!(
            refund_decision(&c),
            RefundDecision::Skip("issuer_destination")
        );

        // Junk that is not a Stellar account id.
        let c = refund_ctx("late", Some("0xdeadbeef"));
        assert_eq!(refund_decision(&c), RefundDecision::Skip("bad_destination"));
    }

    #[test]
    fn declared_refund_address_wins_over_an_inferred_sender() {
        // A user-stated destination beats an inference from an address that
        // may be an exchange omnibus account — and rescues a muxed sender.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.declared_refund_address = Some(T_DECLARED);
        c.sender_muxed = Some("MSENDERXXXX");
        assert_eq!(
            refund_decision(&c),
            RefundDecision::Queue {
                destination: T_DECLARED.to_string(),
                refund_minor: 50_000_000,
            }
        );
    }

    #[test]
    fn caps_and_dust_park_for_review_rather_than_absorbing() {
        // Over the per-refund cap: never partially refund to fit under it —
        // that turns an operational limit into a silent haircut.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.max_minor = 1_000;
        assert_eq!(
            refund_decision(&c),
            RefundDecision::Review {
                destination: T_SENDER.to_string(),
                refund_minor: 50_000_000,
                why: "over_cap",
            }
        );

        // Dust is queued for review, never silently kept.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.amount_minor = Some(1);
        assert_eq!(
            refund_decision(&c),
            RefundDecision::Review {
                destination: T_SENDER.to_string(),
                refund_minor: 1,
                why: "dust",
            }
        );

        // A zero cap disables the currency entirely.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.max_minor = 0;
        assert_eq!(refund_decision(&c), RefundDecision::Skip("disabled"));
    }

    #[test]
    fn usd_float_is_never_refunded_on_chain() {
        // The USD bucket is a bank balance; there is nothing to send.
        let mut c = refund_ctx("late", Some(T_SENDER));
        c.currency = Some(RESERVE_CURRENCY_USD);
        assert_eq!(
            refund_decision(&c),
            RefundDecision::Skip("unsupported_asset")
        );
    }

    #[test]
    fn underpaid_refunds_wait_out_the_deposit_window() {
        // Refunding immediately would race a user topping the order up.
        assert_eq!(
            refund_cooldown_secs("underpaid", 1800),
            1800 + RESERVE_REFUND_COOLDOWN_SECS
        );
        assert_eq!(
            refund_cooldown_secs("late", 1800),
            RESERVE_REFUND_COOLDOWN_SECS
        );
        assert_eq!(
            refund_cooldown_secs("order_failed", 1800),
            RESERVE_REFUND_COOLDOWN_SECS
        );
    }

    // ── Submit classification ──────────────────────────────────────────

    #[test]
    fn only_horizon_400_with_result_codes_is_definitive() {
        let ok: Result<(), AppError> = Ok(());
        assert_eq!(classify_submit(&ok), SubmitOutcome::Settled);

        // The signer encodes "400 with parsed result codes" as BadRequest.
        let rejected: Result<(), AppError> = Err(AppError::BadRequest(
            "Stellar transaction rejected: {\"transaction\":\"tx_failed\"}".into(),
        ));
        assert_eq!(
            classify_submit(&rejected),
            SubmitOutcome::Rejected {
                msg: "Stellar transaction rejected: {\"transaction\":\"tx_failed\"}".into(),
                permanent: false
            }
        );

        // Result codes a retry cannot fix.
        for code in [
            "op_no_trust",
            "op_no_destination",
            "op_line_full",
            "op_not_authorized",
        ] {
            let e: Result<(), AppError> = Err(AppError::BadRequest(format!("rejected: {}", code)));
            match classify_submit(&e) {
                SubmitOutcome::Rejected { permanent, .. } => {
                    assert!(permanent, "{} must be permanent", code)
                }
                other => panic!("expected Rejected, got {:?}", other),
            }
        }

        // EVERYTHING else may still land: 429/503/504, transport, parse.
        // Retrying any of these is how a double-spend happens.
        for e in [
            AppError::InternalError("horizon submit: HTTP 504".into()),
            AppError::InternalError("Horizon request failed".into()),
            AppError::RateLimited { retry_after: 1 },
            AppError::Unauthorized,
        ] {
            let r: Result<(), AppError> = Err(e);
            assert_eq!(classify_submit(&r), SubmitOutcome::Ambiguous);
        }
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
    fn deferring_a_refund_targets_the_state_the_caller_left_behind() {
        // The caller rolls its claim transaction back before deferring, so
        // the row is `queued`, not `inflight`. CASing on the wrong state
        // silently loses the backoff and spins the driver every tick.
        assert!(DEFER_REFUND_SQL.contains("AND status = 'queued'"));
        assert!(!DEFER_REFUND_SQL.contains("'inflight'"));
        assert!(DEFER_REFUND_SQL.contains("next_attempt_at = CURRENT_TIMESTAMP + make_interval"));
    }

    #[test]
    fn unmatched_insert_records_the_payer() {
        // Without the sender there is nothing to refund TO, and the manual
        // queue cannot tell an admin who to pay.
        assert!(UNMATCHED_INSERT_SQL.contains("sender_address"));
        assert!(UNMATCHED_INSERT_SQL.contains("sender_muxed"));
        // 12 columns, 12 placeholders — sqlx does not check this for us.
        let cols = UNMATCHED_INSERT_SQL
            .split_once('(')
            .and_then(|(_, r)| r.split_once(')'))
            .map(|(c, _)| c.matches(',').count() + 1)
            .expect("column list");
        assert_eq!(cols, 12);
        assert!(UNMATCHED_INSERT_SQL.contains("$12"));
        assert!(!UNMATCHED_INSERT_SQL.contains("$13"));
    }

    #[test]
    fn refund_sql_guards_every_transition() {
        // Only `queued` is ever selected or claimed: needs_review waits for
        // an admin, inflight is owned, the rest are terminal.
        assert!(DUE_REFUNDS_SQL.contains("r.status = 'queued'"));
        assert!(DUE_REFUNDS_SQL.contains("r.next_attempt_at <= CURRENT_TIMESTAMP"));
        assert!(CLAIM_REFUND_SQL.contains("AND status = 'queued'"));
        assert!(CLAIM_REFUND_SQL.contains("SET status = 'inflight'"));
        assert!(STALE_REFUND_SQL.contains("status = 'inflight'"));
        assert!(STALE_REFUND_SQL.contains("claimed_at <"));
        // The daily cap MUST net reversals, or a provably-unsent refund
        // would permanently consume the day's budget.
        assert!(DAILY_REFUND_SPEND_SQL.contains("'refund_intent'"));
        assert!(DAILY_REFUND_SPEND_SQL.contains("'refund_reversal'"));
        assert!(DAILY_REFUND_SPEND_SQL.contains("interval '24 hours'"));
    }

    #[test]
    fn expiry_sql_only_touches_awaiting_deposit() {
        assert!(EXPIRABLE_SQL.contains("status = 'awaiting_deposit'"));
        assert!(EXPIRABLE_SQL.contains("provider = 'reserve'"));
    }
}

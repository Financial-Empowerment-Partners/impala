//! Automated replenishment: the reserve selling its accumulated float back
//! into the asset it actually pays out.
//!
//! The pool takes XLM in (customers pay XLM for xlm→usdcxlm swaps) and pays
//! USDC out, so without this USDC drains monotonically while XLM piles up.
//! The USD float behaves the same way against fiat disbursements. Two
//! independently triggered cycle kinds handle those:
//!
//! - `xlm_to_usdc` — sell accumulated XLM through Changelly, receive USDC
//!   back at the reserve address. Fully automatic end to end.
//! - `usdc_to_usd` — off-ramp USDC through OwlPay to the bridge's own bank.
//!   Automatic up to the point the bridge can actually observe: it can see
//!   the USDC leave and the provider's transfer status, but **never a bank
//!   credit**. So the fiat lands as `held` ("in transit") and only an admin
//!   confirming receipt moves it into `available`. The ledger never books
//!   value nobody verified.
//!
//! The legs are deliberately NOT chained: off-ramping the USDC just bought
//! would be self-defeating, and a failed second leg would strand a settled
//! first one.
//!
//! Safety comes from three places. **Caps**: a master flag defaulting off,
//! plus per-cycle, daily, and minimum-float bounds where 0 means
//! *unconfigured, refuse to run* rather than "unlimited". **Price guards**: a
//! floor and a slippage bound against a reference quote, which is what stops
//! a mispriced or manipulated quote dumping the whole float. **One cycle in
//! flight per kind**, enforced by a partial unique index rather than a scan,
//! where `frozen` and `in_transit` deliberately still count as in flight.

use log::{error, info, warn};
use uuid::Uuid;

use crate::constants::{RESERVE_REPLENISH_REFERENCE_XLM, RESERVE_SCALE_STELLAR, RESERVE_SCALE_USD};

/// Why a cycle did not start. Low-cardinality metric labels.
#[derive(Debug, PartialEq)]
pub(crate) enum SkipReason {
    /// The subsystem or this kind is switched off.
    Disabled,
    /// Caps are still at their 0 defaults — unconfigured is not unlimited.
    Unconfigured,
    /// A cycle of this kind is already in flight (including frozen ones).
    InFlight,
    Cooldown,
    /// The rolling 24h spend cap would be exceeded.
    DailyCap,
    /// Nothing to buy: the forecast shows enough coverage.
    NoNeed,
    /// The shortfall is below the configured floor.
    BelowMinimum,
    /// Spending would breach the float that must stay for fees or payouts.
    FloatGuard,
    /// The chain could not be read, so spendability is unproven.
    ChainUnknown,
    /// A customer payout may still be in flight; sharing the account's
    /// sequence number would collide with it.
    PayoutInFlight,
    /// The provider quote is worse than the configured floor.
    PriceFloor,
    /// The at-size quote drifted too far from the reference.
    Slippage,
    /// No usable quote came back.
    NoQuote,
    /// This deployment cannot build a provider leg for the kind
    /// (`usdc_to_usd` has no treasury beneficiary configuration), so a cycle
    /// would only be aborted at creation — see `kind_has_provider_leg`.
    NoProviderLeg,
}

impl SkipReason {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            SkipReason::Disabled => "disabled",
            SkipReason::Unconfigured => "unconfigured",
            SkipReason::InFlight => "in_flight",
            SkipReason::Cooldown => "cooldown",
            SkipReason::DailyCap => "daily_cap",
            SkipReason::NoNeed => "no_need",
            SkipReason::BelowMinimum => "below_minimum",
            SkipReason::FloatGuard => "float_guard",
            SkipReason::ChainUnknown => "chain_unknown",
            SkipReason::PayoutInFlight => "payout_in_flight",
            SkipReason::PriceFloor => "price_floor",
            SkipReason::Slippage => "slippage",
            SkipReason::NoQuote => "no_quote",
            SkipReason::NoProviderLeg => "no_provider_leg",
        }
    }
}

/// The admin-editable caps for one cycle kind.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ReplenishPolicy {
    pub kind: String,
    pub enabled: bool,
    pub target_days: i32,
    pub window_days: i32,
    pub min_need_minor: i64,
    /// 0 means unconfigured — refuse to run.
    pub max_spend_minor: i64,
    /// 0 means unconfigured — refuse to run.
    pub daily_spend_cap_minor: i64,
    pub cooldown_secs: i32,
    /// Never spent: XLM for fees and the Stellar base reserve, or the USDC
    /// kept back to serve customer payouts.
    pub min_float_minor: i64,
    /// Recv minor units per ONE WHOLE spend unit. 0 disables.
    pub min_price_minor: i64,
    pub max_slippage_bps: i32,
}

/// Live state the guards are evaluated against, gathered before the decision
/// so the decision itself stays pure and testable.
#[derive(Debug, Clone)]
pub(crate) struct CycleSnapshot {
    /// A cycle of this kind occupies the slot.
    pub in_flight: bool,
    /// Seconds since the last cycle of this kind started; `None` if never.
    pub since_last_cycle_secs: Option<i64>,
    /// Spend already committed in the rolling 24h window.
    pub spent_24h_minor: i64,
    /// What the forecast says is missing from the RECEIVING bucket.
    pub need_minor: i64,
    /// Ledger `available` of the SPENDING bucket.
    pub spend_available_minor: i64,
    /// On-chain balance of the spending asset in minor units. `None` when
    /// Horizon could not be read — which must skip, never spend.
    pub onchain_spend_minor: Option<i64>,
    /// A customer payout may still be in flight.
    pub payout_in_flight: bool,
}

/// May a cycle start at all? Every guard, in order, first failure wins.
pub(crate) fn guards_allow_cycle(
    policy: &ReplenishPolicy,
    snap: &CycleSnapshot,
) -> Result<(), SkipReason> {
    if !policy.enabled {
        return Err(SkipReason::Disabled);
    }
    // Unconfigured caps are refused rather than treated as unlimited: two
    // independent things must be set before value can move.
    if policy.max_spend_minor <= 0 || policy.daily_spend_cap_minor <= 0 {
        return Err(SkipReason::Unconfigured);
    }
    if snap.in_flight {
        return Err(SkipReason::InFlight);
    }
    if let Some(since) = snap.since_last_cycle_secs {
        if since < policy.cooldown_secs as i64 {
            return Err(SkipReason::Cooldown);
        }
    }
    if snap.spent_24h_minor >= policy.daily_spend_cap_minor {
        return Err(SkipReason::DailyCap);
    }
    if snap.need_minor <= 0 {
        return Err(SkipReason::NoNeed);
    }
    if snap.need_minor < policy.min_need_minor {
        return Err(SkipReason::BelowMinimum);
    }
    // Spendability is proven against the LOWER of ledger and chain: the
    // ledger can include credits the chain has not settled, and the chain
    // includes the base reserve the ledger knows nothing about.
    let onchain = match snap.onchain_spend_minor {
        Some(v) => v,
        None => return Err(SkipReason::ChainUnknown),
    };
    if snap.spend_available_minor.min(onchain) <= policy.min_float_minor {
        return Err(SkipReason::FloatGuard);
    }
    // The reserve account signs payouts and replenishment pay-ins from ONE
    // sequence number. Starting a cycle while a payout may still land would
    // collide with it.
    if snap.payout_in_flight {
        return Err(SkipReason::PayoutInFlight);
    }
    Ok(())
}

/// The most that may be spent this cycle, before pricing.
pub(crate) fn spend_ceiling(policy: &ReplenishPolicy, snap: &CycleSnapshot) -> i64 {
    let spendable = snap
        .spend_available_minor
        .min(snap.onchain_spend_minor.unwrap_or(0))
        .saturating_sub(policy.min_float_minor)
        .max(0);
    let daily_left = policy
        .daily_spend_cap_minor
        .saturating_sub(snap.spent_24h_minor)
        .max(0);
    policy.max_spend_minor.min(spendable).min(daily_left)
}

/// Size an XLM sell from a USDC need, using a reference quote.
///
/// Note the argument order versus pricing an order: this goes value→size, so
/// the reference pair is inverted. [`scale_linear`] floors, which here means
/// spending slightly LESS than needed — the bridge-favourable direction; the
/// residual is picked up by the next cycle.
pub(crate) fn size_spend_from_need(
    need_recv_minor: i64,
    ref_spend_minor: i64,
    ref_recv_minor: i64,
    ceiling_minor: i64,
) -> Option<i64> {
    if ceiling_minor <= 0 {
        return None;
    }
    let wanted =
        crate::exchange::reserve::scale_linear(need_recv_minor, ref_recv_minor, ref_spend_minor)?;
    let sized = wanted.min(ceiling_minor);
    (sized > 0).then_some(sized)
}

/// Recv minor units per ONE WHOLE spend unit, exact in i128.
///
/// This is the number both price guards read, so it is the single place a
/// mispriced quote is caught.
pub(crate) fn implied_price_minor(
    spend_minor: i64,
    recv_minor: i64,
    spend_scale: u8,
) -> Option<i64> {
    if spend_minor <= 0 || recv_minor <= 0 {
        return None;
    }
    let one_unit = 10i128.checked_pow(spend_scale as u32)?;
    let price = (recv_minor as i128)
        .checked_mul(one_unit)?
        .checked_div(spend_minor as i128)?;
    i64::try_from(price).ok()
}

/// Reject a quote that is worse than the floor, or too far from the
/// reference. Either is a sign the quote should not be acted on.
pub(crate) fn price_guards_allow(
    policy: &ReplenishPolicy,
    quoted_price_minor: i64,
    reference_price_minor: i64,
) -> Result<(), SkipReason> {
    if policy.min_price_minor > 0 && quoted_price_minor < policy.min_price_minor {
        return Err(SkipReason::PriceFloor);
    }
    if reference_price_minor > 0 {
        let drift = (reference_price_minor as i128 - quoted_price_minor as i128).abs();
        let bps = drift
            .saturating_mul(10_000)
            .checked_div(reference_price_minor as i128)
            .unwrap_or(i128::MAX);
        if bps > policy.max_slippage_bps as i128 {
            return Err(SkipReason::Slippage);
        }
    }
    Ok(())
}

/// USD cents -> Stellar 7-dp minor units. The checked inverse of
/// `stellar_minor_to_usd_cents_ceil`.
pub(crate) fn usd_cents_to_stellar_minor(cents: i64) -> Option<i64> {
    const FACTOR: i64 = 100_000; // 10^(7-2)
    cents.checked_mul(FACTOR)
}

/// The scale of a bucket's minor unit.
pub(crate) fn scale_for(currency: &str) -> u8 {
    if currency == crate::constants::RESERVE_CURRENCY_USD {
        RESERVE_SCALE_USD
    } else {
        RESERVE_SCALE_STELLAR
    }
}

/// A provider create that failed ambiguously can only be retried when the
/// provider honors an idempotency key; otherwise a retry risks a second
/// order.
///
/// Changelly's `createTransaction` takes no client key — but abandoning an
/// orphan is free, because Changelly only pays out after our pay-in, so a
/// swap we never fund simply expires. OwlPay's transfer create DOES take
/// `X-Idempotency-Key`, so re-POSTing returns the same transfer.
pub(crate) fn ambiguous_create_is_retryable(provider: &str) -> bool {
    provider == crate::constants::EXCHANGE_PROVIDER_OWLPAY
}

/// The reference notional used to price before the real size is known.
pub(crate) fn reference_spend_minor(kind: &str) -> Option<i64> {
    match kind {
        "xlm_to_usdc" => crate::exchange::reserve::parse_decimal_to_minor(
            RESERVE_REPLENISH_REFERENCE_XLM,
            RESERVE_SCALE_STELLAR,
        ),
        // The fiat leg is priced at par plus provider fees, not from a
        // reference notional.
        _ => None,
    }
}

/// Log and count a skip. Kept here so every caller labels consistently.
pub(crate) fn record_skip(metrics: &crate::telemetry::AppMetrics, kind: &str, why: &SkipReason) {
    metrics.record_replenish_skip(why.as_str());
    // Routine "nothing to do" outcomes stay at debug; anything that means a
    // cycle COULD not run despite being wanted is worth seeing.
    match why {
        SkipReason::NoNeed | SkipReason::Cooldown | SkipReason::InFlight | SkipReason::Disabled => {
        }
        other => info!("replenish {}: skipped ({})", kind, other.as_str()),
    }
}

/// Freeze a cycle for admin resolution. The spend hold is NOT released — the
/// funds may genuinely be gone.
pub(crate) async fn freeze_cycle(
    pool: &sqlx::PgPool,
    metrics: &crate::telemetry::AppMetrics,
    cycle_id: Uuid,
    reason: &'static str,
) -> Result<(), crate::error::AppError> {
    let updated = sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET state = 'frozen', last_error = COALESCE(last_error, $2) \
         WHERE cycle_id = $1 AND state NOT IN ('completed', 'failed', 'refunded')",
    )
    .bind(cycle_id)
    .bind(reason)
    .execute(pool)
    .await
    .map_err(|e| {
        error!("replenish freeze {}: {}", cycle_id, e);
        crate::error::AppError::InternalError("Database error".to_string())
    })?;
    if updated.rows_affected() == 1 {
        metrics.record_replenish_outcome("frozen");
        warn!("replenish cycle {} frozen: {}", cycle_id, reason);
    }
    Ok(())
}

// ── SQL ────────────────────────────────────────────────────────────────

/// Mint a cycle. The `uq_crr_inflight` partial unique index makes this the
/// claim: a second INSERT for a kind with a live cycle fails 23505 and the
/// caller aborts, so "one cycle in flight" is a constraint, not a scan.
pub(crate) const CYCLE_INSERT_SQL: &str = "INSERT INTO conversion_reserve_replenishment \
     (cycle_id, kind, state, cycle_ref, trigger_source, admin_account_id, need_minor, \
      spend_currency, spend_minor, recv_currency, quoted_recv_minor, quote_pricing, \
      provider, next_action_at) \
     VALUES ($1, $2, 'planned', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP)";

/// Cycles due for their next step. Ordered so the oldest moves first.
pub(crate) const DUE_CYCLES_SQL: &str = "SELECT cycle_id, kind, state, cycle_ref, \
        spend_currency, spend_minor, recv_currency, quoted_recv_minor, provider, \
        provider_ref, leg_order_id, send_address, send_memo, attempts \
     FROM conversion_reserve_replenishment \
     WHERE state NOT IN ('completed', 'failed', 'refunded', 'frozen', 'in_transit') \
       AND next_action_at <= CURRENT_TIMESTAMP \
     ORDER BY next_action_at LIMIT $1";

/// Guarded state transition. Every advance names the state it came from, so
/// two workers can never both move the same cycle.
pub(crate) const CYCLE_CAS_SQL: &str = "UPDATE conversion_reserve_replenishment \
     SET state = $2 WHERE cycle_id = $1 AND state = $3";

/// Unwind a cycle that provably moved nothing. Covers every state BEFORE a
/// send lands: 'planned' (aborted at creation), 'creating', and 'sending'
/// when the submit was definitively rejected. Never 'sent' or later — the
/// spend has genuinely left by then.
pub(crate) const ABORT_CYCLE_SQL: &str = "UPDATE conversion_reserve_replenishment \
     SET state = 'failed', last_error = $2 \
     WHERE cycle_id = $1 AND state IN ('planned', 'creating', 'sending')";

/// Crashed mid-submit: an intent exists, the outcome was never recorded, and
/// the signed transaction can no longer land.
pub(crate) const STALE_CYCLE_SQL: &str = "SELECT cycle_id FROM conversion_reserve_replenishment \
     WHERE state IN ('creating', 'sending') \
       AND updated_at < CURRENT_TIMESTAMP - make_interval(secs => $1) \
     LIMIT 10";

/// What a stale `sending` cycle armed, so the sweep can decide its fate by
/// hash instead of freezing blind (see `stale_verdict`).
pub(crate) const STALE_CYCLE_ROW_SQL: &str = "SELECT state, kind, send_tx_hash, send_address, \
        spend_currency, spend_minor \
     FROM conversion_reserve_replenishment WHERE cycle_id = $1";

/// Hash before submit, journal half: the cycle's attempt row carries the
/// signed envelope's hash BEFORE Horizon sees it. NULL-CAS: a row that
/// already carries a hash is never overwritten (that envelope may have been
/// submitted). `uq_conversion_reserve_entry_cycle_kind` guarantees at most
/// one such row, so "exactly one row affected" is the arm.
pub(crate) const CYCLE_ENTRY_HASH_SQL: &str = "UPDATE conversion_reserve_entry \
     SET stellar_tx_hash = $2 \
     WHERE cycle_id = $1 AND kind = $3 AND stellar_tx_hash IS NULL";

/// Hash before submit, cycle half: `send_tx_hash` is written while the cycle
/// is `sending` and hashless — the state 032 promised it would be captured
/// in. NULL-CAS for the same reason as the journal half; 037 part D's
/// `uq_crr_send_tx_hash` makes two cycles unable to share one hash.
pub(crate) const CYCLE_ROW_HASH_SQL: &str = "UPDATE conversion_reserve_replenishment \
     SET send_tx_hash = $2 \
     WHERE cycle_id = $1 AND state = 'sending' AND send_tx_hash IS NULL";

/// What `submit_spend` does with a classified outcome. Pure, so the branch
/// that decides whether a hold is released or frozen is testable without a
/// chain.
#[derive(Debug, PartialEq)]
pub(crate) enum SpendDisposition {
    /// The spend landed: record it and release the hold as spent.
    Sent,
    /// Provably nothing left the reserve: unwind the cycle (hold released).
    Abort(&'static str),
    /// The payment MAY land: freeze with the hold intact for a human.
    Freeze(&'static str),
}

/// Map a classified submit result onto a cycle disposition.
///
/// `prepared` is whether the envelope was signed; `hash_armed` is whether
/// its hash was persisted on the write-ahead rows. A rejection while
/// `prepared && !hash_armed` is the pre-submit "hash not recorded" refusal:
/// nothing was sent, so the cycle is ABORTED (hold released) under its own
/// reason — never re-queued, because `requeue_cycle`'s CAS only covers
/// `creating` and the cycle is already `sending`.
pub(crate) fn spend_disposition(
    outcome: &SubmitOutcome,
    prepared: bool,
    hash_armed: bool,
) -> SpendDisposition {
    match outcome {
        SubmitOutcome::Settled => SpendDisposition::Sent,
        SubmitOutcome::Rejected { .. } if prepared && !hash_armed => {
            SpendDisposition::Abort("hash_unrecorded")
        }
        SubmitOutcome::Rejected { .. } => SpendDisposition::Abort("send_rejected"),
        SubmitOutcome::Ambiguous => SpendDisposition::Freeze("send_unknown"),
    }
}

/// What the stale sweep may do with a cycle stuck past
/// `RESERVE_REPLENISH_STALE_SECS`.
#[derive(Debug, PartialEq)]
pub(crate) enum StaleVerdict {
    /// The armed hash settled on-chain: book the spend as sent.
    Settle,
    /// The armed hash provably did not and can no longer land: unwind.
    Abort(&'static str),
    /// Unknown, unreadable or never armed: freeze for a human, as before.
    Freeze(&'static str),
}

/// `chain` is the hash lookup's answer: `Some(Ok(true))` settled,
/// `Some(Ok(false))` proven absent/failed on a fresh Horizon, `Some(Err(()))`
/// inconclusive (lagging or unreachable), `None` not consulted. Only a
/// `sending` cycle that armed a hash is ever resolved; everything else
/// freezes exactly as before this hash existed — a hashless `sending` row
/// may have been armed by a pre-037 binary that submitted first.
pub(crate) fn stale_verdict(
    state: &str,
    armed_hash: bool,
    chain: Option<Result<bool, ()>>,
) -> StaleVerdict {
    if state != "sending" || !armed_hash {
        return StaleVerdict::Freeze("stale_state");
    }
    match chain {
        Some(Ok(true)) => StaleVerdict::Settle,
        Some(Ok(false)) => StaleVerdict::Abort("send_expired"),
        Some(Err(())) | None => StaleVerdict::Freeze("stale_state"),
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct DueCycleRow {
    pub cycle_id: Uuid,
    pub kind: String,
    pub state: String,
    pub cycle_ref: String,
    pub spend_currency: String,
    pub spend_minor: i64,
    /// Read by the arrival classifier via the cycle row, not by the driver.
    #[allow(dead_code)]
    pub recv_currency: String,
    #[allow(dead_code)]
    pub quoted_recv_minor: i64,
    /// Which provider this leg uses; the driver branches on `kind` instead.
    #[allow(dead_code)]
    pub provider: String,
    #[allow(dead_code)]
    pub provider_ref: Option<String>,
    #[allow(dead_code)]
    pub leg_order_id: Option<Uuid>,
    pub send_address: Option<String>,
    pub send_memo: Option<String>,
    /// Surfaced to admins; the driver freezes rather than counting retries,
    /// because an ambiguous send must never be resubmitted.
    #[allow(dead_code)]
    pub attempts: i32,
}

/// The cycle facts a spend outcome needs. A projection of `DueCycleRow`, so
/// the stale sweep can settle or unwind a cycle by hash without re-driving
/// it.
pub(crate) struct SpendCycle<'a> {
    pub cycle_id: Uuid,
    pub kind: &'a str,
    pub spend_currency: &'a str,
    pub spend_minor: i64,
}

impl DueCycleRow {
    fn spend(&self) -> SpendCycle<'_> {
        SpendCycle {
            cycle_id: self.cycle_id,
            kind: &self.kind,
            spend_currency: &self.spend_currency,
            spend_minor: self.spend_minor,
        }
    }
}

// ── Arrival matching ───────────────────────────────────────────────────

/// What an inflow carrying a cycle ref actually is.
///
/// Because the refund address handed to the provider is the reserve's own
/// with the SAME memo, an arrival wearing a cycle ref may be either the
/// bought asset or the spent asset coming back. Dispatch on the ASSET, never
/// the memo alone.
#[derive(Debug, PartialEq)]
pub(crate) enum CycleArrival {
    /// The asset we bought: credit the pool and settle the cycle.
    Credit { amount_minor: i64 },
    /// The provider returned what we sent: the cycle is refunded.
    Refund { amount_minor: i64 },
    /// Neither — fall through to the ordinary unmatched handling.
    Unmatched,
}

/// Pure arrival classification for a cycle-ref payment.
pub(crate) fn classify_cycle_arrival(
    payment_currency: Option<&str>,
    amount_minor: Option<i64>,
    spend_currency: &str,
    recv_currency: &str,
) -> CycleArrival {
    match (payment_currency, amount_minor) {
        (Some(c), Some(a)) if a > 0 && c == recv_currency => {
            CycleArrival::Credit { amount_minor: a }
        }
        (Some(c), Some(a)) if a > 0 && c == spend_currency => {
            CycleArrival::Refund { amount_minor: a }
        }
        _ => CycleArrival::Unmatched,
    }
}

// ── The driver ─────────────────────────────────────────────────────────

use crate::error::AppError;
use crate::exchange::reserve::{
    journal_insert, minor_to_decimal_string, parse_decimal_to_minor, JournalEntry,
    RESERVE_BUCKET_APPLY_SQL, RESERVE_TREASURY_HOLD_SQL,
};
use crate::exchange::reserve_watch::{
    classify_submit, record_intent_hash, IntentKey, ReserveWatchDeps, SubmitOutcome,
};
use crate::stellar::{Asset, PaymentParams};

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("replenish: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// One replenishment pass: advance anything in flight, then consider
/// starting a new cycle per kind.
pub(crate) async fn drive_replenishment(deps: &ReserveWatchDeps) {
    let due: Vec<DueCycleRow> = match sqlx::query_as(DUE_CYCLES_SQL)
        .bind(crate::constants::RESERVE_REPLENISH_MAX_PER_TICK)
        .fetch_all(&deps.pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("replenish: due scan failed: {}", e);
            return;
        }
    };
    for cycle in due {
        if let Err(e) = advance_cycle(deps, &cycle).await {
            error!("replenish cycle {}: {:?}", cycle.cycle_id, e);
        }
    }

    // Only consider starting new work once nothing is mid-flight.
    for kind in crate::constants::VALID_REPLENISH_KINDS {
        if let Err(e) = maybe_start_cycle(deps, kind, "auto", None).await {
            error!("replenish {}: plan failed: {:?}", kind, e);
        }
    }
}

/// Freeze cycles whose provider call or on-chain submit never recorded an
/// outcome. Deliberately never resubmits: the funds may already be gone.
///
/// A `sending` cycle that armed its hash before the submit (037) is first
/// resolved BY that hash — settled on-chain books the spend, proven absent
/// on a fresh Horizon (the row is older than the envelope's validity window,
/// `RESERVE_REPLENISH_STALE_SECS >= 2 * TX_TIMEOUT_SECS`) unwinds it, and
/// anything inconclusive freezes exactly as before.
pub(crate) async fn freeze_stale_cycles(deps: &ReserveWatchDeps) {
    let stale: Vec<(Uuid,)> = match sqlx::query_as(STALE_CYCLE_SQL)
        .bind(crate::constants::RESERVE_REPLENISH_STALE_SECS as f64)
        .fetch_all(&deps.pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("replenish stale sweep failed: {}", e);
            return;
        }
    };
    for (cycle_id,) in stale {
        let reason = match resolve_stale_cycle(deps, cycle_id).await {
            Ok(None) => continue,
            Ok(Some(reason)) => reason,
            Err(e) => {
                error!("replenish stale resolve {}: {:?}", cycle_id, e);
                "stale_state"
            }
        };
        if let Err(e) = freeze_cycle(&deps.pool, &deps.metrics, cycle_id, reason).await {
            error!("replenish stale freeze {}: {:?}", cycle_id, e);
        }
    }
}

/// Decide one stale cycle. `Ok(None)` means it was settled or unwound here;
/// `Ok(Some(reason))` means the caller must freeze it under `reason`.
async fn resolve_stale_cycle(
    deps: &ReserveWatchDeps,
    cycle_id: Uuid,
) -> Result<Option<&'static str>, AppError> {
    type StaleRow = (String, String, Option<String>, Option<String>, String, i64);
    let row: Option<StaleRow> = sqlx::query_as(STALE_CYCLE_ROW_SQL)
        .bind(cycle_id)
        .fetch_optional(&deps.pool)
        .await
        .map_err(db_err("stale row"))?;
    let Some((state, kind, send_tx_hash, send_address, spend_currency, spend_minor)) = row else {
        return Ok(None);
    };
    let cycle = SpendCycle {
        cycle_id,
        kind: &kind,
        spend_currency: &spend_currency,
        spend_minor,
    };
    let armed = match (&send_tx_hash, &send_address, state.as_str()) {
        (Some(hash), Some(to), "sending") => Some((hash, to)),
        _ => None,
    };
    let chain = match armed {
        Some((hash, to)) => {
            let asset = deps.reserve.asset_for_bucket(&spend_currency);
            match crate::handlers::admin_reserve::resolve_intent_by_hash(
                &deps.http,
                &deps.horizon_url,
                hash,
                &deps.reserve.stellar_address,
                to,
                spend_minor,
                asset.as_ref(),
            )
            .await
            {
                Ok(Some(_)) => Some(Ok(true)),
                Ok(None) => Some(Ok(false)),
                Err(e) => {
                    warn!(
                        "replenish cycle {}: stale hash {} inconclusive: {:?}",
                        cycle_id, hash, e
                    );
                    Some(Err(()))
                }
            }
        }
        None => None,
    };
    match stale_verdict(&state, armed.is_some(), chain) {
        StaleVerdict::Settle => {
            let hash = send_tx_hash
                .as_deref()
                .expect("Settle implies an armed hash");
            info!(
                "replenish cycle {}: stale send {} settled on-chain; recording",
                cycle_id, hash
            );
            record_spend_sent(deps, &cycle, hash).await?;
            Ok(None)
        }
        StaleVerdict::Abort(reason) => {
            warn!(
                "replenish cycle {}: stale send {:?} provably did not land; unwinding ({})",
                cycle_id, send_tx_hash, reason
            );
            abort_cycle(deps, &cycle, reason).await?;
            Ok(None)
        }
        StaleVerdict::Freeze(reason) => Ok(Some(reason)),
    }
}

/// Whether this deployment can build a provider leg for `kind`.
///
/// `usdc_to_usd` needs the bridge's own OwlPay treasury beneficiary, and no
/// such configuration exists yet, so `create_provider_leg` aborts every
/// cycle of that kind at creation. This is THE predicate for that: the
/// watcher consults it before planning, and the admin policy/run endpoints
/// refuse to enable or run a kind it rejects — an enabled policy would
/// otherwise churn a `replenish_hold`/`replenish_release` journal pair every
/// cooldown for nothing.
pub(crate) fn kind_has_provider_leg(kind: &str) -> bool {
    kind == crate::constants::REPLENISH_KIND_XLM_TO_USDC
}

/// Evaluate the guards and, if they all pass, plan and claim a cycle.
///
/// Returns the new cycle id, or `None` with the skip already recorded.
pub(crate) async fn maybe_start_cycle(
    deps: &ReserveWatchDeps,
    kind: &str,
    trigger: &str,
    admin_account_id: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    let policy: Option<ReplenishPolicy> = sqlx::query_as(
        "SELECT kind, enabled, target_days, window_days, min_need_minor, max_spend_minor, \
                daily_spend_cap_minor, cooldown_secs, min_float_minor, min_price_minor, \
                max_slippage_bps \
         FROM conversion_reserve_replenish_policy WHERE kind = $1",
    )
    .bind(kind)
    .fetch_optional(&deps.pool)
    .await
    .map_err(db_err("policy"))?;
    let policy = match policy {
        Some(p) => p,
        None => return Ok(None),
    };

    // A kind this deployment cannot build a leg for plans nothing: its hold
    // would only be released again at creation, a journal pair per cooldown
    // for no cycle. The admin endpoints refuse to enable such a kind; this
    // covers a policy row that was enabled before they did.
    if !kind_has_provider_leg(kind) {
        record_skip(&deps.metrics, kind, &SkipReason::NoProviderLeg);
        return Ok(None);
    }

    let (spend_currency, recv_currency, provider) = match kind {
        "xlm_to_usdc" => (
            crate::constants::RESERVE_CURRENCY_XLM,
            crate::constants::RESERVE_CURRENCY_USDC,
            crate::constants::EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
        ),
        _ => (
            crate::constants::RESERVE_CURRENCY_USDC,
            crate::constants::RESERVE_CURRENCY_USD,
            crate::constants::EXCHANGE_PROVIDER_OWLPAY,
        ),
    };

    let snap = gather_snapshot(deps, &policy, spend_currency, recv_currency).await?;
    if let Err(why) = guards_allow_cycle(&policy, &snap) {
        record_skip(&deps.metrics, kind, &why);
        return Ok(None);
    }

    let ceiling = spend_ceiling(&policy, &snap);
    let (spend_minor, quoted_recv_minor, pricing) =
        match price_cycle(deps, &policy, kind, snap.need_minor, ceiling).await {
            Ok(v) => v,
            Err(why) => {
                record_skip(&deps.metrics, kind, &why);
                return Ok(None);
            }
        };

    // Plan + claim in one transaction: the treasury hold and the cycle row
    // commit together, so a cycle can never exist without its funds
    // committed, nor funds be committed without a cycle to account for them.
    let cycle_id = Uuid::new_v4();
    let cycle_ref = crate::exchange::reserve::base32_order_ref(&cycle_id);
    let mut tx = deps.pool.begin().await.map_err(db_err("plan begin"))?;

    let inserted = sqlx::query(CYCLE_INSERT_SQL)
        .bind(cycle_id)
        .bind(kind)
        .bind(&cycle_ref)
        .bind(trigger)
        .bind(admin_account_id)
        .bind(snap.need_minor)
        .bind(spend_currency)
        .bind(spend_minor)
        .bind(recv_currency)
        .bind(quoted_recv_minor)
        .bind(pricing)
        .bind(provider)
        .execute(&mut *tx)
        .await;
    match inserted {
        Ok(_) => {}
        // The in-flight unique index rejected it: another worker won.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            record_skip(&deps.metrics, kind, &SkipReason::InFlight);
            return Ok(None);
        }
        Err(e) => return Err(db_err("cycle insert")(e)),
    }

    // Treasury hold — NOT the customer hold: the half-the-pool fraction
    // guard exists to stop one customer locking the reserve, and applied
    // here it would cap the treasury's own sell.
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_TREASURY_HOLD_SQL)
        .bind(spend_currency)
        .bind(spend_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("treasury hold"))?;
    let (bal_after, held_after, _) = match bucket {
        Some(b) => b,
        None => {
            // The float moved under us between snapshot and hold. Returning
            // here DROPS `tx`, which rolls back — including the cycle INSERT
            // above. That rollback is load-bearing: a committed cycle row
            // with no hold behind it would occupy this kind's single
            // in-flight slot forever, silently stopping all replenishment.
            record_skip(&deps.metrics, kind, &SkipReason::FloatGuard);
            return Ok(None);
        }
    };

    let hold_kind = if kind == "xlm_to_usdc" {
        "replenish_hold"
    } else {
        "offramp_hold"
    };
    journal_insert(JournalEntry {
        currency: spend_currency.to_string(),
        kind: hold_kind.to_string(),
        delta: -spend_minor,
        held_delta: spend_minor,
        balance_after: bal_after,
        held_after,
        cycle_id: Some(cycle_id),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("hold entry"))?;
    tx.commit().await.map_err(db_err("plan commit"))?;

    deps.metrics.record_replenish_outcome("started");
    info!(
        "replenish {}: cycle {} planned — spend {} {} for ~{} {} ({})",
        kind,
        cycle_id,
        minor_to_decimal_string(spend_minor, scale_for(spend_currency)),
        spend_currency,
        minor_to_decimal_string(quoted_recv_minor, scale_for(recv_currency)),
        recv_currency,
        pricing
    );
    Ok(Some(cycle_id))
}

/// Read everything the guards need.
async fn gather_snapshot(
    deps: &ReserveWatchDeps,
    policy: &ReplenishPolicy,
    spend_currency: &str,
    recv_currency: &str,
) -> Result<CycleSnapshot, AppError> {
    let in_flight: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversion_reserve_replenishment \
             WHERE kind = $1 AND state NOT IN ('completed', 'failed', 'refunded'))",
    )
    .bind(&policy.kind)
    .fetch_one(&deps.pool)
    .await
    .map_err(db_err("in flight"))?;

    let since_last_cycle_secs: Option<i64> = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MAX(created_at)))::bigint \
         FROM conversion_reserve_replenishment WHERE kind = $1",
    )
    .bind(&policy.kind)
    .fetch_one(&deps.pool)
    .await
    .map_err(db_err("cooldown"))?;

    let spent_24h_minor: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(spend_minor), 0)::bigint \
         FROM conversion_reserve_replenishment \
         WHERE kind = $1 AND state <> 'failed' \
           AND created_at >= CURRENT_TIMESTAMP - interval '24 hours'",
    )
    .bind(&policy.kind)
    .fetch_one(&deps.pool)
    .await
    .map_err(db_err("daily spend"))?;

    // What the forecast says the receiving bucket is short, over the policy's
    // own window — using the SAME math the admin forecast shows, minus the
    // treasury kinds (see RESERVE_INTERNAL_ENTRY_KINDS).
    let need_minor =
        crate::handlers::admin_reserve::customer_shortfall(&deps.pool, recv_currency, policy)
            .await?;

    let spend_available_minor: i64 =
        sqlx::query_scalar("SELECT available FROM conversion_reserve WHERE currency = $1")
            .bind(spend_currency)
            .fetch_one(&deps.pool)
            .await
            .map_err(db_err("spend bucket"))?;

    // Spendability must be proven on-chain, not just in the ledger.
    let onchain_spend_minor = match crate::stellar::fetch_account_details(
        &deps.http,
        &deps.horizon_url,
        &deps.reserve.stellar_address,
    )
    .await
    {
        Ok(acct) if acct.exists => {
            let raw = if spend_currency == crate::constants::RESERVE_CURRENCY_XLM {
                acct.native_balance.clone()
            } else {
                acct.balances
                    .iter()
                    .find(|b| {
                        b.asset_code.as_deref() == Some(deps.reserve.usdc_code.as_str())
                            && b.asset_issuer.as_deref() == Some(deps.reserve.usdc_issuer.as_str())
                    })
                    .map(|b| b.balance.clone())
            };
            raw.and_then(|v| parse_decimal_to_minor(&v, RESERVE_SCALE_STELLAR))
        }
        _ => None,
    };

    // A payout that may still land shares this account's sequence number.
    let payout_in_flight: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM exchange_order \
             WHERE provider = 'reserve' AND provider_status = 'payout_inflight') \
             OR EXISTS(SELECT 1 FROM conversion_reserve_entry \
             WHERE kind = 'payout_attempt' \
               AND created_at > CURRENT_TIMESTAMP - interval '300 seconds')",
    )
    .fetch_one(&deps.pool)
    .await
    .map_err(db_err("payout in flight"))?;

    Ok(CycleSnapshot {
        in_flight,
        since_last_cycle_secs,
        spent_24h_minor,
        need_minor,
        spend_available_minor,
        onchain_spend_minor,
        payout_in_flight,
    })
}

/// Size and price a cycle, applying both price guards.
async fn price_cycle(
    deps: &ReserveWatchDeps,
    policy: &ReplenishPolicy,
    kind: &str,
    need_minor: i64,
    ceiling: i64,
) -> Result<(i64, i64, &'static str), SkipReason> {
    if ceiling <= 0 {
        return Err(SkipReason::FloatGuard);
    }
    if kind != "xlm_to_usdc" {
        // The fiat leg is par: the provider's fee shows up in the quote at
        // transfer time, and the price floor is applied there.
        let spend_minor = usd_cents_to_stellar_minor(need_minor)
            .map(|m| m.min(ceiling))
            .ok_or(SkipReason::NoQuote)?;
        if spend_minor <= 0 {
            return Err(SkipReason::BelowMinimum);
        }
        let recv_cents = crate::exchange::reserve::stellar_minor_to_usd_cents_ceil(spend_minor);
        return Ok((spend_minor, recv_cents, "usd_par"));
    }

    let changelly = deps.changelly_crypto.as_ref().ok_or(SkipReason::Disabled)?;

    // Reference quote first: it both sizes the sell and anchors the
    // slippage check.
    let ref_spend = reference_spend_minor(kind).ok_or(SkipReason::NoQuote)?;
    let ref_json = changelly
        .get_exchange_amount("xlm", "usdcxlm", RESERVE_REPLENISH_REFERENCE_XLM)
        .await
        .map_err(|_| SkipReason::NoQuote)?;
    let ref_recv = crate::exchange::reserve::extract_estimate_amount_to(&ref_json)
        .and_then(|s| parse_decimal_to_minor(&s, RESERVE_SCALE_STELLAR))
        .filter(|v| *v > 0)
        .ok_or(SkipReason::NoQuote)?;
    let ref_price = implied_price_minor(ref_spend, ref_recv, RESERVE_SCALE_STELLAR)
        .ok_or(SkipReason::NoQuote)?;

    let spend_minor = size_spend_from_need(need_minor, ref_spend, ref_recv, ceiling)
        .ok_or(SkipReason::BelowMinimum)?;

    // Re-quote at the REAL size: provider rates are size-dependent, and the
    // reference is only a sizing aid.
    let sized_json = changelly
        .get_exchange_amount(
            "xlm",
            "usdcxlm",
            &minor_to_decimal_string(spend_minor, RESERVE_SCALE_STELLAR),
        )
        .await
        .map_err(|_| SkipReason::NoQuote)?;
    let recv_minor = crate::exchange::reserve::extract_estimate_amount_to(&sized_json)
        .and_then(|s| parse_decimal_to_minor(&s, RESERVE_SCALE_STELLAR))
        .filter(|v| *v > 0)
        .ok_or(SkipReason::NoQuote)?;
    let price = implied_price_minor(spend_minor, recv_minor, RESERVE_SCALE_STELLAR)
        .ok_or(SkipReason::NoQuote)?;

    price_guards_allow(policy, price, ref_price)?;
    Ok((spend_minor, recv_minor, "provider_estimate"))
}

/// Move one cycle to its next state.
async fn advance_cycle(deps: &ReserveWatchDeps, c: &DueCycleRow) -> Result<(), AppError> {
    match c.state.as_str() {
        "planned" => create_provider_leg(deps, c).await,
        "created" => submit_spend(deps, c).await,
        // `sent` waits for the arrival, which the deposit watcher credits;
        // `settled` is closed there too. Nothing to push here.
        _ => Ok(()),
    }
}

/// Create the provider-side order, then record it.
async fn create_provider_leg(deps: &ReserveWatchDeps, c: &DueCycleRow) -> Result<(), AppError> {
    // Arm first, so a crash during the provider call is visible as
    // `creating` rather than looking like it never started.
    let armed = sqlx::query(CYCLE_CAS_SQL)
        .bind(c.cycle_id)
        .bind("creating")
        .bind("planned")
        .execute(&deps.pool)
        .await
        .map_err(db_err("arm"))?;
    if armed.rows_affected() == 0 {
        return Ok(());
    }

    if !kind_has_provider_leg(&c.kind) {
        // The fiat leg needs the bridge's own OwlPay beneficiary, which is
        // deployment configuration rather than per-cycle data. ABORT rather
        // than freeze: nothing has been sent, so the funds provably never
        // moved and the hold must go back. Freezing would strand real USDC
        // in `held` with no path that can ever release it.
        warn!(
            "replenish {}: fiat off-ramp has no treasury beneficiary configured; \
             aborting cycle {} and releasing its hold (see the runbook)",
            c.kind, c.cycle_id
        );
        return abort_cycle(deps, &c.spend(), "no_treasury_config").await;
    }

    let changelly = match deps.changelly_crypto.as_ref() {
        Some(p) => p,
        None => {
            return freeze_cycle(&deps.pool, &deps.metrics, c.cycle_id, "provider_missing").await
        }
    };

    // The reserve is BOTH the payout and refund destination, and both carry
    // the cycle ref: one memo, two directions, disambiguated by asset.
    let create_tx = crate::exchange::changelly::ChangellyCreateTx {
        from: "xlm".to_string(),
        to: "usdcxlm".to_string(),
        amount_from: minor_to_decimal_string(c.spend_minor, RESERVE_SCALE_STELLAR),
        address: deps.reserve.stellar_address.clone(),
        extra_id: Some(c.cycle_ref.clone()),
        refund_address: Some(deps.reserve.stellar_address.clone()),
        refund_extra_id: Some(c.cycle_ref.clone()),
        rate_id: None,
    };
    let created = changelly.create_transaction(&create_tx).await;
    let tx = match created {
        Ok(t) => t,
        Err(e) => {
            warn!("replenish cycle {}: create failed: {:?}", c.cycle_id, e);
            return if ambiguous_create_is_retryable(&c.provider) {
                // The provider honors an idempotency key, so re-POSTing
                // returns the same order rather than creating a second one.
                requeue_cycle(deps, c, "create_retry").await
            } else {
                // No client idempotency key, so a retry could create a
                // SECOND order. Abandoning is free instead: without our
                // pay-in the swap simply expires unfunded.
                abort_cycle(deps, &c.spend(), "create_failed").await
            };
        }
    };

    // The pay-in memo is mandatory when present — sending without it to a
    // shared pay-in address loses the funds outright.
    if tx.payin_extra_id.as_deref().is_some_and(|m| m.len() > 28) {
        return freeze_cycle(&deps.pool, &deps.metrics, c.cycle_id, "payin_memo_invalid").await;
    }

    sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET provider_ref = $2, send_address = $3, send_memo = $4, state = 'created', \
             provider_status = $5 \
         WHERE cycle_id = $1 AND state = 'creating'",
    )
    .bind(c.cycle_id)
    .bind(&tx.id)
    .bind(&tx.payin_address)
    .bind(&tx.payin_extra_id)
    .bind(&tx.status)
    .execute(&deps.pool)
    .await
    .map_err(db_err("record create"))?;

    info!(
        "replenish cycle {}: swap {} created, pay-in {} memo {:?}",
        c.cycle_id, tx.id, tx.payin_address, tx.payin_extra_id
    );
    Ok(())
}

/// Send the spend asset to the provider's pay-in address.
async fn submit_spend(deps: &ReserveWatchDeps, c: &DueCycleRow) -> Result<(), AppError> {
    let (send_address, send_memo) = match (&c.send_address, &c.send_memo) {
        (Some(a), m) => (a.clone(), m.clone()),
        _ => return freeze_cycle(&deps.pool, &deps.metrics, c.cycle_id, "no_payin").await,
    };

    // Write-ahead intent, then arm: after this a submission may exist, so no
    // path may retry without a human.
    let mut tx = deps.pool.begin().await.map_err(db_err("intent begin"))?;
    let (bal, held): (i64, i64) = sqlx::query_as(
        "SELECT available, held FROM conversion_reserve WHERE currency = $1 FOR UPDATE",
    )
    .bind(&c.spend_currency)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("intent bucket"))?;
    let attempt_kind = if c.kind == "xlm_to_usdc" {
        "replenish_attempt"
    } else {
        "offramp_attempt"
    };
    let intent = journal_insert(JournalEntry {
        currency: c.spend_currency.clone(),
        kind: attempt_kind.to_string(),
        balance_after: bal,
        held_after: held,
        cycle_id: Some(c.cycle_id),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await;
    match intent {
        Ok(_) => {}
        // Another worker owns this submission.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => return Ok(()),
        Err(e) => return Err(db_err("intent")(e)),
    }
    let armed = sqlx::query(CYCLE_CAS_SQL)
        .bind(c.cycle_id)
        .bind("sending")
        .bind("created")
        .execute(&mut *tx)
        .await
        .map_err(db_err("arm send"))?;
    if armed.rows_affected() == 0 {
        return Ok(());
    }
    tx.commit().await.map_err(db_err("intent commit"))?;

    let seed = crate::handlers::managed_seed::load_protected_seed(
        &deps.pool,
        &deps.protector,
        &deps.signer,
        &deps.reserve.reserve_account_id,
    )
    .await?;
    let params = PaymentParams {
        destination: send_address,
        amount: minor_to_decimal_string(c.spend_minor, scale_for(&c.spend_currency)),
        asset: if c.spend_currency == crate::constants::RESERVE_CURRENCY_XLM {
            Asset::Native
        } else {
            Asset::Credit {
                code: deps.reserve.usdc_code.clone(),
                issuer: deps.reserve.usdc_issuer.clone(),
            }
        },
        memo: send_memo,
        fee: None,
    };
    // Prepare, persist the hash on BOTH write-ahead rows (journal attempt +
    // cycle `send_tx_hash`, NULL-CAS each), THEN submit — no hash, no submit
    // (see reserve_watch::record_intent_hash).
    let mut prepared_ok = false;
    let mut hash_armed = false;
    let submitted = match deps.signer.prepare_payment(seed.as_slice(), &params).await {
        Ok(prepared) => {
            prepared_ok = true;
            match record_intent_hash(
                &deps.pool,
                IntentKey::Cycle {
                    cycle_id: c.cycle_id,
                    attempt_kind,
                },
                &prepared.stellar_hash,
            )
            .await
            {
                Ok(()) => {
                    hash_armed = true;
                    deps.signer.submit_prepared(&prepared).await
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };
    // `seed` zeroizes on drop.

    match spend_disposition(&classify_submit(&submitted), prepared_ok, hash_armed) {
        SpendDisposition::Sent => {
            let result = submitted.expect("Sent implies Ok");
            record_spend_sent(deps, &c.spend(), &result.stellar_hash).await
        }
        // Definitive: the transaction provably did not land (or was never
        // submitted because its hash could not be recorded), so the funds
        // are still ours and the cycle can be unwound cleanly.
        SpendDisposition::Abort(reason) => {
            match &submitted {
                Err(e) => warn!(
                    "replenish cycle {}: send aborted ({}): {:?}",
                    c.cycle_id, reason, e
                ),
                Ok(_) => warn!("replenish cycle {}: send aborted ({})", c.cycle_id, reason),
            }
            abort_cycle(deps, &c.spend(), reason).await
        }
        // Ambiguous: the payment MAY land. Freeze with the hold intact.
        SpendDisposition::Freeze(reason) => {
            freeze_cycle(&deps.pool, &deps.metrics, c.cycle_id, reason).await
        }
    }
}

/// The spend left the chain: the held amount is now genuinely gone.
///
/// `send_tx_hash` was armed before the submit (same value, idempotent); the
/// guard refuses to overwrite a DIFFERENT armed hash, because that would
/// mean the settled envelope is not the one this cycle recorded.
async fn record_spend_sent(
    deps: &ReserveWatchDeps,
    c: &SpendCycle<'_>,
    stellar_hash: &str,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("sent begin"))?;
    let updated = sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET state = 'sent', send_tx_hash = $2 \
         WHERE cycle_id = $1 AND state = 'sending' \
           AND (send_tx_hash IS NULL OR send_tx_hash = $2)",
    )
    .bind(c.cycle_id)
    .bind(stellar_hash)
    .execute(&mut *tx)
    .await
    .map_err(db_err("sent update"))?;
    if updated.rows_affected() == 0 {
        error!(
            "REPLENISH SPEND SETTLED BUT CYCLE NOT RECORDABLE — cycle={} hash={}: \
             reconcile the ledger against the chain",
            c.cycle_id, stellar_hash
        );
        return Ok(());
    }

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(c.spend_currency)
        .bind(0i64)
        .bind(-c.spend_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("sent release"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!("replenish cycle {}: held underflow (drift)", c.cycle_id);
        AppError::InternalError("Database error".to_string())
    })?;

    let sent_kind = if c.kind == "xlm_to_usdc" {
        "replenish_sent"
    } else {
        "offramp_sent"
    };
    journal_insert(JournalEntry {
        currency: c.spend_currency.to_string(),
        kind: sent_kind.to_string(),
        held_delta: -c.spend_minor,
        balance_after: bal_after,
        held_after,
        cycle_id: Some(c.cycle_id),
        stellar_tx_hash: Some(stellar_hash.to_string()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("sent entry"))?;
    tx.commit().await.map_err(db_err("sent commit"))?;

    info!(
        "replenish cycle {}: sent {} {} hash={}",
        c.cycle_id,
        minor_to_decimal_string(c.spend_minor, scale_for(c.spend_currency)),
        c.spend_currency,
        stellar_hash
    );
    Ok(())
}

/// Send a cycle back for another attempt, keeping its hold. Only safe when
/// the provider create is idempotent.
async fn requeue_cycle(
    deps: &ReserveWatchDeps,
    c: &DueCycleRow,
    reason: &'static str,
) -> Result<(), AppError> {
    let backoff =
        crate::exchange::reconcile::poll_backoff_secs(deps.reserve.watch_secs, c.attempts) as f64;
    sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET state = 'planned', attempts = attempts + 1, last_error = $2, \
             next_action_at = CURRENT_TIMESTAMP + make_interval(secs => $3) \
         WHERE cycle_id = $1 AND state = 'creating'",
    )
    .bind(c.cycle_id)
    .bind(reason)
    .bind(backoff)
    .execute(&deps.pool)
    .await
    .map_err(db_err("requeue"))?;
    Ok(())
}

/// Unwind a cycle that provably moved nothing: release the hold and close it.
async fn abort_cycle(
    deps: &ReserveWatchDeps,
    c: &SpendCycle<'_>,
    reason: &'static str,
) -> Result<(), AppError> {
    let mut tx = deps.pool.begin().await.map_err(db_err("abort begin"))?;
    let updated = sqlx::query(ABORT_CYCLE_SQL)
        .bind(c.cycle_id)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(db_err("abort update"))?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(c.spend_currency)
        .bind(c.spend_minor)
        .bind(-c.spend_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("abort release"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!("replenish abort {}: held underflow (drift)", c.cycle_id);
        AppError::InternalError("Database error".to_string())
    })?;
    journal_insert(JournalEntry {
        currency: c.spend_currency.to_string(),
        kind: "replenish_release".to_string(),
        delta: c.spend_minor,
        held_delta: -c.spend_minor,
        balance_after: bal_after,
        held_after,
        cycle_id: Some(c.cycle_id),
        note: Some(reason.to_string()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("abort entry"))?;
    tx.commit().await.map_err(db_err("abort commit"))?;

    deps.metrics.record_replenish_outcome("failed");
    info!(
        "replenish cycle {} aborted ({}); hold released",
        c.cycle_id, reason
    );
    Ok(())
}

/// Credit an arrival against its cycle. Called by the deposit watcher.
/// Returns `false` when the arrival was NOT booked here, so the caller must
/// fall through to the ordinary unmatched handling. Returning `Ok(())` for
/// both outcomes previously meant a payment against an already-closed cycle
/// was silently dropped: credited to no bucket, recorded in no queue, and
/// stepped over by the Horizon cursor.
pub(crate) async fn credit_cycle_arrival(
    deps: &ReserveWatchDeps,
    cycle_id: Uuid,
    kind: &str,
    arrival: &CycleArrival,
    currency: &str,
    paging_token: &str,
    tx_hash: &str,
) -> Result<bool, AppError> {
    let (entry_kind, next_state, amount) = match arrival {
        CycleArrival::Credit { amount_minor } => (
            if kind == "xlm_to_usdc" {
                "replenish_credit"
            } else {
                "fiat_in_transit"
            },
            "completed",
            *amount_minor,
        ),
        CycleArrival::Refund { amount_minor } => ("replenish_refund", "refunded", *amount_minor),
        CycleArrival::Unmatched => return Ok(false),
    };

    let mut tx = deps.pool.begin().await.map_err(db_err("arrival begin"))?;
    // Read the spend state under the row lock: a cycle frozen after an
    // ambiguous send still HOLDS its spend, because `replenish_sent` is only
    // written on a known-good submit. Closing it here without releasing that
    // hold would strand the amount in `held` forever — neither abort_cycle
    // (creating/sending only) nor freeze_cycle can touch a terminal cycle.
    let prior: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT state, spend_currency, spend_minor \
         FROM conversion_reserve_replenishment WHERE cycle_id = $1 FOR UPDATE",
    )
    .bind(cycle_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err("arrival prior"))?;
    let (prior_state, spend_currency, spend_minor) = match prior {
        Some(v) => v,
        None => return Ok(false),
    };

    let updated = sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET state = $2, actual_recv_minor = COALESCE(actual_recv_minor, $3) \
         WHERE cycle_id = $1 AND state NOT IN ('completed', 'failed', 'refunded')",
    )
    .bind(cycle_id)
    .bind(next_state)
    .bind(amount)
    .execute(&mut *tx)
    .await
    .map_err(db_err("arrival state"))?;
    if updated.rows_affected() == 0 {
        // Already closed. Report it so the caller books the money through the
        // ordinary unmatched path instead of dropping it on the floor.
        return Ok(false);
    }

    // Release a spend hold whose outcome was never recorded. `sent` and later
    // states already wrote their release; anything earlier did not.
    if matches!(prior_state.as_str(), "sending" | "frozen") {
        let released: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
            .bind(&spend_currency)
            .bind(0i64)
            .bind(-spend_minor)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err("arrival hold release"))?;
        match released {
            Some((sbal, sheld, _)) => {
                let sent_kind = if kind == "xlm_to_usdc" {
                    "replenish_sent"
                } else {
                    "offramp_sent"
                };
                // The arrival proves the spend did leave the chain after all.
                journal_insert(JournalEntry {
                    currency: spend_currency.clone(),
                    kind: sent_kind.to_string(),
                    held_delta: -spend_minor,
                    balance_after: sbal,
                    held_after: sheld,
                    cycle_id: Some(cycle_id),
                    note: Some("settled by arrival after an unrecorded send".to_string()),
                    ..Default::default()
                })
                .execute(&mut *tx)
                .await
                .map_err(db_err("arrival late sent"))?;
            }
            None => error!(
                "replenish arrival {}: held underflow releasing {} {} (drift)",
                cycle_id, spend_minor, spend_currency
            ),
        }
    }

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(currency)
        .bind(amount)
        .bind(0i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("arrival credit"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!(
            "replenish arrival {}: bucket {} missing",
            cycle_id, currency
        );
        AppError::InternalError("Database error".to_string())
    })?;

    journal_insert(JournalEntry {
        currency: currency.to_string(),
        kind: entry_kind.to_string(),
        delta: amount,
        balance_after: bal_after,
        held_after,
        cycle_id: Some(cycle_id),
        paging_token: Some(paging_token.to_string()),
        stellar_tx_hash: Some(tx_hash.to_string()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("arrival entry"))?;
    tx.commit().await.map_err(db_err("arrival commit"))?;

    deps.metrics.record_replenish_outcome(match arrival {
        CycleArrival::Refund { .. } => "refunded",
        _ => "settled",
    });
    info!(
        "replenish cycle {}: {} {} {} credited (tx {})",
        cycle_id,
        entry_kind,
        minor_to_decimal_string(amount, scale_for(currency)),
        currency,
        tx_hash
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ReplenishPolicy {
        ReplenishPolicy {
            kind: "xlm_to_usdc".to_string(),
            enabled: true,
            target_days: 30,
            window_days: 30,
            min_need_minor: 0,
            max_spend_minor: 1_000_000_000, // 100 XLM
            daily_spend_cap_minor: 5_000_000_000,
            cooldown_secs: 3600,
            min_float_minor: 100_000_000, // 10 XLM kept for fees
            min_price_minor: 0,
            max_slippage_bps: 300,
        }
    }

    fn snapshot() -> CycleSnapshot {
        CycleSnapshot {
            in_flight: false,
            since_last_cycle_secs: Some(7200),
            spent_24h_minor: 0,
            need_minor: 100_000_000,
            spend_available_minor: 10_000_000_000,
            onchain_spend_minor: Some(10_000_000_000),
            payout_in_flight: false,
        }
    }

    #[test]
    fn all_clear_allows_a_cycle() {
        assert_eq!(guards_allow_cycle(&policy(), &snapshot()), Ok(()));
    }

    #[test]
    fn unconfigured_caps_refuse_rather_than_meaning_unlimited() {
        // This is the difference between "no limit set" and "no limit".
        let mut p = policy();
        p.max_spend_minor = 0;
        assert_eq!(
            guards_allow_cycle(&p, &snapshot()),
            Err(SkipReason::Unconfigured)
        );
        let mut p = policy();
        p.daily_spend_cap_minor = 0;
        assert_eq!(
            guards_allow_cycle(&p, &snapshot()),
            Err(SkipReason::Unconfigured)
        );
    }

    #[test]
    fn each_guard_fires_on_its_own() {
        let mut p = policy();
        p.enabled = false;
        assert_eq!(
            guards_allow_cycle(&p, &snapshot()),
            Err(SkipReason::Disabled)
        );

        let mut s = snapshot();
        s.in_flight = true;
        assert_eq!(guards_allow_cycle(&policy(), &s), Err(SkipReason::InFlight));

        let mut s = snapshot();
        s.since_last_cycle_secs = Some(60);
        assert_eq!(guards_allow_cycle(&policy(), &s), Err(SkipReason::Cooldown));

        let mut s = snapshot();
        s.spent_24h_minor = 5_000_000_000;
        assert_eq!(guards_allow_cycle(&policy(), &s), Err(SkipReason::DailyCap));

        let mut s = snapshot();
        s.need_minor = 0;
        assert_eq!(guards_allow_cycle(&policy(), &s), Err(SkipReason::NoNeed));

        let mut p = policy();
        p.min_need_minor = 500_000_000;
        assert_eq!(
            guards_allow_cycle(&p, &snapshot()),
            Err(SkipReason::BelowMinimum)
        );

        let mut s = snapshot();
        s.payout_in_flight = true;
        assert_eq!(
            guards_allow_cycle(&policy(), &s),
            Err(SkipReason::PayoutInFlight)
        );
    }

    #[test]
    fn an_unreadable_chain_skips_rather_than_spends() {
        let mut s = snapshot();
        s.onchain_spend_minor = None;
        assert_eq!(
            guards_allow_cycle(&policy(), &s),
            Err(SkipReason::ChainUnknown)
        );
    }

    #[test]
    fn float_guard_reads_the_lower_of_ledger_and_chain() {
        // The ledger can show credits the chain has not settled; the chain
        // includes a base reserve the ledger never sees. Spend only what
        // BOTH agree exists.
        let mut s = snapshot();
        s.onchain_spend_minor = Some(50_000_000); // below min_float
        assert_eq!(
            guards_allow_cycle(&policy(), &s),
            Err(SkipReason::FloatGuard)
        );

        let mut s = snapshot();
        s.spend_available_minor = 50_000_000;
        assert_eq!(
            guards_allow_cycle(&policy(), &s),
            Err(SkipReason::FloatGuard)
        );
    }

    #[test]
    fn spend_ceiling_is_the_tightest_of_every_bound() {
        let p = policy();
        let s = snapshot();
        // max_spend binds here.
        assert_eq!(spend_ceiling(&p, &s), 1_000_000_000);

        // Spendable float binds.
        let mut s2 = s.clone();
        s2.spend_available_minor = 400_000_000;
        s2.onchain_spend_minor = Some(400_000_000);
        assert_eq!(spend_ceiling(&p, &s2), 300_000_000); // minus min_float

        // Daily remainder binds.
        let mut s3 = s.clone();
        s3.spent_24h_minor = 4_800_000_000;
        assert_eq!(spend_ceiling(&p, &s3), 200_000_000);

        // Nothing spendable.
        let mut s4 = s.clone();
        s4.spend_available_minor = 10_000_000;
        s4.onchain_spend_minor = Some(10_000_000);
        assert_eq!(spend_ceiling(&p, &s4), 0);
    }

    #[test]
    fn sizing_inverts_the_reference_pair_and_floors() {
        // Reference: 100 XLM -> 26.18 USDC. Needing 10 USDC should size
        // about 38.19 XLM.
        let ref_spend = 1_000_000_000; // 100 XLM
        let ref_recv = 261_800_000; // 26.18 USDC
        let need = 100_000_000; // 10 USDC
        let sized = size_spend_from_need(need, ref_spend, ref_recv, i64::MAX).unwrap();
        assert!(
            (381_000_000..=382_000_000).contains(&sized),
            "sized {}",
            sized
        );

        // The ceiling always wins.
        let capped = size_spend_from_need(need, ref_spend, ref_recv, 50_000_000).unwrap();
        assert_eq!(capped, 50_000_000);

        // A zero ceiling means nothing can be spent.
        assert_eq!(size_spend_from_need(need, ref_spend, ref_recv, 0), None);
    }

    #[test]
    fn implied_price_is_exact_at_scale() {
        // 100 XLM -> 26.18 USDC is 0.2618 USDC per XLM = 2_618_000 at 7dp.
        assert_eq!(
            implied_price_minor(1_000_000_000, 261_800_000, RESERVE_SCALE_STELLAR),
            Some(2_618_000)
        );
        assert_eq!(implied_price_minor(0, 1, RESERVE_SCALE_STELLAR), None);
        assert_eq!(implied_price_minor(1, 0, RESERVE_SCALE_STELLAR), None);
        // No overflow at the extremes.
        assert!(implied_price_minor(1, i64::MAX, RESERVE_SCALE_STELLAR).is_none());
    }

    #[test]
    fn price_floor_rejects_a_bad_rate() {
        let mut p = policy();
        p.min_price_minor = 2_600_000;
        assert_eq!(price_guards_allow(&p, 2_618_000, 2_618_000), Ok(()));
        assert_eq!(
            price_guards_allow(&p, 2_500_000, 2_618_000),
            Err(SkipReason::PriceFloor)
        );
        // 0 disables the floor.
        let p0 = policy();
        assert_eq!(price_guards_allow(&p0, 1, 0), Ok(()));
    }

    #[test]
    fn slippage_is_bounded_against_the_reference() {
        let p = policy(); // 300 bps
        let reference = 2_618_000;
        // 1% drift passes.
        assert_eq!(price_guards_allow(&p, 2_591_820, reference), Ok(()));
        // 5% drift does not — this is the valve that stops a manipulated
        // quote dumping the float.
        assert_eq!(
            price_guards_allow(&p, 2_487_100, reference),
            Err(SkipReason::Slippage)
        );
        // Exactly at the bound is allowed.
        let at_bound = reference - (reference * 300 / 10_000);
        assert_eq!(price_guards_allow(&p, at_bound, reference), Ok(()));
        // A better-than-reference price is never rejected for slippage.
        assert_eq!(price_guards_allow(&p, reference, reference), Ok(()));
    }

    #[test]
    fn usd_cents_round_trip_through_stellar_minor() {
        for cents in [1i64, 100, 2_000, 20_000] {
            let minor = usd_cents_to_stellar_minor(cents).unwrap();
            assert_eq!(
                crate::exchange::reserve::stellar_minor_to_usd_cents_ceil(minor),
                cents
            );
        }
        assert_eq!(usd_cents_to_stellar_minor(i64::MAX), None);
    }

    #[test]
    fn only_owlpay_creates_are_safe_to_retry_when_ambiguous() {
        // Changelly takes no client idempotency key, so a retry could create
        // a SECOND swap. Abandoning one is free — it expires unfunded.
        assert!(!ambiguous_create_is_retryable("changelly_crypto"));
        assert!(ambiguous_create_is_retryable("owlpay"));
    }

    #[test]
    fn scales_match_their_buckets() {
        assert_eq!(scale_for("USD"), RESERVE_SCALE_USD);
        assert_eq!(scale_for("USDC"), RESERVE_SCALE_STELLAR);
        assert_eq!(scale_for("XLM"), RESERVE_SCALE_STELLAR);
    }

    #[test]
    fn skip_reasons_are_low_cardinality_labels() {
        // Metric labels must be a closed set of &'static str.
        for r in [
            SkipReason::Disabled,
            SkipReason::Unconfigured,
            SkipReason::InFlight,
            SkipReason::Cooldown,
            SkipReason::DailyCap,
            SkipReason::NoNeed,
            SkipReason::BelowMinimum,
            SkipReason::FloatGuard,
            SkipReason::ChainUnknown,
            SkipReason::PayoutInFlight,
            SkipReason::PriceFloor,
            SkipReason::Slippage,
            SkipReason::NoQuote,
        ] {
            assert!(!r.as_str().is_empty());
            assert!(!r.as_str().contains(' '));
        }
    }

    #[test]
    fn arrivals_dispatch_on_asset_not_memo() {
        // The provider's refund address is the reserve's own with the SAME
        // memo, so a cycle ref alone cannot say which direction this is.
        assert_eq!(
            classify_cycle_arrival(Some("USDC"), Some(100), "XLM", "USDC"),
            CycleArrival::Credit { amount_minor: 100 }
        );
        assert_eq!(
            classify_cycle_arrival(Some("XLM"), Some(90), "XLM", "USDC"),
            CycleArrival::Refund { amount_minor: 90 }
        );
        // A third asset, or an unparseable amount, is not ours to interpret.
        assert_eq!(
            classify_cycle_arrival(Some("EURC"), Some(100), "XLM", "USDC"),
            CycleArrival::Unmatched
        );
        assert_eq!(
            classify_cycle_arrival(None, Some(100), "XLM", "USDC"),
            CycleArrival::Unmatched
        );
        assert_eq!(
            classify_cycle_arrival(Some("USDC"), None, "XLM", "USDC"),
            CycleArrival::Unmatched
        );
        assert_eq!(
            classify_cycle_arrival(Some("USDC"), Some(0), "XLM", "USDC"),
            CycleArrival::Unmatched
        );
    }

    #[test]
    fn abort_covers_every_pre_send_state() {
        // A cycle can hold funds from 'planned' onward, so every state that
        // precedes a send must be releasable — otherwise the hold strands.
        for state in ["planned", "creating", "sending"] {
            assert!(
                ABORT_CYCLE_SQL.contains(state),
                "abort must cover {}",
                state
            );
        }
        // ...and must NEVER touch a state where the spend already left.
        assert!(!ABORT_CYCLE_SQL.contains("'sent'"));
        assert!(!ABORT_CYCLE_SQL.contains("'completed'"));
    }

    #[test]
    fn cycle_sql_guards_every_transition() {
        // Terminal AND frozen/in-transit cycles are never re-driven.
        assert!(DUE_CYCLES_SQL
            .contains("state NOT IN ('completed', 'failed', 'refunded', 'frozen', 'in_transit')"));
        assert!(DUE_CYCLES_SQL.contains("next_action_at <= CURRENT_TIMESTAMP"));
        // Every advance names the state it came from.
        assert!(CYCLE_CAS_SQL.contains("AND state = $3"));
        assert!(STALE_CYCLE_SQL.contains("state IN ('creating', 'sending')"));
        // The insert must not name a state: 'planned' is fixed, and the
        // in-flight unique index depends on it.
        assert!(CYCLE_INSERT_SQL.contains("'planned'"));
    }

    /// Hash before submit, pinned on the source text: inside `submit_spend`
    /// the envelope is prepared, its hash recorded on the write-ahead rows,
    /// and only then submitted — and the fused sign+submit is gone from this
    /// file entirely (a fused call has no point at which a hash can be
    /// persisted before Horizon sees the envelope).
    #[test]
    fn submit_spend_records_hash_before_submit() {
        let src = include_str!("replenish.rs");
        let start = src
            .find("async fn submit_spend(")
            .expect("submit_spend present");
        let end = src[start..]
            .find("async fn record_spend_sent(")
            .expect("record_spend_sent follows");
        let body = &src[start..start + end];
        let pos = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("{} missing from submit_spend", needle))
        };
        let prepare = pos("prepare_payment(");
        let record = pos("record_intent_hash(");
        let submit = pos("submit_prepared(");
        assert!(
            prepare < record,
            "the hash comes from the prepared envelope"
        );
        assert!(record < submit, "no persisted hash, no submit");
        assert!(body.contains("IntentKey::Cycle"));
        // Never re-queued from `sending`: requeue's CAS covers `creating` only.
        assert!(!body.contains("requeue_cycle("));
        // The fused signer is banned from this file. Build the needle so this
        // test's own text does not satisfy it.
        let fused = ["sign_and_submit", "_payment("].concat();
        assert!(!src.contains(&fused), "replenish.rs calls the fused signer");
    }

    #[test]
    fn cycle_hash_sql_is_a_null_cas_on_both_rows() {
        for sql in [CYCLE_ENTRY_HASH_SQL, CYCLE_ROW_HASH_SQL] {
            assert!(
                sql.contains("IS NULL"),
                "hash arm must be a NULL-CAS: {}",
                sql
            );
            assert!(sql.contains("cycle_id = $1"));
            assert!(sql.contains("= $2"));
        }
        assert!(CYCLE_ENTRY_HASH_SQL.contains("stellar_tx_hash IS NULL"));
        assert!(CYCLE_ENTRY_HASH_SQL.contains("kind = $3"));
        assert!(CYCLE_ROW_HASH_SQL.contains("send_tx_hash IS NULL"));
        assert!(CYCLE_ROW_HASH_SQL.contains("state = 'sending'"));
        // The settle write may only confirm the armed hash, never replace it.
        let src = include_str!("replenish.rs");
        assert!(src.contains("AND (send_tx_hash IS NULL OR send_tx_hash = $2)"));
    }

    #[test]
    fn hash_unrecorded_aborts_rather_than_requeues() {
        let rejected = SubmitOutcome::Rejected {
            msg: "intent hash not recorded; not submitting".to_string(),
            permanent: false,
        };
        // Prepared but the hash never landed: nothing was sent, unwind under
        // its own reason.
        assert_eq!(
            spend_disposition(&rejected, true, false),
            SpendDisposition::Abort("hash_unrecorded")
        );
        // Armed and definitively rejected by Horizon: ordinary unwind.
        assert_eq!(
            spend_disposition(&rejected, true, true),
            SpendDisposition::Abort("send_rejected")
        );
        // Failed before an envelope existed (sequence fetch, bad params).
        assert_eq!(
            spend_disposition(&rejected, false, false),
            SpendDisposition::Abort("send_rejected")
        );
        assert_eq!(
            spend_disposition(&SubmitOutcome::Settled, true, true),
            SpendDisposition::Sent
        );
        // Ambiguous is never unwound, armed or not: the hold stays.
        assert_eq!(
            spend_disposition(&SubmitOutcome::Ambiguous, true, true),
            SpendDisposition::Freeze("send_unknown")
        );
        assert_eq!(
            spend_disposition(&SubmitOutcome::Ambiguous, true, false),
            SpendDisposition::Freeze("send_unknown")
        );
        // Every abort reason is a state ABORT_CYCLE_SQL can unwind from:
        // the cycle is `sending` at that point.
        assert!(ABORT_CYCLE_SQL.contains("'sending'"));
    }

    #[test]
    fn stale_sending_cycle_resolves_by_hash_before_freezing() {
        // Settled on-chain: book it. Proven absent: unwind. Inconclusive or
        // unreadable: freeze, exactly as before the hash existed.
        assert_eq!(
            stale_verdict("sending", true, Some(Ok(true))),
            StaleVerdict::Settle
        );
        assert_eq!(
            stale_verdict("sending", true, Some(Ok(false))),
            StaleVerdict::Abort("send_expired")
        );
        assert_eq!(
            stale_verdict("sending", true, Some(Err(()))),
            StaleVerdict::Freeze("stale_state")
        );
        assert_eq!(
            stale_verdict("sending", true, None),
            StaleVerdict::Freeze("stale_state")
        );
        // Hashless `sending` (possibly armed by a pre-037 binary that
        // submitted first) and `creating` are never resolved, only frozen —
        // whatever the chain would have said.
        assert_eq!(
            stale_verdict("sending", false, Some(Ok(false))),
            StaleVerdict::Freeze("stale_state")
        );
        assert_eq!(
            stale_verdict("creating", true, Some(Ok(true))),
            StaleVerdict::Freeze("stale_state")
        );
        assert!(STALE_CYCLE_ROW_SQL.contains("send_tx_hash"));
        assert!(STALE_CYCLE_ROW_SQL.contains("WHERE cycle_id = $1"));
    }

    #[test]
    fn reference_notional_only_applies_to_the_crypto_leg() {
        assert_eq!(reference_spend_minor("xlm_to_usdc"), Some(1_000_000_000));
        // The fiat leg is priced at par plus fees, not from a reference.
        assert_eq!(reference_spend_minor("usdc_to_usd"), None);
    }
}

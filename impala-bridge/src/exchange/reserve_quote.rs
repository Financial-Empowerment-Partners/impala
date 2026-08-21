//! Reserved price quotes: a bridge-issued lock on both a price AND the pool
//! capacity behind it, so an order placed against a live quote is guaranteed
//! fulfillable.
//!
//! The capacity is taken exactly once, when the quote is minted, and is never
//! returned to `available` until the quote expires or the order it became
//! finishes. Consuming a quote is therefore a **zero-delta linkage entry**,
//! not a release-and-retake: there is no window in which a racing order could
//! take the capacity, and [`RESERVE_HOLD_SQL`]'s fraction guard is never
//! re-evaluated against capacity that is already ours.
//!
//! Two rules make this safe to expose:
//!
//! - **A named quote is a commitment.** Unlike every other reserve path, a
//!   quoted order never falls through to the provider — creating a provider
//!   order at a different price would be a value surprise, and after a
//!   committed consume it would double-create. The quoted branch returns
//!   `Result<ExchangeOrderResponse>`, never `Ok(None)`.
//! - **The lock is short.** A quote hold delivers nothing to the customer
//!   while it waits (no pay-in is in flight), so it is pure optionality
//!   written against the pool. Total exposure — lock window plus deposit
//!   window — is capped at startup.

use log::{error, info};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::constants::{
    EXCHANGE_PROVIDER_RESERVE, EXCHANGE_STATUS_AWAITING_DEPOSIT,
    RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT, RESERVE_SCALE_STELLAR,
};
use crate::error::AppError;
use crate::exchange::replenish::scale_for;
use crate::exchange::reserve::{
    base32_order_ref, journal_insert, minor_to_decimal_string, parse_decimal_to_minor,
    ConversionReserve, DivertContext, DivertShape, JournalEntry, RESERVE_BUCKET_APPLY_SQL,
    RESERVE_HOLD_SQL,
};
use crate::models::{
    CreateExchangeOrderRequest, ExchangeOrderDetail, ExchangeOrderResponse, ReserveQuoteView,
};

/// Mint a quote row. Only ever called with capacity already held.
pub(crate) const QUOTE_INSERT_SQL: &str = "INSERT INTO conversion_reserve_quote \
     (quote_id, payala_account_id, diverted_provider, shape, direction, from_currency, \
      to_currency, amount_from, amount_to, pricing, hold_currency, hold_minor, \
      payout_address, payout_extra_id, expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
             CURRENT_TIMESTAMP + make_interval(secs => $15))";

/// The one statement that spends a quote.
///
/// Every way a quote can be invalid — unknown id, someone else's, already
/// consumed, expired — collapses into "zero rows", deliberately
/// indistinguishable so quote ids cannot be probed for existence. Under READ
/// COMMITTED a second concurrent create blocks on this row lock, then
/// re-evaluates against the committed new version and matches nothing.
pub(crate) const QUOTE_CLAIM_SQL: &str = "UPDATE conversion_reserve_quote \
     SET status = 'consumed', consumed_at = CURRENT_TIMESTAMP \
     WHERE quote_id = $1 AND payala_account_id = $2 \
       AND status = 'open' AND expires_at > CURRENT_TIMESTAMP \
     RETURNING hold_currency, hold_minor, shape, diverted_provider, direction, \
               from_currency, to_currency, amount_from, amount_to, pricing, \
               payout_address, payout_extra_id";

/// Distinguish "this caller already spent this quote" from "invalid", so a
/// client whose response was lost gets the SAME order back instead of a 400 —
/// making `reserve_quote_id` a true idempotency key. Scoped to the owning
/// account, so it leaks nothing.
pub(crate) const QUOTE_REPLAY_SQL: &str = "SELECT order_id FROM conversion_reserve_quote \
     WHERE quote_id = $1 AND payala_account_id = $2 \
       AND status = 'consumed' AND order_id IS NOT NULL";

/// Link the consumed quote to the order it became. Separate from the claim
/// because the FK to `exchange_order` is IMMEDIATE and the order row does not
/// exist yet at claim time; the claim already holds the row lock, so nothing
/// can slip in between.
pub(crate) const LINK_QUOTE_ORDER_SQL: &str = "UPDATE conversion_reserve_quote \
     SET order_id = $2 WHERE quote_id = $1 AND order_id IS NULL";

/// One account's total open reserve exposure: non-terminal reserve orders
/// PLUS live price locks, capped TOGETHER. Two independent caps would double
/// what a single account can tie up at once.
pub(crate) const OPEN_RESERVE_EXPOSURE_SQL: &str = "SELECT \
     (SELECT COUNT(*) FROM exchange_order \
        WHERE payala_account_id = $1 AND provider = 'reserve' AND status = ANY($2)) \
   + (SELECT COUNT(*) FROM conversion_reserve_quote \
        WHERE payala_account_id = $1 AND status = 'open' \
          AND expires_at > CURRENT_TIMESTAMP)";

/// Expiry sweep, served by the partial index on `(expires_at) WHERE open`.
pub(crate) const QUOTE_EXPIRABLE_SQL: &str = "SELECT quote_id FROM conversion_reserve_quote \
     WHERE status = 'open' AND expires_at <= CURRENT_TIMESTAMP \
     ORDER BY expires_at LIMIT $1";

/// Guarded expiry. Races the claim on the same row; whoever takes the lock
/// first wins and the loser matches zero rows.
pub(crate) const QUOTE_EXPIRE_SQL: &str = "UPDATE conversion_reserve_quote \
     SET status = 'expired' \
     WHERE quote_id = $1 AND status = 'open' AND expires_at <= CURRENT_TIMESTAMP \
     RETURNING hold_currency, hold_minor";

/// Retire a lock that has NOT expired yet — the operator kill switch. Kept
/// separate from [`QUOTE_EXPIRE_SQL`] so the sweeper can never retire a live
/// lock by accident.
pub(crate) const QUOTE_RETIRE_SQL: &str = "UPDATE conversion_reserve_quote \
     SET status = 'expired' \
     WHERE quote_id = $1 AND status = 'open' \
     RETURNING hold_currency, hold_minor";

/// The locked terms a claim returns.
#[derive(sqlx::FromRow)]
pub(crate) struct ClaimedQuote {
    pub hold_currency: String,
    pub hold_minor: i64,
    pub shape: String,
    pub diverted_provider: String,
    pub direction: String,
    pub from_currency: String,
    pub to_currency: String,
    pub amount_from: String,
    pub amount_to: String,
    pub pricing: String,
    pub payout_address: Option<String>,
    pub payout_extra_id: Option<String>,
}

/// Does this order match the terms the quote locked?
///
/// Without this gate a quote is a substitution oracle: quote 10 XLM, then
/// submit 10_000 against the same small hold.
pub(crate) fn quote_matches_order(q: &ClaimedQuote, p: &CreateExchangeOrderRequest) -> bool {
    // Vocabulary fields are compared case-insensitively, matching
    // `divert_shape`'s own ticker handling.
    if !q.diverted_provider.eq_ignore_ascii_case(&p.provider)
        || !q.direction.eq_ignore_ascii_case(&p.direction)
        || !q.from_currency.eq_ignore_ascii_case(&p.from_currency)
        || !q.to_currency.eq_ignore_ascii_case(&p.to_currency)
    {
        return false;
    }
    // Amounts are compared as canonical minor units so "10", "10.0" and
    // "10.0000000" are the same order — a string compare would reject
    // legitimate re-spellings.
    let quoted = parse_decimal_to_minor(&q.amount_from, RESERVE_SCALE_STELLAR);
    let asked = parse_decimal_to_minor(&p.amount_from, RESERVE_SCALE_STELLAR);
    if quoted.is_none() || quoted != asked {
        return false;
    }
    // Addresses are compared EXACTLY: Stellar strkeys are case-sensitive
    // base32, and a case-insensitive compare here would let a caller redirect
    // the payout past the trustline check the quote was bound to.
    if q.payout_address.as_deref() != p.payout_address.as_deref() {
        return false;
    }
    if q.payout_extra_id.as_deref() != p.payout_extra_id.as_deref() {
        return false;
    }
    true
}

/// Mint a price lock, taking the capacity now.
///
/// Best-effort by contract: any reason a lock cannot be issued returns
/// `Ok(None)` and the quote response stays exactly as it is today. The
/// caller must NOT surface a reason — "the pool cannot lock $200 right now"
/// is pool state, and pool state is bridge-private.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mint_quote(
    pool: &PgPool,
    reserve: &ConversionReserve,
    account_id: &str,
    payload: &CreateExchangeOrderRequest,
    shape: DivertShape,
    hold_currency: &str,
    hold_minor: i64,
    pricing: &'static str,
) -> Result<Option<ReserveQuoteView>, AppError> {
    let db_err = |context: &'static str| {
        move |e: sqlx::Error| {
            error!("mint_quote: {}: {}", context, e);
            AppError::InternalError("Database error".to_string())
        }
    };
    let mut tx = pool.begin().await.map_err(db_err("begin"))?;

    // Same per-account serialization as order creation, so the combined cap
    // cannot race itself.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('conv_reserve:' || $1::text))")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("advisory lock"))?;

    let open: i64 = sqlx::query_scalar(OPEN_RESERVE_EXPOSURE_SQL)
        .bind(account_id)
        .bind(crate::exchange::reconcile::non_terminal_statuses())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("exposure count"))?;
    if open >= RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT {
        return Ok(None);
    }

    // The same guarded hold customer orders take, including the
    // half-the-pool fraction guard: a lock is exposure like any other.
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_HOLD_SQL)
        .bind(hold_currency)
        .bind(hold_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("quote hold"))?;
    let (available_after, held_after, _) = match bucket {
        Some(b) => b,
        None => return Ok(None),
    };

    // amount_to is DERIVED from hold_minor, never the reverse: fulfillment
    // releases `held` by parsing this string back, so any divergence between
    // the two would drift the held column.
    let quote_id = Uuid::new_v4();
    // Rendered at the HOLD bucket's own scale: a USD lock is cents, and
    // rendering it at Stellar 7dp would understate the locked payout by five
    // orders of magnitude.
    let amount_to = minor_to_decimal_string(hold_minor, scale_for(hold_currency));
    let shape_str = match shape {
        DivertShape::AutoSwap => "auto_swap",
        DivertShape::Disburse => "disburse",
    };
    sqlx::query(QUOTE_INSERT_SQL)
        .bind(quote_id)
        .bind(account_id)
        .bind(&payload.provider)
        .bind(shape_str)
        .bind(&payload.direction)
        .bind(&payload.from_currency)
        .bind(&payload.to_currency)
        .bind(&payload.amount_from)
        .bind(&amount_to)
        .bind(pricing)
        .bind(hold_currency)
        .bind(hold_minor)
        .bind(&payload.payout_address)
        .bind(&payload.payout_extra_id)
        .bind(reserve.quote_ttl_secs as f64)
        .execute(&mut *tx)
        .await
        .map_err(db_err("quote insert"))?;

    journal_insert(JournalEntry {
        currency: hold_currency.to_string(),
        kind: "quote_hold".to_string(),
        delta: -hold_minor,
        held_delta: hold_minor,
        balance_after: available_after,
        held_after,
        diverted_provider: Some(payload.provider.clone()),
        quote_id: Some(quote_id),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("quote hold entry"))?;

    tx.commit().await.map_err(db_err("commit"))?;

    info!(
        "mint_quote: quote={} account={} {} {} -> {} (ttl {}s)",
        quote_id,
        account_id,
        payload.amount_from,
        payload.from_currency,
        amount_to,
        reserve.quote_ttl_secs
    );
    Ok(Some(ReserveQuoteView {
        quote_id,
        from_currency: payload.from_currency.clone(),
        to_currency: payload.to_currency.clone(),
        amount_from: payload.amount_from.clone(),
        amount_to,
        expires_in_secs: reserve.quote_ttl_secs as i64,
    }))
}

/// Create an order against a locked quote.
///
/// Returns `Err` rather than falling through: see the module note on why a
/// named quote must never become a provider order.
pub(crate) async fn divert_quoted_order(
    ctx: &DivertContext<'_>,
    payload: &CreateExchangeOrderRequest,
    quote_id: Uuid,
) -> Result<ExchangeOrderResponse, AppError> {
    let db_err = |context: &'static str| {
        move |e: sqlx::Error| {
            error!("divert_quoted_order: {}: {}", context, e);
            AppError::InternalError("Database error".to_string())
        }
    };
    let invalid = || {
        AppError::BadRequest(
            "reserve quote is not valid (unknown, expired, or already used)".to_string(),
        )
    };

    // Re-checked before the transaction, because these can change between
    // minting and consuming and both are cheap to verify.
    let shape = crate::exchange::reserve::divert_shape(payload).ok_or_else(|| {
        AppError::BadRequest("this order cannot be served from the conversion reserve".to_string())
    })?;

    // `enabled: false` is the operator's kill switch — it must actually stop
    // new exposure, even against an already-issued lock.
    let policy: Option<(bool, i64)> = sqlx::query_as(
        "SELECT enabled, threshold_usd_cents FROM conversion_reserve_policy WHERE provider = $1",
    )
    .bind(&payload.provider)
    .fetch_optional(ctx.pool)
    .await
    .map_err(db_err("policy"))?;
    if !matches!(policy, Some((true, _))) {
        // Do not leave the capacity idle through an incident: retire the
        // lock so the pool drains immediately rather than at its natural
        // expiry.
        let _ = retire_quote_now(ctx.pool, quote_id).await;
        return Err(AppError::Conflict(
            "conversion reserve routing is unavailable".to_string(),
        ));
    }

    // The trustline can be removed after minting, and a payout that is
    // guaranteed to fail op_no_trust AFTER the customer deposits is far worse
    // than a 400 now. The quote stays open — the caller may fix it and retry.
    if shape == DivertShape::AutoSwap {
        let payout_address = payload
            .payout_address
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("payout_address is required".to_string()))?;
        if !crate::exchange::reserve::payout_has_usdc_trustline(
            ctx.http,
            ctx.horizon_url,
            payout_address,
            &ctx.reserve.usdc_code,
            &ctx.reserve.usdc_issuer,
        )
        .await
        {
            return Err(AppError::BadRequest(
                "the payout address does not hold a trustline for the payout asset".to_string(),
            ));
        }
    }

    let order_id = Uuid::new_v4();
    let order_ref = base32_order_ref(&order_id);
    let mut tx = ctx.pool.begin().await.map_err(db_err("begin"))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('conv_reserve:' || $1::text))")
        .bind(&payload.account_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("advisory lock"))?;

    let claimed: Option<ClaimedQuote> = sqlx::query_as(QUOTE_CLAIM_SQL)
        .bind(quote_id)
        .bind(&payload.account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("claim"))?;
    let claimed = match claimed {
        Some(c) => c,
        None => {
            drop(tx);
            // Already spent by this caller? Hand back the original order so a
            // lost response is not a failed order.
            let existing: Option<Uuid> = sqlx::query_scalar(QUOTE_REPLAY_SQL)
                .bind(quote_id)
                .bind(&payload.account_id)
                .fetch_optional(ctx.pool)
                .await
                .map_err(db_err("replay"))?;
            let order_id = existing.ok_or_else(invalid)?;
            let detail = read_back(ctx.pool, order_id).await?;
            return Ok(ExchangeOrderResponse {
                success: true,
                message: "Exchange order already created for this quote".to_string(),
                order: Some(detail),
            });
        }
    };

    if !quote_matches_order(&claimed, payload) {
        // Roll back, leaving the quote open and reusable.
        return Err(AppError::BadRequest(
            "order terms do not match the quoted terms".to_string(),
        ));
    }

    // NO bucket movement and NO `hold` entry: the capacity was taken at mint
    // and simply changes owner here. The zero-delta entry records the
    // handoff so the journal still replays exactly.
    let (bal, held): (i64, i64) = sqlx::query_as(
        "SELECT available, held FROM conversion_reserve WHERE currency = $1 FOR UPDATE",
    )
    .bind(&claimed.hold_currency)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("bucket snapshot"))?;

    let provider_payload = json!({
        "diverted_from": claimed.diverted_provider,
        "pricing": claimed.pricing,
        "hold_currency": claimed.hold_currency,
        "hold_minor": claimed.hold_minor,
        "shape": claimed.shape,
        "beneficiary": payload.beneficiary,
        "payout_instrument": payload.payout_instrument,
        "refund_address": payload.refund_address,
        "reserve_quote_id": quote_id.to_string(),
    });
    let next_poll_at =
        chrono::Utc::now() + chrono::Duration::seconds(ctx.reserve.watch_secs as i64);
    sqlx::query(crate::handlers::exchange::CREATE_ORDER_INSERT_SQL)
        .bind(order_id)
        .bind(&payload.account_id)
        .bind(EXCHANGE_PROVIDER_RESERVE)
        .bind(&payload.direction)
        .bind(&payload.from_currency)
        .bind(&payload.to_currency)
        .bind(&payload.amount_from)
        // The locked price, verbatim.
        .bind(Some(claimed.amount_to.clone()))
        .bind(EXCHANGE_STATUS_AWAITING_DEPOSIT)
        .bind(Option::<String>::None)
        .bind(&order_ref)
        .bind(Some(ctx.reserve.stellar_address.clone()))
        .bind(Some(order_ref.clone()))
        .bind(&payload.payout_address)
        .bind(&payload.payout_extra_id)
        .bind(Option::<String>::None)
        .bind(Option::<serde_json::Value>::None)
        .bind(&provider_payload)
        .bind(next_poll_at)
        .execute(&mut *tx)
        .await
        .map_err(db_err("order insert"))?;

    sqlx::query(LINK_QUOTE_ORDER_SQL)
        .bind(quote_id)
        .bind(order_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("link"))?;

    journal_insert(JournalEntry {
        currency: claimed.hold_currency.clone(),
        kind: "quote_consume".to_string(),
        balance_after: bal,
        held_after: held,
        order_id: Some(order_id),
        quote_id: Some(quote_id),
        diverted_provider: Some(claimed.diverted_provider.clone()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("consume entry"))?;

    crate::events::emit_event(
        &mut tx,
        &crate::events::AccountEvent::ExchangeOrderCreated {
            account_id: payload.account_id.clone(),
            order_id: order_id.to_string(),
            provider: EXCHANGE_PROVIDER_RESERVE.to_string(),
            direction: payload.direction.clone(),
            from_currency: payload.from_currency.clone(),
            to_currency: payload.to_currency.clone(),
            amount_from: payload.amount_from.clone(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;

    ctx.metrics
        .record_exchange_order(EXCHANGE_PROVIDER_RESERVE, "success");
    ctx.metrics
        .record_reserve_diverted(&claimed.diverted_provider);
    ctx.metrics.reserve_quotes_consumed.add(1, &[]);
    info!(
        "divert_quoted_order: order {} from quote {} account={} amount_to={}",
        order_id, quote_id, payload.account_id, claimed.amount_to
    );

    let detail = read_back(ctx.pool, order_id).await?;
    let deadline =
        chrono::Utc::now() + chrono::Duration::seconds(ctx.reserve.deposit_ttl_secs as i64);
    Ok(ExchangeOrderResponse {
        success: true,
        message: format!(
            "Exchange order created at the quoted rate. Send the pay-in WITH THE MEMO before \
             {} — late pay-ins expire",
            deadline.format("%Y-%m-%dT%H:%M:%SZ")
        ),
        order: Some(detail),
    })
}

async fn read_back(pool: &PgPool, order_id: Uuid) -> Result<ExchangeOrderDetail, AppError> {
    sqlx::query_as::<_, ExchangeOrderDetail>(&format!(
        "SELECT {} FROM exchange_order WHERE order_id = $1",
        crate::handlers::exchange::exchange_order_detail_columns()
    ))
    .bind(order_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        error!("reserve_quote: read-back error: {}", e);
        AppError::InternalError("Database error".to_string())
    })
}

/// Expire one quote and return its capacity. Shared by the sweeper and the
/// policy-disabled path.
pub(crate) async fn expire_quote_now(pool: &PgPool, quote_id: Uuid) -> Result<bool, AppError> {
    release_quote(pool, quote_id, QUOTE_EXPIRE_SQL).await
}

/// Retire a still-live lock (kill switch) and return its capacity.
pub(crate) async fn retire_quote_now(pool: &PgPool, quote_id: Uuid) -> Result<bool, AppError> {
    release_quote(pool, quote_id, QUOTE_RETIRE_SQL).await
}

async fn release_quote(pool: &PgPool, quote_id: Uuid, sql: &str) -> Result<bool, AppError> {
    let db_err = |context: &'static str| {
        move |e: sqlx::Error| {
            error!("expire_quote: {}: {}", context, e);
            AppError::InternalError("Database error".to_string())
        }
    };
    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let expired: Option<(String, i64)> = sqlx::query_as(sql)
        .bind(quote_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("expire"))?;
    // Zero rows means a concurrent create consumed it — nothing to release.
    let (currency, hold_minor) = match expired {
        Some(v) => v,
        None => return Ok(false),
    };

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&currency)
        .bind(hold_minor)
        .bind(-hold_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("release"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        error!("expire_quote {}: held underflow (drift)", quote_id);
        AppError::InternalError("Database error".to_string())
    })?;

    journal_insert(JournalEntry {
        currency,
        kind: "quote_release".to_string(),
        delta: hold_minor,
        held_delta: -hold_minor,
        balance_after: bal_after,
        held_after,
        quote_id: Some(quote_id),
        note: Some("price lock expired".to_string()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("release entry"))?;
    tx.commit().await.map_err(db_err("commit"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claimed() -> ClaimedQuote {
        ClaimedQuote {
            hold_currency: "USDC".to_string(),
            hold_minor: 261_800_000,
            shape: "auto_swap".to_string(),
            diverted_provider: "changelly_crypto".to_string(),
            direction: "crypto_to_crypto".to_string(),
            from_currency: "xlm".to_string(),
            to_currency: "usdcxlm".to_string(),
            amount_from: "100".to_string(),
            amount_to: "26.1800000".to_string(),
            pricing: "provider_estimate".to_string(),
            payout_address: Some(
                "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37".to_string(),
            ),
            payout_extra_id: None,
        }
    }

    fn order() -> CreateExchangeOrderRequest {
        serde_json::from_value(json!({
            "account_id": "acct-1",
            "provider": "changelly_crypto",
            "direction": "crypto_to_crypto",
            "from_currency": "xlm",
            "to_currency": "usdcxlm",
            "amount_from": "100",
            "payout_address": "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37"
        }))
        .expect("valid request json")
    }

    #[test]
    fn matching_terms_are_accepted() {
        assert!(quote_matches_order(&claimed(), &order()));
    }

    #[test]
    fn amounts_match_on_value_not_spelling() {
        // "100", "100.0" and "100.0000000" are the same order.
        for spelling in ["100", "100.0", "100.0000000"] {
            let mut o = order();
            o.amount_from = spelling.to_string();
            assert!(quote_matches_order(&claimed(), &o), "{}", spelling);
        }
        // But a different VALUE is a substitution attempt.
        let mut o = order();
        o.amount_from = "10000".to_string();
        assert!(!quote_matches_order(&claimed(), &o));
    }

    #[test]
    fn tickers_match_case_insensitively() {
        let mut o = order();
        o.from_currency = "XLM".to_string();
        o.to_currency = "USDCXLM".to_string();
        o.provider = "CHANGELLY_CRYPTO".to_string();
        assert!(quote_matches_order(&claimed(), &o));
    }

    #[test]
    fn payout_address_must_match_exactly() {
        // Case-insensitive here would let a caller redirect the payout past
        // the trustline check the quote was bound to.
        let mut o = order();
        o.payout_address = Some(o.payout_address.unwrap().to_lowercase());
        assert!(!quote_matches_order(&claimed(), &o));

        let mut o = order();
        o.payout_address = Some("GDIFFERENTADDRESS".to_string());
        assert!(!quote_matches_order(&claimed(), &o));

        let mut o = order();
        o.payout_address = None;
        assert!(!quote_matches_order(&claimed(), &o));
    }

    #[test]
    fn every_locked_term_is_checked() {
        for mutate in [
            (|o: &mut CreateExchangeOrderRequest| o.provider = "owlpay".to_string()) as fn(&mut _),
            |o: &mut CreateExchangeOrderRequest| o.direction = "crypto_to_fiat".to_string(),
            |o: &mut CreateExchangeOrderRequest| o.from_currency = "btc".to_string(),
            |o: &mut CreateExchangeOrderRequest| o.to_currency = "usdc".to_string(),
            |o: &mut CreateExchangeOrderRequest| o.payout_extra_id = Some("memo".to_string()),
        ] {
            let mut o = order();
            mutate(&mut o);
            assert!(!quote_matches_order(&claimed(), &o));
        }
    }

    #[test]
    fn amount_to_is_derived_from_the_hold() {
        // Fulfillment releases `held` by parsing amount_to back, so the two
        // must round-trip exactly or the held column drifts.
        let q = claimed();
        assert_eq!(
            parse_decimal_to_minor(&q.amount_to, RESERVE_SCALE_STELLAR),
            Some(q.hold_minor)
        );
        for minor in [1i64, 999, 261_800_000, 2_000_000_000] {
            let s = minor_to_decimal_string(minor, RESERVE_SCALE_STELLAR);
            assert_eq!(
                parse_decimal_to_minor(&s, RESERVE_SCALE_STELLAR),
                Some(minor)
            );
        }
    }

    // ── SQL shape pins ─────────────────────────────────────────────────

    #[test]
    fn claim_sql_collapses_every_invalid_case_to_zero_rows() {
        assert!(QUOTE_CLAIM_SQL.contains("status = 'open'"));
        assert!(QUOTE_CLAIM_SQL.contains("expires_at > CURRENT_TIMESTAMP"));
        // Ownership is enforced in the same statement, so a quote id cannot
        // be spent by another account or probed for existence.
        assert!(QUOTE_CLAIM_SQL.contains("payala_account_id = $2"));
        assert!(QUOTE_CLAIM_SQL.contains("SET status = 'consumed'"));
        for col in [
            "hold_currency",
            "hold_minor",
            "shape",
            "diverted_provider",
            "direction",
            "from_currency",
            "to_currency",
            "amount_from",
            "amount_to",
            "pricing",
            "payout_address",
            "payout_extra_id",
        ] {
            assert!(QUOTE_CLAIM_SQL.contains(col), "claim must return {}", col);
        }
    }

    #[test]
    fn expiry_and_replay_sql_are_guarded() {
        assert!(QUOTE_EXPIRE_SQL.contains("status = 'open'"));
        assert!(QUOTE_EXPIRE_SQL.contains("SET status = 'expired'"));
        assert!(QUOTE_EXPIRE_SQL.contains("RETURNING hold_currency, hold_minor"));
        assert!(QUOTE_EXPIRABLE_SQL.contains("status = 'open'"));
        assert!(QUOTE_EXPIRABLE_SQL.contains("expires_at <= CURRENT_TIMESTAMP"));
        // The replay lookup must stay account-scoped, or it leaks whether a
        // quote id exists.
        assert!(QUOTE_REPLAY_SQL.contains("payala_account_id = $2"));
        assert!(QUOTE_REPLAY_SQL.contains("status = 'consumed'"));
        assert!(LINK_QUOTE_ORDER_SQL.contains("order_id IS NULL"));
    }

    #[test]
    fn exposure_cap_counts_orders_and_quotes_together() {
        // Two independent caps would double what one account can lock.
        assert!(OPEN_RESERVE_EXPOSURE_SQL.contains("FROM exchange_order"));
        assert!(OPEN_RESERVE_EXPOSURE_SQL.contains("FROM conversion_reserve_quote"));
        assert!(OPEN_RESERVE_EXPOSURE_SQL.contains("expires_at > CURRENT_TIMESTAMP"));
    }
}

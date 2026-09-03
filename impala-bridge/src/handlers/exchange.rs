//! Exchange-order REST endpoints (`/exchange/*`): provider discovery, quotes,
//! and order creation/inspection for the OwlPay Harbor and Changelly
//! (crypto + fiat) integrations.
//!
//! Amounts are provider-quoted decimal STRINGS end-to-end — never parsed into
//! floats. The order id is generated BEFORE the provider call and doubles as
//! the provider-side external reference / idempotency key, so a crash between
//! the provider call and the local INSERT is recoverable by that reference.
//! Every order-state write is one DB transaction with an `event_outbox`
//! append; metrics are recorded only after commit.

use axum::extract::{Extension, Path, Query};
use axum::Json;
use log::{error, info, warn};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::client_source::ClientSource;
use crate::constants::{
    EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO, EXCHANGE_DIRECTION_CRYPTO_TO_FIAT,
    EXCHANGE_DIRECTION_FIAT_TO_CRYPTO, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
    EXCHANGE_PROVIDER_CHANGELLY_FIAT, EXCHANGE_PROVIDER_OWLPAY, EXCHANGE_STATUS_CREATED,
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, VALID_EXCHANGE_DIRECTIONS,
    VALID_EXCHANGE_PROVIDERS, VALID_EXCHANGE_STATUSES,
};
use crate::error::AppError;
use crate::exchange::changelly::{
    map_changelly_crypto_status, map_changelly_fiat_status, ChangellyCreateTx, ChangellyCrypto,
    ChangellyFiat, FiatOfferQuery, FiatOrder,
};
use crate::exchange::owlpay::{map_owlpay_status, OwlPayProvider, OwlPayTransfer};
use crate::exchange::reconcile::{
    is_terminal_exchange_status, refresh_order_once, truncate_chars, ReconcileConfig,
};
use crate::handlers::transaction::TS_FMT;
use crate::models::{
    CreateExchangeOrderRequest, ExchangeOrderDetail, ExchangeOrderResponse, ExchangeProviderStatus,
    ExchangeProvidersResponse, ExchangeQuoteRequest, ExchangeQuoteResponse, ExchangeReferenceQuery,
    ExchangeReferenceResponse, GetExchangeOrderQuery, ListExchangeOrdersQuery, PaginatedResponse,
};
use crate::telemetry::AppMetrics;

/// Changelly crypto rate types (`rate_type` request field).
const RATE_TYPE_FLOAT: &str = "float";
const RATE_TYPE_FIXED: &str = "fixed";

/// How many poll intervals a webhook-backed order waits before its
/// safety-net poll: webhooks normally settle these, so polling them on the
/// same cadence as the webhook-less provider would be wasted provider budget.
const WEBHOOK_SAFETY_NET_POLL_FACTOR: u64 = 4;

/// OwlPay quote party types (`customer_type` request field).
const OWLPAY_CUSTOMER_TYPE_INDIVIDUAL: &str = "individual";
const OWLPAY_CUSTOMER_TYPES: &[&str] = &[OWLPAY_CUSTOMER_TYPE_INDIVIDUAL, "business"];

/// Order INSERT shape, lifted to a const so the test below pins the explicit
/// `order_id` column (the id must be the pre-generated provider reference,
/// never a DB-side default) and the initial `next_poll_at`.
pub(crate) const CREATE_ORDER_INSERT_SQL: &str = "INSERT INTO exchange_order \
     (order_id, payala_account_id, provider, direction, from_currency, to_currency, \
      amount_from, amount_to, status, provider_status, provider_order_id, \
      payin_address, payin_extra_id, payout_address, payout_extra_id, redirect_url, \
      transfer_instructions, provider_payload, next_poll_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)";

/// Column list for reading an order back as [`ExchangeOrderDetail`]
/// (timestamps as text via `to_char`, sqlx chrono decode not used here).
pub(crate) fn exchange_order_detail_columns() -> String {
    format!(
        "order_id, payala_account_id, provider, direction, from_currency, to_currency, \
         amount_from, amount_to, status, provider_status, provider_order_id, \
         payin_address, payin_extra_id, payout_address, payout_extra_id, redirect_url, \
         transfer_instructions, btxid, last_error, \
         to_char(created_at AT TIME ZONE 'UTC', '{ts}') AS created_at, \
         to_char(updated_at AT TIME ZONE 'UTC', '{ts}') AS updated_at",
        ts = TS_FMT
    )
}

/// Directions each provider supports (also the `/exchange/providers` payload).
pub(crate) fn provider_directions(provider: &str) -> &'static [&'static str] {
    match provider {
        EXCHANGE_PROVIDER_OWLPAY | EXCHANGE_PROVIDER_CHANGELLY_FIAT => &[
            EXCHANGE_DIRECTION_FIAT_TO_CRYPTO,
            EXCHANGE_DIRECTION_CRYPTO_TO_FIAT,
        ],
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => &[EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO],
        _ => &[],
    }
}

fn build_provider_status(provider: &str, enabled: bool) -> ExchangeProviderStatus {
    ExchangeProviderStatus {
        provider: provider.to_string(),
        enabled,
        directions: provider_directions(provider)
            .iter()
            .map(|d| d.to_string())
            .collect(),
    }
}

/// Unwrap an optional provider Extension or fail with the uniform
/// "not configured" message (github.rs:115 precedent).
fn require_provider<'a, T>(
    ext: &'a Option<Extension<Arc<T>>>,
    provider: &str,
) -> Result<&'a Arc<T>, AppError> {
    ext.as_ref()
        .map(|Extension(p)| p)
        .ok_or_else(|| AppError::BadRequest(format!("{} is not configured", provider)))
}

// ── Request validation (pure, unit-tested) ─────────────────────────────

fn validate_provider(provider: &str) -> Result<(), AppError> {
    if !VALID_EXCHANGE_PROVIDERS.contains(&provider) {
        return Err(AppError::BadRequest(format!(
            "Invalid provider '{}'. Must be one of: {}",
            provider,
            VALID_EXCHANGE_PROVIDERS.join(", ")
        )));
    }
    Ok(())
}

fn validate_direction(direction: &str) -> Result<(), AppError> {
    if !VALID_EXCHANGE_DIRECTIONS.contains(&direction) {
        return Err(AppError::BadRequest(format!(
            "Invalid direction '{}'. Must be one of: {}",
            direction,
            VALID_EXCHANGE_DIRECTIONS.join(", ")
        )));
    }
    Ok(())
}

fn validate_provider_direction(provider: &str, direction: &str) -> Result<(), AppError> {
    if !provider_directions(provider).contains(&direction) {
        return Err(AppError::BadRequest(format!(
            "{} does not support direction '{}'",
            provider, direction
        )));
    }
    Ok(())
}

fn validate_rate_type(rate_type: Option<&str>) -> Result<(), AppError> {
    match rate_type {
        None | Some(RATE_TYPE_FLOAT) | Some(RATE_TYPE_FIXED) => Ok(()),
        Some(other) => Err(AppError::BadRequest(format!(
            "Invalid rate_type '{}'. Must be one of: {}, {}",
            other, RATE_TYPE_FLOAT, RATE_TYPE_FIXED
        ))),
    }
}

fn is_fixed_rate(rate_type: Option<&str>) -> bool {
    rate_type == Some(RATE_TYPE_FIXED)
}

/// ISO 3166-1 alpha-2 country code shape check (providers do the real lookup).
fn validate_country_code(country: &str) -> Result<(), AppError> {
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(AppError::BadRequest(
            "country must be an ISO 3166-1 alpha-2 code".to_string(),
        ));
    }
    Ok(())
}

/// US state / region code shape check (2-3 ASCII alphanumerics).
fn validate_state_code(state: &str) -> Result<(), AppError> {
    if !(2..=3).contains(&state.len()) || !state.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(AppError::BadRequest(
            "state must be a 2-3 character region code".to_string(),
        ));
    }
    Ok(())
}

/// Generic bound for opaque provider tokens (rate ids, quote ids, customer
/// uuids, provider codes): printable ASCII without spaces, length-capped.
fn validate_token_field(field: &str, value: &str, max_len: usize) -> Result<(), AppError> {
    if value.is_empty()
        || value.len() > max_len
        || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(AppError::BadRequest(format!(
            "{} must be 1-{} printable ASCII characters without spaces",
            field, max_len
        )));
    }
    Ok(())
}

/// Required-field accessor with a uniform error message.
fn require_field<'a>(
    value: Option<&'a str>,
    field: &str,
    context: &str,
) -> Result<&'a str, AppError> {
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::BadRequest(format!("{} is required for {}", field, context)))
}

/// Validate a quote request: vocabulary, provider/direction pairing, currency
/// and amount formats, and the optional provider-specific fields.
pub(crate) fn validate_quote_request(p: &ExchangeQuoteRequest) -> Result<(), AppError> {
    // Lock coordinates are validated when supplied; their ABSENCE simply
    // means no lock is issued, keeping `reserve_lock` best-effort.
    if p.reserve_lock.unwrap_or(false) {
        if let Some(a) = p.payout_address.as_deref() {
            crate::validate::validate_exchange_address(a)?;
        }
        if let Some(x) = p.payout_extra_id.as_deref() {
            crate::validate::validate_exchange_extra_id(x)?;
        }
    }
    validate_provider(&p.provider)?;
    validate_direction(&p.direction)?;
    validate_provider_direction(&p.provider, &p.direction)?;
    crate::validate::validate_exchange_currency(&p.from_currency)?;
    crate::validate::validate_exchange_currency(&p.to_currency)?;
    crate::validate::validate_decimal_amount(&p.amount_from)?;
    validate_rate_type(p.rate_type.as_deref())?;
    if let Some(ref c) = p.country {
        validate_country_code(c)?;
    }
    if let Some(ref s) = p.state {
        validate_state_code(s)?;
    }
    if let Some(ref c) = p.source_country {
        validate_country_code(c)?;
    }
    if let Some(ref c) = p.destination_country {
        validate_country_code(c)?;
    }
    if let Some(ref ch) = p.source_chain {
        validate_token_field("source_chain", ch, 24)?;
    }
    if let Some(ref ch) = p.destination_chain {
        validate_token_field("destination_chain", ch, 24)?;
    }
    if let Some(ref ct) = p.customer_type {
        if !OWLPAY_CUSTOMER_TYPES.contains(&ct.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid customer_type '{}'. Must be one of: {}",
                ct,
                OWLPAY_CUSTOMER_TYPES.join(", ")
            )));
        }
    }
    Ok(())
}

/// Validate an order-creation request. Per-provider REQUIRED fields are
/// enforced by the body builders below; this covers formats and vocabulary.
pub(crate) fn validate_order_request(p: &CreateExchangeOrderRequest) -> Result<(), AppError> {
    validate_provider(&p.provider)?;
    validate_direction(&p.direction)?;
    validate_provider_direction(&p.provider, &p.direction)?;
    crate::validate::validate_exchange_currency(&p.from_currency)?;
    crate::validate::validate_exchange_currency(&p.to_currency)?;
    crate::validate::validate_decimal_amount(&p.amount_from)?;
    if let Some(ref a) = p.payout_address {
        crate::validate::validate_exchange_address(a)?;
    }
    if let Some(ref x) = p.payout_extra_id {
        crate::validate::validate_exchange_extra_id(x)?;
    }
    if let Some(ref a) = p.refund_address {
        crate::validate::validate_exchange_address(a)?;
    }
    if let Some(ref x) = p.refund_extra_id {
        crate::validate::validate_exchange_extra_id(x)?;
    }
    validate_rate_type(p.rate_type.as_deref())?;
    if let Some(ref v) = p.rate_id {
        validate_token_field("rate_id", v, 256)?;
    }
    if let Some(v) = p.reserve_quote_id.as_deref() {
        uuid::Uuid::parse_str(v)
            .map_err(|_| AppError::BadRequest("reserve_quote_id must be a UUID".to_string()))?;
        // The reserve cannot honor a bridge lock and a provider fixed-rate
        // contract at once — divert_shape refuses the latter outright.
        if p.rate_id.is_some() || is_fixed_rate(p.rate_type.as_deref()) {
            return Err(AppError::BadRequest(
                "reserve_quote_id cannot be combined with rate_id or rate_type=fixed".to_string(),
            ));
        }
    }
    if let Some(ref v) = p.quote_id {
        validate_token_field("quote_id", v, 128)?;
    }
    if let Some(ref v) = p.customer_uuid {
        validate_token_field("customer_uuid", v, 128)?;
    }
    if let Some(ref v) = p.provider_code {
        validate_token_field("provider_code", v, 64)?;
    }
    if let Some(ref v) = p.payment_method {
        validate_token_field("payment_method", v, 64)?;
    }
    if let Some(ref v) = p.transfer_purpose {
        validate_token_field("transfer_purpose", v, 64)?;
    }
    if let Some(ref c) = p.country {
        validate_country_code(c)?;
    }
    if let Some(ref s) = p.state {
        validate_state_code(s)?;
    }
    // User-redirect URLs forwarded to the fiat provider; reuse the house SSRF
    // validator (scheme + private-range checks) even though the bridge itself
    // never fetches them.
    if let Some(ref u) = p.return_success_url {
        crate::validate::validate_callback_url(u)?;
    }
    if let Some(ref u) = p.return_failed_url {
        crate::validate::validate_callback_url(u)?;
    }
    for (name, value) in [
        ("beneficiary", &p.beneficiary),
        ("payout_instrument", &p.payout_instrument),
        ("source_payment_instrument", &p.source_payment_instrument),
    ] {
        if let Some(v) = value {
            if !v.is_object() {
                return Err(AppError::BadRequest(format!(
                    "{} must be a JSON object",
                    name
                )));
            }
        }
    }
    Ok(())
}

/// Resolve the end-user IP the Changelly Fiat API requires: explicit
/// `user_ip`, else the request's attributed client source (the
/// `X-Forwarded-For` entry the trusted proxy appended, or the TCP peer —
/// see `client_source.rs`; never the sender-written leftmost entry or
/// `X-Real-Ip`). An explicit value must parse as an IP address; an
/// unattributable source is an error, not a guess.
pub(crate) fn resolve_client_ip(explicit: Option<&str>, source: &str) -> Result<String, AppError> {
    if let Some(ip) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return if ip.parse::<std::net::IpAddr>().is_ok() {
            Ok(ip.to_string())
        } else {
            Err(AppError::BadRequest(
                "user_ip must be a valid IP address".to_string(),
            ))
        };
    }
    if source != crate::client_source::UNKNOWN_SOURCE {
        return Ok(source.to_string());
    }
    Err(AppError::BadRequest(
        "user_ip is required (no client IP could be determined from the connection)".to_string(),
    ))
}

// ── Provider request-body builders (pure, unit-tested) ─────────────────

/// OwlPay v2 quote body from a quote request. `customer_type` defaults to
/// "individual"; country/chain are optional (quote by asset pair + amount).
pub(crate) fn build_owlpay_quote_body(p: &ExchangeQuoteRequest) -> serde_json::Value {
    let customer_type = p
        .customer_type
        .as_deref()
        .unwrap_or(OWLPAY_CUSTOMER_TYPE_INDIVIDUAL);
    let mut source = serde_json::Map::new();
    source.insert("asset".to_string(), json!(p.from_currency));
    source.insert("amount".to_string(), json!(p.amount_from));
    source.insert("type".to_string(), json!(customer_type));
    if let Some(ref c) = p.source_country {
        source.insert("country".to_string(), json!(c));
    }
    if let Some(ref ch) = p.source_chain {
        source.insert("chain".to_string(), json!(ch));
    }
    let mut destination = serde_json::Map::new();
    destination.insert("asset".to_string(), json!(p.to_currency));
    destination.insert("type".to_string(), json!(customer_type));
    if let Some(ref c) = p.destination_country {
        destination.insert("country".to_string(), json!(c));
    }
    if let Some(ref ch) = p.destination_chain {
        destination.insert("chain".to_string(), json!(ch));
    }
    json!({ "source": source, "destination": destination })
}

/// Changelly Fiat on-ramp (buy) order body. `externalOrderId` is our
/// pre-generated order id; `externalUserId` the Payala account id.
pub(crate) fn build_fiat_buy_order_body(
    p: &CreateExchangeOrderRequest,
    order_id: &Uuid,
    ip: &str,
) -> Result<serde_json::Value, AppError> {
    let provider_code = require_field(
        p.provider_code.as_deref(),
        "provider_code",
        "changelly_fiat orders",
    )?;
    let country = require_field(p.country.as_deref(), "country", "changelly_fiat orders")?;
    let wallet_address = require_field(
        p.payout_address.as_deref(),
        "payout_address",
        "changelly_fiat fiat_to_crypto orders",
    )?;
    let mut body = serde_json::Map::new();
    body.insert("externalOrderId".to_string(), json!(order_id.to_string()));
    body.insert("externalUserId".to_string(), json!(p.account_id));
    body.insert("providerCode".to_string(), json!(provider_code));
    body.insert("currencyFrom".to_string(), json!(p.from_currency));
    body.insert("currencyTo".to_string(), json!(p.to_currency));
    body.insert("amountFrom".to_string(), json!(p.amount_from));
    body.insert("country".to_string(), json!(country));
    body.insert("ip".to_string(), json!(ip));
    body.insert("walletAddress".to_string(), json!(wallet_address));
    if let Some(ref s) = p.state {
        body.insert("state".to_string(), json!(s));
    }
    if let Some(ref x) = p.payout_extra_id {
        body.insert("walletExtraId".to_string(), json!(x));
    }
    if let Some(ref m) = p.payment_method {
        body.insert("paymentMethod".to_string(), json!(m));
    }
    if let Some(ref u) = p.return_success_url {
        body.insert("returnSuccessUrl".to_string(), json!(u));
    }
    if let Some(ref u) = p.return_failed_url {
        body.insert("returnFailedUrl".to_string(), json!(u));
    }
    Ok(serde_json::Value::Object(body))
}

/// Changelly Fiat off-ramp (sell) order body. No `walletAddress` — the user
/// receives deposit instructions on the provider's redirect page; an optional
/// `refundAddress` covers failed matches.
pub(crate) fn build_fiat_sell_order_body(
    p: &CreateExchangeOrderRequest,
    order_id: &Uuid,
    ip: &str,
) -> Result<serde_json::Value, AppError> {
    let provider_code = require_field(
        p.provider_code.as_deref(),
        "provider_code",
        "changelly_fiat orders",
    )?;
    let country = require_field(p.country.as_deref(), "country", "changelly_fiat orders")?;
    let mut body = serde_json::Map::new();
    body.insert("externalOrderId".to_string(), json!(order_id.to_string()));
    body.insert("externalUserId".to_string(), json!(p.account_id));
    body.insert("providerCode".to_string(), json!(provider_code));
    body.insert("currencyFrom".to_string(), json!(p.from_currency));
    body.insert("currencyTo".to_string(), json!(p.to_currency));
    body.insert("amountFrom".to_string(), json!(p.amount_from));
    body.insert("country".to_string(), json!(country));
    body.insert("ip".to_string(), json!(ip));
    if let Some(ref s) = p.state {
        body.insert("state".to_string(), json!(s));
    }
    if let Some(ref m) = p.payment_method {
        body.insert("paymentMethod".to_string(), json!(m));
    }
    if let Some(ref r) = p.refund_address {
        body.insert("refundAddress".to_string(), json!(r));
    }
    Ok(serde_json::Value::Object(body))
}

/// OwlPay v2 transfer body: quote reference + our order id as the
/// application transfer uuid, with beneficiary/payout-instrument passthrough.
pub(crate) fn build_owlpay_transfer_body(
    p: &CreateExchangeOrderRequest,
    order_id: &Uuid,
) -> Result<serde_json::Value, AppError> {
    let customer_uuid =
        require_field(p.customer_uuid.as_deref(), "customer_uuid", "owlpay orders")?;
    let quote_id = require_field(p.quote_id.as_deref(), "quote_id", "owlpay orders")?;
    let mut body = serde_json::Map::new();
    body.insert("on_behalf_of".to_string(), json!(customer_uuid));
    body.insert("quote_id".to_string(), json!(quote_id));
    body.insert(
        "application_transfer_uuid".to_string(),
        json!(order_id.to_string()),
    );
    if let Some(ref inst) = p.source_payment_instrument {
        body.insert("source".to_string(), json!({ "payment_instrument": inst }));
    }
    let mut destination = serde_json::Map::new();
    if let Some(ref b) = p.beneficiary {
        destination.insert("beneficiary_info".to_string(), b.clone());
    }
    if let Some(ref pi) = p.payout_instrument {
        destination.insert("payout_instrument".to_string(), pi.clone());
    }
    if let Some(ref tp) = p.transfer_purpose {
        destination.insert("transfer_purpose".to_string(), json!(tp));
    }
    if let Some(is_self) = p.is_self_transfer {
        destination.insert("is_self_transfer".to_string(), json!(is_self));
    }
    if !destination.is_empty() {
        body.insert(
            "destination".to_string(),
            serde_json::Value::Object(destination),
        );
    }
    Ok(serde_json::Value::Object(body))
}

/// Changelly crypto create-transaction params. Fixed rate requires both the
/// quoted `rate_id` and a `refund_address` (auto-refund on rate miss/timeout).
pub(crate) fn build_changelly_create_tx(
    p: &CreateExchangeOrderRequest,
) -> Result<ChangellyCreateTx, AppError> {
    let address = require_field(
        p.payout_address.as_deref(),
        "payout_address",
        "changelly_crypto orders",
    )?;
    let fixed = is_fixed_rate(p.rate_type.as_deref());
    let rate_id = if fixed {
        Some(
            require_field(
                p.rate_id.as_deref(),
                "rate_id",
                "fixed-rate changelly_crypto orders",
            )?
            .to_string(),
        )
    } else {
        None
    };
    if fixed
        && p.refund_address
            .as_deref()
            .filter(|s| !s.is_empty())
            .is_none()
    {
        return Err(AppError::BadRequest(
            "refund_address is required for fixed-rate changelly_crypto orders".to_string(),
        ));
    }
    Ok(ChangellyCreateTx {
        from: p.from_currency.clone(),
        to: p.to_currency.clone(),
        amount_from: p.amount_from.clone(),
        address: address.to_string(),
        extra_id: p.payout_extra_id.clone(),
        refund_address: p.refund_address.clone(),
        refund_extra_id: p.refund_extra_id.clone(),
        rate_id,
    })
}

/// Validated, provider-ready order request (built BEFORE any network call so
/// user-input errors never count as provider errors).
pub(crate) enum PreparedOrder {
    ChangellyCrypto {
        create_tx: ChangellyCreateTx,
        fixed: bool,
    },
    ChangellyFiatBuy {
        body: serde_json::Value,
    },
    ChangellyFiatSell {
        body: serde_json::Value,
    },
    OwlPay {
        body: serde_json::Value,
    },
}

/// Build the provider-specific request for an order. `ip` must be resolved
/// for changelly_fiat (the Fiat API requires the end-user IP).
pub(crate) fn prepare_order(
    p: &CreateExchangeOrderRequest,
    order_id: &Uuid,
    ip: Option<&str>,
) -> Result<PreparedOrder, AppError> {
    match p.provider.as_str() {
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => Ok(PreparedOrder::ChangellyCrypto {
            fixed: is_fixed_rate(p.rate_type.as_deref()),
            create_tx: build_changelly_create_tx(p)?,
        }),
        EXCHANGE_PROVIDER_CHANGELLY_FIAT => {
            let ip = ip.ok_or_else(|| {
                AppError::BadRequest("user_ip is required for changelly_fiat orders".to_string())
            })?;
            if p.direction == EXCHANGE_DIRECTION_FIAT_TO_CRYPTO {
                Ok(PreparedOrder::ChangellyFiatBuy {
                    body: build_fiat_buy_order_body(p, order_id, ip)?,
                })
            } else {
                Ok(PreparedOrder::ChangellyFiatSell {
                    body: build_fiat_sell_order_body(p, order_id, ip)?,
                })
            }
        }
        EXCHANGE_PROVIDER_OWLPAY => Ok(PreparedOrder::OwlPay {
            body: build_owlpay_transfer_body(p, order_id)?,
        }),
        // Unreachable after validate_order_request; defensive only.
        other => Err(AppError::BadRequest(format!(
            "Invalid provider '{}'",
            other
        ))),
    }
}

// ── Provider responses, normalized ─────────────────────────────────────

/// Provider-neutral view of a freshly created order.
pub(crate) struct ProviderOrder {
    pub provider_order_id: String,
    pub status: &'static str,
    pub provider_status: Option<String>,
    pub payin_address: Option<String>,
    pub payin_extra_id: Option<String>,
    pub amount_to: Option<String>,
    pub redirect_url: Option<String>,
    pub transfer_instructions: Option<serde_json::Value>,
    pub provider_payload: serde_json::Value,
    /// Fixed-rate pay-in deadline (changelly_crypto); surfaced in the
    /// response message — a late pay-in expires the swap.
    pub pay_till: Option<String>,
}

pub(crate) fn changelly_fiat_provider_order(o: FiatOrder) -> ProviderOrder {
    let status = match o.status.as_deref() {
        Some(s) => map_changelly_fiat_status(s),
        None => EXCHANGE_STATUS_CREATED,
    };
    ProviderOrder {
        provider_order_id: o.order_id,
        status,
        provider_status: o.status,
        payin_address: None,
        payin_extra_id: None,
        amount_to: None,
        redirect_url: o.redirect_url,
        transfer_instructions: None,
        provider_payload: o.raw,
        pay_till: None,
    }
}

pub(crate) fn owlpay_provider_order(t: OwlPayTransfer, direction: &str) -> ProviderOrder {
    // Harbor reports its own view of the flow; a mismatch with the requested
    // direction means the quote_id didn't match the caller's intent.
    if let Some(ref transfer_type) = t.transfer_type {
        let expected = match direction {
            EXCHANGE_DIRECTION_FIAT_TO_CRYPTO => Some("on-ramp"),
            EXCHANGE_DIRECTION_CRYPTO_TO_FIAT => Some("off-ramp"),
            _ => None,
        };
        if let Some(expected) = expected {
            if transfer_type != expected {
                warn!(
                    "create_order: owlpay transfer type '{}' does not match requested direction '{}'",
                    transfer_type, direction
                );
            }
        }
    }
    let status = map_owlpay_status(&t.status);
    ProviderOrder {
        provider_order_id: t.uuid,
        status,
        provider_status: Some(t.status),
        payin_address: None,
        payin_extra_id: None,
        amount_to: t.destination_amount,
        redirect_url: None,
        transfer_instructions: t.transfer_instructions,
        provider_payload: t.raw,
        pay_till: None,
    }
}

/// Initial `next_poll_at` delay, derived from the configured poll cadence.
/// changelly_crypto has NO webhooks, so it polls at the base interval;
/// webhook-backed providers wait a safety-net multiple of it in case the
/// webhook never arrives.
pub(crate) fn initial_poll_delay_secs(provider: &str, poll_secs: u64) -> u64 {
    if provider == EXCHANGE_PROVIDER_CHANGELLY_CRYPTO {
        poll_secs
    } else {
        poll_secs
            .saturating_mul(WEBHOOK_SAFETY_NET_POLL_FACTOR)
            .max(1)
    }
}

// ── Handlers ───────────────────────────────────────────────────────────

/// List exchange providers with enablement + directions (`GET /exchange/providers`).
pub async fn list_providers(
    _user: AuthenticatedUser,
    owlpay: Option<Extension<Arc<OwlPayProvider>>>,
    changelly_crypto: Option<Extension<Arc<ChangellyCrypto>>>,
    changelly_fiat: Option<Extension<Arc<ChangellyFiat>>>,
) -> Result<Json<ExchangeProvidersResponse>, AppError> {
    Ok(Json(ExchangeProvidersResponse {
        providers: vec![
            build_provider_status(EXCHANGE_PROVIDER_OWLPAY, owlpay.is_some()),
            build_provider_status(
                EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
                changelly_crypto.is_some(),
            ),
            build_provider_status(EXCHANGE_PROVIDER_CHANGELLY_FIAT, changelly_fiat.is_some()),
        ],
    }))
}

/// Get exchange quotes/offers from a provider (`POST /exchange/quote`).
#[allow(clippy::too_many_arguments)]
pub async fn create_quote(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    owlpay: Option<Extension<Arc<OwlPayProvider>>>,
    changelly_crypto: Option<Extension<Arc<ChangellyCrypto>>>,
    changelly_fiat: Option<Extension<Arc<ChangellyFiat>>>,
    reserve: Option<Extension<Arc<crate::exchange::reserve::ConversionReserve>>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<ExchangeQuoteRequest>,
) -> Result<Json<ExchangeQuoteResponse>, AppError> {
    info!(
        "POST /exchange/quote: provider={} direction={} {}->{} amount={}",
        payload.provider,
        payload.direction,
        payload.from_currency,
        payload.to_currency,
        payload.amount_from
    );

    // Quotes hit upstream provider APIs — rate limit per account before work.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "exchange_quote",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    validate_quote_request(&payload)?;

    let quotes = match payload.provider.as_str() {
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => {
            let provider = require_provider(&changelly_crypto, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO)?;
            if is_fixed_rate(payload.rate_type.as_deref()) {
                provider
                    .get_fix_rate_for_amount(
                        &payload.from_currency,
                        &payload.to_currency,
                        &payload.amount_from,
                    )
                    .await?
            } else {
                provider
                    .get_exchange_amount(
                        &payload.from_currency,
                        &payload.to_currency,
                        &payload.amount_from,
                    )
                    .await?
            }
        }
        EXCHANGE_PROVIDER_CHANGELLY_FIAT => {
            let provider = require_provider(&changelly_fiat, EXCHANGE_PROVIDER_CHANGELLY_FIAT)?;
            let country = require_field(
                payload.country.as_deref(),
                "country",
                "changelly_fiat quotes",
            )?;
            let ip = resolve_client_ip(payload.user_ip.as_deref(), &source)?;
            let query = FiatOfferQuery {
                currency_from: payload.from_currency.clone(),
                currency_to: payload.to_currency.clone(),
                amount_from: payload.amount_from.clone(),
                country: country.to_string(),
                state: payload.state.clone(),
                ip,
                provider_code: None,
                payment_method: None,
                external_user_id: Some(user.account_id.clone()),
            };
            if payload.direction == EXCHANGE_DIRECTION_FIAT_TO_CRYPTO {
                provider.get_offers(&query).await?
            } else {
                provider.get_sell_offers(&query).await?
            }
        }
        // validate_quote_request pinned the vocabulary; owlpay is what's left.
        _ => {
            let provider = require_provider(&owlpay, EXCHANGE_PROVIDER_OWLPAY)?;
            provider
                .create_quote(&build_owlpay_quote_body(&payload))
                .await?
        }
    };

    // Price lock, best effort. Any reason a lock cannot be issued leaves the
    // response byte-identical to what it has always been — and carries NO
    // reason, because "the pool cannot cover this" is pool state.
    let reserve_quote = match (payload.reserve_lock.unwrap_or(false), &reserve) {
        (true, Some(Extension(reserve))) => {
            // A lock moves pool capacity, unlike a passthrough quote, so it
            // gets the tighter custodial budget rather than the quote budget.
            crate::redis_helpers::check_rate_limit(
                &redis_pool,
                "exchange_quote_lock",
                &user.account_id,
                crate::constants::SIGN_RATE_LIMIT_MAX_REQUESTS,
                crate::constants::SIGN_RATE_LIMIT_WINDOW_SECS,
            )
            .await?;
            let ctx = crate::exchange::reserve::DivertContext {
                pool: &pool,
                metrics: &metrics,
                reserve,
                changelly_crypto: changelly_crypto.as_ref().map(|ext| &ext.0),
                http: &http,
                horizon_url: &stellar_config.horizon_url,
            };
            // Best-effort by contract: a lock that cannot be minted — for
            // any reason, including a database hiccup — must not turn an
            // otherwise good quote response into an error.
            let issued = match crate::exchange::reserve::try_lock_quote(
                &ctx,
                &user.account_id,
                &payload,
                &quotes,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("create_quote: price lock unavailable: {:?}", e);
                    None
                }
            };
            if issued.is_some() {
                metrics.reserve_quotes_issued.add(1, &[]);
            }
            issued
        }
        _ => None,
    };

    Ok(Json(ExchangeQuoteResponse {
        success: true,
        message: "Quotes retrieved successfully".to_string(),
        quotes: Some(quotes),
        reserve_quote,
    }))
}

/// Reference kinds accepted by `GET /exchange/reference`.
const REFERENCE_KIND_CURRENCIES: &str = "currencies";
const REFERENCE_KIND_PAIRS: &str = "pairs";
const REFERENCE_KIND_PROVIDERS: &str = "providers";

/// Pure validation for the reference query's enum-ish filters.
fn validate_reference_filters(
    currency_type: Option<&str>,
    flow: Option<&str>,
) -> Result<(), AppError> {
    if let Some(t) = currency_type {
        if t != "crypto" && t != "fiat" {
            return Err(AppError::BadRequest(
                "Invalid type; expected one of: crypto, fiat".to_string(),
            ));
        }
    }
    if let Some(f) = flow {
        if f != "buy" && f != "sell" {
            return Err(AppError::BadRequest(
                "Invalid flow; expected one of: buy, sell".to_string(),
            ));
        }
    }
    Ok(())
}

/// Provider reference data (`GET /exchange/reference`): currency/network
/// tickers, tradable pairs, and aggregated fiat sub-providers. Clients need
/// these to discover e.g. the `usdcxlm` ticker or a MoonPay `provider_code`
/// before quoting; responses are provider payloads passed through verbatim.
pub async fn get_reference(
    user: AuthenticatedUser,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    changelly_crypto: Option<Extension<Arc<ChangellyCrypto>>>,
    changelly_fiat: Option<Extension<Arc<ChangellyFiat>>>,
    Query(q): Query<ExchangeReferenceQuery>,
) -> Result<Json<ExchangeReferenceResponse>, AppError> {
    info!(
        "GET /exchange/reference: account_id={} provider={} kind={:?}",
        user.account_id, q.provider, q.kind
    );

    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "exchange_reference",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    validate_provider(&q.provider)?;
    validate_reference_filters(q.currency_type.as_deref(), q.flow.as_deref())?;

    let kind = q.kind.as_deref().unwrap_or(REFERENCE_KIND_CURRENCIES);
    let data = match (q.provider.as_str(), kind) {
        (EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, REFERENCE_KIND_CURRENCIES) => {
            let provider = require_provider(&changelly_crypto, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO)?;
            provider.get_currencies_full().await?
        }
        (EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, REFERENCE_KIND_PAIRS) => {
            let provider = require_provider(&changelly_crypto, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO)?;
            if let Some(ref from) = q.from {
                crate::validate::validate_exchange_currency(from)?;
            }
            if let Some(ref to) = q.to {
                crate::validate::validate_exchange_currency(to)?;
            }
            provider
                .get_pairs(q.from.as_deref(), q.to.as_deref())
                .await?
        }
        (EXCHANGE_PROVIDER_CHANGELLY_FIAT, REFERENCE_KIND_CURRENCIES) => {
            let provider = require_provider(&changelly_fiat, EXCHANGE_PROVIDER_CHANGELLY_FIAT)?;
            provider
                .get_currencies(q.currency_type.as_deref(), q.flow.as_deref())
                .await?
        }
        (EXCHANGE_PROVIDER_CHANGELLY_FIAT, REFERENCE_KIND_PROVIDERS) => {
            let provider = require_provider(&changelly_fiat, EXCHANGE_PROVIDER_CHANGELLY_FIAT)?;
            provider.get_providers().await?
        }
        (EXCHANGE_PROVIDER_OWLPAY, _) => {
            return Err(AppError::BadRequest(
                "OwlPay has no reference listing; corridors are discovered via quotes".to_string(),
            ));
        }
        (_, other) => {
            return Err(AppError::BadRequest(format!(
                "Invalid kind '{}' for provider '{}'",
                other, q.provider
            )));
        }
    };

    Ok(Json(ExchangeReferenceResponse {
        success: true,
        message: "Reference data retrieved successfully".to_string(),
        data: Some(data),
    }))
}

/// OwlPay corridor-specific transfer requirements
/// (`GET /exchange/owlpay/quotes/{quote_id}/requirements`): the JSON Schema a
/// caller must satisfy in `beneficiary` / `payout_instrument` when creating
/// an order from that quote.
pub async fn get_owlpay_quote_requirements(
    user: AuthenticatedUser,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    owlpay: Option<Extension<Arc<OwlPayProvider>>>,
    Path(quote_id): Path<String>,
) -> Result<Json<ExchangeReferenceResponse>, AppError> {
    info!(
        "GET /exchange/owlpay/quotes/{{quote_id}}/requirements: account_id={}",
        user.account_id
    );

    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "exchange_reference",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let provider = require_provider(&owlpay, EXCHANGE_PROVIDER_OWLPAY)?;
    // The client rejects malformed path segments before building the request.
    let data = provider.get_quote_requirements(&quote_id).await?;

    Ok(Json(ExchangeReferenceResponse {
        success: true,
        message: "Quote requirements retrieved successfully".to_string(),
        data: Some(data),
    }))
}

/// Claim (trust-on-first-use) or re-assert the binding between an account and
/// a provider-side customer identifier.
///
/// OwlPay executes transfers `on_behalf_of` a Harbor customer uuid supplied in
/// the request body. `require_owner` proves only that the caller owns the
/// *Payala* account named in the payload — nothing about the OwlPay customer —
/// so without this binding an authenticated caller could name another
/// customer's `cus_...` and move value against it. The unique index on
/// `(provider, provider_customer_id)` makes the claim exclusive: a second
/// account naming an already-claimed customer is rejected by the DB, which
/// also settles the race between two concurrent first-use attempts.
///
/// Re-binding an account to a *different* (unclaimed) customer id is allowed:
/// customers are legitimately re-onboarded, and the exclusivity that protects
/// other accounts is enforced by the customer-side index, not this row's key.
const CLAIM_CUSTOMER_SQL: &str = "INSERT INTO exchange_customer \
     (payala_account_id, provider, provider_customer_id) \
     VALUES ($1, $2, $3) \
     ON CONFLICT (payala_account_id, provider) \
     DO UPDATE SET provider_customer_id = EXCLUDED.provider_customer_id, \
                   updated_at = CURRENT_TIMESTAMP";

async fn bind_provider_customer(
    pool: &PgPool,
    account_id: &str,
    provider: &str,
    customer_id: &str,
) -> Result<(), AppError> {
    sqlx::query(CLAIM_CUSTOMER_SQL)
        .bind(account_id)
        .bind(provider)
        .bind(customer_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| {
            // 23505: the customer id is already bound to a different account.
            if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505") {
                warn!(
                    "create_order: account {} attempted to use {} customer id bound to another account",
                    account_id, provider
                );
                return AppError::Forbidden;
            }
            error!("create_order: customer binding error: {}", e);
            AppError::InternalError("Database error".to_string())
        })
}

/// LOUD failure path: the provider-side order exists but the local row could
/// not be written — needs operator attention / manual reconciliation.
fn order_db_fail(
    metrics: &AppMetrics,
    provider: &str,
    provider_order_id: &str,
    order_id: Uuid,
    context: &'static str,
) -> AppError {
    error!(
        "create_order: {} failed AFTER provider order creation — provider={} \
         provider_order_id={} order_id={} — the provider order has NO local row",
        context, provider, provider_order_id, order_id
    );
    metrics.record_exchange_order(provider, "db_error");
    AppError::InternalError("Database error".to_string())
}

/// Create a Changelly swap and normalize the result.
///
/// `pub(crate)` because the replenishment job creates provider orders
/// server-side, off the HTTP path — see `exchange::replenish`.
pub(crate) async fn changelly_crypto_order(
    provider: &Arc<ChangellyCrypto>,
    p: &CreateExchangeOrderRequest,
    create_tx: &ChangellyCreateTx,
    fixed: bool,
) -> Result<ProviderOrder, AppError> {
    // Provider-side payout address validation before committing funds paths.
    let (valid, reason) = provider
        .validate_address(
            &p.to_currency,
            &create_tx.address,
            create_tx.extra_id.as_deref(),
        )
        .await?;
    if !valid {
        warn!(
            "create_order: changelly_crypto rejected payout address for {}",
            p.to_currency
        );
        return Err(AppError::BadRequest(match reason {
            Some(r) => format!("Invalid payout address: {}", truncate_chars(&r, 200)),
            None => "Invalid payout address".to_string(),
        }));
    }
    let tx = if fixed {
        provider.create_fix_transaction(create_tx).await?
    } else {
        provider.create_transaction(create_tx).await?
    };
    // Fixed-rate flows may settle on a slightly different pay-in amount than
    // requested; flag it so reconciliation discrepancies are explicable.
    if let Some(ref expected_from) = tx.amount_expected_from {
        if expected_from != &create_tx.amount_from {
            warn!(
                "create_order: changelly_crypto adjusted amount_from {} -> {}",
                create_tx.amount_from, expected_from
            );
        }
    }
    let status = map_changelly_crypto_status(&tx.status);
    Ok(ProviderOrder {
        provider_order_id: tx.id,
        status,
        provider_status: Some(tx.status),
        payin_address: Some(tx.payin_address),
        payin_extra_id: tx.payin_extra_id,
        amount_to: tx.amount_expected_to,
        redirect_url: None,
        transfer_instructions: None,
        provider_payload: tx.raw,
        pay_till: tx.pay_till,
    })
}

async fn changelly_fiat_buy_order(
    provider: &Arc<ChangellyFiat>,
    p: &CreateExchangeOrderRequest,
    body: &serde_json::Value,
) -> Result<ProviderOrder, AppError> {
    // build_fiat_buy_order_body already required payout_address.
    let wallet_address = p.payout_address.as_deref().unwrap_or_default();
    let (valid, reason) = provider
        .validate_address(&p.to_currency, wallet_address, p.payout_extra_id.as_deref())
        .await?;
    if !valid {
        warn!(
            "create_order: changelly_fiat rejected wallet address for {}",
            p.to_currency
        );
        return Err(AppError::BadRequest(match reason {
            Some(r) => format!("Invalid payout address: {}", truncate_chars(&r, 200)),
            None => "Invalid payout address".to_string(),
        }));
    }
    provider
        .create_order(body)
        .await
        .map(changelly_fiat_provider_order)
}

/// Create an exchange order (`POST /exchange/orders`). Owner-only.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an extractor
pub async fn create_order(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(reconcile_cfg): Extension<Arc<ReconcileConfig>>,
    owlpay: Option<Extension<Arc<OwlPayProvider>>>,
    changelly_crypto: Option<Extension<Arc<ChangellyCrypto>>>,
    changelly_fiat: Option<Extension<Arc<ChangellyFiat>>>,
    reserve: Option<Extension<Arc<crate::exchange::reserve::ConversionReserve>>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<CreateExchangeOrderRequest>,
) -> Result<Json<ExchangeOrderResponse>, AppError> {
    info!(
        "POST /exchange/orders: account_id={} provider={} direction={} {}->{} amount={}",
        payload.account_id,
        payload.provider,
        payload.direction,
        payload.from_currency,
        payload.to_currency,
        payload.amount_from
    );

    crate::auth::require_owner(&user, &payload.account_id)?;

    // Order creation moves real value — tighter accounting than the global
    // per-account API limit.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "exchange_create",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    validate_order_request(&payload)?;

    // Conversion reserve: orders under the per-provider threshold whose
    // shape the pool can serve end-to-end are fulfilled from the bridge's
    // own reserve instead of the provider. Every miss (shape, policy,
    // threshold, funds, quote, trustline) falls through to the normal
    // provider path below — the reserve must never break it.
    if payload.reserve_quote_id.is_some() && reserve.is_none() {
        return Err(AppError::BadRequest(
            "reserve_quote_id was supplied but the conversion reserve is not configured"
                .to_string(),
        ));
    }
    if let Some(Extension(ref reserve)) = reserve {
        let ctx = crate::exchange::reserve::DivertContext {
            pool: &pool,
            metrics: &metrics,
            reserve,
            changelly_crypto: changelly_crypto.as_ref().map(|ext| &ext.0),
            http: &http,
            horizon_url: &stellar_config.horizon_url,
        };
        if let Some(response) = crate::exchange::reserve::try_divert_order(&ctx, &payload).await? {
            return Ok(Json(response));
        }
    }

    // Fail fast (clean 400, no provider_error metric) when unconfigured.
    match payload.provider.as_str() {
        EXCHANGE_PROVIDER_OWLPAY => {
            require_provider(&owlpay, EXCHANGE_PROVIDER_OWLPAY)?;
        }
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => {
            require_provider(&changelly_crypto, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO)?;
        }
        _ => {
            require_provider(&changelly_fiat, EXCHANGE_PROVIDER_CHANGELLY_FIAT)?;
        }
    }

    let ip = if payload.provider == EXCHANGE_PROVIDER_CHANGELLY_FIAT {
        Some(resolve_client_ip(payload.user_ip.as_deref(), &source)?)
    } else {
        None
    };

    // Bind the provider-side customer id to this account BEFORE any provider
    // call: naming someone else's OwlPay customer must fail closed, and the
    // check must not be observable as a partially-created transfer.
    if let Some(ref customer_uuid) = payload.customer_uuid {
        bind_provider_customer(&pool, &payload.account_id, &payload.provider, customer_uuid)
            .await?;
    }

    // Generated FIRST: the order id is the provider-side external reference /
    // idempotency key (externalOrderId / application_transfer_uuid).
    let order_id = Uuid::new_v4();
    let prepared = prepare_order(&payload, &order_id, ip.as_deref())?;

    // Provider call BEFORE the DB transaction (never hold a tx across I/O).
    let created = match &prepared {
        PreparedOrder::ChangellyCrypto { create_tx, fixed } => {
            let provider = require_provider(&changelly_crypto, EXCHANGE_PROVIDER_CHANGELLY_CRYPTO)?;
            changelly_crypto_order(provider, &payload, create_tx, *fixed).await
        }
        PreparedOrder::ChangellyFiatBuy { body } => {
            let provider = require_provider(&changelly_fiat, EXCHANGE_PROVIDER_CHANGELLY_FIAT)?;
            changelly_fiat_buy_order(provider, &payload, body).await
        }
        PreparedOrder::ChangellyFiatSell { body } => {
            let provider = require_provider(&changelly_fiat, EXCHANGE_PROVIDER_CHANGELLY_FIAT)?;
            provider
                .create_sell_order(body)
                .await
                .map(changelly_fiat_provider_order)
        }
        PreparedOrder::OwlPay { body } => {
            let provider = require_provider(&owlpay, EXCHANGE_PROVIDER_OWLPAY)?;
            provider
                .create_transfer(body, &order_id.to_string())
                .await
                .map(|t| owlpay_provider_order(t, &payload.direction))
        }
    };
    let created = match created {
        Ok(o) => o,
        Err(e) => {
            metrics.record_exchange_order(&payload.provider, "provider_error");
            return Err(e);
        }
    };

    let next_poll_at = chrono::Utc::now()
        + chrono::Duration::seconds(initial_poll_delay_secs(
            &payload.provider,
            reconcile_cfg.poll_secs,
        ) as i64);

    // Insert the order row and append the admin-feed event atomically.
    let mut tx = pool.begin().await.map_err(|e| {
        error!("create_order: begin tx error: {}", e);
        order_db_fail(
            &metrics,
            &payload.provider,
            &created.provider_order_id,
            order_id,
            "begin",
        )
    })?;

    sqlx::query(CREATE_ORDER_INSERT_SQL)
        .bind(order_id)
        .bind(&payload.account_id)
        .bind(&payload.provider)
        .bind(&payload.direction)
        .bind(&payload.from_currency)
        .bind(&payload.to_currency)
        .bind(&payload.amount_from)
        .bind(&created.amount_to)
        .bind(created.status)
        .bind(&created.provider_status)
        .bind(&created.provider_order_id)
        .bind(&created.payin_address)
        .bind(&created.payin_extra_id)
        .bind(&payload.payout_address)
        .bind(&payload.payout_extra_id)
        .bind(&created.redirect_url)
        .bind(&created.transfer_instructions)
        .bind(&created.provider_payload)
        .bind(next_poll_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("create_order: insert error: {}", e);
            order_db_fail(
                &metrics,
                &payload.provider,
                &created.provider_order_id,
                order_id,
                "insert",
            )
        })?;

    crate::events::emit_event(
        &mut tx,
        &crate::events::AccountEvent::ExchangeOrderCreated {
            account_id: payload.account_id.clone(),
            order_id: order_id.to_string(),
            provider: payload.provider.clone(),
            direction: payload.direction.clone(),
            from_currency: payload.from_currency.clone(),
            to_currency: payload.to_currency.clone(),
            amount_from: payload.amount_from.clone(),
        },
    )
    .await
    .map_err(|_| {
        order_db_fail(
            &metrics,
            &payload.provider,
            &created.provider_order_id,
            order_id,
            "event emit",
        )
    })?;

    tx.commit().await.map_err(|e| {
        error!("create_order: commit error: {}", e);
        order_db_fail(
            &metrics,
            &payload.provider,
            &created.provider_order_id,
            order_id,
            "commit",
        )
    })?;

    // Metrics only after commit — nothing may claim state that didn't land.
    metrics.record_exchange_order(&payload.provider, "success");

    info!(
        "create_order: created order {} provider={} provider_order_id={} status={}",
        order_id, payload.provider, created.provider_order_id, created.status
    );

    let detail = sqlx::query_as::<_, ExchangeOrderDetail>(&format!(
        "SELECT {} FROM exchange_order WHERE order_id = $1",
        exchange_order_detail_columns()
    ))
    .bind(order_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("create_order: read-back error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let message = match &created.pay_till {
        Some(pay_till) => format!(
            "Exchange order created successfully. Send the pay-in before {} — late pay-ins expire",
            pay_till
        ),
        None => "Exchange order created successfully".to_string(),
    };
    Ok(Json(ExchangeOrderResponse {
        success: true,
        message,
        order: Some(detail),
    }))
}

/// Pure builder for the dynamic `WHERE` fragment + ordered binds shared by
/// the count and page queries (transaction.rs `build_tx_filters` shape).
fn build_order_filters(
    status: Option<&str>,
    provider: Option<&str>,
    account_id: Option<&str>,
) -> (String, Vec<String>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    let mut n = 1;

    if let Some(s) = status {
        clauses.push(format!("status = ${}", n));
        n += 1;
        binds.push(s.to_string());
    }
    if let Some(p) = provider {
        clauses.push(format!("provider = ${}", n));
        n += 1;
        binds.push(p.to_string());
    }
    if let Some(a) = account_id {
        clauses.push(format!("payala_account_id = ${}", n));
        binds.push(a.to_string());
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" AND {}", clauses.join(" AND "))
    };
    (where_sql, binds)
}

/// List exchange orders (`GET /exchange/orders`). Admins see all (optionally
/// filtered by `account_id`); a regular caller is scoped to their own orders.
pub async fn list_orders(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<ListExchangeOrdersQuery>,
) -> Result<Json<PaginatedResponse<ExchangeOrderDetail>>, AppError> {
    if let Some(ref s) = q.status {
        if !VALID_EXCHANGE_STATUSES.contains(&s.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid status '{}'. Must be one of: {}",
                s,
                VALID_EXCHANGE_STATUSES.join(", ")
            )));
        }
    }
    // The list filter accepts the ROW vocabulary — one wider than the
    // request vocabulary, because reserve-diverted orders exist as rows with
    // provider='reserve' even though clients can never request that value.
    if let Some(ref p) = q.provider {
        if !crate::constants::EXCHANGE_ORDER_ROW_PROVIDERS.contains(&p.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid provider '{}'. Must be one of: {}",
                p,
                crate::constants::EXCHANGE_ORDER_ROW_PROVIDERS.join(", ")
            )));
        }
    }

    // Owner scoping: admins see across accounts unconditionally. Non-admin
    // ReadReserve holders (treasurer, auditor) see across accounts ONLY for
    // reserve-provider listings — that is the documented grant (the
    // disbursement/frozen work queues are cross-account reserve rows, and
    // pinning a treasurer to their own account would render the queues
    // silently empty). It must not widen further: an unrestricted listing
    // would hand lateral roles every customer's OwlPay/Changelly orders
    // (payout addresses, transfer instructions) their mandate never covers.
    // Everyone else is pinned to their own account (an explicit foreign
    // account_id is a 403).
    let cross_account = user.is_admin()
        || (crate::auth::role_has_capability(&user.role, crate::auth::Capability::ReadReserve)
            && q.provider.as_deref() == Some(crate::constants::EXCHANGE_PROVIDER_RESERVE));
    let scope_account: Option<String> = if cross_account {
        q.account_id.clone()
    } else {
        if let Some(ref a) = q.account_id {
            crate::auth::require_owner(&user, a)?;
        }
        Some(user.account_id.clone())
    };

    let per_page = q.per_page.clamp(1, 100);
    // Upper-bound the page as well as the lower: `(page - 1) * per_page` on an
    // unbounded client-supplied page overflows i64 (a panic in debug builds, a
    // wrapped negative OFFSET in release).
    let page = q.page.clamp(1, crate::models::MAX_PAGE as i64);
    let offset = (page - 1) * per_page;

    let (where_sql, binds) = build_order_filters(
        q.status.as_deref(),
        q.provider.as_deref(),
        scope_account.as_deref(),
    );
    let n_limit = binds.len() + 1;
    let n_offset = binds.len() + 2;

    let count_sql = format!("SELECT COUNT(*) FROM exchange_order WHERE 1=1{}", where_sql);
    let select_sql = format!(
        "SELECT {cols} FROM exchange_order WHERE 1=1{where_sql} \
         ORDER BY created_at DESC LIMIT ${n_limit} OFFSET ${n_offset}",
        cols = exchange_order_detail_columns(),
        where_sql = where_sql,
        n_limit = n_limit,
        n_offset = n_offset
    );

    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        cq = cq.bind(b.clone());
    }
    let total = cq.fetch_one(&pool).await.map_err(|e| {
        error!("list_orders: count error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let mut sq = sqlx::query_as::<_, ExchangeOrderDetail>(&select_sql);
    for b in &binds {
        sq = sq.bind(b.clone());
    }
    let rows = sq
        .bind(per_page)
        .bind(offset)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("list_orders: query error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

    Ok(Json(PaginatedResponse {
        data: rows,
        page: page as u64,
        per_page: per_page as u64,
        total: total as u64,
    }))
}

/// Owner-scoped single-order read; a non-owned existing order returns `None`
/// so the handler yields 404 (no existence leak).
async fn fetch_order_detail(
    pool: &PgPool,
    order_id: Uuid,
    user: &AuthenticatedUser,
) -> Result<Option<ExchangeOrderDetail>, AppError> {
    // Same scoping rule as list_orders: admins fetch any order; non-admin
    // ReadReserve holders may additionally drill into reserve-provider rows
    // (the work-queue orders belong to other accounts) but nothing else;
    // everyone else is owner-scoped. Expressed in the WHERE clause so a
    // non-owned non-reserve row 404s exactly like today (no existence leak).
    let is_admin = user.is_admin();
    let reserve_read =
        crate::auth::role_has_capability(&user.role, crate::auth::Capability::ReadReserve);
    let mut sql = format!(
        "SELECT {} FROM exchange_order WHERE order_id = $1",
        exchange_order_detail_columns()
    );
    if !is_admin {
        if reserve_read {
            // Keep this predicate in lockstep with list_orders' cross_account
            // rule above — the two express one scoping contract (admin: all;
            // ReadReserve: own + reserve-provider rows; else: own).
            sql.push_str(&format!(
                " AND (payala_account_id = $2 OR provider = '{}')",
                crate::constants::EXCHANGE_PROVIDER_RESERVE
            ));
        } else {
            sql.push_str(" AND payala_account_id = $2");
        }
    }
    let mut q = sqlx::query_as::<_, ExchangeOrderDetail>(&sql).bind(order_id);
    if !is_admin {
        q = q.bind(&user.account_id);
    }
    q.fetch_optional(pool).await.map_err(|e| {
        error!("get_order: db error: {}", e);
        AppError::InternalError("Database error".to_string())
    })
}

/// Fetch a single exchange order (`GET /exchange/orders/{order_id}`).
/// Admin or owner; `?refresh=true` re-polls the provider for a non-terminal
/// order before returning the (re-read) row.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an extractor
pub async fn get_order(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(reconcile_cfg): Extension<Arc<ReconcileConfig>>,
    owlpay: Option<Extension<Arc<OwlPayProvider>>>,
    changelly_crypto: Option<Extension<Arc<ChangellyCrypto>>>,
    changelly_fiat: Option<Extension<Arc<ChangellyFiat>>>,
    Path(order_id): Path<Uuid>,
    Query(q): Query<GetExchangeOrderQuery>,
) -> Result<Json<ExchangeOrderResponse>, AppError> {
    let detail = fetch_order_detail(&pool, order_id, &user)
        .await?
        .ok_or_else(|| AppError::NotFound("Exchange order not found".to_string()))?;

    // Reserve orders have no provider to poll: state is driven by the
    // deposit watcher. A refresh must NOT reach refresh_order_once — its
    // unknown-provider defer path would stamp last_error and push
    // next_poll_at (the very column the watcher schedules on) forward.
    // This also keeps cross-account reads side-effect free: a non-admin
    // ReadReserve holder can only fetch foreign RESERVE rows (see
    // fetch_order_detail), which this predicate always excludes — a read
    // capability must never trigger a write, even a bookkeeping one.
    let refreshable = q.refresh
        && detail.provider != crate::constants::EXCHANGE_PROVIDER_RESERVE
        && !is_terminal_exchange_status(&detail.status);
    let detail = if refreshable {
        // A refresh reaches the provider, so it carries the same per-account
        // budget as every other provider-touching endpoint here — the global
        // 100/60s auth limit alone would allow bursts well past Changelly's
        // account-wide request budget.
        crate::redis_helpers::check_rate_limit(
            &redis_pool,
            "exchange_refresh",
            &user.account_id,
            RATE_LIMIT_MAX_REQUESTS,
            RATE_LIMIT_WINDOW_SECS,
        )
        .await?;

        refresh_order_once(
            &pool,
            owlpay.as_ref().map(|Extension(p)| p),
            changelly_crypto.as_ref().map(|Extension(p)| p),
            changelly_fiat.as_ref().map(|Extension(p)| p),
            &metrics,
            order_id,
            reconcile_cfg.poll_secs,
        )
        .await?;
        fetch_order_detail(&pool, order_id, &user)
            .await?
            .ok_or_else(|| AppError::NotFound("Exchange order not found".to_string()))?
    } else {
        detail
    };

    Ok(Json(ExchangeOrderResponse {
        success: true,
        message: "Exchange order retrieved successfully".to_string(),
        order: Some(detail),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_EXCHANGE_POLL_SECS, TERMINAL_EXCHANGE_STATUSES};

    fn quote_req(v: serde_json::Value) -> ExchangeQuoteRequest {
        serde_json::from_value(v).unwrap()
    }

    fn order_req(v: serde_json::Value) -> CreateExchangeOrderRequest {
        serde_json::from_value(v).unwrap()
    }

    fn test_order_id() -> Uuid {
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap()
    }

    #[test]
    fn test_validate_reference_filters() {
        assert!(validate_reference_filters(None, None).is_ok());
        assert!(validate_reference_filters(Some("crypto"), Some("buy")).is_ok());
        assert!(validate_reference_filters(Some("fiat"), Some("sell")).is_ok());
        assert!(validate_reference_filters(Some("stocks"), None).is_err());
        assert!(validate_reference_filters(None, Some("swap")).is_err());
        // Uppercase is not normalized — providers expect the exact tokens.
        assert!(validate_reference_filters(Some("Crypto"), None).is_err());
    }

    fn base_crypto_quote() -> serde_json::Value {
        json!({
            "provider": "changelly_crypto", "direction": "crypto_to_crypto",
            "from_currency": "xlm", "to_currency": "usdcxlm", "amount_from": "100"
        })
    }

    fn base_fiat_quote() -> serde_json::Value {
        json!({
            "provider": "changelly_fiat", "direction": "fiat_to_crypto",
            "from_currency": "USD", "to_currency": "USDCXLM", "amount_from": "50.25",
            "country": "US", "state": "AZ", "user_ip": "203.0.113.7"
        })
    }

    fn base_crypto_order() -> serde_json::Value {
        json!({
            "account_id": "acct-1", "provider": "changelly_crypto",
            "direction": "crypto_to_crypto", "from_currency": "xlm",
            "to_currency": "usdcxlm", "amount_from": "100",
            "payout_address": "GDUKMGUGDZQK6YHYA5Z6AY2G4XDSZPSZ3SW5UN3ARVMO6QSRDWP5YLEX"
        })
    }

    fn base_fiat_buy_order() -> serde_json::Value {
        json!({
            "account_id": "acct-1", "provider": "changelly_fiat",
            "direction": "fiat_to_crypto", "from_currency": "USD",
            "to_currency": "USDCXLM", "amount_from": "50",
            "payout_address": "GDUKMGUGDZQK6YHYA5Z6AY2G4XDSZPSZ3SW5UN3ARVMO6QSRDWP5YLEX",
            "provider_code": "moonpay", "country": "US", "user_ip": "203.0.113.7"
        })
    }

    fn base_owlpay_order() -> serde_json::Value {
        json!({
            "account_id": "acct-1", "provider": "owlpay",
            "direction": "fiat_to_crypto", "from_currency": "USD",
            "to_currency": "USDC", "amount_from": "250",
            "customer_uuid": "cus_123", "quote_id": "quote_abc"
        })
    }

    // ── provider vocabulary ────────────────────────────────────────────

    #[test]
    fn test_provider_directions_match_contract() {
        assert_eq!(
            provider_directions(EXCHANGE_PROVIDER_OWLPAY),
            &[
                EXCHANGE_DIRECTION_FIAT_TO_CRYPTO,
                EXCHANGE_DIRECTION_CRYPTO_TO_FIAT
            ]
        );
        assert_eq!(
            provider_directions(EXCHANGE_PROVIDER_CHANGELLY_CRYPTO),
            &[EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO]
        );
        assert_eq!(
            provider_directions(EXCHANGE_PROVIDER_CHANGELLY_FIAT),
            &[
                EXCHANGE_DIRECTION_FIAT_TO_CRYPTO,
                EXCHANGE_DIRECTION_CRYPTO_TO_FIAT
            ]
        );
        assert!(provider_directions("nonesuch").is_empty());
    }

    #[test]
    fn test_build_provider_status() {
        let s = build_provider_status(EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, false);
        assert_eq!(s.provider, "changelly_crypto");
        assert!(!s.enabled);
        assert_eq!(s.directions, vec!["crypto_to_crypto"]);
    }

    // ── constants ↔ DDL drift guards ───────────────────────────────────

    #[test]
    fn test_valid_exchange_vocab_matches_ddl() {
        // Request-side provider vocabulary stays the three externals (the
        // row CHECK in 031 additionally admits 'reserve'; see
        // EXCHANGE_ORDER_ROW_PROVIDERS drift guard in models.rs).
        assert_eq!(VALID_EXCHANGE_PROVIDERS.len(), 3);
        for p in ["owlpay", "changelly_crypto", "changelly_fiat"] {
            assert!(VALID_EXCHANGE_PROVIDERS.contains(&p));
        }
        assert_eq!(VALID_EXCHANGE_DIRECTIONS.len(), 3);
        for d in ["fiat_to_crypto", "crypto_to_fiat", "crypto_to_crypto"] {
            assert!(VALID_EXCHANGE_DIRECTIONS.contains(&d));
        }
        assert_eq!(VALID_EXCHANGE_STATUSES.len(), 8);
        for s in [
            "created",
            "awaiting_deposit",
            "processing",
            "on_hold",
            "completed",
            "failed",
            "refunded",
            "expired",
        ] {
            assert!(VALID_EXCHANGE_STATUSES.contains(&s));
        }
        assert_eq!(TERMINAL_EXCHANGE_STATUSES.len(), 4);
        for s in TERMINAL_EXCHANGE_STATUSES {
            assert!(VALID_EXCHANGE_STATUSES.contains(s));
        }
    }

    // ── resolve_client_ip ──────────────────────────────────────────────

    #[test]
    fn test_resolve_client_ip_explicit_wins() {
        assert_eq!(
            resolve_client_ip(Some(" 203.0.113.7 "), "10.0.0.1").unwrap(),
            "203.0.113.7"
        );
    }

    #[test]
    fn test_resolve_client_ip_explicit_invalid_rejected() {
        // A bad explicit value is an error, not silently ignored.
        assert!(resolve_client_ip(Some("not-an-ip"), "10.0.0.1").is_err());
    }

    /// Without an explicit value the attributed source is used verbatim —
    /// it has already been reduced to the trusted proxy's entry (or the
    /// TCP peer) by `client_source`, so no header parsing happens here.
    #[test]
    fn test_resolve_client_ip_falls_back_to_attributed_source() {
        assert_eq!(
            resolve_client_ip(None, "203.0.113.7").unwrap(),
            "203.0.113.7"
        );
        assert_eq!(
            resolve_client_ip(None, "2001:db8::1").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_resolve_client_ip_unattributable_source_rejected() {
        assert!(resolve_client_ip(None, crate::client_source::UNKNOWN_SOURCE).is_err());
    }

    #[test]
    fn test_resolve_client_ip_empty_explicit_falls_through() {
        assert_eq!(
            resolve_client_ip(Some("  "), "198.51.100.4").unwrap(),
            "198.51.100.4"
        );
    }

    // ── validate_quote_request ─────────────────────────────────────────

    #[test]
    fn test_validate_quote_request_ok() {
        assert!(validate_quote_request(&quote_req(base_crypto_quote())).is_ok());
        assert!(validate_quote_request(&quote_req(base_fiat_quote())).is_ok());

        let mut owlpay = base_fiat_quote();
        owlpay["provider"] = json!("owlpay");
        owlpay["source_country"] = json!("US");
        owlpay["destination_chain"] = json!("stellar");
        owlpay["customer_type"] = json!("business");
        assert!(validate_quote_request(&quote_req(owlpay)).is_ok());

        let mut fixed = base_crypto_quote();
        fixed["rate_type"] = json!("fixed");
        assert!(validate_quote_request(&quote_req(fixed)).is_ok());
    }

    #[test]
    fn test_validate_quote_request_bad_provider_rejected() {
        let mut q = base_crypto_quote();
        q["provider"] = json!("kraken");
        assert!(validate_quote_request(&quote_req(q)).is_err());
    }

    #[test]
    fn test_validate_quote_request_bad_direction_rejected() {
        let mut q = base_crypto_quote();
        q["direction"] = json!("sideways");
        assert!(validate_quote_request(&quote_req(q)).is_err());
    }

    #[test]
    fn test_validate_quote_request_provider_direction_mismatch_rejected() {
        // owlpay does not swap crypto->crypto...
        let mut q = base_crypto_quote();
        q["provider"] = json!("owlpay");
        assert!(validate_quote_request(&quote_req(q)).is_err());
        // ...and changelly_crypto does not touch fiat.
        let mut q = base_fiat_quote();
        q["provider"] = json!("changelly_crypto");
        assert!(validate_quote_request(&quote_req(q)).is_err());
    }

    #[test]
    fn test_validate_quote_request_bad_amount_rejected() {
        for bad in ["0", "-3", "1.2.3", "1e5", ""] {
            let mut q = base_crypto_quote();
            q["amount_from"] = json!(bad);
            assert!(
                validate_quote_request(&quote_req(q)).is_err(),
                "amount '{}' must be rejected",
                bad
            );
        }
    }

    #[test]
    fn test_validate_quote_request_bad_rate_type_rejected() {
        let mut q = base_crypto_quote();
        q["rate_type"] = json!("locked");
        assert!(validate_quote_request(&quote_req(q)).is_err());
    }

    #[test]
    fn test_validate_quote_request_bad_country_and_customer_type_rejected() {
        let mut q = base_fiat_quote();
        q["country"] = json!("USA");
        assert!(validate_quote_request(&quote_req(q)).is_err());

        let mut q = base_fiat_quote();
        q["provider"] = json!("owlpay");
        q["customer_type"] = json!("robot");
        assert!(validate_quote_request(&quote_req(q)).is_err());
    }

    // ── validate_order_request ─────────────────────────────────────────

    #[test]
    fn test_validate_order_request_ok() {
        assert!(validate_order_request(&order_req(base_crypto_order())).is_ok());
        assert!(validate_order_request(&order_req(base_fiat_buy_order())).is_ok());
        assert!(validate_order_request(&order_req(base_owlpay_order())).is_ok());
    }

    #[test]
    fn test_validate_order_request_bad_address_rejected() {
        let mut o = base_crypto_order();
        o["payout_address"] = json!("has a space");
        assert!(validate_order_request(&order_req(o)).is_err());
    }

    #[test]
    fn test_validate_order_request_bad_return_url_rejected() {
        let mut o = base_fiat_buy_order();
        o["return_success_url"] = json!("ftp://example.com/done");
        assert!(validate_order_request(&order_req(o)).is_err());
    }

    #[test]
    fn test_validate_order_request_passthrough_must_be_objects() {
        let mut o = base_owlpay_order();
        o["beneficiary"] = json!("not-an-object");
        assert!(validate_order_request(&order_req(o)).is_err());

        let mut o = base_owlpay_order();
        o["payout_instrument"] = json!({"address": "GABC"});
        assert!(validate_order_request(&order_req(o)).is_ok());
    }

    #[test]
    fn test_validate_token_field_bounds() {
        assert!(validate_token_field("rate_id", "abc-123_XYZ", 64).is_ok());
        assert!(validate_token_field("rate_id", "", 64).is_err());
        assert!(validate_token_field("rate_id", "has space", 64).is_err());
        assert!(validate_token_field("rate_id", &"x".repeat(65), 64).is_err());
        assert!(validate_token_field("rate_id", "\u{e9}", 64).is_err()); // non-ASCII
    }

    // ── provider body builders ─────────────────────────────────────────

    #[test]
    fn test_build_owlpay_quote_body_defaults_and_optionals() {
        let q = quote_req(json!({
            "provider": "owlpay", "direction": "fiat_to_crypto",
            "from_currency": "USD", "to_currency": "USDC", "amount_from": "250",
            "source_country": "US", "destination_chain": "stellar"
        }));
        let body = build_owlpay_quote_body(&q);
        assert_eq!(body["source"]["asset"], "USD");
        assert_eq!(body["source"]["amount"], "250"); // decimal string, not a number
        assert_eq!(body["source"]["country"], "US");
        assert_eq!(body["source"]["type"], "individual"); // default
        assert_eq!(body["destination"]["asset"], "USDC");
        assert_eq!(body["destination"]["chain"], "stellar");
        assert!(body["source"].get("chain").is_none());
        assert!(body["destination"].get("country").is_none());
    }

    #[test]
    fn test_build_fiat_buy_order_body_full() {
        let mut o = base_fiat_buy_order();
        o["state"] = json!("AZ");
        o["payout_extra_id"] = json!("memo123");
        o["payment_method"] = json!("card");
        o["return_success_url"] = json!("https://example.com/ok");
        let body =
            build_fiat_buy_order_body(&order_req(o), &test_order_id(), "203.0.113.7").unwrap();
        assert_eq!(body["externalOrderId"], test_order_id().to_string());
        assert_eq!(body["externalUserId"], "acct-1");
        assert_eq!(body["providerCode"], "moonpay");
        assert_eq!(body["currencyFrom"], "USD");
        assert_eq!(body["currencyTo"], "USDCXLM");
        assert_eq!(body["amountFrom"], "50");
        assert_eq!(body["country"], "US");
        assert_eq!(body["state"], "AZ");
        assert_eq!(body["ip"], "203.0.113.7");
        assert_eq!(
            body["walletAddress"],
            "GDUKMGUGDZQK6YHYA5Z6AY2G4XDSZPSZ3SW5UN3ARVMO6QSRDWP5YLEX"
        );
        assert_eq!(body["walletExtraId"], "memo123");
        assert_eq!(body["paymentMethod"], "card");
        assert_eq!(body["returnSuccessUrl"], "https://example.com/ok");
        assert!(body.get("returnFailedUrl").is_none()); // unset optionals omitted
    }

    #[test]
    fn test_build_fiat_buy_order_body_requires_fields() {
        for missing in ["provider_code", "country", "payout_address"] {
            let mut o = base_fiat_buy_order();
            o.as_object_mut().unwrap().remove(missing);
            assert!(
                build_fiat_buy_order_body(&order_req(o), &test_order_id(), "1.2.3.4").is_err(),
                "missing {} must be rejected",
                missing
            );
        }
    }

    #[test]
    fn test_build_fiat_sell_order_body_shape() {
        let mut o = base_fiat_buy_order();
        o["direction"] = json!("crypto_to_fiat");
        o["from_currency"] = json!("USDCXLM");
        o["to_currency"] = json!("EUR");
        o.as_object_mut().unwrap().remove("payout_address");
        o["refund_address"] = json!("GABCREFUND");
        let body =
            build_fiat_sell_order_body(&order_req(o), &test_order_id(), "203.0.113.7").unwrap();
        assert!(body.get("walletAddress").is_none()); // sell orders carry no wallet
        assert_eq!(body["refundAddress"], "GABCREFUND");
        assert_eq!(body["currencyFrom"], "USDCXLM");
        assert_eq!(body["currencyTo"], "EUR");
        assert_eq!(body["externalOrderId"], test_order_id().to_string());
    }

    #[test]
    fn test_build_fiat_sell_order_body_requires_fields() {
        for missing in ["provider_code", "country"] {
            let mut o = base_fiat_buy_order();
            o["direction"] = json!("crypto_to_fiat");
            o.as_object_mut().unwrap().remove(missing);
            assert!(
                build_fiat_sell_order_body(&order_req(o), &test_order_id(), "1.2.3.4").is_err()
            );
        }
    }

    #[test]
    fn test_build_owlpay_transfer_body_shape() {
        let mut o = base_owlpay_order();
        o["beneficiary"] = json!({"beneficiary_name": "Jane Doe"});
        o["payout_instrument"] = json!({"address": "GABC", "address_memo": "42"});
        o["transfer_purpose"] = json!("TRANSFER_TO_OWN_ACCOUNT");
        o["is_self_transfer"] = json!(true);
        o["source_payment_instrument"] = json!({"wallet_uuid": "wallet_1"});
        let body = build_owlpay_transfer_body(&order_req(o), &test_order_id()).unwrap();
        assert_eq!(body["on_behalf_of"], "cus_123");
        assert_eq!(body["quote_id"], "quote_abc");
        assert_eq!(
            body["application_transfer_uuid"],
            test_order_id().to_string()
        );
        assert_eq!(
            body["source"]["payment_instrument"]["wallet_uuid"],
            "wallet_1"
        );
        assert_eq!(
            body["destination"]["beneficiary_info"]["beneficiary_name"],
            "Jane Doe"
        );
        assert_eq!(body["destination"]["payout_instrument"]["address"], "GABC");
        assert_eq!(
            body["destination"]["transfer_purpose"],
            "TRANSFER_TO_OWN_ACCOUNT"
        );
        assert_eq!(body["destination"]["is_self_transfer"], true);
    }

    #[test]
    fn test_build_owlpay_transfer_body_omits_empty_sections() {
        let body =
            build_owlpay_transfer_body(&order_req(base_owlpay_order()), &test_order_id()).unwrap();
        assert!(body.get("source").is_none());
        assert!(body.get("destination").is_none());
    }

    #[test]
    fn test_build_owlpay_transfer_body_requires_fields() {
        for missing in ["customer_uuid", "quote_id"] {
            let mut o = base_owlpay_order();
            o.as_object_mut().unwrap().remove(missing);
            assert!(build_owlpay_transfer_body(&order_req(o), &test_order_id()).is_err());
        }
    }

    #[test]
    fn test_build_changelly_create_tx_float() {
        let tx = build_changelly_create_tx(&order_req(base_crypto_order())).unwrap();
        assert_eq!(tx.from, "xlm");
        assert_eq!(tx.to, "usdcxlm");
        assert_eq!(tx.amount_from, "100");
        assert!(tx.rate_id.is_none());
    }

    #[test]
    fn test_build_changelly_create_tx_requires_payout_address() {
        let mut o = base_crypto_order();
        o.as_object_mut().unwrap().remove("payout_address");
        assert!(build_changelly_create_tx(&order_req(o)).is_err());
    }

    #[test]
    fn test_build_changelly_create_tx_fixed_requirements() {
        // fixed without rate_id
        let mut o = base_crypto_order();
        o["rate_type"] = json!("fixed");
        o["refund_address"] = json!("GABCREFUND");
        assert!(build_changelly_create_tx(&order_req(o)).is_err());

        // fixed without refund_address
        let mut o = base_crypto_order();
        o["rate_type"] = json!("fixed");
        o["rate_id"] = json!("rate123");
        assert!(build_changelly_create_tx(&order_req(o)).is_err());

        // fixed with both
        let mut o = base_crypto_order();
        o["rate_type"] = json!("fixed");
        o["rate_id"] = json!("rate123");
        o["refund_address"] = json!("GABCREFUND");
        let tx = build_changelly_create_tx(&order_req(o)).unwrap();
        assert_eq!(tx.rate_id.as_deref(), Some("rate123"));
        assert_eq!(tx.refund_address.as_deref(), Some("GABCREFUND"));
    }

    // ── prepare_order dispatch ─────────────────────────────────────────

    #[test]
    fn test_prepare_order_dispatch() {
        let id = test_order_id();
        assert!(matches!(
            prepare_order(&order_req(base_crypto_order()), &id, None).unwrap(),
            PreparedOrder::ChangellyCrypto { fixed: false, .. }
        ));
        assert!(matches!(
            prepare_order(&order_req(base_fiat_buy_order()), &id, Some("1.2.3.4")).unwrap(),
            PreparedOrder::ChangellyFiatBuy { .. }
        ));
        let mut sell = base_fiat_buy_order();
        sell["direction"] = json!("crypto_to_fiat");
        sell.as_object_mut().unwrap().remove("payout_address");
        assert!(matches!(
            prepare_order(&order_req(sell), &id, Some("1.2.3.4")).unwrap(),
            PreparedOrder::ChangellyFiatSell { .. }
        ));
        assert!(matches!(
            prepare_order(&order_req(base_owlpay_order()), &id, None).unwrap(),
            PreparedOrder::OwlPay { .. }
        ));
    }

    #[test]
    fn test_prepare_order_fiat_requires_ip() {
        assert!(prepare_order(&order_req(base_fiat_buy_order()), &test_order_id(), None).is_err());
    }

    // ── provider response normalization ────────────────────────────────

    #[test]
    fn test_changelly_fiat_provider_order_mapping() {
        let raw = json!({"orderId": "ord-1", "status": "pending"});
        let o = changelly_fiat_provider_order(FiatOrder {
            order_id: "ord-1".to_string(),
            status: Some("pending".to_string()),
            redirect_url: Some("https://sell.example/x".to_string()),
            raw: raw.clone(),
        });
        assert_eq!(o.provider_order_id, "ord-1");
        assert_eq!(o.status, "processing"); // contract-pinned fiat mapping
        assert_eq!(o.provider_status.as_deref(), Some("pending"));
        assert_eq!(o.redirect_url.as_deref(), Some("https://sell.example/x"));
        assert_eq!(o.provider_payload, raw);

        // A missing provider status defaults to our 'created'.
        let o = changelly_fiat_provider_order(FiatOrder {
            order_id: "ord-2".to_string(),
            status: None,
            redirect_url: None,
            raw: json!({}),
        });
        assert_eq!(o.status, EXCHANGE_STATUS_CREATED);
        assert!(o.provider_status.is_none());
    }

    #[test]
    fn test_owlpay_provider_order_mapping() {
        let raw = json!({"uuid": "transfer_1"});
        let o = owlpay_provider_order(
            OwlPayTransfer {
                uuid: "transfer_1".to_string(),
                status: "pending_customer_transfer_start".to_string(),
                transfer_type: Some("on-ramp".to_string()),
                transfer_instructions: Some(json!({"narrative": "ABC123"})),
                destination_amount: Some("99.50".to_string()),
                raw: raw.clone(),
            },
            EXCHANGE_DIRECTION_FIAT_TO_CRYPTO,
        );
        assert_eq!(o.provider_order_id, "transfer_1");
        assert_eq!(o.status, "awaiting_deposit"); // contract-pinned owlpay mapping
        assert_eq!(o.amount_to.as_deref(), Some("99.50"));
        assert_eq!(
            o.transfer_instructions,
            Some(json!({"narrative": "ABC123"}))
        );
        assert_eq!(o.provider_payload, raw);
    }

    #[test]
    fn test_initial_poll_delay_tracks_configured_cadence() {
        // The webhook-less provider polls at exactly the configured cadence.
        assert_eq!(
            initial_poll_delay_secs(
                EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
                DEFAULT_EXCHANGE_POLL_SECS
            ),
            DEFAULT_EXCHANGE_POLL_SECS
        );
        assert_eq!(
            initial_poll_delay_secs(EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, 15),
            15
        );

        // Webhook-backed providers wait a multiple of it as a safety net.
        assert_eq!(
            initial_poll_delay_secs(EXCHANGE_PROVIDER_OWLPAY, 15),
            15 * WEBHOOK_SAFETY_NET_POLL_FACTOR
        );
        assert_eq!(
            initial_poll_delay_secs(EXCHANGE_PROVIDER_CHANGELLY_FIAT, 15),
            15 * WEBHOOK_SAFETY_NET_POLL_FACTOR
        );

        // Never schedules an immediate re-poll, whatever the configuration.
        assert!(initial_poll_delay_secs(EXCHANGE_PROVIDER_OWLPAY, 0) >= 1);
    }

    // ── list filters ───────────────────────────────────────────────────

    #[test]
    fn test_build_order_filters_empty() {
        let (where_sql, binds) = build_order_filters(None, None, None);
        assert!(where_sql.is_empty());
        assert!(binds.is_empty());
    }

    #[test]
    fn test_build_order_filters_numbering() {
        let (where_sql, binds) =
            build_order_filters(Some("processing"), Some("owlpay"), Some("acct-1"));
        assert!(where_sql.contains("status = $1"));
        assert!(where_sql.contains("provider = $2"));
        assert!(where_sql.contains("payala_account_id = $3"));
        assert_eq!(binds, vec!["processing", "owlpay", "acct-1"]);
    }

    #[test]
    fn test_build_order_filters_owner_scope_only() {
        let (where_sql, binds) = build_order_filters(None, None, Some("acct-1"));
        assert_eq!(where_sql, " AND payala_account_id = $1");
        assert_eq!(binds, vec!["acct-1"]);
    }

    // ── SQL shape pins ─────────────────────────────────────────────────

    /// Pins the explicit pre-generated order id (the provider reference) and
    /// the initial poll schedule in the INSERT.
    #[test]
    fn test_create_order_insert_sql_shape() {
        assert!(CREATE_ORDER_INSERT_SQL.starts_with("INSERT INTO exchange_order"));
        assert!(CREATE_ORDER_INSERT_SQL.contains("(order_id,"));
        assert!(CREATE_ORDER_INSERT_SQL.contains("next_poll_at"));
        assert!(CREATE_ORDER_INSERT_SQL.contains("$19"));
        assert!(!CREATE_ORDER_INSERT_SQL.contains("$20"));
    }

    #[test]
    fn test_detail_columns_shape() {
        let cols = exchange_order_detail_columns();
        // Timestamps go out as text in the house TS_FMT (RFC3339 UTC).
        assert!(cols.contains(&format!(
            "to_char(created_at AT TIME ZONE 'UTC', '{}') AS created_at",
            TS_FMT
        )));
        assert!(cols.contains("transfer_instructions"));
        assert!(cols.contains("provider_order_id"));
        assert!(cols.contains("last_error"));
        // The raw provider payload is internal — never returned to clients.
        assert!(!cols.contains("provider_payload"));
    }
}

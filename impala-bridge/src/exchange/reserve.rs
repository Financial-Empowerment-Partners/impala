//! Conversion reserve: a bridge-owned pool that fulfills small exchange
//! orders (under a per-provider $20-$200 threshold) instead of routing them
//! to the external provider.
//!
//! Diverted orders are ordinary `exchange_order` rows with
//! `provider = 'reserve'`: the caller receives the reserve Stellar account as
//! the pay-in address plus an order-unique text memo, exactly like a
//! Changelly swap. The deposit watcher ([`super::reserve_watch`]) matches
//! incoming payments by that memo and drives fulfillment.
//!
//! Money rules (see migration 031):
//! - All arithmetic is i64 minor units (USDC/XLM 7 dp, USD cents); the one
//!   string<->minor boundary is [`parse_decimal_to_minor`] /
//!   [`minor_to_decimal_string`]. Floats are forbidden on money paths.
//! - Every pool mutation is a guarded single-statement UPDATE plus a journal
//!   entry written under the same row lock; order-linked entries are
//!   idempotent via `UNIQUE(order_id, kind)`.
//! - Any pre-commit failure passes the order through to the provider
//!   silently (`reserve.fallbacks` metric) — the reserve is an optimization
//!   and must never break the existing path. Failures once the creation
//!   transaction may have committed surface as errors instead, so a client
//!   retry cannot produce both a reserve and a provider order.

use std::sync::Arc;

use log::{error, info, warn};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::constants::{
    EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO, EXCHANGE_DIRECTION_CRYPTO_TO_FIAT,
    EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, EXCHANGE_PROVIDER_OWLPAY, EXCHANGE_PROVIDER_RESERVE,
    EXCHANGE_STATUS_AWAITING_DEPOSIT, RESERVE_CURRENCY_USD, RESERVE_CURRENCY_USDC,
    RESERVE_CURRENCY_USDT0, RESERVE_CURRENCY_XLM, RESERVE_DEFAULT_USDT0_CODE,
    RESERVE_DEPOSIT_TTL_MAX_SECS, RESERVE_DEPOSIT_TTL_MIN_SECS,
    RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT, RESERVE_QUOTE_TTL_MAX_SECS, RESERVE_QUOTE_TTL_MIN_SECS,
    RESERVE_SCALE_STELLAR, RESERVE_SCALE_USD, RESERVE_STELLAR_USDC_TICKERS, RESERVE_TICKER_XLM,
    RESERVE_TOTAL_PRICE_WINDOW_MAX_SECS, RESERVE_USD_TICKERS,
};
use crate::error::AppError;
use crate::exchange::changelly::ChangellyCrypto;
use crate::exchange::reconcile::json_decimal_string;
use crate::models::{CreateExchangeOrderRequest, ExchangeOrderDetail, ExchangeOrderResponse};
use crate::stellar::Asset;
use crate::telemetry::AppMetrics;

/// Reference notional (XLM) for pricing orders below the provider's own
/// estimate minimum: fetch the rate at this size and scale down linearly.
const REFERENCE_XLM_AMOUNT: &str = "100";

/// Guarded hold: moves `available -> held` only when the bucket can cover it
/// AND total holds stay under half the pool (one actor must not be able to
/// lock the whole reserve with free-to-abandon orders). `available + held`
/// is invariant under the move, so the fraction guard reads pre-state.
pub(crate) const RESERVE_HOLD_SQL: &str = "UPDATE conversion_reserve \
     SET available = available - $2, held = held + $2 \
     WHERE currency = $1 AND available >= $2 \
       AND (held + $2) * 2 <= (available + held) \
     RETURNING available, held, low_water";

/// Unconditional-direction guarded apply used by every non-hold mutation:
/// both columns must stay non-negative or no row updates.
pub(crate) const RESERVE_BUCKET_APPLY_SQL: &str = "UPDATE conversion_reserve \
     SET available = available + $2, held = held + $3 \
     WHERE currency = $1 AND available + $2 >= 0 AND held + $3 >= 0 \
     RETURNING available, held, low_water";

/// Journal INSERT shared by EVERY writer — one shape for one append-only
/// money table. `UNIQUE(order_id, kind)` turns a replayed order-linked write
/// into a constraint error the caller treats as "already done".
///
/// The five linkage columns ($13-$17) are appended rather than interleaved so
/// the twelve original bind positions are untouched, and they are bound
/// through [`EntryLinks`] rather than positionally: three consecutive
/// `Option<Uuid>` parameters would otherwise transpose silently.
pub(crate) const RESERVE_ENTRY_INSERT_SQL: &str = "INSERT INTO conversion_reserve_entry \
     (currency, kind, delta, held_delta, balance_after, held_after, order_id, \
      diverted_provider, stellar_tx_hash, paging_token, admin_account_id, note, \
      quote_id, cycle_id, refund_id, sender_address, sender_muxed) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)";

/// One journal row, by name.
///
/// Every writer goes through [`journal_insert`] rather than binding
/// [`RESERVE_ENTRY_INSERT_SQL`] positionally. sqlx's dynamic query API does
/// NOT check bind count at compile time — a writer that missed a column
/// would fail at runtime, mid-transaction, on a money path — and three
/// consecutive `Option<Uuid>` linkage columns would transpose silently. With
/// named fields plus `..Default::default()`, adding a column later is one
/// edit here and the call sites keep compiling.
#[derive(Default)]
pub(crate) struct JournalEntry {
    pub currency: String,
    pub kind: String,
    /// Signed effect on `available`.
    pub delta: i64,
    /// Signed effect on `held`.
    pub held_delta: i64,
    /// Bucket snapshot AFTER this entry, read under the bucket's row lock.
    pub balance_after: i64,
    pub held_after: i64,
    pub order_id: Option<Uuid>,
    /// Which provider the order would have used (utilization attribution).
    pub diverted_provider: Option<String>,
    pub stellar_tx_hash: Option<String>,
    /// Horizon operation cursor — the per-payment idempotency anchor.
    pub paging_token: Option<String>,
    pub admin_account_id: Option<String>,
    pub note: Option<String>,
    /// Pre-order capacity lock (reserved price quotes).
    pub quote_id: Option<Uuid>,
    /// Treasury replenishment cycle.
    pub cycle_id: Option<Uuid>,
    /// Refund obligation.
    pub refund_id: Option<Uuid>,
    /// Counterparty of an inbound payment — where a refund would go back to.
    pub sender_address: Option<String>,
    /// Horizon `from_muxed`, when the sender used a muxed account. Its
    /// presence means `sender_address` is a SHARED base address, so the funds
    /// cannot be safely returned to it automatically.
    pub sender_muxed: Option<String>,
}

/// Build the fully-bound journal INSERT. The only way this table is written.
pub(crate) fn journal_insert(
    e: JournalEntry,
) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(e.currency)
        .bind(e.kind)
        .bind(e.delta)
        .bind(e.held_delta)
        .bind(e.balance_after)
        .bind(e.held_after)
        .bind(e.order_id)
        .bind(e.diverted_provider)
        .bind(e.stellar_tx_hash)
        .bind(e.paging_token)
        .bind(e.admin_account_id)
        .bind(e.note)
        .bind(e.quote_id)
        .bind(e.cycle_id)
        .bind(e.refund_id)
        .bind(e.sender_address)
        .bind(e.sender_muxed)
}

/// The hold an order owns, whichever anchor took it: its own `hold` entry
/// (a directly-diverted order) or a consumed quote's `quote_hold` (a
/// quote-backed order). Exactly one exists.
///
/// Before 032 both release paths read `WHERE order_id = $1 AND kind = 'hold'`
/// and hard-errored when absent — which every quote-backed order would have
/// hit on expiry or resolve-fail, aborting the transaction and locking its
/// hold forever. The `IS NOT NULL` guard keeps "no hold at all" a ZERO-ROW
/// result so those callers' existing drift branches still fire.
pub(crate) const ORDER_HOLD_SQL: &str =
    "SELECT COALESCE(e.currency, q.hold_currency) AS currency, \
        COALESCE(-e.delta, q.hold_minor) AS hold_minor \
     FROM exchange_order o \
     LEFT JOIN conversion_reserve_entry e \
       ON e.order_id = o.order_id AND e.kind = 'hold' \
     LEFT JOIN conversion_reserve_quote q \
       ON q.order_id = o.order_id AND q.status = 'consumed' \
     WHERE o.order_id = $1 \
       AND (e.entry_id IS NOT NULL OR q.quote_id IS NOT NULL)";

/// Guarded hold for TREASURY movements (replenishment).
///
/// Deliberately without [`RESERVE_HOLD_SQL`]'s `(held + x) * 2 <= ...`
/// fraction guard: that clause exists to stop one CUSTOMER locking the pool
/// with free-to-abandon orders, and applied here it would cap a treasury sell
/// at roughly half the bucket — the opposite of "sell the accumulated float".
pub(crate) const RESERVE_TREASURY_HOLD_SQL: &str = "UPDATE conversion_reserve \
     SET available = available - $2, held = held + $2 \
     WHERE currency = $1 AND available >= $2 \
     RETURNING available, held, low_water";

/// Open (non-terminal) reserve orders for one account — the per-account cap.
const OPEN_RESERVE_ORDERS_SQL: &str = "SELECT COUNT(*) FROM exchange_order \
     WHERE payala_account_id = $1 AND provider = 'reserve' AND status = ANY($2)";

/// Shared handle for the configured reserve (optional Extension, exchange
/// provider pattern): present iff `RESERVE_ACCOUNT_ID` is set and startup
/// validation passed.
pub struct ConversionReserve {
    /// The designated managed-seed account's payala id. Quarantined from
    /// user-facing custodial endpoints (see handlers/managed_seed.rs).
    pub reserve_account_id: String,
    /// The reserve account's public G-address (pay-in destination).
    pub stellar_address: String,
    /// Stellar asset the pool pays out and recognizes as USDC deposits.
    pub usdc_code: String,
    pub usdc_issuer: String,
    /// Optional second Stellar stablecoin (USDT0): present iff
    /// `RESERVE_USDT0_ISSUER` passed startup validation. Absent means the
    /// USDT0 bucket is inert — nothing classifies to it, nothing pays out
    /// of it, no order diverts to it.
    pub usdt0: Option<ReserveAsset>,
    /// Lowercased exchange-provider tickers meaning "USDT0 on Stellar";
    /// operator-verified per provider, empty by default.
    pub usdt0_tickers: Vec<String>,
    /// Deposit window == price-validity window (seconds).
    pub deposit_ttl_secs: u64,
    /// Watcher cadence (seconds).
    pub watch_secs: u64,
    /// Price-lock window for reserved quotes (seconds).
    pub quote_ttl_secs: u64,
}

/// A Stellar stablecoin the reserve tracks, pinned to ONE `(code, issuer)`.
///
/// The issuer is the entire trust anchor: asset codes are not unique on
/// Stellar (anyone can issue a "USDC" or a "USDT0"), so every match in the
/// reserve compares both fields and never the code alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveAsset {
    /// Bucket key (`conversion_reserve.currency`), e.g. `USDT0`.
    pub currency: &'static str,
    pub code: String,
    pub issuer: String,
}

impl ConversionReserve {
    /// The configured stablecoins as `(bucket, code, issuer)` — USDC always,
    /// USDT0 when configured. Every asset-identity decision in the reserve
    /// (deposit classification, payout/refund asset, balances, burn guards,
    /// trustlines) goes through this one list.
    pub fn stablecoins(&self) -> impl Iterator<Item = (&'static str, &str, &str)> + '_ {
        std::iter::once((
            RESERVE_CURRENCY_USDC,
            self.usdc_code.as_str(),
            self.usdc_issuer.as_str(),
        ))
        .chain(
            self.usdt0
                .iter()
                .map(|a| (a.currency, a.code.as_str(), a.issuer.as_str())),
        )
    }

    /// `(code, issuer)` behind a stablecoin bucket key; `None` for XLM/USD
    /// or for a stablecoin that is not configured.
    pub fn stablecoin(&self, currency: &str) -> Option<(&str, &str)> {
        self.stablecoins()
            .find(|(c, _, _)| *c == currency)
            .map(|(_, code, issuer)| (code, issuer))
    }

    /// Map an on-chain asset to a reserve bucket. `None` = not money the
    /// reserve tracks (a foreign token, a pool share, a same-code asset from
    /// a different issuer). The `asset_type` tag is consulted only to
    /// recognize native XLM — `credit_alphanum4` vs `credit_alphanum12`
    /// (USDT0 is five characters) is irrelevant to identity.
    pub fn bucket_for_asset(
        &self,
        asset_type: &str,
        code: Option<&str>,
        issuer: Option<&str>,
    ) -> Option<&'static str> {
        if asset_type == "native" {
            return Some(RESERVE_CURRENCY_XLM);
        }
        let (code, issuer) = (code?, issuer?);
        self.stablecoins()
            .find(|(_, c, i)| *c == code && *i == issuer)
            .map(|(bucket, _, _)| bucket)
    }

    /// Same mapping for stored rows that keep no `asset_type`
    /// (`conversion_reserve_unmatched`): a NULL code is native XLM (031).
    pub fn bucket_for_stored_asset(
        &self,
        code: Option<&str>,
        issuer: Option<&str>,
    ) -> Option<&'static str> {
        match code {
            None => Some(RESERVE_CURRENCY_XLM),
            Some(c) => self.bucket_for_asset("credit", Some(c), issuer),
        }
    }

    /// The asset to SEND for a bucket: native for XLM, the pinned credit
    /// asset for a configured stablecoin. `None` for USD (a bank balance —
    /// nothing to send on-chain) and for an unconfigured stablecoin, so a
    /// caller can never fall back to sending the wrong asset.
    pub fn asset_for_bucket(&self, currency: &str) -> Option<Asset> {
        if currency == RESERVE_CURRENCY_XLM {
            return Some(Asset::Native);
        }
        self.stablecoin(currency)
            .map(|(code, issuer)| Asset::Credit {
                code: code.to_string(),
                issuer: issuer.to_string(),
            })
    }

    /// Every configured issuer address — the addresses a payment must never
    /// be sent to, because paying an issued asset to its issuer burns it.
    pub fn issuer_addresses(&self) -> Vec<&str> {
        self.stablecoins().map(|(_, _, i)| i).collect()
    }

    pub fn is_asset_issuer(&self, address: &str) -> bool {
        self.stablecoins().any(|(_, _, i)| i == address)
    }
}

/// Validate the optional USDT0 configuration into a pinned asset.
///
/// Pure (no I/O) so the rules are unit-tested: a strkey-checksummed issuer,
/// a 1-12 alphanumeric code, an identity distinct from USDC's, and ticker
/// hygiene — provider tickers for USDT0 may not collide with the tickers
/// that already mean XLM or USDC (a collision would silently divert USDC
/// orders to the USDT0 leg), and tickers without an issuer are refused
/// rather than ignored (a half-configured money path fails closed).
pub(crate) fn validate_usdt0_config(
    issuer: Option<&str>,
    code: &str,
    tickers: &[String],
    usdc_code: &str,
    usdc_issuer: &str,
) -> Result<Option<ReserveAsset>, String> {
    let issuer = match issuer.map(str::trim).filter(|s| !s.is_empty()) {
        Some(i) => i,
        None => {
            if !tickers.is_empty() {
                return Err(
                    "RESERVE_USDT0_TICKERS is set but RESERVE_USDT0_ISSUER is not; orders \
                     would match the USDT0 leg with no asset to pay"
                        .to_string(),
                );
            }
            return Ok(None);
        }
    };
    crate::validate::validate_stellar_account_id_checksum(issuer).map_err(|e| {
        format!(
            "RESERVE_USDT0_ISSUER is not a valid Stellar account id: {}",
            e
        )
    })?;
    if code.is_empty() || code.len() > 12 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("RESERVE_USDT0_CODE must be 1-12 alphanumeric characters".to_string());
    }
    // Stellar asset codes are byte-compared: `usdt0` and `USDT0` from one
    // issuer are two different assets, and a trustline to the lowercase one
    // succeeds on-chain while every real deposit bounces at the sender. A
    // case variant of the canonical code is never intended — refuse it.
    if code != RESERVE_DEFAULT_USDT0_CODE && code.eq_ignore_ascii_case(RESERVE_DEFAULT_USDT0_CODE) {
        return Err(format!(
            "RESERVE_USDT0_CODE '{}' is a case variant of {}; asset codes are case-sensitive",
            code, RESERVE_DEFAULT_USDT0_CODE
        ));
    }
    if code == usdc_code && issuer == usdc_issuer {
        return Err(
            "RESERVE_USDT0_CODE/RESERVE_USDT0_ISSUER are identical to the USDC asset".to_string(),
        );
    }
    for t in tickers {
        let t = t.to_ascii_lowercase();
        if t == RESERVE_TICKER_XLM
            || t == "usdc"
            || RESERVE_STELLAR_USDC_TICKERS.iter().any(|u| t == *u)
        {
            return Err(format!(
                "RESERVE_USDT0_TICKERS entry '{}' already means XLM or USDC",
                t
            ));
        }
    }
    Ok(Some(ReserveAsset {
        currency: RESERVE_CURRENCY_USDT0,
        code: code.to_string(),
        issuer: issuer.to_string(),
    }))
}

/// The configured reserve account id, independent of whether the reserve
/// actually initialized.
///
/// [`ConversionReserve`] is absent whenever initialization failed or was
/// deferred — including the bootstrap window in which `RESERVE_ACCOUNT_ID` is
/// set but its custodial seed has not been provisioned yet. Any guard that
/// keys off the handle therefore disarms exactly when the reserve account is
/// unclaimed and most worth protecting. This one is always present and keyed
/// off configuration, so it stays armed through that window.
pub struct ReserveAccountGuard {
    account_id: Option<String>,
}

impl ReserveAccountGuard {
    pub fn from_config(config: &Config) -> Self {
        ReserveAccountGuard {
            account_id: config
                .reserve_account_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .map(str::to_string),
        }
    }

    /// True when `payala_account_id` is the designated reserve account.
    pub fn matches(&self, payala_account_id: &str) -> bool {
        self.account_id.as_deref() == Some(payala_account_id)
    }

    /// True when `RESERVE_ACCOUNT_ID` is set — the reserve is at least
    /// *armed*, whether or not a live handle exists. Lets `/health` tell
    /// "off" from "armed but inactive" without exposing the account id.
    pub fn is_configured(&self) -> bool {
        self.account_id.is_some()
    }
}

/// Build the reserve handle from config. `Ok(None)` = feature off
/// (RESERVE_ACCOUNT_ID unset); `Err` = configured but unusable — a hard
/// startup error, because a half-configured pool on a money path must fail
/// closed (exchange-provider precedent).
pub async fn init_conversion_reserve(
    config: &Config,
    pool: &PgPool,
) -> Result<Option<Arc<ConversionReserve>>, String> {
    let account_id = match config.reserve_account_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return Ok(None),
    };
    let issuer = config
        .reserve_usdc_issuer
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or("RESERVE_ACCOUNT_ID is set but RESERVE_USDC_ISSUER is not")?
        .to_string();
    // Checksummed, not merely well-formed: a mistyped issuer is the one
    // configuration error that makes every real deposit look foreign and
    // every payout fail at submit, while looking valid on inspection.
    crate::validate::validate_stellar_account_id_checksum(&issuer).map_err(|e| {
        format!(
            "RESERVE_USDC_ISSUER is not a valid Stellar account id: {}",
            e
        )
    })?;
    let code = config.reserve_usdc_code.clone();
    if code.is_empty() || code.len() > 12 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("RESERVE_USDC_CODE must be 1-12 alphanumeric characters".to_string());
    }
    if code != "USDC" && code.eq_ignore_ascii_case("USDC") {
        return Err(format!(
            "RESERVE_USDC_CODE '{}' is a case variant of USDC; asset codes are case-sensitive",
            code
        ));
    }
    let usdt0 = validate_usdt0_config(
        config.reserve_usdt0_issuer.as_deref(),
        &config.reserve_usdt0_code,
        &config.reserve_usdt0_tickers,
        &code,
        &issuer,
    )?;
    // The bucket row is the FK target of every USDT0 journal entry. Without
    // it (036 not applied) the first USDT0 deposit would fail to book, and
    // the watcher would replay that failure every tick — so refuse to start
    // rather than run a configured asset with nowhere to account for it.
    if usdt0.is_some() {
        let seeded: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM conversion_reserve WHERE currency = $1)",
        )
        .bind(RESERVE_CURRENCY_USDT0)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("reserve init: USDT0 bucket lookup failed: {}", e))?;
        if !seeded {
            return Err(
                "RESERVE_USDT0_ISSUER is set but the USDT0 bucket does not exist — apply \
                 migration 036 (RUN_MODE=migrate) before enabling USDT0"
                    .to_string(),
            );
        }
    }

    // The reserve must be a managed-seed account this bridge can sign for.
    let stellar_address: Option<String> = sqlx::query_scalar(
        "SELECT stellar_account_id FROM managed_seed WHERE payala_account_id = $1",
    )
    .bind(&account_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("reserve init: managed seed lookup failed: {}", e))?;
    let stellar_address = match stellar_address {
        Some(addr) => addr,
        // Armed but inactive. The endpoint that provisions this seed
        // (`POST /admin/stellar-seeds/generate`) lives inside this process, so
        // exiting here would make the reserve unrecoverable without a
        // configuration change: the bridge would crash-loop on the very
        // condition the endpoint exists to repair. Diversion stays off — every
        // order passes through to its provider, which is the reserve's
        // existing behaviour on any miss — and `ReserveAccountGuard` keeps the
        // account quarantined from the user-facing custodial endpoints
        // throughout, because that guard reads configuration rather than this
        // handle.
        None if config.key_import_enabled => {
            error!(
                "RESERVE_ACCOUNT_ID '{}' has no managed seed. The conversion reserve is \
                 ARMED BUT INACTIVE: no order will divert to it and no payout can be \
                 signed. Provision the seed with POST /admin/stellar-seeds/generate and \
                 restart. (The account stays quarantined from /managed-account/* meanwhile.)",
                account_id
            );
            return Ok(None);
        }
        None => {
            return Err(format!(
                "RESERVE_ACCOUNT_ID '{}' has no managed seed — provision one with \
                 POST /admin/stellar-seeds/generate (requires KEY_IMPORT_ENABLED=true) \
                 and restart",
                account_id
            ));
        }
    };
    // The reserve must never be its own issuer: an asset it issued is
    // minted, not held, and every burn guard keyed on the issuer address
    // would refuse the reserve's own payouts.
    if issuer == stellar_address || usdt0.as_ref().is_some_and(|a| a.issuer == stellar_address) {
        return Err(format!(
            "reserve account {} is configured as an asset issuer; the reserve cannot issue \
             the assets it holds",
            stellar_address
        ));
    }

    // Initialize the deposit-scan cursor BEFORE any order can be created:
    // the watcher's first tick runs up to watch_secs after startup, and a
    // cursor initialized there to "latest" would skip any deposit that
    // landed in between. Doing it here (routes are not serving yet) makes
    // the cursor provably older than every divertable order. Fail closed on
    // Horizon being unreachable — the reserve cannot safely take deposits
    // it might never see.
    let cursor: Option<String> =
        sqlx::query_scalar("SELECT horizon_cursor FROM conversion_reserve_state WHERE id")
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("reserve init: cursor read failed: {}", e))?
            .flatten();
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.http_client_timeout_secs,
        ))
        .build()
        .map_err(|e| format!("reserve init: http client: {}", e))?;
    if cursor.is_none() {
        let latest = crate::stellar::horizon::fetch_latest_cursor(
            &http,
            &config.stellar_horizon_url,
            &stellar_address,
        )
        .await
        .map_err(|_| {
            "reserve init: Horizon unreachable while initializing the deposit cursor".to_string()
        })?;
        if let Some(latest) = latest {
            sqlx::query(
                "UPDATE conversion_reserve_state SET horizon_cursor = $1 \
                 WHERE id AND horizon_cursor IS NULL",
            )
            .bind(&latest)
            .execute(pool)
            .await
            .map_err(|e| format!("reserve init: cursor write failed: {}", e))?;
        }
        // An empty feed needs no cursor: scanning from the beginning is
        // then equivalent.
    }

    // Total price-option exposure is the lock window PLUS the deposit window:
    // a client holds a fixed amount_to across both and may walk away for
    // free. Cap it at the ceiling 031 sanctioned for the deposit window
    // alone, so adding locks cannot widen the option beyond what was
    // reviewed. This depends on configured values, so it cannot be a const
    // assert — and it fails startup closed, like every other misconfigured
    // money path here.
    let quote_ttl = config
        .reserve_quote_ttl_secs
        .clamp(RESERVE_QUOTE_TTL_MIN_SECS, RESERVE_QUOTE_TTL_MAX_SECS);
    let deposit_ttl = config
        .reserve_deposit_ttl_secs
        .clamp(RESERVE_DEPOSIT_TTL_MIN_SECS, RESERVE_DEPOSIT_TTL_MAX_SECS);
    if quote_ttl + deposit_ttl > RESERVE_TOTAL_PRICE_WINDOW_MAX_SECS {
        return Err(format!(
            "RESERVE_QUOTE_TTL_SECS ({}) + RESERVE_DEPOSIT_TTL_SECS ({}) = {} exceeds the {}s \
             ceiling on total price-option exposure; lower one of them",
            quote_ttl,
            deposit_ttl,
            quote_ttl + deposit_ttl,
            RESERVE_TOTAL_PRICE_WINDOW_MAX_SECS
        ));
    }
    let quote_ttl_secs = quote_ttl;

    let reserve = ConversionReserve {
        reserve_account_id: account_id,
        stellar_address,
        usdc_code: code,
        usdc_issuer: issuer,
        usdt0,
        usdt0_tickers: config.reserve_usdt0_tickers.clone(),
        deposit_ttl_secs: config
            .reserve_deposit_ttl_secs
            .clamp(RESERVE_DEPOSIT_TTL_MIN_SECS, RESERVE_DEPOSIT_TTL_MAX_SECS),
        watch_secs: config.reserve_watch_secs.max(5),
        quote_ttl_secs,
    };

    // Trustline audit for every configured stablecoin. Deliberately not
    // fatal: a missing trustline cannot lose money (a payment to an account
    // without one fails at the SENDER), but it makes the bucket silently
    // unreachable — so it is shouted here, surfaced per bucket on
    // GET /admin/exchange-reserve, and repaired by POST .../trustlines.
    match crate::stellar::fetch_account_details(
        &http,
        &config.stellar_horizon_url,
        &reserve.stellar_address,
    )
    .await
    {
        Ok(acct) if acct.exists => {
            for (bucket, code, issuer) in reserve.stablecoins() {
                let trusted = acct.balances.iter().any(|b| {
                    b.asset_code.as_deref() == Some(code)
                        && b.asset_issuer.as_deref() == Some(issuer)
                });
                if !trusted {
                    error!(
                        "RESERVE: account {} holds NO trustline for {} ({}:{}) — it can neither \
                         receive nor pay that asset until an admin adds one with \
                         POST /admin/exchange-reserve/trustlines",
                        reserve.stellar_address, bucket, code, issuer
                    );
                }
            }
        }
        Ok(_) => log::warn!(
            "reserve init: account {} is not funded on-chain yet; trustlines unverified",
            reserve.stellar_address
        ),
        Err(_) => log::warn!("reserve init: Horizon unreachable; stablecoin trustlines unverified"),
    }

    Ok(Some(Arc::new(reserve)))
}

// ── Money conversions (the ONE string<->minor-unit boundary) ───────────

/// Parse a validated decimal string into i64 minor units at `scale` decimal
/// places. Checked arithmetic throughout; rejects more fraction digits than
/// the scale allows (silent truncation on money is a bug, not a rounding
/// mode) and anything but ASCII digits and one dot.
pub fn parse_decimal_to_minor(s: &str, scale: u8) -> Option<i64> {
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    if frac_part.len() > scale as usize {
        return None;
    }
    let mut value: i64 = 0;
    for c in int_part.chars() {
        value = value
            .checked_mul(10)?
            .checked_add((c as u8 - b'0') as i64)?;
    }
    let mut frac: i64 = 0;
    for c in frac_part.chars() {
        frac = frac.checked_mul(10)?.checked_add((c as u8 - b'0') as i64)?;
    }
    for _ in frac_part.len()..scale as usize {
        frac = frac.checked_mul(10)?;
    }
    value
        .checked_mul(10i64.checked_pow(scale as u32)?)?
        .checked_add(frac)
}

/// Render minor units back to a canonical decimal string ("12.5" at scale 7
/// renders "12.5000000"; scale 0 renders bare integers).
pub fn minor_to_decimal_string(minor: i64, scale: u8) -> String {
    let base = 10i64.pow(scale as u32);
    if scale == 0 {
        return minor.to_string();
    }
    // Sign handled explicitly: integer division truncates toward zero, so
    // -5 cents would render "0.05" if the sign rode on `minor / base`.
    let sign = if minor < 0 { "-" } else { "" };
    let abs = minor.unsigned_abs();
    format!(
        "{}{}.{:0width$}",
        sign,
        abs / base.unsigned_abs(),
        abs % base.unsigned_abs(),
        width = scale as usize
    )
}

/// 7-dp Stellar minor units -> USD cents, rounding UP: threshold eligibility
/// must err toward "too big" (200.0000001 USDC is over a $200 threshold).
pub fn stellar_minor_to_usd_cents_ceil(minor: i64) -> i64 {
    const FACTOR: i64 = 100_000; // 10^(7-2)
    minor / FACTOR + i64::from(minor % FACTOR != 0)
}

/// Linear scaling for sub-minimum pricing: `amount * ref_to / ref_from`,
/// exact in i128, floored (bridge-favorable). None on nonsensical inputs.
pub fn scale_linear(amount_minor: i64, ref_from_minor: i64, ref_to_minor: i64) -> Option<i64> {
    if amount_minor <= 0 || ref_from_minor <= 0 || ref_to_minor <= 0 {
        return None;
    }
    let scaled = (amount_minor as i128)
        .checked_mul(ref_to_minor as i128)?
        .checked_div(ref_from_minor as i128)?;
    i64::try_from(scaled).ok().filter(|v| *v > 0)
}

// ── Order reference / pay-in memo ──────────────────────────────────────

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford-base32 rendering of the order UUID's 128 bits: 26 uppercase
/// chars, well under Stellar's 28-byte MEMO_TEXT limit. Doubles as the
/// `provider_order_id` (unique via `uq_exchange_order_provider_ref`) and the
/// pay-in memo the watcher matches on. Deterministic so crash recovery and
/// support can always re-derive it from the order id.
pub fn base32_order_ref(order_id: &Uuid) -> String {
    let mut n = order_id.as_u128();
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(n & 0x1f) as usize];
        n >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("base32 alphabet is ASCII")
}

/// Case-insensitive memo comparison (some wallet UIs lowercase memo input).
pub fn memo_matches_ref(memo: &str, order_ref: &str) -> bool {
    memo.trim().eq_ignore_ascii_case(order_ref)
}

// ── Eligibility ────────────────────────────────────────────────────────

/// The two divertable order shapes.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DivertShape {
    /// changelly_crypto XLM -> Stellar-USDC swap: automatic on-chain payout.
    AutoSwap,
    /// owlpay Stellar-USDC -> USD off-ramp: pay-in auto-detected, fiat leg is
    /// an admin disbursement work-queue item.
    Disburse,
}

fn is_stellar_usdc_ticker(t: &str) -> bool {
    RESERVE_STELLAR_USDC_TICKERS
        .iter()
        .any(|u| t.eq_ignore_ascii_case(u))
}

/// Which stablecoin bucket a provider ticker denotes on Stellar, if any:
/// the built-in USDC tickers, or the operator-configured USDT0 tickers when
/// USDT0 is configured. Without a reserve handle only USDC is known — the
/// USDT0 leg can never be selected by a ticker the operator did not verify.
pub fn stablecoin_for_ticker(reserve: Option<&ConversionReserve>, t: &str) -> Option<&'static str> {
    if is_stellar_usdc_ticker(t) {
        return Some(RESERVE_CURRENCY_USDC);
    }
    let r = reserve?;
    let usdt0 = r.usdt0.as_ref()?;
    r.usdt0_tickers
        .iter()
        .any(|u| t.eq_ignore_ascii_case(u))
        .then_some(usdt0.currency)
}

/// A divertable order: its shape plus the Stellar stablecoin leg — the
/// payout asset of an auto-swap, the pay-in asset of a disburse.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Divert {
    pub shape: DivertShape,
    pub stablecoin: &'static str,
}

/// Shape-only view of [`divert_with`] with the USDC-only ticker set (the
/// pure gate the shape tests exercise; production always passes a reserve).
#[cfg(test)]
pub(crate) fn divert_shape(payload: &CreateExchangeOrderRequest) -> Option<DivertShape> {
    divert_with(payload, None).map(|d| d.shape)
}

/// Pure shape gate. Deliberately strict: anything the reserve cannot serve
/// end-to-end passes through untouched — bare "usdc" swap targets commonly
/// mean non-Stellar USDC on Changelly, fixed-rate orders carry a provider
/// contract the reserve would silently discard, and an owlpay order without
/// beneficiary/payout_instrument leaves the admin queue nothing to pay.
/// `reserve` widens the recognized stablecoin tickers to the configured
/// USDT0 set; `None` recognizes USDC only.
pub fn divert_with(
    payload: &CreateExchangeOrderRequest,
    reserve: Option<&ConversionReserve>,
) -> Option<Divert> {
    match payload.provider.as_str() {
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => {
            if payload.direction != EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO {
                return None;
            }
            if !payload
                .from_currency
                .eq_ignore_ascii_case(RESERVE_TICKER_XLM)
            {
                return None;
            }
            let stablecoin = stablecoin_for_ticker(reserve, &payload.to_currency)?;
            if payload.rate_type.as_deref() == Some("fixed") || payload.rate_id.is_some() {
                return None;
            }
            // A payout address is required to have anywhere to send USDC.
            payload.payout_address.as_deref()?;
            // The receiver's memo rides the payout as MEMO_TEXT (<= 28
            // bytes). A longer one would fail at submit time — after the
            // deposit was taken — so it must fall through to the provider.
            if payload
                .payout_extra_id
                .as_deref()
                .is_some_and(|m| m.len() > 28)
            {
                return None;
            }
            Some(Divert {
                shape: DivertShape::AutoSwap,
                stablecoin,
            })
        }
        EXCHANGE_PROVIDER_OWLPAY => {
            if payload.direction != EXCHANGE_DIRECTION_CRYPTO_TO_FIAT {
                return None;
            }
            // OwlPay names Stellar USDC by the bare "usdc" ticker (the chain
            // rides separately), which is why it is accepted here and not
            // on the Changelly swap side.
            let stablecoin = match stablecoin_for_ticker(reserve, &payload.from_currency) {
                Some(s) => s,
                None if payload.from_currency.eq_ignore_ascii_case("usdc") => RESERVE_CURRENCY_USDC,
                None => return None,
            };
            if !RESERVE_USD_TICKERS
                .iter()
                .any(|u| payload.to_currency.eq_ignore_ascii_case(u))
            {
                return None;
            }
            if payload.beneficiary.is_none() && payload.payout_instrument.is_none() {
                return None;
            }
            Some(Divert {
                shape: DivertShape::Disburse,
                stablecoin,
            })
        }
        _ => None,
    }
}

/// Extract `amountTo` from a Changelly estimation result (array-of-one form).
pub(crate) fn extract_estimate_amount_to(v: &serde_json::Value) -> Option<String> {
    let obj = if let Some(arr) = v.as_array() {
        arr.first()?
    } else {
        v
    };
    json_decimal_string(&obj["amountTo"])
}

/// Price an AutoSwap in USDC minor units via the diverted provider's own
/// float estimate; below the provider's estimate minimum, scale linearly
/// from a reference-notional estimate. Returns `(amount_to_minor, pricing)`.
pub(crate) async fn price_auto_swap(
    changelly: &ChangellyCrypto,
    payload: &CreateExchangeOrderRequest,
    amount_from_minor: i64,
) -> Option<(i64, &'static str)> {
    match changelly
        .get_exchange_amount(
            &payload.from_currency,
            &payload.to_currency,
            &payload.amount_from,
        )
        .await
    {
        Ok(v) => {
            let s = extract_estimate_amount_to(&v)?;
            let minor = parse_decimal_to_minor(&s, RESERVE_SCALE_STELLAR)?;
            (minor > 0).then_some((minor, "provider_estimate"))
        }
        // Provider minimum violations surface as BadRequest; price those from
        // a reference notional instead. Transport/provider errors stay None.
        Err(AppError::BadRequest(_)) => {
            let v = changelly
                .get_exchange_amount(
                    &payload.from_currency,
                    &payload.to_currency,
                    REFERENCE_XLM_AMOUNT,
                )
                .await
                .ok()?;
            let ref_to =
                parse_decimal_to_minor(&extract_estimate_amount_to(&v)?, RESERVE_SCALE_STELLAR)?;
            let ref_from = parse_decimal_to_minor(REFERENCE_XLM_AMOUNT, RESERVE_SCALE_STELLAR)?;
            let minor = scale_linear(amount_from_minor, ref_from, ref_to)?;
            Some((minor, "scaled_reference"))
        }
        Err(_) => None,
    }
}

/// Best-effort payout destination check: the account must exist and hold a
/// trustline for the payout asset, or the payment is guaranteed to fail
/// op_no_trust AFTER the user has deposited. Indeterminate (Horizon error)
/// reads as "not verified" — pass through, the provider validates.
pub(crate) async fn payout_has_trustline(
    http: &reqwest::Client,
    horizon_url: &str,
    address: &str,
    code: &str,
    issuer: &str,
) -> bool {
    match crate::stellar::fetch_account_details(http, horizon_url, address).await {
        Ok(acct) => {
            acct.exists
                && acct.balances.iter().any(|b| {
                    b.asset_code.as_deref() == Some(code)
                        && b.asset_issuer.as_deref() == Some(issuer)
                })
        }
        Err(_) => false,
    }
}

// ── Price locks (called from create_quote) ─────────────────────────────

/// Decide whether a quote request can be price-locked, and mint the lock.
///
/// Eligibility runs through the SAME [`divert_shape`] gate order creation
/// uses, by way of a synthetic order request: one gate, zero drift. A quote
/// the gate would accept but order creation would refuse could otherwise
/// mint a lock that can never be consumed, burning capacity until it expires.
pub(crate) async fn try_lock_quote(
    ctx: &DivertContext<'_>,
    account_id: &str,
    q: &crate::models::ExchangeQuoteRequest,
    provider_quotes: &serde_json::Value,
) -> Result<Option<crate::models::ReserveQuoteView>, AppError> {
    let synthetic: CreateExchangeOrderRequest = match serde_json::from_value(json!({
        "account_id": account_id,
        "provider": q.provider,
        "direction": q.direction,
        "from_currency": q.from_currency,
        "to_currency": q.to_currency,
        "amount_from": q.amount_from,
        "payout_address": q.payout_address,
        "payout_extra_id": q.payout_extra_id,
        "rate_type": q.rate_type,
        // A quote request carries no beneficiary; disburse shapes supply it
        // at order time, so stand in with a placeholder purely so the shared
        // shape gate sees the same request the order will present.
        "beneficiary": if q.direction == EXCHANGE_DIRECTION_CRYPTO_TO_FIAT {
            Some(json!({}))
        } else {
            None
        },
    })) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let divert = match divert_with(&synthetic, Some(ctx.reserve)) {
        Some(d) => d,
        None => return Ok(None),
    };
    let shape = divert.shape;

    let policy: Option<(bool, i64)> = sqlx::query_as(
        "SELECT enabled, threshold_usd_cents FROM conversion_reserve_policy WHERE provider = $1",
    )
    .bind(&q.provider)
    .fetch_optional(ctx.pool)
    .await
    .map_err(|e| {
        error!("try_lock_quote: policy lookup error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    let threshold_usd_cents = match policy {
        Some((true, t)) => t,
        _ => return Ok(None),
    };

    let amount_from_minor = match parse_decimal_to_minor(&q.amount_from, RESERVE_SCALE_STELLAR) {
        Some(v) if v > 0 => v,
        _ => return Ok(None),
    };

    let (hold_currency, hold_minor, pricing) = match shape {
        DivertShape::AutoSwap => {
            let payout_address = match synthetic.payout_address.as_deref() {
                Some(a) if crate::validate::validate_stellar_account_id(a).is_ok() => a,
                _ => return Ok(None),
            };
            // Reuse the estimate the handler already fetched — quoting twice
            // would spend the provider's request budget for nothing.
            let amount_to_minor = match extract_estimate_amount_to(provider_quotes)
                .and_then(|s| parse_decimal_to_minor(&s, RESERVE_SCALE_STELLAR))
                .filter(|v| *v > 0)
            {
                Some(v) => (v, "provider_estimate"),
                None => {
                    let changelly = match ctx.changelly_crypto {
                        Some(c) => c,
                        None => return Ok(None),
                    };
                    match price_auto_swap(changelly, &synthetic, amount_from_minor).await {
                        Some(p) => p,
                        None => return Ok(None),
                    }
                }
            };
            let (amount_to_minor, pricing) = amount_to_minor;
            if stellar_minor_to_usd_cents_ceil(amount_to_minor) > threshold_usd_cents {
                return Ok(None);
            }
            let Some((code, issuer)) = ctx.reserve.stablecoin(divert.stablecoin) else {
                return Ok(None);
            };
            if !payout_has_trustline(ctx.http, ctx.horizon_url, payout_address, code, issuer).await
            {
                return Ok(None);
            }
            (divert.stablecoin, amount_to_minor, pricing)
        }
        DivertShape::Disburse => {
            let usd_cents = stellar_minor_to_usd_cents_ceil(amount_from_minor);
            if usd_cents > threshold_usd_cents {
                return Ok(None);
            }
            (RESERVE_CURRENCY_USD, usd_cents, "usd_par")
        }
    };

    crate::exchange::reserve_quote::mint_quote(
        ctx.pool,
        ctx.reserve,
        account_id,
        &synthetic,
        shape,
        hold_currency,
        hold_minor,
        pricing,
    )
    .await
}

// ── Diversion (called from create_order before provider dispatch) ──────

pub struct DivertContext<'a> {
    pub pool: &'a PgPool,
    pub metrics: &'a AppMetrics,
    pub reserve: &'a ConversionReserve,
    pub changelly_crypto: Option<&'a Arc<ChangellyCrypto>>,
    pub http: &'a reqwest::Client,
    pub horizon_url: &'a str,
}

/// Divert a small order to the reserve when every condition holds.
/// `Ok(None)` = not diverted, continue to the provider (the common case and
/// every pre-commit failure); `Ok(Some)` = diverted, respond with it;
/// `Err` = the creation transaction may have committed — surface the error,
/// a silent provider fallback here could double-create.
pub async fn try_divert_order(
    ctx: &DivertContext<'_>,
    payload: &CreateExchangeOrderRequest,
) -> Result<Option<ExchangeOrderResponse>, AppError> {
    // Defence in depth against self-dealing. The replenishment job creates
    // xlm->usdcxlm orders OWNED BY the reserve account and paid TO the
    // reserve address — a shape divert_shape otherwise accepts. It bypasses
    // this function entirely, but if any future caller does not, diverting
    // would mean the reserve buying from itself while no XLM ever leaves.
    // These run BEFORE the quoted branch so no path can skip them.
    if payload.account_id == ctx.reserve.reserve_account_id {
        return Ok(None);
    }
    if payload.payout_address.as_deref() == Some(ctx.reserve.stellar_address.as_str()) {
        return Ok(None);
    }

    // A named quote is a commitment: honor it or refuse. Never fall through
    // to the provider at a different price, and never after a consume that
    // may already have committed.
    if let Some(raw) = payload.reserve_quote_id.as_deref() {
        let quote_id = uuid::Uuid::parse_str(raw)
            .map_err(|_| AppError::BadRequest("reserve_quote_id must be a UUID".to_string()))?;
        return crate::exchange::reserve_quote::divert_quoted_order(ctx, payload, quote_id)
            .await
            .map(Some);
    }

    let divert = match divert_with(payload, Some(ctx.reserve)) {
        Some(d) => d,
        None => return Ok(None),
    };
    let shape = divert.shape;

    // Runtime policy (admin-editable): enabled + threshold for THIS provider.
    let policy: Option<(bool, i64)> = sqlx::query_as(
        "SELECT enabled, threshold_usd_cents FROM conversion_reserve_policy WHERE provider = $1",
    )
    .bind(&payload.provider)
    .fetch_optional(ctx.pool)
    .await
    .map_err(|e| {
        error!("try_divert_order: policy lookup error: {}", e);
        AppError::InternalError("Database error".to_string())
    })
    .unwrap_or(None);
    let threshold_usd_cents = match policy {
        Some((true, t)) => t,
        _ => return Ok(None),
    };

    let amount_from_minor =
        match parse_decimal_to_minor(&payload.amount_from, RESERVE_SCALE_STELLAR) {
            Some(v) if v > 0 => v,
            _ => {
                ctx.metrics.record_reserve_fallback("amount_parse");
                return Ok(None);
            }
        };

    // Shape-specific pricing, threshold check, and hold target.
    let (hold_currency, hold_minor, amount_to_string, pricing) = match shape {
        DivertShape::AutoSwap => {
            let payout_address = payload
                .payout_address
                .as_deref()
                .expect("divert_shape requires payout_address");
            if crate::validate::validate_stellar_account_id(payout_address).is_err() {
                ctx.metrics.record_reserve_fallback("payout_not_stellar");
                return Ok(None);
            }
            let changelly = match ctx.changelly_crypto {
                Some(c) => c,
                None => {
                    ctx.metrics.record_reserve_fallback("quote_unavailable");
                    return Ok(None);
                }
            };
            let (amount_to_minor, pricing) =
                match price_auto_swap(changelly, payload, amount_from_minor).await {
                    Some(p) => p,
                    None => {
                        ctx.metrics.record_reserve_fallback("quote_failed");
                        return Ok(None);
                    }
                };
            if stellar_minor_to_usd_cents_ceil(amount_to_minor) > threshold_usd_cents {
                return Ok(None); // ordinary big order — not a fallback
            }
            let Some((code, issuer)) = ctx.reserve.stablecoin(divert.stablecoin) else {
                ctx.metrics.record_reserve_fallback("payout_untrusted");
                return Ok(None);
            };
            if !payout_has_trustline(ctx.http, ctx.horizon_url, payout_address, code, issuer).await
            {
                ctx.metrics.record_reserve_fallback("payout_untrusted");
                return Ok(None);
            }
            (
                divert.stablecoin,
                amount_to_minor,
                minor_to_decimal_string(amount_to_minor, RESERVE_SCALE_STELLAR),
                pricing,
            )
        }
        DivertShape::Disburse => {
            let usd_cents = stellar_minor_to_usd_cents_ceil(amount_from_minor);
            if usd_cents > threshold_usd_cents {
                return Ok(None);
            }
            (
                RESERVE_CURRENCY_USD,
                usd_cents,
                minor_to_decimal_string(usd_cents, RESERVE_SCALE_USD),
                "usd_par",
            )
        }
    };

    // Everything from here mutates state: one transaction, advisory-locked
    // per account so the open-order cap cannot race itself.
    let order_id = Uuid::new_v4();
    let order_ref = base32_order_ref(&order_id);
    let deposit_currency = deposit_currency_for(&divert);
    match run_creation_tx(
        ctx,
        payload,
        shape,
        order_id,
        &order_ref,
        hold_currency,
        hold_minor,
        &amount_to_string,
        pricing,
        deposit_currency,
    )
    .await?
    {
        CreationOutcome::Created => {}
        CreationOutcome::CapExceeded => {
            ctx.metrics.record_reserve_fallback("open_order_cap");
            return Ok(None);
        }
        CreationOutcome::Insufficient => {
            ctx.metrics.record_reserve_fallback("insufficient");
            return Ok(None);
        }
    }

    // Metrics only after commit (house rule).
    ctx.metrics
        .record_exchange_order(EXCHANGE_PROVIDER_RESERVE, "success");
    ctx.metrics.record_reserve_diverted(&payload.provider);
    info!(
        "try_divert_order: diverted order {} from {} account={} amount_from={} amount_to={} ({})",
        order_id,
        payload.provider,
        payload.account_id,
        payload.amount_from,
        amount_to_string,
        pricing
    );

    let detail = sqlx::query_as::<_, ExchangeOrderDetail>(&format!(
        "SELECT {} FROM exchange_order WHERE order_id = $1",
        crate::handlers::exchange::exchange_order_detail_columns()
    ))
    .bind(order_id)
    .fetch_one(ctx.pool)
    .await
    .map_err(|e| {
        error!("try_divert_order: read-back error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let deadline =
        chrono::Utc::now() + chrono::Duration::seconds(ctx.reserve.deposit_ttl_secs as i64);
    Ok(Some(ExchangeOrderResponse {
        success: true,
        message: format!(
            "Exchange order created successfully. Send the pay-in WITH THE MEMO before {} — \
             late pay-ins expire",
            deadline.format("%Y-%m-%dT%H:%M:%SZ")
        ),
        order: Some(detail),
    }))
}

enum CreationOutcome {
    Created,
    CapExceeded,
    Insufficient,
}

/// The bucket an auto-swap order pays out of, from the `hold_currency` its
/// provider_payload recorded at creation. Only bucket keys the reserve
/// defines are honored — an unknown value falls back to USDC rather than
/// being trusted as a bucket name (pre-036 rows always carried
/// `hold_currency`, so the fallback only covers a malformed payload).
/// Shared by the watcher's payout driver and the admin resolve path so the
/// two can never disagree about which bucket a payout settles from.
pub fn payout_bucket_for_hold_currency(hold_currency: Option<&str>) -> &'static str {
    match hold_currency {
        Some(c) if c == RESERVE_CURRENCY_USDT0 => RESERVE_CURRENCY_USDT0,
        _ => RESERVE_CURRENCY_USDC,
    }
}

/// The bucket an order's pay-in must arrive in: native XLM for an auto-swap,
/// the stablecoin leg for a disburse. Persisted on the order so the deposit
/// watcher matches against what was agreed, not against current config.
pub(crate) fn deposit_currency_for(divert: &Divert) -> &'static str {
    match divert.shape {
        DivertShape::AutoSwap => RESERVE_CURRENCY_XLM,
        DivertShape::Disburse => divert.stablecoin,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_creation_tx(
    ctx: &DivertContext<'_>,
    payload: &CreateExchangeOrderRequest,
    shape: DivertShape,
    order_id: Uuid,
    order_ref: &str,
    hold_currency: &str,
    hold_minor: i64,
    amount_to_string: &str,
    pricing: &'static str,
    deposit_currency: &'static str,
) -> Result<CreationOutcome, AppError> {
    let db_err = |context: &'static str| {
        move |e: sqlx::Error| {
            error!("reserve creation tx: {}: {}", context, e);
            AppError::InternalError("Database error".to_string())
        }
    };

    let mut tx = ctx.pool.begin().await.map_err(db_err("begin"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('conv_reserve:' || $1::text))")
        .bind(&payload.account_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("advisory lock"))?;

    let open: i64 = sqlx::query_scalar(OPEN_RESERVE_ORDERS_SQL)
        .bind(&payload.account_id)
        .bind(crate::exchange::reconcile::non_terminal_statuses())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("open-order count"))?;
    if open >= RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT {
        return Ok(CreationOutcome::CapExceeded);
    }

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_HOLD_SQL)
        .bind(hold_currency)
        .bind(hold_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("hold"))?;
    let (available_after, held_after, low_water) = match bucket {
        Some(b) => b,
        None => return Ok(CreationOutcome::Insufficient),
    };

    // Beneficiary/payout coordinates ride in provider_payload, which client
    // responses deliberately exclude — only the admin disburse queue reads it.
    let provider_payload = json!({
        "diverted_from": payload.provider,
        "pricing": pricing,
        "hold_currency": hold_currency,
        "hold_minor": hold_minor,
        "deposit_currency": deposit_currency,
        "shape": match shape {
            DivertShape::AutoSwap => "auto_swap",
            DivertShape::Disburse => "disburse",
        },
        "beneficiary": payload.beneficiary,
        "payout_instrument": payload.payout_instrument,
        // Persisted so a refund honors the destination the customer stated,
        // rather than inferring one from a possibly-omnibus sender address.
        "refund_address": payload.refund_address,
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
        .bind(Some(amount_to_string.to_string()))
        .bind(EXCHANGE_STATUS_AWAITING_DEPOSIT)
        .bind(Option::<String>::None)
        .bind(order_ref)
        .bind(Some(ctx.reserve.stellar_address.clone()))
        .bind(Some(order_ref.to_string()))
        .bind(&payload.payout_address)
        .bind(&payload.payout_extra_id)
        .bind(Option::<String>::None)
        .bind(Option::<serde_json::Value>::None)
        .bind(&provider_payload)
        .bind(next_poll_at)
        .execute(&mut *tx)
        .await
        .map_err(db_err("order insert"))?;

    journal_insert(JournalEntry {
        currency: hold_currency.to_string(),
        kind: "hold".to_string(),
        delta: -hold_minor,
        held_delta: hold_minor,
        balance_after: available_after,
        held_after,
        order_id: Some(order_id),
        diverted_provider: Some(payload.provider.clone()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("hold entry"))?;

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

    if low_water > 0 && available_after < low_water {
        warn!(
            "conversion reserve {} below low water: available={} low_water={}",
            hold_currency, available_after, low_water
        );
        crate::events::emit_event(
            &mut tx,
            &crate::events::AccountEvent::ReserveLowWater {
                account_id: ctx.reserve.reserve_account_id.clone(),
                currency: hold_currency.to_string(),
                available_minor: available_after,
                low_water_minor: low_water,
            },
        )
        .await?;
    }

    tx.commit().await.map_err(db_err("commit"))?;
    Ok(CreationOutcome::Created)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order_request() -> CreateExchangeOrderRequest {
        serde_json::from_value(json!({
            "account_id": "acct-1",
            "provider": "changelly_crypto",
            "direction": "crypto_to_crypto",
            "from_currency": "xlm",
            "to_currency": "usdcxlm",
            "amount_from": "50.5",
            "payout_address": "GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37"
        }))
        .expect("valid request json")
    }

    // ── parse_decimal_to_minor ─────────────────────────────────────────

    #[test]
    fn parses_plain_and_fractional_amounts() {
        assert_eq!(parse_decimal_to_minor("0", 7), Some(0));
        assert_eq!(parse_decimal_to_minor("1", 7), Some(10_000_000));
        assert_eq!(parse_decimal_to_minor("25.5", 7), Some(255_000_000));
        assert_eq!(parse_decimal_to_minor("0.0000001", 7), Some(1));
        assert_eq!(parse_decimal_to_minor("12.34", 2), Some(1234));
        assert_eq!(
            parse_decimal_to_minor("200.0000001", 7),
            Some(2_000_000_001)
        );
        // Leading zeros are fine (validate_decimal_amount allows them).
        assert_eq!(parse_decimal_to_minor("007", 2), Some(700));
        // Trailing dot forms.
        assert_eq!(parse_decimal_to_minor("5.", 2), Some(500));
        assert_eq!(parse_decimal_to_minor(".5", 2), Some(50));
    }

    #[test]
    fn rejects_excess_precision_signs_and_junk() {
        // More fraction digits than the scale carries would silently drop
        // value — reject instead.
        assert_eq!(parse_decimal_to_minor("1.001", 2), None);
        assert_eq!(parse_decimal_to_minor("1.00000001", 7), None);
        assert_eq!(parse_decimal_to_minor("-1", 7), None);
        assert_eq!(parse_decimal_to_minor("+1", 7), None);
        assert_eq!(parse_decimal_to_minor("1e5", 7), None);
        assert_eq!(parse_decimal_to_minor("", 7), None);
        assert_eq!(parse_decimal_to_minor(".", 7), None);
        assert_eq!(parse_decimal_to_minor("1.2.3", 7), None);
        assert_eq!(parse_decimal_to_minor("1 0", 7), None);
    }

    #[test]
    fn rejects_overflow() {
        // i64::MAX at 7dp is ~922 billion whole units; this overflows.
        assert_eq!(parse_decimal_to_minor("999999999999999", 7), None);
        // Well inside range parses.
        assert_eq!(
            parse_decimal_to_minor("922337203685.4775807", 7),
            Some(i64::MAX)
        );
    }

    #[test]
    fn minor_to_decimal_keeps_sign_on_small_negatives() {
        // Truncating division loses the sign of sub-unit negatives.
        assert_eq!(minor_to_decimal_string(-5, 2), "-0.05");
        assert_eq!(minor_to_decimal_string(-1, 7), "-0.0000001");
        assert_eq!(minor_to_decimal_string(-1234, 2), "-12.34");
        assert_eq!(minor_to_decimal_string(-7, 0), "-7");
    }

    #[test]
    fn minor_to_decimal_round_trips() {
        for (minor, scale, s) in [
            (255_000_000, 7, "25.5000000"),
            (1, 7, "0.0000001"),
            (1234, 2, "12.34"),
            (0, 7, "0.0000000"),
            (2000, 0, "2000"),
        ] {
            assert_eq!(minor_to_decimal_string(minor, scale), s);
            assert_eq!(parse_decimal_to_minor(s, scale), Some(minor));
        }
    }

    // ── threshold conversion ───────────────────────────────────────────

    #[test]
    fn usd_cents_ceiling_rounds_against_eligibility() {
        assert_eq!(stellar_minor_to_usd_cents_ceil(0), 0);
        // 200 USDC exactly -> 20000 cents.
        assert_eq!(stellar_minor_to_usd_cents_ceil(2_000_000_000), 20_000);
        // One stroop over $200 must round UP and become ineligible.
        assert_eq!(stellar_minor_to_usd_cents_ceil(2_000_000_001), 20_001);
        // $19.999.. rounds up to exactly 2000 cents.
        assert_eq!(stellar_minor_to_usd_cents_ceil(199_999_991), 2_000);
    }

    #[test]
    fn scale_linear_is_exact_and_floored() {
        // 10 XLM at a 100 XLM -> 26.18 USDC reference = 2.618 USDC.
        assert_eq!(
            scale_linear(100_000_000, 1_000_000_000, 261_800_000),
            Some(26_180_000)
        );
        // Floors, never rounds up.
        assert_eq!(scale_linear(1, 3, 1), None); // 1/3 floors to 0 -> None
        assert_eq!(scale_linear(2, 3, 2), Some(1));
        assert_eq!(scale_linear(-5, 3, 2), None);
        assert_eq!(scale_linear(5, 0, 2), None);
    }

    // ── order ref / memo ───────────────────────────────────────────────

    #[test]
    fn order_ref_is_26_uppercase_crockford_chars_and_deterministic() {
        let id = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        let r = base32_order_ref(&id);
        assert_eq!(r.len(), 26);
        assert!(r.len() <= 28, "must fit Stellar MEMO_TEXT");
        assert!(r.chars().all(|c| CROCKFORD.contains(&(c as u8))));
        // Deterministic.
        assert_eq!(r, base32_order_ref(&id));
        // Distinct ids -> distinct refs.
        let id2 = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c9").unwrap();
        assert_ne!(r, base32_order_ref(&id2));
    }

    #[test]
    fn memo_matching_is_case_insensitive_and_trimmed() {
        let id = Uuid::new_v4();
        let r = base32_order_ref(&id);
        assert!(memo_matches_ref(&r, &r));
        assert!(memo_matches_ref(&r.to_lowercase(), &r));
        assert!(memo_matches_ref(&format!(" {} ", r), &r));
        assert!(!memo_matches_ref("", &r));
        assert!(!memo_matches_ref(&r[1..], &r));
    }

    // ── shape gate ─────────────────────────────────────────────────────

    #[test]
    fn auto_swap_shape_accepts_the_target_order() {
        assert_eq!(divert_shape(&order_request()), Some(DivertShape::AutoSwap));
    }

    #[test]
    fn auto_swap_shape_is_strict() {
        let mut p = order_request();
        p.to_currency = "usdc".to_string(); // non-Stellar USDC form
        assert_eq!(divert_shape(&p), None);

        let mut p = order_request();
        p.from_currency = "btc".to_string();
        assert_eq!(divert_shape(&p), None);

        let mut p = order_request();
        p.direction = "crypto_to_fiat".to_string();
        assert_eq!(divert_shape(&p), None);

        let mut p = order_request();
        p.rate_type = Some("fixed".to_string());
        assert_eq!(divert_shape(&p), None);

        let mut p = order_request();
        p.rate_id = Some("r-1".to_string());
        assert_eq!(divert_shape(&p), None);

        let mut p = order_request();
        p.payout_address = None;
        assert_eq!(divert_shape(&p), None);

        // Case-insensitive tickers still divert.
        let mut p = order_request();
        p.from_currency = "XLM".to_string();
        p.to_currency = "USDCXLM".to_string();
        assert_eq!(divert_shape(&p), Some(DivertShape::AutoSwap));

        // A payout memo that cannot fit Stellar MEMO_TEXT (28 bytes) would
        // fail at submit time — AFTER the deposit was taken — so it must
        // pass through to the provider instead.
        let mut p = order_request();
        p.payout_extra_id = Some("x".repeat(29));
        assert_eq!(divert_shape(&p), None);
        p.payout_extra_id = Some("x".repeat(28));
        assert_eq!(divert_shape(&p), Some(DivertShape::AutoSwap));
    }

    #[test]
    fn disburse_shape_requires_usd_and_payout_coordinates() {
        let mut p = order_request();
        p.provider = "owlpay".to_string();
        p.direction = "crypto_to_fiat".to_string();
        p.from_currency = "usdcxlm".to_string();
        p.to_currency = "usd".to_string();
        p.beneficiary = Some(json!({"name": "A"}));
        assert_eq!(divert_shape(&p), Some(DivertShape::Disburse));

        // Bare usdc from-ticker is allowed for owlpay (chain is enforced by
        // where the deposit must physically arrive).
        p.from_currency = "USDC".to_string();
        assert_eq!(divert_shape(&p), Some(DivertShape::Disburse));

        p.to_currency = "eur".to_string();
        assert_eq!(divert_shape(&p), None);
        p.to_currency = "usd".to_string();

        p.beneficiary = None;
        p.payout_instrument = None;
        assert_eq!(divert_shape(&p), None);
        p.payout_instrument = Some(json!({"iban": "x"}));
        assert_eq!(divert_shape(&p), Some(DivertShape::Disburse));

        p.from_currency = "eth".to_string();
        assert_eq!(divert_shape(&p), None);
    }

    #[test]
    fn fiat_to_crypto_and_changelly_fiat_never_divert() {
        let mut p = order_request();
        p.provider = "changelly_fiat".to_string();
        assert_eq!(divert_shape(&p), None);

        let mut p = order_request();
        p.provider = "owlpay".to_string();
        p.direction = "fiat_to_crypto".to_string();
        p.beneficiary = Some(json!({}));
        assert_eq!(divert_shape(&p), None);
    }

    // ── estimate extraction ────────────────────────────────────────────

    #[test]
    fn extracts_amount_to_from_estimation_shapes() {
        assert_eq!(
            extract_estimate_amount_to(&json!([{ "amountTo": "26.18" }])),
            Some("26.18".to_string())
        );
        assert_eq!(
            extract_estimate_amount_to(&json!({ "amountTo": 26.0 })),
            Some("26.0".to_string())
        );
        assert_eq!(extract_estimate_amount_to(&json!([])), None);
        assert_eq!(extract_estimate_amount_to(&json!([{ "other": 1 }])), None);
    }

    // ── SQL shape pins (house style) ───────────────────────────────────

    #[test]
    fn hold_sql_guards_balance_and_fraction() {
        assert!(RESERVE_HOLD_SQL.contains("available >= $2"));
        assert!(RESERVE_HOLD_SQL.contains("(held + $2) * 2 <= (available + held)"));
        assert!(RESERVE_HOLD_SQL.contains("RETURNING available, held, low_water"));
    }

    #[test]
    fn bucket_apply_sql_guards_both_columns() {
        assert!(RESERVE_BUCKET_APPLY_SQL.contains("available + $2 >= 0"));
        assert!(RESERVE_BUCKET_APPLY_SQL.contains("held + $3 >= 0"));
    }

    #[test]
    fn entry_insert_covers_all_journal_columns() {
        for col in [
            "currency",
            "kind",
            "delta",
            "held_delta",
            "balance_after",
            "held_after",
            "order_id",
            "diverted_provider",
            "stellar_tx_hash",
            "paging_token",
            "admin_account_id",
            "note",
        ] {
            assert!(
                RESERVE_ENTRY_INSERT_SQL.contains(col),
                "missing column {}",
                col
            );
        }
    }

    // ── USDT0: pinned second stablecoin ─────────────────────────────────

    const USDT0_ISSUER: &str = "GATISXX6BZ6NC7IKQBY37CJD4SOZL3CYZJWXEDG6JVIY4WBS6KXJHN6Q";
    const USDC_ISSUER: &str = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7";

    fn test_reserve(usdt0: bool) -> ConversionReserve {
        ConversionReserve {
            reserve_account_id: "svc-reserve".to_string(),
            stellar_address: "GRESERVE".to_string(),
            usdc_code: "USDC".to_string(),
            usdc_issuer: USDC_ISSUER.to_string(),
            usdt0: usdt0.then(|| ReserveAsset {
                currency: RESERVE_CURRENCY_USDT0,
                code: "USDT0".to_string(),
                issuer: USDT0_ISSUER.to_string(),
            }),
            usdt0_tickers: if usdt0 {
                vec!["usdt0xlm".to_string()]
            } else {
                vec![]
            },
            deposit_ttl_secs: 1800,
            watch_secs: 30,
            quote_ttl_secs: 300,
        }
    }

    #[test]
    fn usdt0_config_is_off_when_unset() {
        assert_eq!(
            validate_usdt0_config(None, "USDT0", &[], "USDC", USDC_ISSUER),
            Ok(None)
        );
        // Whitespace-only counts as unset.
        assert_eq!(
            validate_usdt0_config(Some("  "), "USDT0", &[], "USDC", USDC_ISSUER),
            Ok(None)
        );
    }

    #[test]
    fn usdt0_config_pins_a_checksummed_issuer() {
        let a = validate_usdt0_config(Some(USDT0_ISSUER), "USDT0", &[], "USDC", USDC_ISSUER)
            .unwrap()
            .unwrap();
        assert_eq!(a.currency, RESERVE_CURRENCY_USDT0);
        assert_eq!(a.code, "USDT0");
        assert_eq!(a.issuer, USDT0_ISSUER);
        // A single mistyped character is refused (structurally valid but not
        // an address) — the failure that would otherwise make every real
        // deposit look foreign.
        let typo = format!("{}A", &USDT0_ISSUER[..55]);
        assert!(validate_usdt0_config(Some(&typo), "USDT0", &[], "USDC", USDC_ISSUER).is_err());
    }

    #[test]
    fn usdt0_config_rejects_bad_codes_and_usdc_collision() {
        assert!(validate_usdt0_config(Some(USDT0_ISSUER), "", &[], "USDC", USDC_ISSUER).is_err());
        assert!(validate_usdt0_config(
            Some(USDT0_ISSUER),
            "TOO-LONG-CODE!",
            &[],
            "USDC",
            USDC_ISSUER
        )
        .is_err());
        // Same (code, issuer) as USDC is a copy-paste error, not a second asset.
        assert!(
            validate_usdt0_config(Some(USDC_ISSUER), "USDC", &[], "USDC", USDC_ISSUER).is_err()
        );
        // Same issuer with a different code is legal Stellar and allowed.
        assert!(
            validate_usdt0_config(Some(USDC_ISSUER), "USDT0", &[], "USDC", USDC_ISSUER).is_ok()
        );
    }

    #[test]
    fn usdt0_tickers_cannot_shadow_xlm_or_usdc_and_need_an_issuer() {
        for bad in ["xlm", "USDCXLM", "usdc"] {
            assert!(validate_usdt0_config(
                Some(USDT0_ISSUER),
                "USDT0",
                &[bad.to_string()],
                "USDC",
                USDC_ISSUER
            )
            .is_err());
        }
        assert!(validate_usdt0_config(
            Some(USDT0_ISSUER),
            "USDT0",
            &["usdt0xlm".to_string()],
            "USDC",
            USDC_ISSUER
        )
        .is_ok());
        // Tickers with no asset behind them fail closed.
        assert!(validate_usdt0_config(
            None,
            "USDT0",
            &["usdt0xlm".to_string()],
            "USDC",
            USDC_ISSUER
        )
        .is_err());
    }

    #[test]
    fn bucket_for_asset_pins_code_and_issuer() {
        let r = test_reserve(true);
        assert_eq!(
            r.bucket_for_asset("native", None, None),
            Some(RESERVE_CURRENCY_XLM)
        );
        assert_eq!(
            r.bucket_for_asset("credit_alphanum4", Some("USDC"), Some(USDC_ISSUER)),
            Some(RESERVE_CURRENCY_USDC)
        );
        assert_eq!(
            r.bucket_for_asset("credit_alphanum12", Some("USDT0"), Some(USDT0_ISSUER)),
            Some(RESERVE_CURRENCY_USDT0)
        );
        // The type tag never decides identity (alphanum4 vs alphanum12).
        assert_eq!(
            r.bucket_for_asset("credit_alphanum4", Some("USDT0"), Some(USDT0_ISSUER)),
            Some(RESERVE_CURRENCY_USDT0)
        );
        // Right code, wrong issuer: foreign. Both directions.
        assert_eq!(
            r.bucket_for_asset("credit_alphanum12", Some("USDT0"), Some(USDC_ISSUER)),
            None
        );
        assert_eq!(
            r.bucket_for_asset("credit_alphanum4", Some("USDC"), Some(USDT0_ISSUER)),
            None
        );
        // Missing identity on a non-native asset (e.g. a pool share): foreign.
        assert_eq!(
            r.bucket_for_asset("liquidity_pool_shares", None, None),
            None
        );
        // Unconfigured USDT0 is foreign even from the real issuer.
        let off = test_reserve(false);
        assert_eq!(
            off.bucket_for_asset("credit_alphanum12", Some("USDT0"), Some(USDT0_ISSUER)),
            None
        );
        // Stored rows: NULL code is native.
        assert_eq!(
            r.bucket_for_stored_asset(None, None),
            Some(RESERVE_CURRENCY_XLM)
        );
        assert_eq!(
            r.bucket_for_stored_asset(Some("USDT0"), Some(USDT0_ISSUER)),
            Some(RESERVE_CURRENCY_USDT0)
        );
        assert_eq!(r.bucket_for_stored_asset(Some("USDT0"), None), None);
    }

    #[test]
    fn asset_for_bucket_never_substitutes_an_asset() {
        let r = test_reserve(true);
        assert_eq!(r.asset_for_bucket("XLM"), Some(Asset::Native));
        assert!(matches!(
            r.asset_for_bucket("USDT0"),
            Some(Asset::Credit { ref code, ref issuer }) if code == "USDT0" && issuer == USDT0_ISSUER
        ));
        assert!(matches!(
            r.asset_for_bucket("USDC"),
            Some(Asset::Credit { ref code, ref issuer }) if code == "USDC" && issuer == USDC_ISSUER
        ));
        // USD is a bank balance; an unconfigured USDT0 has nothing to send.
        assert!(r.asset_for_bucket("USD").is_none());
        assert!(test_reserve(false).asset_for_bucket("USDT0").is_none());
        assert!(r.asset_for_bucket("EURC").is_none());
    }

    #[test]
    fn issuer_burn_guard_covers_every_configured_issuer() {
        let r = test_reserve(true);
        assert!(r.is_asset_issuer(USDC_ISSUER));
        assert!(r.is_asset_issuer(USDT0_ISSUER));
        assert!(!r.is_asset_issuer("GRESERVE"));
        assert_eq!(r.issuer_addresses(), vec![USDC_ISSUER, USDT0_ISSUER]);
        assert!(!test_reserve(false).is_asset_issuer(USDT0_ISSUER));
    }

    #[test]
    fn stablecoin_tickers_are_operator_gated() {
        let on = test_reserve(true);
        let off = test_reserve(false);
        assert_eq!(
            stablecoin_for_ticker(None, "usdcxlm"),
            Some(RESERVE_CURRENCY_USDC)
        );
        assert_eq!(
            stablecoin_for_ticker(Some(&on), "USDCXLM"),
            Some(RESERVE_CURRENCY_USDC)
        );
        // The USDT0 ticker is recognized only with a reserve that configured
        // it — never bare, never when USDT0 is off.
        assert_eq!(
            stablecoin_for_ticker(Some(&on), "usdt0xlm"),
            Some(RESERVE_CURRENCY_USDT0)
        );
        assert_eq!(
            stablecoin_for_ticker(Some(&on), "USDT0XLM"),
            Some(RESERVE_CURRENCY_USDT0)
        );
        assert_eq!(stablecoin_for_ticker(None, "usdt0xlm"), None);
        assert_eq!(stablecoin_for_ticker(Some(&off), "usdt0xlm"), None);
        assert_eq!(stablecoin_for_ticker(Some(&on), "usdt"), None);
    }

    #[test]
    fn payout_bucket_follows_hold_currency_and_never_trusts_unknown_keys() {
        assert_eq!(
            payout_bucket_for_hold_currency(Some("USDT0")),
            RESERVE_CURRENCY_USDT0
        );
        assert_eq!(
            payout_bucket_for_hold_currency(Some("USDC")),
            RESERVE_CURRENCY_USDC
        );
        assert_eq!(payout_bucket_for_hold_currency(None), RESERVE_CURRENCY_USDC);
        assert_eq!(
            payout_bucket_for_hold_currency(Some("EURC")),
            RESERVE_CURRENCY_USDC
        );
        assert_eq!(
            payout_bucket_for_hold_currency(Some("usdt0")),
            RESERVE_CURRENCY_USDC
        );
    }

    #[test]
    fn auto_swap_diverts_to_the_usdt0_leg_only_when_configured() {
        let mut p = order_request();
        p.to_currency = "usdt0xlm".to_string();
        // Shape-only gate (USDC tickers): not divertable.
        assert_eq!(divert_shape(&p), None);
        assert_eq!(divert_with(&p, Some(&test_reserve(false))), None);
        let d = divert_with(&p, Some(&test_reserve(true))).unwrap();
        assert_eq!(d.shape, DivertShape::AutoSwap);
        assert_eq!(d.stablecoin, RESERVE_CURRENCY_USDT0);
        assert_eq!(deposit_currency_for(&d), RESERVE_CURRENCY_XLM);
        // USDC orders are untouched by USDT0 being on.
        let usdc = divert_with(&order_request(), Some(&test_reserve(true))).unwrap();
        assert_eq!(usdc.stablecoin, RESERVE_CURRENCY_USDC);
    }

    #[test]
    fn disburse_records_the_stablecoin_it_expects() {
        let mut p = order_request();
        p.provider = "owlpay".to_string();
        p.direction = "crypto_to_fiat".to_string();
        p.from_currency = "usdt0xlm".to_string();
        p.to_currency = "usd".to_string();
        p.beneficiary = Some(json!({"name": "A"}));
        assert_eq!(divert_shape(&p), None);
        let d = divert_with(&p, Some(&test_reserve(true))).unwrap();
        assert_eq!(d.shape, DivertShape::Disburse);
        assert_eq!(d.stablecoin, RESERVE_CURRENCY_USDT0);
        assert_eq!(deposit_currency_for(&d), RESERVE_CURRENCY_USDT0);
        // Bare "usdc" still means Stellar USDC for owlpay, with USDT0 on.
        p.from_currency = "usdc".to_string();
        let d = divert_with(&p, Some(&test_reserve(true))).unwrap();
        assert_eq!(d.stablecoin, RESERVE_CURRENCY_USDC);
        assert_eq!(deposit_currency_for(&d), RESERVE_CURRENCY_USDC);
    }

    #[test]
    fn usdt0_code_case_variants_are_refused() {
        // A case variant of the canonical code is a typo, not an asset: the
        // trustline would succeed on-chain while real deposits bounce.
        for typo in ["usdt0", "Usdt0", "USDt0"] {
            assert!(
                validate_usdt0_config(Some(USDT0_ISSUER), typo, &[], "USDC", USDC_ISSUER).is_err(),
                "{typo} must be refused"
            );
        }
        // A genuinely different code (e.g. a testnet test asset) is fine.
        assert!(
            validate_usdt0_config(Some(USDT0_ISSUER), "TUSDT", &[], "USDC", USDC_ISSUER).is_ok()
        );
    }
}

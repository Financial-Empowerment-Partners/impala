//! Admin management of the conversion reserve (`/admin/exchange-reserve/*`).
//!
//! All endpoints are `AdminUser`-gated. Value-moving ones (manual entries,
//! disburse, resolve) additionally carry the custodial-sign rate limit
//! (5/min) and write audit `info!` lines plus outbox events. Every ledger
//! mutation follows the module rules from `exchange/reserve.rs`: guarded
//! single-statement bucket UPDATE + journal entry in one transaction,
//! idempotent per order via `UNIQUE(order_id, kind)`.
//!
//! Forecasting is pure integer arithmetic over the journal's daily net
//! flows: mean, EWMA (alpha 0.3), least-squares trend, projected days to
//! depletion, and a suggested top-up for a target coverage window. The math
//! lives in pure functions so it is unit-tested without a database.

use axum::extract::{Path, Query};
use axum::{Extension, Json};
use chrono::{Duration as ChronoDuration, NaiveDate, Utc};
use log::{error, info, warn};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::constants::{
    RESERVE_ADMIN_ENTRY_KINDS, RESERVE_CURRENCY_USDC, RESERVE_DISBURSE_MAX_MULTIPLE,
    RESERVE_RESOLVE_FAIL_MIN_INTENT_AGE_SECS, RESERVE_SCALE_STELLAR, RESERVE_SCALE_USD,
    RESERVE_SUPPORTED_POLICY_PROVIDERS, RESERVE_THRESHOLD_MAX_USD_CENTS,
    RESERVE_THRESHOLD_MIN_USD_CENTS, RESERVE_WATCH_PAGE_LIMIT, SIGN_RATE_LIMIT_MAX_REQUESTS,
    SIGN_RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::events::AccountEvent;
use crate::exchange::reserve::{
    memo_matches_ref, minor_to_decimal_string, parse_decimal_to_minor, ConversionReserve,
    RESERVE_BUCKET_APPLY_SQL, RESERVE_ENTRY_INSERT_SQL,
};
use crate::models::{
    PaginationParams, ReserveBucketUpdateRequest, ReserveBucketView, ReserveCurrencyForecast,
    ReserveDailyFlow, ReserveDisburseRequest, ReserveEntryRequest, ReserveEntryView,
    ReserveForecastQuery, ReserveForecastResponse, ReservePendingCounts,
    ReservePolicyUpdateRequest, ReservePolicyView, ReserveProviderUtilization,
    ReserveResolveRequest, ReserveStatusResponse, ReserveUnmatchedView,
};
use crate::telemetry::AppMetrics;

const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("admin_reserve: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// Standard envelope for admin mutations here.
#[derive(serde::Serialize)]
pub struct ReserveActionResponse {
    pub success: bool,
    pub message: String,
}

fn ok(message: impl Into<String>) -> Json<ReserveActionResponse> {
    Json(ReserveActionResponse {
        success: true,
        message: message.into(),
    })
}

// ── Status ─────────────────────────────────────────────────────────────

/// `GET /admin/exchange-reserve` — buckets, policies, pending queues, and a
/// best-effort on-chain snapshot for drift visibility.
pub async fn get_status(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    reserve: Option<Extension<Arc<ConversionReserve>>>,
) -> Result<Json<ReserveStatusResponse>, AppError> {
    let mut buckets: Vec<ReserveBucketView> = sqlx::query_as(
        "SELECT currency, minor_scale, available AS available_minor, held AS held_minor, \
                low_water AS low_water_minor \
         FROM conversion_reserve ORDER BY currency",
    )
    .fetch_all(&pool)
    .await
    .map_err(db_err("buckets"))?;

    let mut policies: Vec<ReservePolicyView> = sqlx::query_as(&format!(
        "SELECT provider, enabled, threshold_usd_cents, \
                to_char(updated_at AT TIME ZONE 'UTC', '{ts}') AS updated_at \
         FROM conversion_reserve_policy ORDER BY provider",
        ts = TS_FMT
    ))
    .fetch_all(&pool)
    .await
    .map_err(db_err("policies"))?;
    for p in &mut policies {
        p.supported = RESERVE_SUPPORTED_POLICY_PROVIDERS.contains(&p.provider.as_str());
    }

    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) FROM exchange_order \
         WHERE provider = 'reserve' AND status IN ('awaiting_deposit', 'processing', 'on_hold') \
         GROUP BY status",
    )
    .fetch_all(&pool)
    .await
    .map_err(db_err("pending counts"))?;
    let mut pending = ReservePendingCounts::default();
    for (status, n) in counts {
        match status.as_str() {
            "awaiting_deposit" => pending.awaiting_deposit = n,
            "processing" => pending.processing = n,
            "on_hold" => pending.on_hold = n,
            _ => {}
        }
    }
    pending.awaiting_disbursement = sqlx::query_scalar(
        "SELECT COUNT(*) FROM exchange_order \
         WHERE provider = 'reserve' AND status = 'processing' \
           AND provider_status = 'awaiting_disbursement'",
    )
    .fetch_one(&pool)
    .await
    .map_err(db_err("disbursement count"))?;

    let (configured, stellar_address, ttl) = match &reserve {
        Some(Extension(r)) => (
            true,
            Some(r.stellar_address.clone()),
            Some(r.deposit_ttl_secs),
        ),
        None => (false, None, None),
    };

    // Best-effort chain snapshot; never fails the endpoint.
    if let Some(Extension(r)) = &reserve {
        match crate::stellar::fetch_account_details(
            &http,
            &stellar_config.horizon_url,
            &r.stellar_address,
        )
        .await
        {
            Ok(acct) if acct.exists => {
                for b in &mut buckets {
                    b.onchain_balance = match b.currency.as_str() {
                        "XLM" => acct.native_balance.clone(),
                        "USDC" => acct
                            .balances
                            .iter()
                            .find(|bal| {
                                bal.asset_code.as_deref() == Some(r.usdc_code.as_str())
                                    && bal.asset_issuer.as_deref() == Some(r.usdc_issuer.as_str())
                            })
                            .map(|bal| bal.balance.clone()),
                        _ => None,
                    };
                }
            }
            Ok(_) => warn!("admin_reserve: reserve account not found on-chain"),
            Err(_) => warn!("admin_reserve: on-chain snapshot unavailable"),
        }
    }

    Ok(Json(ReserveStatusResponse {
        configured,
        stellar_address,
        deposit_ttl_secs: ttl,
        buckets,
        policies,
        pending,
    }))
}

// ── Policies / buckets ─────────────────────────────────────────────────

/// `PUT /admin/exchange-reserve/policies/{provider}` — enable/threshold.
pub async fn update_policy(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Path(provider): Path<String>,
    Json(payload): Json<ReservePolicyUpdateRequest>,
) -> Result<Json<ReserveActionResponse>, AppError> {
    if !RESERVE_SUPPORTED_POLICY_PROVIDERS.contains(&provider.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Reserve fulfillment for '{}' is not supported. Supported providers: {}",
            provider,
            RESERVE_SUPPORTED_POLICY_PROVIDERS.join(", ")
        )));
    }
    if payload.threshold_usd_cents < RESERVE_THRESHOLD_MIN_USD_CENTS
        || payload.threshold_usd_cents > RESERVE_THRESHOLD_MAX_USD_CENTS
    {
        return Err(AppError::BadRequest(format!(
            "threshold_usd_cents must be between {} ($20) and {} ($200)",
            RESERVE_THRESHOLD_MIN_USD_CENTS, RESERVE_THRESHOLD_MAX_USD_CENTS
        )));
    }

    let mut tx = pool.begin().await.map_err(db_err("policy begin"))?;
    sqlx::query(
        "INSERT INTO conversion_reserve_policy (provider, enabled, threshold_usd_cents, updated_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (provider) DO UPDATE \
             SET enabled = EXCLUDED.enabled, \
                 threshold_usd_cents = EXCLUDED.threshold_usd_cents, \
                 updated_by = EXCLUDED.updated_by",
    )
    .bind(&provider)
    .bind(payload.enabled)
    .bind(payload.threshold_usd_cents)
    .bind(&user.account_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err("policy upsert"))?;
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReservePolicyUpdated {
            account_id: user.account_id.clone(),
            provider: provider.clone(),
            enabled: payload.enabled,
            threshold_usd_cents: payload.threshold_usd_cents,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("policy commit"))?;

    info!(
        "update_policy: provider={} enabled={} threshold_usd_cents={} by={}",
        provider, payload.enabled, payload.threshold_usd_cents, user.account_id
    );
    Ok(ok("Reserve policy updated"))
}

/// `PUT /admin/exchange-reserve/buckets/{currency}` — low-water mark.
pub async fn update_bucket(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Path(currency): Path<String>,
    Json(payload): Json<ReserveBucketUpdateRequest>,
) -> Result<Json<ReserveActionResponse>, AppError> {
    if payload.low_water_minor < 0 {
        return Err(AppError::BadRequest(
            "low_water_minor must be >= 0".to_string(),
        ));
    }
    let updated = sqlx::query("UPDATE conversion_reserve SET low_water = $2 WHERE currency = $1")
        .bind(&currency)
        .bind(payload.low_water_minor)
        .execute(&pool)
        .await
        .map_err(db_err("bucket update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("No such reserve bucket".to_string()));
    }
    info!(
        "update_bucket: currency={} low_water={} by={}",
        currency, payload.low_water_minor, user.account_id
    );
    Ok(ok("Reserve bucket updated"))
}

// ── Manual ledger entries ──────────────────────────────────────────────

/// `POST /admin/exchange-reserve/entries` — topup/withdrawal/adjustment/
/// held_adjustment. The ledger tracks the chain: record a topup only after
/// the matching on-chain/bank funding actually happened (runbook).
pub async fn create_entry(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Json(payload): Json<ReserveEntryRequest>,
) -> Result<Json<ReserveActionResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "reserve_admin",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    if !RESERVE_ADMIN_ENTRY_KINDS.contains(&payload.kind.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid kind '{}'. Must be one of: {}",
            payload.kind,
            RESERVE_ADMIN_ENTRY_KINDS.join(", ")
        )));
    }
    if payload.amount_minor == 0 {
        return Err(AppError::BadRequest(
            "amount_minor must not be zero".to_string(),
        ));
    }
    if matches!(payload.kind.as_str(), "topup" | "withdrawal") && payload.amount_minor < 0 {
        return Err(AppError::BadRequest(
            "topup/withdrawal take a positive magnitude; use 'adjustment' for signed corrections"
                .to_string(),
        ));
    }
    if let Some(note) = &payload.note {
        if note.len() > 500 {
            return Err(AppError::BadRequest(
                "note must be at most 500 characters".to_string(),
            ));
        }
    }

    // Signed effect per kind.
    let (delta, held_delta) = match payload.kind.as_str() {
        "topup" => (payload.amount_minor, 0),
        "withdrawal" => (-payload.amount_minor, 0),
        "adjustment" => (payload.amount_minor, 0),
        _ => (0, payload.amount_minor), // held_adjustment
    };

    let mut tx = pool.begin().await.map_err(db_err("entry begin"))?;
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&payload.currency)
        .bind(delta)
        .bind(held_delta)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("entry apply"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        AppError::Conflict("No such bucket, or the operation would overdraw it".to_string())
    })?;

    sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(&payload.currency)
        .bind(&payload.kind)
        .bind(delta)
        .bind(held_delta)
        .bind(bal_after)
        .bind(held_after)
        .bind(Option::<Uuid>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Some(user.account_id.clone()))
        .bind(&payload.note)
        .execute(&mut *tx)
        .await
        .map_err(db_err("entry insert"))?;
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReserveEntryRecorded {
            account_id: user.account_id.clone(),
            currency: payload.currency.clone(),
            kind: payload.kind.clone(),
            amount_minor: payload.amount_minor,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("entry commit"))?;

    metrics.record_reserve_manual_entry(&payload.kind);
    info!(
        "create_entry: {} {} {} by={} (available={} held={})",
        payload.kind,
        payload.amount_minor,
        payload.currency,
        user.account_id,
        bal_after,
        held_after
    );
    Ok(ok("Reserve entry recorded"))
}

/// `GET /admin/exchange-reserve/entries` — paginated journal.
#[derive(Debug, serde::Deserialize)]
pub struct ReserveEntryListQuery {
    #[serde(flatten)]
    pub page: PaginationParams,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
}

pub async fn list_entries(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<ReserveEntryListQuery>,
) -> Result<Json<crate::models::PaginatedResponse<ReserveEntryView>>, AppError> {
    if let Some(k) = &q.kind {
        if !crate::constants::VALID_RESERVE_ENTRY_KINDS.contains(&k.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid kind '{}'. Must be one of: {}",
                k,
                crate::constants::VALID_RESERVE_ENTRY_KINDS.join(", ")
            )));
        }
    }
    let (per_page, offset) = q.page.clamped();

    let mut where_sql = String::from("WHERE true");
    if q.currency.is_some() {
        where_sql.push_str(" AND currency = $3");
    }
    if q.kind.is_some() {
        where_sql.push_str(if q.currency.is_some() {
            " AND kind = $4"
        } else {
            " AND kind = $3"
        });
    }

    let count_sql = format!(
        "SELECT COUNT(*) FROM conversion_reserve_entry {}",
        where_sql
    )
    .replace("$3", "$1")
    .replace("$4", "$2");
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(c) = &q.currency {
        count_q = count_q.bind(c);
    }
    if let Some(k) = &q.kind {
        count_q = count_q.bind(k);
    }
    let total: i64 = count_q
        .fetch_one(&pool)
        .await
        .map_err(db_err("entry count"))?;

    let list_sql = format!(
        "SELECT entry_id, currency, kind, delta, held_delta, balance_after, held_after, \
                order_id, diverted_provider, stellar_tx_hash, admin_account_id, note, \
                to_char(created_at AT TIME ZONE 'UTC', '{ts}') AS created_at \
         FROM conversion_reserve_entry {w} \
         ORDER BY created_at DESC, entry_id DESC LIMIT $1 OFFSET $2",
        ts = TS_FMT,
        w = where_sql
    );
    let mut list_q = sqlx::query_as::<_, ReserveEntryView>(&list_sql)
        .bind(per_page)
        .bind(offset);
    if let Some(c) = &q.currency {
        list_q = list_q.bind(c);
    }
    if let Some(k) = &q.kind {
        list_q = list_q.bind(k);
    }
    let data = list_q
        .fetch_all(&pool)
        .await
        .map_err(db_err("entry list"))?;

    Ok(Json(crate::models::PaginatedResponse {
        data,
        page: ((offset / per_page) + 1) as u64,
        per_page: per_page as u64,
        total: total.max(0) as u64,
    }))
}

/// `GET /admin/exchange-reserve/unmatched` — stray-inflow work queue.
pub async fn list_unmatched(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<PaginationParams>,
) -> Result<Json<crate::models::PaginatedResponse<ReserveUnmatchedView>>, AppError> {
    let (per_page, offset) = q.clamped();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conversion_reserve_unmatched")
        .fetch_one(&pool)
        .await
        .map_err(db_err("unmatched count"))?;
    let data = sqlx::query_as::<_, ReserveUnmatchedView>(&format!(
        "SELECT paging_token, tx_hash, op_type, asset_code, asset_issuer, amount, \
                amount_minor, memo, matched_order_id, reason, \
                to_char(seen_at AT TIME ZONE 'UTC', '{ts}') AS seen_at \
         FROM conversion_reserve_unmatched \
         ORDER BY seen_at DESC, paging_token DESC LIMIT $1 OFFSET $2",
        ts = TS_FMT
    ))
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(db_err("unmatched list"))?;

    Ok(Json(crate::models::PaginatedResponse {
        data,
        page: ((offset / per_page) + 1) as u64,
        per_page: per_page as u64,
        total: total.max(0) as u64,
    }))
}

// ── Forecast ───────────────────────────────────────────────────────────

/// Integer EWMA with alpha = 0.3: `(3*today + 7*prev) / 10`, seeded with the
/// first observation.
pub(crate) fn ewma_daily(series: &[i64]) -> i64 {
    let mut it = series.iter();
    let mut ewma = match it.next() {
        Some(v) => *v,
        None => return 0,
    };
    for v in it {
        ewma = (3 * v + 7 * ewma) / 10;
    }
    ewma
}

/// Least-squares slope over evenly spaced observations, in value-units per
/// day. Exact i128 internally, rounded toward zero.
pub(crate) fn trend_slope(series: &[i64]) -> i64 {
    let n = series.len() as i128;
    if n < 2 {
        return 0;
    }
    let sum_x: i128 = (0..n).sum();
    let sum_y: i128 = series.iter().map(|v| *v as i128).sum();
    let sum_xy: i128 = series
        .iter()
        .enumerate()
        .map(|(i, v)| i as i128 * *v as i128)
        .sum();
    let sum_x2: i128 = (0..n).map(|x| x * x).sum();
    let denom = n * sum_x2 - sum_x * sum_x;
    if denom == 0 {
        return 0;
    }
    ((n * sum_xy - sum_x * sum_y) / denom) as i64
}

/// Fill `[as_of - window + 1 .. as_of]` from sparse (day, out, in) rows.
pub(crate) fn fill_daily_series(
    rows: &[(NaiveDate, i64, i64)],
    as_of: NaiveDate,
    window_days: i64,
) -> Vec<ReserveDailyFlow> {
    let by_day: HashMap<NaiveDate, (i64, i64)> =
        rows.iter().map(|(d, o, i)| (*d, (*o, *i))).collect();
    (0..window_days)
        .map(|i| {
            let day = as_of - ChronoDuration::days(window_days - 1 - i);
            let (outflow, inflow) = by_day.get(&day).copied().unwrap_or((0, 0));
            ReserveDailyFlow {
                day: day.format("%Y-%m-%d").to_string(),
                outflow_minor: outflow,
                inflow_minor: inflow,
            }
        })
        .collect()
}

/// Build one currency's forecast from its filled daily series and bucket
/// state. Pure; `as_of` is a parameter so tests are deterministic.
#[allow(clippy::too_many_arguments)]
pub(crate) fn forecast_currency(
    currency: &str,
    minor_scale: i16,
    available: i64,
    held: i64,
    low_water: i64,
    daily: Vec<ReserveDailyFlow>,
    as_of: NaiveDate,
    target_days: i64,
) -> ReserveCurrencyForecast {
    let outflows: Vec<i64> = daily.iter().map(|d| d.outflow_minor).collect();
    let n = outflows.len().max(1) as i64;
    let avg = outflows.iter().sum::<i64>() / n;
    let ewma = ewma_daily(&outflows);
    let trend = trend_slope(&outflows);

    let (days, date) = if ewma > 0 {
        let days = available / ewma;
        let date = as_of + ChronoDuration::days(days);
        (Some(days), Some(date.format("%Y-%m-%d").to_string()))
    } else {
        (None, None)
    };
    let suggested = (target_days.saturating_mul(ewma.max(0)) - available).max(0);

    ReserveCurrencyForecast {
        currency: currency.to_string(),
        minor_scale,
        available_minor: available,
        held_minor: held,
        low_water_minor: low_water,
        low_water_breached: low_water > 0 && available < low_water,
        avg_daily_outflow_minor: avg,
        ewma_daily_outflow_minor: ewma,
        trend_minor_per_day: trend,
        projected_days_to_depletion: days,
        projected_depletion_date: date,
        suggested_topup_minor: suggested,
        daily,
    }
}

/// `GET /admin/exchange-reserve/forecast` — utilization prediction.
pub async fn get_forecast(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<ReserveForecastQuery>,
) -> Result<Json<ReserveForecastResponse>, AppError> {
    let window_days = q.window_days.clamp(1, 365);
    let target_days = q.target_days.clamp(1, 365);
    let as_of = Utc::now().date_naive();

    // Net flow per entry is delta + held_delta: holds and releases cancel to
    // zero, deposits/topups are positive, fulfillments/disbursements/
    // withdrawals negative — exactly the pool's real in/out.
    let rows: Vec<(String, NaiveDate, i64, i64)> = sqlx::query_as(
        "SELECT currency, (created_at AT TIME ZONE 'UTC')::date AS day, \
                COALESCE(SUM(GREATEST(-(delta + held_delta), 0)), 0)::bigint AS outflow, \
                COALESCE(SUM(GREATEST(delta + held_delta, 0)), 0)::bigint AS inflow \
         FROM conversion_reserve_entry \
         WHERE created_at >= CURRENT_TIMESTAMP - make_interval(days => $1::int) \
         GROUP BY currency, day",
    )
    .bind(window_days as i32)
    .fetch_all(&pool)
    .await
    .map_err(db_err("forecast flows"))?;

    let buckets: Vec<(String, i16, i64, i64, i64)> = sqlx::query_as(
        "SELECT currency, minor_scale, available, held, low_water \
         FROM conversion_reserve ORDER BY currency",
    )
    .fetch_all(&pool)
    .await
    .map_err(db_err("forecast buckets"))?;

    let currencies = buckets
        .into_iter()
        .map(|(currency, scale, available, held, low_water)| {
            let mine: Vec<(NaiveDate, i64, i64)> = rows
                .iter()
                .filter(|(c, ..)| *c == currency)
                .map(|(_, d, o, i)| (*d, *o, *i))
                .collect();
            let daily = fill_daily_series(&mine, as_of, window_days);
            forecast_currency(
                &currency,
                scale,
                available,
                held,
                low_water,
                daily,
                as_of,
                target_days,
            )
        })
        .collect();

    let provider_utilization: Vec<ReserveProviderUtilization> = sqlx::query_as(
        "SELECT diverted_provider AS provider, COUNT(*)::bigint AS orders, \
                COALESCE(SUM(-delta), 0)::bigint AS volume_minor \
         FROM conversion_reserve_entry \
         WHERE kind = 'hold' AND diverted_provider IS NOT NULL \
           AND created_at >= CURRENT_TIMESTAMP - make_interval(days => $1::int) \
         GROUP BY diverted_provider ORDER BY diverted_provider",
    )
    .bind(window_days as i32)
    .fetch_all(&pool)
    .await
    .map_err(db_err("forecast utilization"))?;

    Ok(Json(ReserveForecastResponse {
        window_days,
        target_days,
        as_of: as_of.format("%Y-%m-%d").to_string(),
        currencies,
        provider_utilization,
    }))
}

// ── Order actions: disburse / resolve ──────────────────────────────────

#[derive(sqlx::FromRow)]
struct ReserveOrderActionRow {
    payala_account_id: String,
    status: String,
    amount_to: Option<String>,
    payout_address: Option<String>,
    payout_extra_id: Option<String>,
    /// The reserve Stellar address the pay-in targeted (source of the payout).
    payin_address: Option<String>,
    provider_order_id: String,
    shape: Option<String>,
    hold_minor: Option<i64>,
    hold_currency: Option<String>,
}

async fn load_reserve_order(
    pool: &PgPool,
    order_id: Uuid,
) -> Result<ReserveOrderActionRow, AppError> {
    sqlx::query_as(
        "SELECT payala_account_id, status, amount_to, payout_address, payout_extra_id, \
                payin_address, provider_order_id, \
                provider_payload->>'shape' AS shape, \
                (provider_payload->>'hold_minor')::bigint AS hold_minor, \
                provider_payload->>'hold_currency' AS hold_currency \
         FROM exchange_order WHERE order_id = $1 AND provider = 'reserve'",
    )
    .bind(order_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err("order load"))?
    .ok_or_else(|| AppError::NotFound("No such reserve order".to_string()))
}

/// `POST /admin/exchange-reserve/orders/{order_id}/disburse` — complete a
/// fiat off-ramp order: the admin paid `amount_usd_cents` out of the USD
/// float (bank/OwlPay balance) and records it here.
pub async fn disburse_order(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Path(order_id): Path<Uuid>,
    Json(payload): Json<ReserveDisburseRequest>,
) -> Result<Json<ReserveActionResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "reserve_admin",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let order = load_reserve_order(&pool, order_id).await?;
    if order.shape.as_deref() != Some("disburse") {
        return Err(AppError::BadRequest("Not a disbursement order".to_string()));
    }
    let hold = order
        .hold_minor
        .ok_or_else(|| AppError::InternalError("Corrupt order payload".to_string()))?;
    if payload.amount_usd_cents <= 0 {
        return Err(AppError::BadRequest(
            "amount_usd_cents must be positive".to_string(),
        ));
    }
    if payload.amount_usd_cents > hold.saturating_mul(RESERVE_DISBURSE_MAX_MULTIPLE) {
        return Err(AppError::BadRequest(format!(
            "amount_usd_cents exceeds {}x the order's hold of {} cents",
            RESERVE_DISBURSE_MAX_MULTIPLE, hold
        )));
    }

    let actual = payload.amount_usd_cents;
    let mut tx = pool.begin().await.map_err(db_err("disburse begin"))?;
    let updated = sqlx::query(
        "UPDATE exchange_order \
         SET status = 'completed', provider_status = 'disbursed', last_error = NULL, \
             amount_to = $2 \
         WHERE order_id = $1 AND status = 'processing' \
           AND provider_status = 'awaiting_disbursement'",
    )
    .bind(order_id)
    .bind(minor_to_decimal_string(actual, RESERVE_SCALE_USD))
    .execute(&mut *tx)
    .await
    .map_err(db_err("disburse update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "Order is not awaiting disbursement".to_string(),
        ));
    }

    // Net pool effect: hold - actual on available (negative when the payout
    // exceeded the 1:1 hold), full hold released from held.
    let currency = order.hold_currency.as_deref().unwrap_or("USD").to_string();
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&currency)
        .bind(hold - actual)
        .bind(-hold)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("disburse apply"))?;
    let (bal_after, held_after, _) = bucket.ok_or_else(|| {
        AppError::Conflict("USD float cannot cover this disbursement".to_string())
    })?;

    let note = match (&payload.external_ref, &payload.note) {
        (Some(r), Some(n)) => Some(format!("ref={} {}", r, n)),
        (Some(r), None) => Some(format!("ref={}", r)),
        (None, n) => n.clone(),
    };
    sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(&currency)
        .bind("disbursement")
        .bind(hold - actual)
        .bind(-hold)
        .bind(bal_after)
        .bind(held_after)
        .bind(order_id)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Some(user.account_id.clone()))
        .bind(&note)
        .execute(&mut *tx)
        .await
        .map_err(db_err("disburse entry"))?;

    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ExchangeOrderUpdated {
            account_id: order.payala_account_id.clone(),
            order_id: order_id.to_string(),
            provider: "reserve".to_string(),
            status: "completed".to_string(),
            provider_status: "disbursed".to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("disburse commit"))?;

    metrics.record_exchange_order_update("reserve", "completed", "admin");
    info!(
        "disburse_order: order={} amount_usd_cents={} by={}",
        order_id, actual, user.account_id
    );
    Ok(ok("Disbursement recorded; order completed"))
}

/// Search the reserve account's recent outgoing payments for the one that
/// fulfilled this order. Matching is memo-primary: the watcher tags every
/// payout with the order ref unless the receiver required its own memo
/// (payout_extra_id), in which case that memo plus the exact destination and
/// amount must all agree — destination+amount alone could confuse two
/// payouts to the same address. All candidates are reserve-signed (the feed
/// only carries the reserve's own operations), so none are forgeable.
async fn find_onchain_payout(
    http: &reqwest::Client,
    horizon_url: &str,
    reserve_address: &str,
    order_ref: &str,
    payout_extra_id: Option<&str>,
    payout_address: Option<&str>,
    amount_to: Option<&str>,
) -> Result<Option<String>, AppError> {
    let url = format!(
        "{}/accounts/{}/payments?order=desc&limit={}&join=transactions",
        horizon_url.trim_end_matches('/'),
        reserve_address,
        RESERVE_WATCH_PAGE_LIMIT
    );
    let resp = http.get(&url).send().await.map_err(|e| {
        error!("find_onchain_payout: horizon error: {}", e);
        AppError::InternalError("Cannot verify on-chain state; retry later".to_string())
    })?;
    if !resp.status().is_success() {
        error!("find_onchain_payout: horizon HTTP {}", resp.status());
        return Err(AppError::InternalError(
            "Cannot verify on-chain state; retry later".to_string(),
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| {
        error!("find_onchain_payout: parse error: {}", e);
        AppError::InternalError("Cannot verify on-chain state; retry later".to_string())
    })?;
    let amount_minor = amount_to.and_then(|a| parse_decimal_to_minor(a, RESERVE_SCALE_STELLAR));
    for p in crate::stellar::horizon::parse_payments_page(&body).records {
        // Outgoing only — the pay-in deposit carries the same memo.
        if p.to == reserve_address {
            continue;
        }
        let hit = match payout_extra_id {
            None => p
                .memo_text
                .as_deref()
                .map(|m| memo_matches_ref(m, order_ref))
                .unwrap_or(false),
            Some(extra) => {
                p.memo_text.as_deref() == Some(extra)
                    && payout_address == Some(p.to.as_str())
                    && amount_minor.is_some()
                    && parse_decimal_to_minor(&p.amount, RESERVE_SCALE_STELLAR) == amount_minor
            }
        };
        if hit {
            return Ok(Some(p.tx_hash));
        }
    }
    Ok(None)
}

/// `POST /admin/exchange-reserve/orders/{order_id}/resolve` — resolve a
/// reserve order that is waiting on an admin: `complete` records a payout
/// that did land on-chain (frozen auto-swaps); `fail` releases the hold —
/// for frozen auto-swaps once the chain verifiably has no matching payout,
/// and for disbursement orders whose fiat leg cannot be executed (their only
/// other exit is a real disbursement).
#[allow(clippy::too_many_arguments)]
pub async fn resolve_order(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    reserve: Option<Extension<Arc<ConversionReserve>>>,
    Path(order_id): Path<Uuid>,
    Json(payload): Json<ReserveResolveRequest>,
) -> Result<Json<ReserveActionResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "reserve_admin",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    if !matches!(payload.action.as_str(), "complete" | "fail") {
        return Err(AppError::BadRequest(
            "action must be 'complete' or 'fail'".to_string(),
        ));
    }

    let order = load_reserve_order(&pool, order_id).await?;
    let disburse_pending =
        order.status == "processing" && order.shape.as_deref() == Some("disburse");
    if order.status != "on_hold" && !disburse_pending {
        return Err(AppError::Conflict(
            "Only on_hold orders (or disbursement orders awaiting their fiat leg) can be resolved"
                .to_string(),
        ));
    }

    // Whether a payout may ever have been submitted, and how long ago the
    // order last changed state. The wait guard measures the LATEST state
    // change (the freeze), not the first intent: retries re-sign with fresh
    // 300s validity windows, so only "frozen for >= 600s" proves no
    // submission can still land.
    let intent_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversion_reserve_entry \
             WHERE order_id = $1 AND kind = 'payout_attempt')",
    )
    .bind(order_id)
    .fetch_one(&pool)
    .await
    .map_err(db_err("intent lookup"))?;
    let state_age_secs: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - updated_at))::bigint \
         FROM exchange_order WHERE order_id = $1",
    )
    .bind(order_id)
    .fetch_one(&pool)
    .await
    .map_err(db_err("state age"))?;

    match payload.action.as_str() {
        "fail" => {
            if intent_exists {
                if state_age_secs < RESERVE_RESOLVE_FAIL_MIN_INTENT_AGE_SECS {
                    return Err(AppError::Conflict(format!(
                        "The order changed state {}s ago and a submitted transaction may still \
                         land. Retry after {}s",
                        state_age_secs, RESERVE_RESOLVE_FAIL_MIN_INTENT_AGE_SECS
                    )));
                }
                // Fail closed: refuse when the chain cannot be checked. This
                // needs the configured reserve for the account to search.
                let Some(Extension(ref reserve)) = reserve else {
                    return Err(AppError::Conflict(
                        "A payout may exist on-chain but the reserve is not configured to \
                         verify it; re-set RESERVE_ACCOUNT_ID or resolve with action=complete \
                         and an explicit stellar_tx_hash"
                            .to_string(),
                    ));
                };
                if let Some(hash) = find_onchain_payout(
                    &http,
                    &stellar_config.horizon_url,
                    &reserve.stellar_address,
                    &order.provider_order_id,
                    order.payout_extra_id.as_deref(),
                    order.payout_address.as_deref(),
                    order.amount_to.as_deref(),
                )
                .await?
                {
                    return Err(AppError::Conflict(format!(
                        "A payout matching this order exists on-chain (tx {}); resolve with \
                         action=complete instead",
                        hash
                    )));
                }
            }
            resolve_fail(&pool, &metrics, &user, order_id, &order, &payload.note).await
        }
        _ => {
            if disburse_pending {
                return Err(AppError::BadRequest(
                    "Disbursement orders complete via the disburse endpoint".to_string(),
                ));
            }
            let hash = match payload.stellar_tx_hash.clone() {
                Some(h) => h,
                None => {
                    let Some(Extension(ref reserve)) = reserve else {
                        return Err(AppError::BadRequest(
                            "Reserve not configured; supply stellar_tx_hash explicitly".to_string(),
                        ));
                    };
                    find_onchain_payout(
                        &http,
                        &stellar_config.horizon_url,
                        &reserve.stellar_address,
                        &order.provider_order_id,
                        order.payout_extra_id.as_deref(),
                        order.payout_address.as_deref(),
                        order.amount_to.as_deref(),
                    )
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest(
                            "No matching on-chain payout found; supply stellar_tx_hash".to_string(),
                        )
                    })?
                }
            };
            resolve_complete(&pool, &metrics, &user, order_id, &order, &hash).await
        }
    }
}

async fn resolve_fail(
    pool: &PgPool,
    metrics: &AppMetrics,
    user: &AdminUser,
    order_id: Uuid,
    order: &ReserveOrderActionRow,
    note: &Option<String>,
) -> Result<Json<ReserveActionResponse>, AppError> {
    let mut tx = pool.begin().await.map_err(db_err("fail begin"))?;
    // Two resolvable shapes share this exit: frozen auto-swap payouts
    // (on_hold) and disbursement orders whose fiat leg cannot be executed
    // (processing/awaiting_disbursement — their only other exit is a real
    // disbursement, which would strand them forever when the beneficiary
    // data is unusable).
    let updated = sqlx::query(
        "UPDATE exchange_order SET status = 'failed', provider_status = 'resolved_failed' \
         WHERE order_id = $1 \
           AND (status = 'on_hold' \
                OR (status = 'processing' AND provider_status = 'awaiting_disbursement'))",
    )
    .bind(order_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err("fail update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "Order is no longer resolvable".to_string(),
        ));
    }

    let hold: Option<(String, i64)> = sqlx::query_as(
        "SELECT currency, -delta FROM conversion_reserve_entry \
         WHERE order_id = $1 AND kind = 'hold'",
    )
    .bind(order_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err("fail hold lookup"))?;
    let (currency, hold_minor) =
        hold.ok_or_else(|| AppError::InternalError("Hold entry missing".to_string()))?;

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(&currency)
        .bind(hold_minor)
        .bind(-hold_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("fail release"))?;
    let (bal_after, held_after, _) =
        bucket.ok_or_else(|| AppError::InternalError("Held underflow (drift)".to_string()))?;

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
        .bind(Some(user.account_id.clone()))
        .bind(note)
        .execute(&mut *tx)
        .await
        .map_err(db_err("fail entry"))?;
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ExchangeOrderUpdated {
            account_id: order.payala_account_id.clone(),
            order_id: order_id.to_string(),
            provider: "reserve".to_string(),
            status: "failed".to_string(),
            provider_status: "resolved_failed".to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("fail commit"))?;

    metrics.record_exchange_order_update("reserve", "failed", "admin");
    info!(
        "resolve_order: order={} action=fail by={}",
        order_id, user.account_id
    );
    Ok(ok(
        "Order failed; hold released. The user's deposit (if any) remains in reserve \
         inventory — refund it via ops runbook",
    ))
}

async fn resolve_complete(
    pool: &PgPool,
    metrics: &AppMetrics,
    user: &AdminUser,
    order_id: Uuid,
    order: &ReserveOrderActionRow,
    stellar_hash: &str,
) -> Result<Json<ReserveActionResponse>, AppError> {
    let amount_to_minor = order
        .amount_to
        .as_deref()
        .and_then(|a| parse_decimal_to_minor(a, RESERVE_SCALE_STELLAR))
        .ok_or_else(|| AppError::InternalError("Corrupt order amount".to_string()))?;

    let mut tx = pool.begin().await.map_err(db_err("complete begin"))?;
    let updated = sqlx::query(
        "UPDATE exchange_order \
         SET status = 'completed', provider_status = 'paid', last_error = NULL \
         WHERE order_id = $1 AND status = 'on_hold'",
    )
    .bind(order_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err("complete update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict("Order is no longer on_hold".to_string()));
    }

    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(RESERVE_CURRENCY_USDC)
        .bind(0i64)
        .bind(-amount_to_minor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("complete apply"))?;
    let (bal_after, held_after, _) =
        bucket.ok_or_else(|| AppError::InternalError("Held underflow (drift)".to_string()))?;

    sqlx::query(RESERVE_ENTRY_INSERT_SQL)
        .bind(RESERVE_CURRENCY_USDC)
        .bind("fulfillment")
        .bind(0i64)
        .bind(-amount_to_minor)
        .bind(bal_after)
        .bind(held_after)
        .bind(order_id)
        .bind(Option::<String>::None)
        .bind(Some(stellar_hash.to_string()))
        .bind(Option::<String>::None)
        .bind(Some(user.account_id.clone()))
        .bind(Option::<String>::None)
        .execute(&mut *tx)
        .await
        .map_err(db_err("complete entry"))?;

    let btxid: Uuid = sqlx::query_scalar(
        "INSERT INTO transaction \
             (stellar_tx_id, stellar_hash, source_account, memo, account_id, origin) \
         VALUES ($1, $2, $3, $4, $5, 'conversion_reserve') \
         RETURNING btxid",
    )
    .bind(stellar_hash)
    .bind(stellar_hash)
    // The order's own payin_address IS the reserve account that signed the
    // payout — using it keeps this path working after deconfiguration.
    .bind(order.payin_address.as_deref().unwrap_or(""))
    .bind(&order.provider_order_id)
    .bind(&order.payala_account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err("complete transaction row"))?;
    sqlx::query("UPDATE exchange_order SET btxid = $2 WHERE order_id = $1")
        .bind(order_id)
        .bind(btxid)
        .execute(&mut *tx)
        .await
        .map_err(db_err("complete btxid"))?;

    crate::events::emit_event(
        &mut tx,
        &AccountEvent::ReserveFulfilled {
            account_id: order.payala_account_id.clone(),
            order_id: order_id.to_string(),
            currency: RESERVE_CURRENCY_USDC.to_string(),
            amount_minor: amount_to_minor,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("complete commit"))?;

    metrics.reserve_fulfillments.add(1, &[]);
    metrics.record_exchange_order_update("reserve", "completed", "admin");
    info!(
        "resolve_order: order={} action=complete hash={} by={}",
        order_id, stellar_hash, user.account_id
    );
    Ok(ok("Payout recorded; order completed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── EWMA ───────────────────────────────────────────────────────────

    #[test]
    fn ewma_of_constant_series_is_the_constant() {
        assert_eq!(ewma_daily(&[100, 100, 100, 100]), 100);
        assert_eq!(ewma_daily(&[]), 0);
        assert_eq!(ewma_daily(&[42]), 42);
    }

    #[test]
    fn ewma_weights_recent_days_more() {
        // Jump at the end pulls the estimate up but not all the way.
        let e = ewma_daily(&[0, 0, 0, 1000]);
        assert!(e > 0 && e < 1000, "got {}", e);
        assert_eq!(e, 300); // (3*1000 + 7*0)/10
                            // A jump at the start decays.
        let e = ewma_daily(&[1000, 0, 0, 0]);
        assert!(e < 500, "got {}", e);
    }

    // ── trend ──────────────────────────────────────────────────────────

    #[test]
    fn trend_slope_matches_linear_series() {
        assert_eq!(trend_slope(&[0, 10, 20, 30]), 10);
        assert_eq!(trend_slope(&[30, 20, 10, 0]), -10);
        assert_eq!(trend_slope(&[5, 5, 5]), 0);
        assert_eq!(trend_slope(&[7]), 0);
        assert_eq!(trend_slope(&[]), 0);
    }

    // ── series fill ────────────────────────────────────────────────────

    #[test]
    fn fill_daily_series_covers_window_with_zeros() {
        let as_of = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let rows = vec![
            (NaiveDate::from_ymd_opt(2026, 8, 19).unwrap(), 500, 0),
            (NaiveDate::from_ymd_opt(2026, 8, 20).unwrap(), 200, 100),
        ];
        let daily = fill_daily_series(&rows, as_of, 4);
        assert_eq!(daily.len(), 4);
        assert_eq!(daily[0].day, "2026-08-17");
        assert_eq!(daily[0].outflow_minor, 0);
        assert_eq!(daily[2].day, "2026-08-19");
        assert_eq!(daily[2].outflow_minor, 500);
        assert_eq!(daily[3].day, "2026-08-20");
        assert_eq!(daily[3].inflow_minor, 100);
    }

    // ── forecast ───────────────────────────────────────────────────────

    fn forecast_with(
        outflows: &[i64],
        available: i64,
        target_days: i64,
    ) -> ReserveCurrencyForecast {
        let as_of = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let daily: Vec<ReserveDailyFlow> = outflows
            .iter()
            .enumerate()
            .map(|(i, o)| ReserveDailyFlow {
                day: (as_of - ChronoDuration::days(outflows.len() as i64 - 1 - i as i64))
                    .format("%Y-%m-%d")
                    .to_string(),
                outflow_minor: *o,
                inflow_minor: 0,
            })
            .collect();
        forecast_currency("USDC", 7, available, 0, 0, daily, as_of, target_days)
    }

    #[test]
    fn depletion_projection_from_steady_outflow() {
        // 100/day steady, 1000 available -> 10 days.
        let f = forecast_with(&[100, 100, 100, 100, 100], 1000, 30);
        assert_eq!(f.ewma_daily_outflow_minor, 100);
        assert_eq!(f.projected_days_to_depletion, Some(10));
        assert_eq!(f.projected_depletion_date.as_deref(), Some("2026-08-30"));
        // 30 days of coverage needs 3000; suggest the 2000 gap.
        assert_eq!(f.suggested_topup_minor, 2000);
    }

    #[test]
    fn zero_outflow_has_no_depletion_and_no_topup() {
        let f = forecast_with(&[0, 0, 0], 1000, 30);
        assert_eq!(f.projected_days_to_depletion, None);
        assert!(f.projected_depletion_date.is_none());
        assert_eq!(f.suggested_topup_minor, 0);
    }

    #[test]
    fn low_water_breach_flag() {
        let as_of = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let f = forecast_currency("USDC", 7, 100, 0, 500, vec![], as_of, 30);
        assert!(f.low_water_breached);
        let f = forecast_currency("USDC", 7, 100, 0, 0, vec![], as_of, 30);
        assert!(!f.low_water_breached, "low_water 0 disables the alert");
    }

    #[test]
    fn suggested_topup_never_negative() {
        let f = forecast_with(&[10, 10], 1_000_000, 30);
        assert_eq!(f.suggested_topup_minor, 0);
    }
}

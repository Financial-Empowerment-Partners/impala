//! Admin control of automated replenishment
//! (`/admin/exchange-reserve/replenishment/*`).
//!
//! Kept out of `admin_reserve.rs`, which is already large. All endpoints are
//! capability-gated (`Privileged<ReadReserve>` reads, `Privileged<ManageReserve>`
//! mutations); the ones that can move value carry the custodial-sign
//! rate limit and write audit lines.
//!
//! The manual "run now" endpoint takes the **watcher's own advisory lock**
//! before doing anything. The reserve account signs from a single sequence
//! number, so a handler-driven submission racing the watcher's would collide
//! — the lock is what makes a manual trigger safe rather than a second
//! writer.

use axum::extract::{Path, Query};
use axum::{Extension, Json};
use log::{error, info};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{ManageReserve, Privileged, ReadReserve};
use crate::constants::{
    RESERVE_CURRENCY_USD, RESERVE_WATCHER_LOCK_KEY, SIGN_RATE_LIMIT_MAX_REQUESTS,
    SIGN_RATE_LIMIT_WINDOW_SECS, VALID_REPLENISH_KINDS,
};
use crate::error::AppError;
use crate::exchange::reserve::{journal_insert, JournalEntry, RESERVE_BUCKET_APPLY_SQL};
use crate::models::{
    PaginationParams, ReplenishConfirmFiatRequest, ReplenishCycleView,
    ReplenishPolicyUpdateRequest, ReplenishPolicyView, ReplenishRunRequest,
    ReplenishStatusResponse,
};
use crate::telemetry::AppMetrics;

const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("admin_replenish: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

#[derive(serde::Serialize)]
pub struct ReplenishActionResponse {
    pub success: bool,
    pub message: String,
}

fn ok(message: impl Into<String>) -> Json<ReplenishActionResponse> {
    Json(ReplenishActionResponse {
        success: true,
        message: message.into(),
    })
}

fn cycle_columns() -> String {
    format!(
        "cycle_id, kind, state, trigger_source, spend_currency, spend_minor, \
         recv_currency, quoted_recv_minor, actual_recv_minor, quote_pricing, \
         provider, provider_ref, send_tx_hash, fiat_minor, last_error, \
         to_char(created_at AT TIME ZONE 'UTC', '{ts}') AS created_at",
        ts = TS_FMT
    )
}

/// `GET /admin/exchange-reserve/replenishment` — policies plus recent cycles.
pub async fn get_status(
    _user: Privileged<ReadReserve>,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<PaginationParams>,
) -> Result<Json<ReplenishStatusResponse>, AppError> {
    let (per_page, _) = q.clamped();
    let policies: Vec<ReplenishPolicyView> = sqlx::query_as(&format!(
        "SELECT kind, enabled, target_days, window_days, min_need_minor, max_spend_minor, \
                daily_spend_cap_minor, cooldown_secs, min_float_minor, min_price_minor, \
                max_slippage_bps, \
                to_char(updated_at AT TIME ZONE 'UTC', '{ts}') AS updated_at \
         FROM conversion_reserve_replenish_policy ORDER BY kind",
        ts = TS_FMT
    ))
    .fetch_all(&pool)
    .await
    .map_err(db_err("policies"))?;

    let cycles: Vec<ReplenishCycleView> = sqlx::query_as(&format!(
        "SELECT {} FROM conversion_reserve_replenishment \
         ORDER BY created_at DESC LIMIT $1",
        cycle_columns()
    ))
    .bind(per_page)
    .fetch_all(&pool)
    .await
    .map_err(db_err("cycles"))?;

    Ok(Json(ReplenishStatusResponse { policies, cycles }))
}

/// `PUT /admin/exchange-reserve/replenishment/policies/{kind}`.
pub async fn update_policy(
    user: Privileged<ManageReserve>,
    Extension(pool): Extension<PgPool>,
    Path(kind): Path<String>,
    Json(p): Json<ReplenishPolicyUpdateRequest>,
) -> Result<Json<ReplenishActionResponse>, AppError> {
    if !VALID_REPLENISH_KINDS.contains(&kind.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid kind '{}'. Must be one of: {}",
            kind,
            VALID_REPLENISH_KINDS.join(", ")
        )));
    }
    // Bands mirror the CHECK constraints, so a bad value is a clean 400
    // rather than a database error.
    if !(1..=365).contains(&p.target_days) || !(1..=365).contains(&p.window_days) {
        return Err(AppError::BadRequest(
            "target_days and window_days must be between 1 and 365".to_string(),
        ));
    }
    if !(60..=604_800).contains(&p.cooldown_secs) {
        return Err(AppError::BadRequest(
            "cooldown_secs must be between 60 and 604800".to_string(),
        ));
    }
    if !(0..=5_000).contains(&p.max_slippage_bps) {
        return Err(AppError::BadRequest(
            "max_slippage_bps must be between 0 and 5000".to_string(),
        ));
    }
    for (name, v) in [
        ("min_need_minor", p.min_need_minor),
        ("max_spend_minor", p.max_spend_minor),
        ("daily_spend_cap_minor", p.daily_spend_cap_minor),
        ("min_float_minor", p.min_float_minor),
        ("min_price_minor", p.min_price_minor),
    ] {
        if v < 0 {
            return Err(AppError::BadRequest(format!("{} must be >= 0", name)));
        }
    }
    // Enabling with unset caps would be a no-op that LOOKS armed; say so
    // rather than letting an admin believe replenishment is running.
    if p.enabled && (p.max_spend_minor == 0 || p.daily_spend_cap_minor == 0) {
        return Err(AppError::BadRequest(
            "max_spend_minor and daily_spend_cap_minor must be set before enabling: 0 means \
             unconfigured, and the cycle will refuse to run"
                .to_string(),
        ));
    }

    let updated = sqlx::query(
        "UPDATE conversion_reserve_replenish_policy \
         SET enabled = $2, target_days = $3, window_days = $4, min_need_minor = $5, \
             max_spend_minor = $6, daily_spend_cap_minor = $7, cooldown_secs = $8, \
             min_float_minor = $9, min_price_minor = $10, max_slippage_bps = $11, \
             updated_by = $12 \
         WHERE kind = $1",
    )
    .bind(&kind)
    .bind(p.enabled)
    .bind(p.target_days)
    .bind(p.window_days)
    .bind(p.min_need_minor)
    .bind(p.max_spend_minor)
    .bind(p.daily_spend_cap_minor)
    .bind(p.cooldown_secs)
    .bind(p.min_float_minor)
    .bind(p.min_price_minor)
    .bind(p.max_slippage_bps)
    .bind(&user.account_id)
    .execute(&pool)
    .await
    .map_err(db_err("policy update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("No such replenishment kind".to_string()));
    }

    info!(
        "update_policy: replenish kind={} enabled={} max_spend={} daily_cap={} by={}",
        kind, p.enabled, p.max_spend_minor, p.daily_spend_cap_minor, user.account_id
    );
    Ok(ok("Replenishment policy updated"))
}

/// `POST /admin/exchange-reserve/replenishment/run` — start one cycle now.
///
/// Takes the watcher's advisory lock for the duration: the reserve account
/// signs from one sequence number, so a submission racing the watcher's
/// would collide.
#[allow(clippy::too_many_arguments)]
pub async fn run_now(
    user: Privileged<ManageReserve>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(signer): Extension<Arc<dyn crate::stellar::StellarSigner>>,
    Extension(protector): Extension<Arc<dyn crate::seed_protect::SeedProtector>>,
    reserve: Option<Extension<Arc<crate::exchange::reserve::ConversionReserve>>>,
    changelly_crypto: Option<Extension<Arc<crate::exchange::changelly::ChangellyCrypto>>>,
    Json(payload): Json<ReplenishRunRequest>,
) -> Result<Json<ReplenishActionResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "reserve_admin",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    if !VALID_REPLENISH_KINDS.contains(&payload.kind.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid kind '{}'. Must be one of: {}",
            payload.kind,
            VALID_REPLENISH_KINDS.join(", ")
        )));
    }
    let Extension(reserve) = reserve
        .ok_or_else(|| AppError::BadRequest("conversion reserve is not configured".to_string()))?;

    let mut lock_conn = pool.acquire().await.map_err(db_err("acquire"))?;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(RESERVE_WATCHER_LOCK_KEY)
        .fetch_one(&mut *lock_conn)
        .await
        .map_err(db_err("try lock"))?;
    if !got {
        return Err(AppError::Conflict(
            "The reserve watcher is mid-tick; retry in a moment".to_string(),
        ));
    }

    let deps = crate::exchange::reserve_watch::ReserveWatchDeps {
        pool: pool.clone(),
        http,
        horizon_url: stellar_config.horizon_url.clone(),
        reserve,
        signer,
        protector,
        metrics,
        changelly_crypto: changelly_crypto.map(|Extension(p)| p),
    };
    let started = crate::exchange::replenish::maybe_start_cycle(
        &deps,
        &payload.kind,
        "admin",
        Some(&user.account_id),
    )
    .await;

    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(RESERVE_WATCHER_LOCK_KEY)
        .fetch_one(&mut *lock_conn)
        .await;
    if unlocked.is_err() {
        // Never return a connection that may still hold the session lock.
        drop(lock_conn.detach());
    }

    match started? {
        Some(cycle_id) => {
            info!(
                "run_now: replenish kind={} cycle={} by={}",
                payload.kind, cycle_id, user.account_id
            );
            Ok(ok(format!("Replenishment cycle {} started", cycle_id)))
        }
        // The skip reason is already recorded as a metric; the guards are
        // visible on the status endpoint.
        None => Ok(ok(
            "No cycle started — a guard declined it (see the replenishment status and metrics)",
        )),
    }
}

/// `POST /admin/exchange-reserve/replenishment/{cycle_id}/confirm-fiat`.
///
/// The bridge can see USDC leave and the provider's status, but never a bank
/// credit — so the fiat sits in `held` until a human confirms it arrived.
/// This is the one step that cannot be automated honestly.
pub async fn confirm_fiat(
    user: Privileged<ManageReserve>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Path(cycle_id): Path<Uuid>,
    Json(payload): Json<ReplenishConfirmFiatRequest>,
) -> Result<Json<ReplenishActionResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "reserve_admin",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let row: Option<(String, Option<i64>)> = sqlx::query_as(
        "SELECT state, fiat_minor FROM conversion_reserve_replenishment WHERE cycle_id = $1",
    )
    .bind(cycle_id)
    .fetch_optional(&pool)
    .await
    .map_err(db_err("cycle lookup"))?;
    let (state, in_transit) =
        row.ok_or_else(|| AppError::NotFound("No such replenishment cycle".to_string()))?;
    if state != "in_transit" {
        return Err(AppError::Conflict(
            "Only a cycle awaiting bank confirmation can be confirmed".to_string(),
        ));
    }
    let in_transit = in_transit
        .ok_or_else(|| AppError::InternalError("Cycle has no in-transit amount".to_string()))?;
    let actual = payload.amount_usd_cents.unwrap_or(in_transit);
    if actual <= 0 {
        return Err(AppError::BadRequest(
            "amount_usd_cents must be positive".to_string(),
        ));
    }
    // Fat-finger bound, mirroring the disbursement path.
    if actual > in_transit.saturating_mul(crate::constants::RESERVE_DISBURSE_MAX_MULTIPLE) {
        return Err(AppError::BadRequest(format!(
            "amount_usd_cents exceeds {}x the in-transit amount of {} cents",
            crate::constants::RESERVE_DISBURSE_MAX_MULTIPLE,
            in_transit
        )));
    }

    let mut tx = pool.begin().await.map_err(db_err("confirm begin"))?;
    let updated = sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET state = 'completed', fiat_confirmed_by = $2, \
             fiat_confirmed_at = CURRENT_TIMESTAMP, external_ref = $3, \
             actual_recv_minor = $4 \
         WHERE cycle_id = $1 AND state = 'in_transit'",
    )
    .bind(cycle_id)
    .bind(&user.account_id)
    .bind(&payload.external_ref)
    .bind(actual)
    .execute(&mut *tx)
    .await
    .map_err(db_err("confirm update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "Cycle is no longer awaiting confirmation".to_string(),
        ));
    }

    // Move the fiat from "in transit" into spendable float. Any shortfall
    // versus what the provider reported is recorded, not hidden.
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(RESERVE_CURRENCY_USD)
        .bind(actual)
        .bind(-in_transit)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("confirm apply"))?;
    let (bal_after, held_after, _) = bucket
        .ok_or_else(|| AppError::Conflict("Confirming would overdraw the USD float".to_string()))?;

    journal_insert(JournalEntry {
        currency: RESERVE_CURRENCY_USD.to_string(),
        kind: "fiat_confirmed".to_string(),
        delta: actual,
        held_delta: -in_transit,
        balance_after: bal_after,
        held_after,
        cycle_id: Some(cycle_id),
        admin_account_id: Some(user.account_id.clone()),
        note: payload.note.clone(),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("confirm entry"))?;
    tx.commit().await.map_err(db_err("confirm commit"))?;

    info!(
        "confirm_fiat: cycle={} cents={} by={}",
        cycle_id, actual, user.account_id
    );
    Ok(ok("Bank receipt confirmed; the float is now spendable"))
}

/// `POST /admin/exchange-reserve/replenishment/{cycle_id}/write-off`.
///
/// The escape hatch for fiat that never arrived. Without it the USD `held`
/// column stays poisoned and the kind stays permanently blocked — but it
/// writes off real money, so it demands a note and is loudly audited.
pub async fn write_off(
    user: Privileged<ManageReserve>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Path(cycle_id): Path<Uuid>,
    Json(payload): Json<ReplenishConfirmFiatRequest>,
) -> Result<Json<ReplenishActionResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "reserve_admin",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    let note = payload
        .note
        .as_deref()
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| {
            AppError::BadRequest("a note is required to write off in-transit funds".to_string())
        })?;

    let row: Option<(String, Option<i64>)> = sqlx::query_as(
        "SELECT state, fiat_minor FROM conversion_reserve_replenishment WHERE cycle_id = $1",
    )
    .bind(cycle_id)
    .fetch_optional(&pool)
    .await
    .map_err(db_err("cycle lookup"))?;
    let (state, in_transit) =
        row.ok_or_else(|| AppError::NotFound("No such replenishment cycle".to_string()))?;
    if state != "in_transit" {
        return Err(AppError::Conflict(
            "Only a cycle awaiting bank confirmation can be written off".to_string(),
        ));
    }
    let in_transit = in_transit.unwrap_or(0);

    let mut tx = pool.begin().await.map_err(db_err("write off begin"))?;
    let updated = sqlx::query(
        "UPDATE conversion_reserve_replenishment \
         SET state = 'failed', last_error = $2, fiat_confirmed_by = $3, \
             fiat_confirmed_at = CURRENT_TIMESTAMP \
         WHERE cycle_id = $1 AND state = 'in_transit'",
    )
    .bind(cycle_id)
    .bind(note)
    .bind(&user.account_id)
    .execute(&mut *tx)
    .await
    .map_err(db_err("write off update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "Cycle is no longer awaiting confirmation".to_string(),
        ));
    }
    let bucket: Option<(i64, i64, i64)> = sqlx::query_as(RESERVE_BUCKET_APPLY_SQL)
        .bind(RESERVE_CURRENCY_USD)
        .bind(0i64)
        .bind(-in_transit)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("write off apply"))?;
    let (bal_after, held_after, _) =
        bucket.ok_or_else(|| AppError::InternalError("Held underflow (drift)".to_string()))?;
    journal_insert(JournalEntry {
        currency: RESERVE_CURRENCY_USD.to_string(),
        kind: "fiat_written_off".to_string(),
        held_delta: -in_transit,
        balance_after: bal_after,
        held_after,
        cycle_id: Some(cycle_id),
        admin_account_id: Some(user.account_id.clone()),
        note: Some(note.to_string()),
        ..Default::default()
    })
    .execute(&mut *tx)
    .await
    .map_err(db_err("write off entry"))?;
    tx.commit().await.map_err(db_err("write off commit"))?;

    error!(
        "WRITE-OFF: replenishment cycle {} wrote off {} USD cents that never arrived — by={} note={}",
        cycle_id, in_transit, user.account_id, note
    );
    Ok(ok("In-transit funds written off"))
}

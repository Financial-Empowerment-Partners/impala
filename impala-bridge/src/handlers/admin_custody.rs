//! Custody administration (`/admin/custody/*`, 037).
//!
//! Reads take `Privileged<ReadCustody>` (admin, treasurer, auditor);
//! mutations `Privileged<ManageCustody>` (admin, treasurer) — except
//! `resume`, which is governance (`AdminUser`): money-ops may pull the brake
//! and never releases it alone. Every mutation is rate-limited under the
//! custodial-sign budget and audited INSIDE its own transaction.
//!
//! Money rules: the policy row is the only switch (`custody::policy`);
//! resolution of an open intent writes only after the chain has been read
//! (`complete` verifies the settlement by hash; `fail` requires the stale
//! window to have elapsed AND a fresh Horizon that lacks the hash or shows
//! it failed — an inconclusive read fails closed).

use axum::extract::{Path, Query};
use axum::{Extension, Json};
use futures::StreamExt;
use log::{error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{AdminUser, ManageCustody, Privileged, ReadCustody};
use crate::constants::{
    CUSTODIAL_STALE_INTENT_SECS, CUSTODY_ADMIN_RATE_LIMIT_SCOPE,
    RECONCILIATION_HORIZON_CONCURRENCY, SIGN_RATE_LIMIT_MAX_REQUESTS, SIGN_RATE_LIMIT_WINDOW_SECS,
    VALID_CUSTODIAL_INTENT_ORIGINS, VALID_CUSTODIAL_INTENT_STATUSES,
};
use crate::custody::intent::{
    finish_view, intent_view_columns, record_settlement, reject_by_hash, OpenIntentRow,
    SettleOutcome, OPEN_INTENT_BY_ID_SQL, TS_FMT,
};
use crate::custody::policy::PolicyRow;
use crate::custody::sweep::OPEN_COUNTS_SQL;
use crate::error::AppError;
use crate::events::AccountEvent;
use crate::exchange::reserve::ReserveAccountGuard;
use crate::models::{
    AdminCustodialIntentListQuery, CustodialAccountView, CustodialIntentView, CustodialOpenIntents,
    CustodialPolicyUpdateRequest, CustodialPolicyView, CustodyAccountLimitRequest,
    CustodyAccountsQuery, CustodyChangedResponse, CustodyPauseRequest, CustodyResolveRequest,
    CustodyResolveResponse, CustodyResumeRequest, PaginatedResponse, PaginationParams,
};

// ── SQL (pinned by custody_admin_mutations_are_guarded_single_statements) ──

/// Caps edit: absent fields keep their value (COALESCE), one row (`WHERE id`).
pub(crate) const LIMITS_SQL: &str = "UPDATE custodial_policy \
     SET per_tx_max_stroops = COALESCE($1, per_tx_max_stroops), \
         per_account_daily_max_stroops = COALESCE($2, per_account_daily_max_stroops), \
         require_idempotency_key = COALESCE($3, require_idempotency_key), \
         updated_by = $4 \
     WHERE id \
     RETURNING per_tx_max_stroops, per_account_daily_max_stroops, require_idempotency_key";

/// Pull the brake. Zero rows = already paused (idempotent, no event).
pub(crate) const PAUSE_SQL: &str = "UPDATE custodial_policy \
     SET paused = true, paused_by = $1, paused_at = CURRENT_TIMESTAMP, pause_reason = $2, \
         updated_by = $1 \
     WHERE id AND paused = false";

/// Release the brake. Zero rows = already running (idempotent, no event).
pub(crate) const RESUME_SQL: &str = "UPDATE custodial_policy \
     SET paused = false, paused_by = NULL, paused_at = NULL, pause_reason = NULL, \
         updated_by = $1 \
     WHERE id AND paused = true";

/// Per-account override; NULL clears it.
pub(crate) const ACCOUNT_LIMIT_UPDATE_SQL: &str = "UPDATE impala_account \
     SET custodial_daily_max_stroops = $2 WHERE payala_account_id = $1";

/// Open intents whose chain state is unknown — the resume gate.
pub(crate) const AMBIGUOUS_COUNT_SQL: &str = "SELECT COUNT(*) FROM custodial_payment_intent \
     WHERE status = 'ambiguous'";

/// The resume confirmation phrase, served by `GET /admin/custody/policy`
/// and required verbatim by `POST /admin/custody/resume`.
pub(crate) fn resume_phrase(network: &str) -> String {
    format!("resume custody {}", network)
}

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("admin_custody: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

async fn rate_limit(redis_pool: &deadpool_redis::Pool, actor: &str) -> Result<(), AppError> {
    crate::redis_helpers::check_rate_limit(
        redis_pool,
        CUSTODY_ADMIN_RATE_LIMIT_SCOPE,
        actor,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await
}

fn changed(changed: bool, message: &str) -> Json<CustodyChangedResponse> {
    Json(CustodyChangedResponse {
        success: true,
        changed,
        message: message.to_string(),
    })
}

#[derive(sqlx::FromRow)]
struct PolicyViewRow {
    paused: bool,
    paused_by: Option<String>,
    paused_at: Option<String>,
    pause_reason: Option<String>,
    per_tx_max_stroops: i64,
    per_account_daily_max_stroops: i64,
    require_idempotency_key: bool,
    updated_by: Option<String>,
    updated_at: String,
}

async fn open_intents(pool: &PgPool) -> Result<CustodialOpenIntents, AppError> {
    let counts: Vec<(String, i64)> = sqlx::query_as(OPEN_COUNTS_SQL)
        .fetch_all(pool)
        .await
        .map_err(db_err("open counts"))?;
    let mut open = CustodialOpenIntents::default();
    for (status, n) in counts {
        match status.as_str() {
            "prepared" => open.prepared = n,
            "submitted" => open.submitted = n,
            "ambiguous" => open.ambiguous = n,
            _ => {}
        }
    }
    Ok(open)
}

// ── Policy ─────────────────────────────────────────────────────────────

/// `GET /admin/custody/policy`.
pub async fn get_policy(
    _user: Privileged<ReadCustody>,
    Extension(pool): Extension<PgPool>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
) -> Result<Json<CustodialPolicyView>, AppError> {
    let row: Option<PolicyViewRow> = sqlx::query_as(&format!(
        "SELECT paused, paused_by, \
                to_char(paused_at AT TIME ZONE 'UTC', '{ts}') AS paused_at, pause_reason, \
                per_tx_max_stroops, per_account_daily_max_stroops, require_idempotency_key, \
                updated_by, to_char(updated_at AT TIME ZONE 'UTC', '{ts}') AS updated_at \
         FROM custodial_policy WHERE id",
        ts = TS_FMT
    ))
    .fetch_optional(&pool)
    .await
    .map_err(db_err("policy read"))?;
    let row = row.ok_or_else(|| {
        error!("custodial_policy row is missing (run migration 037)");
        AppError::InternalError("custodial policy row missing".to_string())
    })?;
    let configured = PolicyRow {
        paused: row.paused,
        per_tx_max_stroops: row.per_tx_max_stroops,
        per_account_daily_max_stroops: row.per_account_daily_max_stroops,
        require_idempotency_key: row.require_idempotency_key,
    }
    .is_configured();
    Ok(Json(CustodialPolicyView {
        paused: row.paused,
        paused_by: row.paused_by,
        paused_at: row.paused_at,
        pause_reason: row.pause_reason,
        per_tx_max_stroops: row.per_tx_max_stroops,
        per_account_daily_max_stroops: row.per_account_daily_max_stroops,
        require_idempotency_key: row.require_idempotency_key,
        configured,
        updated_by: row.updated_by,
        updated_at: row.updated_at,
        open_intents: open_intents(&pool).await?,
        resume_phrase: resume_phrase(stellar_config.network.as_str()),
    }))
}

/// `PUT /admin/custody/policy` — caps and the key requirement.
pub async fn update_policy(
    user: Privileged<ManageCustody>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<CustodialPolicyUpdateRequest>,
) -> Result<Json<CustodyChangedResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    for (name, v) in [
        ("per_tx_max_stroops", payload.per_tx_max_stroops),
        (
            "per_account_daily_max_stroops",
            payload.per_account_daily_max_stroops,
        ),
    ] {
        if v.is_some_and(|v| v < 0) {
            return Err(AppError::BadRequest(format!("{} must be >= 0", name)));
        }
    }
    if payload.per_tx_max_stroops.is_none()
        && payload.per_account_daily_max_stroops.is_none()
        && payload.require_idempotency_key.is_none()
    {
        return Err(AppError::BadRequest(
            "Nothing to update: supply per_tx_max_stroops, per_account_daily_max_stroops \
             or require_idempotency_key"
                .to_string(),
        ));
    }
    let mut tx = pool.begin().await.map_err(db_err("policy begin"))?;
    let (per_tx, daily, require_key): (i64, i64, bool) = sqlx::query_as(LIMITS_SQL)
        .bind(payload.per_tx_max_stroops)
        .bind(payload.per_account_daily_max_stroops)
        .bind(payload.require_idempotency_key)
        .bind(&user.account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("policy update"))?;
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::CustodyPolicyUpdated {
            account_id: user.account_id.clone(),
            per_tx_max_stroops: per_tx,
            per_account_daily_max_stroops: daily,
            require_idempotency_key: require_key,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("policy commit"))?;
    info!(
        "custody policy updated: per_tx_max={} daily_max={} require_key={} by={}",
        per_tx, daily, require_key, user.account_id
    );
    Ok(changed(true, "Custodial policy updated"))
}

/// `POST /admin/custody/pause` — the money brake (money-ops may pull it).
pub async fn pause(
    user: Privileged<ManageCustody>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<CustodyPauseRequest>,
) -> Result<Json<CustodyChangedResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    let reason = payload.reason.trim();
    if reason.is_empty() || reason.chars().count() > 200 {
        return Err(AppError::BadRequest(
            "reason must be 1-200 characters".to_string(),
        ));
    }
    let mut tx = pool.begin().await.map_err(db_err("pause begin"))?;
    let updated = sqlx::query(PAUSE_SQL)
        .bind(&user.account_id)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(db_err("pause update"))?;
    if updated.rows_affected() == 0 {
        return Ok(changed(false, "Custodial payments were already paused"));
    }
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::CustodyPaused {
            account_id: user.account_id.clone(),
            reason: reason.to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("pause commit"))?;
    warn!(
        "CUSTODIAL PAYMENTS PAUSED by {}: {}",
        user.account_id, reason
    );
    Ok(changed(true, "Custodial payments paused"))
}

/// `POST /admin/custody/resume` — governance only. Refuses while any intent
/// is `ambiguous` unless `force`: reopening with unknown chain state is the
/// double-pay moment.
pub async fn resume(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Json(payload): Json<CustodyResumeRequest>,
) -> Result<Json<CustodyChangedResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    let phrase = resume_phrase(stellar_config.network.as_str());
    if !crate::keys::tokens_match(payload.confirm_phrase.trim(), &phrase) {
        return Err(AppError::BadRequest(format!(
            "Resuming custodial payments requires confirm_phrase=\"{}\"",
            phrase
        )));
    }
    let ambiguous: i64 = sqlx::query_scalar(AMBIGUOUS_COUNT_SQL)
        .fetch_one(&pool)
        .await
        .map_err(db_err("ambiguous count"))?;
    if ambiguous > 0 && !payload.force {
        return Err(AppError::Conflict(format!(
            "{} custodial payment(s) have an unknown on-chain outcome; resolve them \
             (GET /admin/custody/intents?status=ambiguous) or resume with force=true",
            ambiguous
        )));
    }
    let mut tx = pool.begin().await.map_err(db_err("resume begin"))?;
    let updated = sqlx::query(RESUME_SQL)
        .bind(&user.account_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("resume update"))?;
    if updated.rows_affected() == 0 {
        return Ok(changed(false, "Custodial payments were not paused"));
    }
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::CustodyResumed {
            account_id: user.account_id.clone(),
            forced: payload.force,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("resume commit"))?;
    warn!(
        "custodial payments RESUMED by {} (forced={}, ambiguous open={})",
        user.account_id, payload.force, ambiguous
    );
    Ok(changed(true, "Custodial payments resumed"))
}

// ── Accounts ───────────────────────────────────────────────────────────

/// `PUT /admin/custody/accounts/{account_id}/limit` — per-account daily
/// override (`null` clears, `0` freezes).
pub async fn set_account_limit(
    user: Privileged<ManageCustody>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(reserve_guard): Extension<Arc<ReserveAccountGuard>>,
    Path(account_id): Path<String>,
    Json(payload): Json<CustodyAccountLimitRequest>,
) -> Result<Json<CustodyChangedResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    if reserve_guard.matches(&account_id) {
        return Err(AppError::Conflict(
            "This account is the configured conversion reserve; its spending is governed by \
             the reserve policies, not custodial limits"
                .to_string(),
        ));
    }
    if payload.custodial_daily_max_stroops.is_some_and(|v| v < 0) {
        return Err(AppError::BadRequest(
            "custodial_daily_max_stroops must be >= 0 or null".to_string(),
        ));
    }
    let mut tx = pool.begin().await.map_err(db_err("limit begin"))?;
    let updated = sqlx::query(ACCOUNT_LIMIT_UPDATE_SQL)
        .bind(&account_id)
        .bind(payload.custodial_daily_max_stroops)
        .execute(&mut *tx)
        .await
        .map_err(db_err("limit update"))?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("Account not found".to_string()));
    }
    crate::events::emit_event(
        &mut tx,
        &AccountEvent::CustodyAccountLimitUpdated {
            account_id: user.account_id.clone(),
            target_account_id: account_id.clone(),
            custodial_daily_max_stroops: payload.custodial_daily_max_stroops,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("limit commit"))?;
    info!(
        "custody account limit: account={} limit={:?} by={}",
        account_id, payload.custodial_daily_max_stroops, user.account_id
    );
    Ok(changed(true, "Custodial account limit updated"))
}

/// `GET /admin/custody/accounts` — every custodial account (managed seed),
/// the reserve account excluded (it is reported under the reserve). With
/// `onchain=true` each address is read on Horizon, best-effort.
pub async fn list_accounts(
    _user: Privileged<ReadCustody>,
    Extension(pool): Extension<PgPool>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    Extension(reserve_guard): Extension<Arc<ReserveAccountGuard>>,
    Query(q): Query<CustodyAccountsQuery>,
) -> Result<Json<PaginatedResponse<CustodialAccountView>>, AppError> {
    let (per_page, offset) = PaginationParams {
        page: q.page,
        per_page: q.per_page,
    }
    .clamped();
    let reserve_id = reserve_guard.account_id().map(str::to_string);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM managed_seed \
         WHERE ($1::text IS NULL OR payala_account_id <> $1)",
    )
    .bind(&reserve_id)
    .fetch_one(&pool)
    .await
    .map_err(db_err("accounts count"))?;
    let mut rows: Vec<CustodialAccountView> = sqlx::query_as(&format!(
        "SELECT s.payala_account_id, s.stellar_account_id, s.origin, s.format_version, \
                s.backend, to_char(s.created_at AT TIME ZONE 'UTC', '{ts}') AS created_at, \
                a.custodial_daily_max_stroops \
         FROM managed_seed s \
         LEFT JOIN impala_account a ON a.payala_account_id = s.payala_account_id \
         WHERE ($1::text IS NULL OR s.payala_account_id <> $1) \
         ORDER BY s.id LIMIT $2 OFFSET $3",
        ts = TS_FMT
    ))
    .bind(&reserve_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(db_err("accounts list"))?;

    if q.onchain {
        let horizon = stellar_config.horizon_url.clone();
        let addresses: Vec<(usize, String)> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| (i, r.stellar_account_id.clone()))
            .collect();
        let lookups = futures::stream::iter(addresses.into_iter().map(|(i, address)| {
            let http = http.clone();
            let horizon = horizon.clone();
            async move {
                (
                    i,
                    crate::stellar::fetch_account_details(&http, &horizon, &address).await,
                )
            }
        }))
        .buffer_unordered(RECONCILIATION_HORIZON_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        for (i, result) in lookups {
            match result {
                Ok(acct) => rows[i].onchain = Some(acct),
                Err(_) => rows[i].unreachable = true,
            }
        }
    }

    Ok(Json(PaginatedResponse {
        data: rows,
        page: ((offset / per_page) + 1) as u64,
        per_page: per_page as u64,
        total: total.max(0) as u64,
    }))
}

// ── Intents ────────────────────────────────────────────────────────────

/// `GET /admin/custody/intents?status&account&origin&page&per_page`.
pub async fn list_intents(
    _user: Privileged<ReadCustody>,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<AdminCustodialIntentListQuery>,
) -> Result<Json<PaginatedResponse<CustodialIntentView>>, AppError> {
    if let Some(st) = &q.status {
        if !VALID_CUSTODIAL_INTENT_STATUSES.contains(&st.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid status '{}'. Must be one of: {}",
                st,
                VALID_CUSTODIAL_INTENT_STATUSES.join(", ")
            )));
        }
    }
    if let Some(o) = &q.origin {
        if !VALID_CUSTODIAL_INTENT_ORIGINS.contains(&o.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid origin '{}'. Must be one of: {}",
                o,
                VALID_CUSTODIAL_INTENT_ORIGINS.join(", ")
            )));
        }
    }
    let (per_page, offset) = PaginationParams {
        page: q.page,
        per_page: q.per_page,
    }
    .clamped();
    let filter = "WHERE ($1::text IS NULL OR status = $1) \
         AND ($2::text IS NULL OR payala_account_id = $2) \
         AND ($3::text IS NULL OR origin = $3)";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM custodial_payment_intent {}",
        filter
    ))
    .bind(&q.status)
    .bind(&q.account)
    .bind(&q.origin)
    .fetch_one(&pool)
    .await
    .map_err(db_err("intent count"))?;
    let rows: Vec<CustodialIntentView> = sqlx::query_as(&format!(
        "SELECT {} FROM custodial_payment_intent {} \
         ORDER BY created_at DESC, intent_id DESC LIMIT $4 OFFSET $5",
        intent_view_columns(),
        filter
    ))
    .bind(&q.status)
    .bind(&q.account)
    .bind(&q.origin)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(db_err("intent list"))?;
    Ok(Json(PaginatedResponse {
        data: rows.into_iter().map(finish_view).collect(),
        page: ((offset / per_page) + 1) as u64,
        per_page: per_page as u64,
        total: total.max(0) as u64,
    }))
}

/// `GET /admin/custody/intents/{intent_id}`.
pub async fn get_intent(
    _user: Privileged<ReadCustody>,
    Extension(pool): Extension<PgPool>,
    Path(intent_id): Path<Uuid>,
) -> Result<Json<CustodialIntentView>, AppError> {
    let row: Option<CustodialIntentView> = sqlx::query_as(&format!(
        "SELECT {} FROM custodial_payment_intent WHERE intent_id = $1",
        intent_view_columns()
    ))
    .bind(intent_id)
    .fetch_optional(&pool)
    .await
    .map_err(db_err("intent read"))?;
    row.map(|v| Json(finish_view(v)))
        .ok_or_else(|| AppError::NotFound("No such intent".to_string()))
}

/// `POST /admin/custody/intents/{intent_id}/resolve` — settle or fail a
/// `submitted`/`ambiguous` intent after reading the chain.
pub async fn resolve_intent(
    user: Privileged<ManageCustody>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    Path(intent_id): Path<Uuid>,
    Json(payload): Json<CustodyResolveRequest>,
) -> Result<Json<CustodyResolveResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    let row: Option<OpenIntentRow> = sqlx::query_as(OPEN_INTENT_BY_ID_SQL)
        .bind(intent_id)
        .fetch_optional(&pool)
        .await
        .map_err(db_err("intent read"))?;
    let row = row.ok_or_else(|| AppError::NotFound("No such intent".to_string()))?;
    if !matches!(row.status.as_str(), "submitted" | "ambiguous") {
        return Err(AppError::Conflict(format!(
            "Intent is {}; only submitted or ambiguous intents can be resolved",
            row.status
        )));
    }
    let row_hash = row
        .stellar_hash
        .clone()
        .ok_or_else(|| AppError::InternalError("Corrupt intent record".to_string()))?;
    let asset = row.asset();
    let horizon = &stellar_config.horizon_url;

    match payload.action.as_str() {
        "complete" => {
            let candidate = payload.stellar_hash.as_deref().unwrap_or(&row_hash);
            let hash = crate::handlers::admin_reserve::verify_settlement_hash(
                &http,
                horizon,
                candidate,
                &row.source_account,
                &row.destination,
                row.amount_minor,
                Some(&asset),
            )
            .await?;
            if hash != row_hash {
                // The row's hash is the signed envelope; a different settling
                // hash means a different transaction paid this — reconcile by
                // hand rather than tie the row to evidence it did not sign.
                return Err(AppError::Conflict(format!(
                    "Transaction {} settles the payment but is not this intent's signed \
                     envelope ({}); reconcile by hand",
                    hash, row_hash
                )));
            }
            let audit = AccountEvent::CustodyIntentResolved {
                account_id: user.account_id.clone(),
                intent_id: intent_id.to_string(),
                action: "complete".to_string(),
                resolution: "admin_complete".to_string(),
            };
            match record_settlement(
                &pool,
                &row.settlement(&hash, "admin_complete"),
                Some(&audit),
            )
            .await?
            {
                SettleOutcome::Settled { btxid } => {
                    info!(
                        "custody resolve: intent {} completed by {} (btxid {})",
                        intent_id, user.account_id, btxid
                    );
                    Ok(Json(CustodyResolveResponse {
                        success: true,
                        message: "Intent settled from verified on-chain evidence".to_string(),
                        intent_id,
                        status: "settled".to_string(),
                        resolution: "admin_complete".to_string(),
                        btxid: Some(btxid),
                    }))
                }
                SettleOutcome::AlreadySettled => Err(AppError::Conflict(
                    "Intent was resolved concurrently; re-read it".to_string(),
                )),
            }
        }
        "fail" => {
            let age = row
                .armed_at
                .map(|t| (chrono::Utc::now() - t).num_seconds())
                .unwrap_or(0);
            if age < CUSTODIAL_STALE_INTENT_SECS {
                return Err(AppError::Conflict(format!(
                    "Intent was armed {}s ago; the signed transaction may still land within its \
                     validity window. Retry after {}s",
                    age, CUSTODIAL_STALE_INTENT_SECS
                )));
            }
            // Ok(None) = failed on-chain, or absent from a FRESH Horizon;
            // Some(_) = it landed; Err = inconclusive (fails closed).
            let landed = crate::handlers::admin_reserve::resolve_intent_by_hash(
                &http,
                horizon,
                &row_hash,
                &row.source_account,
                &row.destination,
                row.amount_minor,
                Some(&asset),
            )
            .await?;
            if let Some(hash) = landed {
                return Err(AppError::Conflict(format!(
                    "Transaction {} settled on-chain; resolve with action=complete instead",
                    hash
                )));
            }
            let audit = AccountEvent::CustodyIntentResolved {
                account_id: user.account_id.clone(),
                intent_id: intent_id.to_string(),
                action: "fail".to_string(),
                resolution: "admin_fail".to_string(),
            };
            let done = reject_by_hash(
                &pool,
                intent_id,
                &row_hash,
                "admin_fail",
                "proven absent or failed on-chain by admin resolution",
                Some(&audit),
            )
            .await?;
            if !done {
                return Err(AppError::Conflict(
                    "Intent was resolved concurrently; re-read it".to_string(),
                ));
            }
            info!(
                "custody resolve: intent {} failed by {} after on-chain absence proof",
                intent_id, user.account_id
            );
            Ok(Json(CustodyResolveResponse {
                success: true,
                message: "Intent marked failed; nothing landed on-chain".to_string(),
                intent_id,
                status: "rejected".to_string(),
                resolution: "admin_fail".to_string(),
                btxid: None,
            }))
        }
        other => Err(AppError::BadRequest(format!(
            "action must be 'complete' or 'fail', got '{}'",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mutation names its from-state (or the single row) in its WHERE
    /// clause: a replayed request is a zero-row no-op, never a second event.
    #[test]
    fn custody_admin_mutations_are_guarded_single_statements() {
        assert!(PAUSE_SQL.ends_with("WHERE id AND paused = false"));
        assert!(RESUME_SQL.ends_with("WHERE id AND paused = true"));
        assert!(LIMITS_SQL.contains("WHERE id RETURNING"));
        assert!(!LIMITS_SQL.contains("INSERT"));
        for sql in [PAUSE_SQL, RESUME_SQL, LIMITS_SQL, ACCOUNT_LIMIT_UPDATE_SQL] {
            assert_eq!(sql.matches("UPDATE ").count(), 1, "one statement: {}", sql);
            assert!(!sql.contains(';'));
        }
        assert!(ACCOUNT_LIMIT_UPDATE_SQL.ends_with("WHERE payala_account_id = $1"));
        assert!(AMBIGUOUS_COUNT_SQL.contains("status = 'ambiguous'"));
    }

    #[test]
    fn resume_phrase_names_the_network() {
        assert_eq!(resume_phrase("testnet"), "resume custody testnet");
        assert_eq!(resume_phrase("pubnet"), "resume custody pubnet");
        assert_ne!(
            resume_phrase("testnet"),
            crate::keys::confirm_phrase("owlpay", "testnet")
        );
    }

    /// The resume gate must read the ambiguous count from the intent
    /// table, not a cache, and the handler must consult it before the
    /// UPDATE.
    #[test]
    fn resume_refuses_while_ambiguous_intents_exist() {
        let src = include_str!("admin_custody.rs");
        let resume = &src[src.find("pub async fn resume(").unwrap()..];
        let resume = &resume[..resume.find("pub async fn set_account_limit").unwrap()];
        let count = resume.find("AMBIGUOUS_COUNT_SQL").expect("gate present");
        let update = resume.find("RESUME_SQL").expect("update present");
        assert!(count < update, "the ambiguous gate must precede the update");
        assert!(resume.contains("!payload.force"));
        assert!(resume.contains("tokens_match("));
        assert!(!resume.to_ascii_lowercase().contains("redis_helpers::get"));
    }

    /// `fail` may only follow the stale window AND a chain read; `complete`
    /// may only follow a verified hash.
    #[test]
    fn resolve_reads_the_chain_before_every_write() {
        let src = include_str!("admin_custody.rs");
        let resolve = &src[src.find("pub async fn resolve_intent(").unwrap()..];
        let resolve = &resolve[..resolve.find("#[cfg(test)]").unwrap()];
        let complete_arm = resolve.find("\"complete\" =>").unwrap();
        let fail_arm = resolve.find("\"fail\" =>").unwrap();
        let complete = &resolve[complete_arm..fail_arm];
        assert!(
            complete.find("verify_settlement_hash(").unwrap()
                < complete.find("record_settlement(").unwrap()
        );
        let fail = &resolve[fail_arm..];
        assert!(
            fail.find("CUSTODIAL_STALE_INTENT_SECS").unwrap()
                < fail.find("resolve_intent_by_hash(").unwrap()
        );
        assert!(
            fail.find("resolve_intent_by_hash(").unwrap() < fail.find("reject_by_hash(").unwrap()
        );
    }
}

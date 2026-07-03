//! Admin-only, cross-account endpoints backing the web admin console.
//!
//! All handlers begin with `require_admin`. They deliberately bypass the
//! per-owner `require_owner` discipline used elsewhere because acting across
//! accounts (list / delete / grant-role / force directory sync) is the point of
//! the admin console.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;

use crate::auth::{require_admin, AuthenticatedUser};
use crate::constants::{ROLE_ADMIN, SYNC_MODE_RESERVE};
use crate::error::AppError;
use crate::ldap::LdapConfig;
use crate::models::{
    AdminAccountListItem, DeleteAccountResponse, ListAccountsQuery, PaginatedResponse,
    PaginationParams, SetRoleRequest, SetRoleResponse, SetSyncModeRequest, SetSyncModeResponse,
    SyncProfileResponse,
};

const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

/// Pure guard: would setting `new_role` on the target remove the last admin?
fn would_remove_last_admin(admin_count: i64, target_is_admin: bool, new_role: &str) -> bool {
    target_is_admin && new_role != ROLE_ADMIN && admin_count <= 1
}

/// `GET /accounts` — paginated, searchable list of all accounts (admin only).
pub async fn list_accounts(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<ListAccountsQuery>,
) -> Result<Json<PaginatedResponse<AdminAccountListItem>>, AppError> {
    require_admin(&user)?;

    let (per_page, offset) = PaginationParams {
        page: q.page,
        per_page: q.per_page,
    }
    .clamped();
    let search = q
        .search
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM impala_account
           WHERE ($1::text IS NULL
              OR payala_account_id ILIKE '%'||$1||'%'
              OR stellar_account_id ILIKE '%'||$1||'%'
              OR first_name ILIKE '%'||$1||'%'
              OR last_name  ILIKE '%'||$1||'%')"#,
    )
    .bind(&search)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("list_accounts: count error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let select_sql = format!(
        r#"SELECT payala_account_id, stellar_account_id, first_name, middle_name, last_name,
                  nickname, affiliation, gender, role, sync_mode, profile_source,
                  to_char(created_at AT TIME ZONE 'UTC', '{ts}') AS created_at
           FROM impala_account
           WHERE ($1::text IS NULL
              OR payala_account_id ILIKE '%'||$1||'%'
              OR stellar_account_id ILIKE '%'||$1||'%'
              OR first_name ILIKE '%'||$1||'%'
              OR last_name  ILIKE '%'||$1||'%')
           ORDER BY created_at DESC, id DESC
           LIMIT $2 OFFSET $3"#,
        ts = TS_FMT
    );

    let rows = sqlx::query_as::<_, AdminAccountListItem>(&select_sql)
        .bind(&search)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("list_accounts: query error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

    Ok(Json(PaginatedResponse {
        data: rows,
        page: q.page.max(1),
        per_page: per_page as u64,
        total: total as u64,
    }))
}

/// `PUT /admin/accounts/:account_id/role` — set an account's role (admin only).
pub async fn set_account_role(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(account_id): Path<String>,
    Json(payload): Json<SetRoleRequest>,
) -> Result<Json<SetRoleResponse>, AppError> {
    require_admin(&user)?;
    crate::validate::validate_role(&payload.role)?;

    // Block demoting the last remaining admin (incl. self-demotion).
    if payload.role != ROLE_ADMIN {
        let admin_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM impala_account WHERE role = 'admin'")
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("set_account_role: admin count error: {}", e);
                    AppError::InternalError("Database error".to_string())
                })?;
        let target_is_admin: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM impala_account WHERE payala_account_id = $1 AND role = 'admin'",
        )
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            error!("set_account_role: target lookup error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
        if would_remove_last_admin(admin_count, target_is_admin == 1, &payload.role) {
            return Err(AppError::Conflict(
                "Cannot demote the last remaining admin".to_string(),
            ));
        }
    }

    let res = sqlx::query(
        "UPDATE impala_account SET role = $1, updated_at = NOW() WHERE payala_account_id = $2",
    )
    .bind(&payload.role)
    .bind(&account_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("set_account_role: update error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Account not found".to_string()));
    }

    info!(
        "set_account_role: account_id={} role={} by={}",
        account_id, payload.role, user.account_id
    );
    Ok(Json(SetRoleResponse {
        success: true,
        message: "Role updated".to_string(),
        account_id,
        role: payload.role,
    }))
}

/// `PUT /admin/accounts/:account_id/sync-mode` — set an account's Payala sync
/// mode (admin only). Flips are forward-only: existing reserve balances and
/// mirrored rows are untouched, and only future batches follow the new mode.
/// Leaving `reserve` while a nonzero balance remains requires `force: true`
/// (the balance would otherwise sit frozen and easy to overlook).
pub async fn set_sync_mode(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(account_id): Path<String>,
    Json(payload): Json<SetSyncModeRequest>,
) -> Result<Json<SetSyncModeResponse>, AppError> {
    require_admin(&user)?;
    crate::validate::validate_sync_mode(&payload.sync_mode)?;

    // Guard and flip run in one transaction under the same per-account
    // advisory lock as sync_payala, so the nonzero-balance check cannot race
    // an in-flight batch (which would otherwise land a reserve delta between
    // the check and the UPDATE, silently bypassing the 409).
    let mut tx = pool.begin().await.map_err(|e| {
        error!("set_sync_mode: begin error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('payala_sync:' || $1))")
        .bind(&account_id)
        .execute(&mut tx)
        .await
        .map_err(|e| {
            error!("set_sync_mode: advisory lock error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

    let current_mode: String =
        sqlx::query_scalar("SELECT sync_mode FROM impala_account WHERE payala_account_id = $1")
            .bind(&account_id)
            .fetch_optional(&mut tx)
            .await
            .map_err(|e| {
                error!("set_sync_mode: mode lookup error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?
            .ok_or_else(|| AppError::NotFound("Account not found".to_string()))?;

    if current_mode == SYNC_MODE_RESERVE
        && payload.sync_mode != SYNC_MODE_RESERVE
        && payload.force != Some(true)
    {
        let nonzero: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM payala_reserve WHERE payala_account_id = $1 AND balance != 0 LIMIT 1",
        )
        .bind(&account_id)
        .fetch_optional(&mut tx)
        .await
        .map_err(|e| {
            error!("set_sync_mode: reserve check error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
        if nonzero.is_some() {
            return Err(AppError::Conflict(
                "account has a nonzero reserve balance; pass force=true to switch anyway"
                    .to_string(),
            ));
        }
    }

    sqlx::query(
        "UPDATE impala_account SET sync_mode = $1, updated_at = NOW() WHERE payala_account_id = $2",
    )
    .bind(&payload.sync_mode)
    .bind(&account_id)
    .execute(&mut tx)
    .await
    .map_err(|e| {
        error!("set_sync_mode: update error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    tx.commit().await.map_err(|e| {
        error!("set_sync_mode: commit error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    info!(
        "set_sync_mode: account_id={} sync_mode={} by={}",
        account_id, payload.sync_mode, user.account_id
    );
    Ok(Json(SetSyncModeResponse {
        success: true,
        message: "Sync mode updated".to_string(),
        account_id,
        sync_mode: payload.sync_mode,
    }))
}

/// `DELETE /admin/accounts/:account_id` — delete an account (admin only).
///
/// Cascades to `impala_auth` / `impala_mfa` / `card` via FKs; the remaining
/// per-account tables have no cascade FK, so they are deleted explicitly within
/// a single transaction to avoid orphaning rows (notably a custodial seed).
pub async fn delete_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(account_id): Path<String>,
) -> Result<Json<DeleteAccountResponse>, AppError> {
    require_admin(&user)?;

    if account_id == user.account_id {
        return Err(AppError::BadRequest(
            "Admins cannot delete their own account".to_string(),
        ));
    }

    // Block deleting the last remaining admin.
    let target_is_admin: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM impala_account WHERE payala_account_id = $1 AND role = 'admin'",
    )
    .bind(&account_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("delete_account: target lookup error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    if target_is_admin == 1 {
        let admin_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM impala_account WHERE role = 'admin'")
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("delete_account: admin count error: {}", e);
                    AppError::InternalError("Database error".to_string())
                })?;
        if admin_count <= 1 {
            return Err(AppError::Conflict(
                "Cannot delete the last remaining admin".to_string(),
            ));
        }
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!("delete_account: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    // Child tables without an ON DELETE CASCADE FK to impala_account.
    // notify_log references notify(id) (RESTRICT), so purge it first.
    for stmt in [
        "DELETE FROM notify_log WHERE notify_id IN (SELECT id FROM notify WHERE account_id = $1)",
        "DELETE FROM notify WHERE account_id = $1",
        "DELETE FROM notification_subscription WHERE account_id = $1",
        "DELETE FROM device_token WHERE account_id = $1",
        "DELETE FROM managed_seed WHERE payala_account_id = $1",
    ] {
        sqlx::query(stmt)
            .bind(&account_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("delete_account: child delete error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;
    }

    let res = sqlx::query("DELETE FROM impala_account WHERE payala_account_id = $1")
        .bind(&account_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("delete_account: account delete error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

    if res.rows_affected() == 0 {
        // Nothing deleted — roll back the child deletes and report not found.
        let _ = tx.rollback().await;
        return Err(AppError::NotFound("Account not found".to_string()));
    }

    tx.commit().await.map_err(|e| {
        error!("delete_account: commit error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    info!(
        "delete_account: account_id={} deleted by={}",
        account_id, user.account_id
    );
    Ok(Json(DeleteAccountResponse {
        success: true,
        message: "Account deleted".to_string(),
        rows_affected: res.rows_affected(),
    }))
}

/// `POST /admin/accounts/:account_id/sync-profile` — force a directory re-pull
/// for the account's profile source (admin only).
pub async fn sync_profile(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(ldap_config): Extension<Arc<LdapConfig>>,
    Path(account_id): Path<String>,
) -> Result<Json<SyncProfileResponse>, AppError> {
    require_admin(&user)?;

    let source: String = sqlx::query_scalar(
        "SELECT profile_source FROM impala_account WHERE payala_account_id = $1",
    )
    .bind(&account_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("sync_profile: lookup error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?
    .ok_or_else(|| AppError::NotFound("Account not found".to_string()))?;

    match source.as_str() {
        "ldap" => {
            let profile =
                crate::ldap::sync_account_profile(&pool, &ldap_config, &account_id).await?;
            let synced_at: Option<String> = sqlx::query_scalar(&format!(
                "SELECT to_char(profile_synced_at AT TIME ZONE 'UTC', '{ts}') \
                 FROM impala_account WHERE payala_account_id = $1",
                ts = TS_FMT
            ))
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("sync_profile: synced_at lookup error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;

            info!(
                "sync_profile: account_id={} synced from LDAP by={}",
                account_id, user.account_id
            );
            Ok(Json(SyncProfileResponse {
                success: true,
                message: "Profile synced from LDAP".to_string(),
                profile_source: source,
                profile_synced_at: synced_at,
                profile: Some(profile),
            }))
        }
        "okta" => {
            warn!(
                "sync_profile: okta force-sync not supported (account_id={})",
                account_id
            );
            Err(AppError::BadRequest(
                "Okta profiles cannot be force-synced server-side: no Okta refresh token is \
                 stored and the access-token claims carry only email/username (no name fields). \
                 The user must re-authenticate via Okta to refresh their profile."
                    .to_string(),
            ))
        }
        _ => Err(AppError::BadRequest(
            "Local profiles have no external source to sync from.".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_would_remove_last_admin() {
        // demoting the only admin → blocked
        assert!(would_remove_last_admin(1, true, "view-only"));
        // demoting a non-admin → allowed
        assert!(!would_remove_last_admin(1, false, "view-only"));
        // demoting an admin when others remain → allowed
        assert!(!would_remove_last_admin(2, true, "token"));
        // setting an admin to admin (no-op) → allowed
        assert!(!would_remove_last_admin(1, true, "admin"));
    }
}

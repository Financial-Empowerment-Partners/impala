use axum::extract::{Extension, Query};
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::constants::MAX_NAME_LENGTH;
use crate::error::AppError;
use crate::models::{
    CreateAccountRequest, CreateAccountResponse, GetAccountQuery, GetAccountResponse,
    UpdateAccountRequest, UpdateAccountResponse,
};
use crate::notifications::{self, NotificationEvent};

/// Create a new linked Stellar/Payala account (`POST /account`).
pub async fn create_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, AppError> {
    // Admins may create an account for any payala id (admin console); a regular
    // caller may only create their own (self-service).
    if !user.is_admin() {
        crate::auth::require_owner(&user, &payload.payala_account_id)?;
    }
    info!(
        "POST /account: creating account for stellar_id={}",
        payload.stellar_account_id
    );

    crate::validate::validate_stellar_account_id(&payload.stellar_account_id)?;

    if payload.first_name.trim().is_empty() || payload.last_name.trim().is_empty() {
        warn!("create_account: empty name fields");
        return Ok(Json(CreateAccountResponse {
            success: false,
            message: "first_name and last_name must not be empty".to_string(),
        }));
    }

    if payload.first_name.len() > MAX_NAME_LENGTH || payload.last_name.len() > MAX_NAME_LENGTH {
        warn!(
            "create_account: name fields exceed {} characters",
            MAX_NAME_LENGTH
        );
        return Ok(Json(CreateAccountResponse {
            success: false,
            message: format!("Name fields must not exceed {} characters", MAX_NAME_LENGTH),
        }));
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!("create_account: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let result = sqlx::query(
        r#"
        INSERT INTO impala_account
            (stellar_account_id, payala_account_id, first_name, middle_name,
             last_name, nickname, affiliation, gender)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&payload.stellar_account_id)
    .bind(&payload.payala_account_id)
    .bind(&payload.first_name)
    .bind(&payload.middle_name)
    .bind(&payload.last_name)
    .bind(&payload.nickname)
    .bind(&payload.affiliation)
    .bind(&payload.gender)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            // Append the admin-feed event in the same transaction.
            crate::events::emit_event(
                &mut tx,
                &crate::events::AccountEvent::AccountCreated {
                    account_id: payload.payala_account_id.clone(),
                    stellar_account_id: payload.stellar_account_id.clone(),
                },
            )
            .await?;
            tx.commit().await.map_err(|e| {
                error!("create_account: commit error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;
            info!(
                "create_account: account created for stellar_id={}",
                payload.stellar_account_id
            );
            Ok(Json(CreateAccountResponse {
                success: true,
                message: "Account created successfully".to_string(),
            }))
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("duplicate key") || err_str.contains("unique constraint") {
                warn!(
                    "create_account: duplicate account for stellar_id={}",
                    payload.stellar_account_id
                );
                return Ok(Json(CreateAccountResponse {
                    success: false,
                    message: "An account with this identifier already exists".to_string(),
                }));
            }
            error!("create_account: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Look up an account by Stellar account ID (`GET /account?stellar_account_id=...`).
///
/// Admins may read any account; a regular caller is scoped to their own row.
pub async fn get_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Query(params): Query<GetAccountQuery>,
) -> Result<Json<GetAccountResponse>, AppError> {
    debug!(
        "GET /account: lookup stellar_id={}",
        params.stellar_account_id
    );

    let mut sql = String::from(
        r#"
        SELECT payala_account_id, stellar_account_id, first_name, middle_name, last_name,
               nickname, affiliation, gender, role, sync_mode, profile_source,
               to_char(profile_synced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS profile_synced_at,
               to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
        FROM impala_account
        WHERE stellar_account_id = $1
        "#,
    );
    // ReadAccounts holders (admin, auditor, key-custodian) read any account —
    // the console drawer and compliance reads are cross-account by nature.
    let cross_account =
        crate::auth::role_has_capability(&user.role, crate::auth::Capability::ReadAccounts);
    if !cross_account {
        sql.push_str(" AND payala_account_id = $2");
    }

    let mut query = sqlx::query_as::<_, GetAccountResponse>(&sql).bind(&params.stellar_account_id);
    if !cross_account {
        query = query.bind(&user.account_id);
    }

    let result = query.fetch_optional(&pool).await;

    match result {
        Ok(Some(mut account)) => {
            // Same effective-privilege marking as the accounts list: the
            // drawer hosting the role-grant control must not understate an
            // allowlisted account's real authority.
            account.allowlisted = admin_ids.contains(&account.payala_account_id);
            Ok(Json(account))
        }
        Ok(None) => {
            debug!(
                "get_account: not found for stellar_id={}",
                params.stellar_account_id
            );
            Err(AppError::NotFound("Account not found".to_string()))
        }
        Err(e) => {
            error!("get_account: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Fetch live on-chain details for an account from this bridge's configured
/// network (`GET /account/onchain?stellar_account_id=...`). Owner or admin.
pub async fn get_account_onchain(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    Query(params): Query<GetAccountQuery>,
) -> Result<Json<crate::stellar::OnchainAccount>, AppError> {
    crate::validate::validate_stellar_account_id(&params.stellar_account_id)?;

    // Authorize: the owner of this stellar id, or any admin.
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT payala_account_id FROM impala_account WHERE stellar_account_id = $1",
    )
    .bind(&params.stellar_account_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("get_account_onchain: owner lookup error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let is_owner = owner.as_deref() == Some(user.account_id.as_str());
    if !is_owner
        && !crate::auth::role_has_capability(&user.role, crate::auth::Capability::ReadAccounts)
    {
        return Err(AppError::Forbidden);
    }

    let account = crate::stellar::fetch_account_details(
        &http,
        &stellar_config.horizon_url,
        &params.stellar_account_id,
    )
    .await?;

    Ok(Json(account))
}

/// Update account fields (`PUT /account`).
pub async fn update_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<crate::sns::SnsTopicArn>>,
    Json(payload): Json<UpdateAccountRequest>,
) -> Result<Json<UpdateAccountResponse>, AppError> {
    info!("PUT /account: updating account");
    // Admins may update any account (admin console); regular callers are
    // scoped to their own row — via require_owner here on the payala-keyed
    // path, or the ownership conjunct build_account_update appends to the
    // WHERE clause on the stellar-keyed path.
    let is_admin = user.is_admin();
    let where_value = if let Some(ref stellar_id) = payload.stellar_account_id {
        stellar_id.clone()
    } else if let Some(ref payala_id) = payload.payala_account_id {
        if !is_admin {
            crate::auth::require_owner(&user, payala_id)?;
        }
        payala_id.clone()
    } else {
        warn!("update_account: no identifier provided");
        return Ok(Json(UpdateAccountResponse {
            success: false,
            message: "Either stellar_account_id or payala_account_id must be provided".to_string(),
            rows_affected: 0,
        }));
    };

    if let Some(ref stellar_id) = payload.stellar_account_id {
        crate::validate::validate_stellar_account_id(stellar_id)?;
    }

    let Some(mut qb) = build_account_update(&payload, &user.account_id, is_admin) else {
        warn!("update_account: no fields provided to update");
        return Ok(Json(UpdateAccountResponse {
            success: false,
            message: "No fields provided to update".to_string(),
            rows_affected: 0,
        }));
    };

    // Collect field names for notification
    let mut changed_fields = Vec::new();
    if payload.first_name.is_some() {
        changed_fields.push("first_name".to_string());
    }
    if payload.middle_name.is_some() {
        changed_fields.push("middle_name".to_string());
    }
    if payload.last_name.is_some() {
        changed_fields.push("last_name".to_string());
    }
    if payload.nickname.is_some() {
        changed_fields.push("nickname".to_string());
    }
    if payload.affiliation.is_some() {
        changed_fields.push("affiliation".to_string());
    }
    if payload.gender.is_some() {
        changed_fields.push("gender".to_string());
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!("update_account: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let result = qb.build().execute(&mut *tx).await;

    match result {
        Ok(res) => {
            let rows_affected = res.rows_affected();
            if rows_affected == 0 {
                debug!("update_account: no matching account found");
                Ok(Json(UpdateAccountResponse {
                    success: false,
                    message: "No account found with the provided identifier".to_string(),
                    rows_affected: 0,
                }))
            } else {
                info!("update_account: updated {} row(s)", rows_affected);

                // Append the admin-feed event in the same transaction.
                crate::events::emit_event(
                    &mut tx,
                    &crate::events::AccountEvent::AccountUpdated {
                        account_id: where_value.clone(),
                        fields: changed_fields.clone(),
                    },
                )
                .await?;
                tx.commit().await.map_err(|e| {
                    error!("update_account: commit error: {}", e);
                    AppError::InternalError("Database error".to_string())
                })?;

                // Fire-and-forget user notification for profile update.
                let sns_c = sns_client.as_ref().map(|e| &e.0);
                let sns_a = sns_topic_arn.as_ref().map(|e| &e.0 .0);
                notifications::dispatch_event(
                    &pool,
                    sns_c,
                    sns_a,
                    NotificationEvent::ProfileUpdated {
                        account_id: where_value.clone(),
                        fields: changed_fields,
                    },
                    None,
                )
                .await;

                Ok(Json(UpdateAccountResponse {
                    success: true,
                    message: "Account updated successfully".to_string(),
                    rows_affected,
                }))
            }
        }
        Err(e) => {
            error!("update_account: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Build the UPDATE statement for `PUT /account`. Returns `None` when no SET
/// fields are present.
///
/// INVARIANT (cross-account write protection): for non-admin callers every
/// generated WHERE clause constrains the caller's account — directly when
/// keyed by `payala_account_id` (ownership enforced by `require_owner`
/// upstream), or via the appended `payala_account_id = <caller>` conjunct
/// when keyed by `stellar_account_id`. Admins (server-side `role` claim) skip
/// the conjunct so the admin console can update any account. The invariant
/// tests below pin both shapes.
fn build_account_update<'a>(
    payload: &'a UpdateAccountRequest,
    user_account_id: &'a str,
    is_admin: bool,
) -> Option<sqlx::QueryBuilder<'a, sqlx::Postgres>> {
    let keyed_by_stellar = payload.stellar_account_id.is_some();
    if !keyed_by_stellar && payload.payala_account_id.is_none() {
        return None;
    }

    let mut qb = sqlx::QueryBuilder::new("UPDATE impala_account SET ");
    let mut any_set = false;
    {
        let mut sets = qb.separated(", ");
        // Same field order as the legacy string generator. A payala id can be
        // SET only when the row is keyed by stellar id (when keyed by payala,
        // the payala id *is* the key).
        if keyed_by_stellar {
            if let Some(ref v) = payload.payala_account_id {
                sets.push("payala_account_id = ");
                sets.push_bind_unseparated(v);
                any_set = true;
            }
        }
        if let Some(ref v) = payload.first_name {
            sets.push("first_name = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.middle_name {
            sets.push("middle_name = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.last_name {
            sets.push("last_name = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.nickname {
            sets.push("nickname = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.affiliation {
            sets.push("affiliation = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
        if let Some(ref v) = payload.gender {
            sets.push("gender = ");
            sets.push_bind_unseparated(v);
            any_set = true;
        }
    }
    if !any_set {
        return None;
    }

    if keyed_by_stellar {
        qb.push(" WHERE stellar_account_id = ");
        qb.push_bind(payload.stellar_account_id.as_ref().unwrap());
        if !is_admin {
            qb.push(" AND payala_account_id = ");
            qb.push_bind(user_account_id);
        }
    } else {
        qb.push(" WHERE payala_account_id = ");
        qb.push_bind(payload.payala_account_id.as_ref().unwrap());
    }

    Some(qb)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_payload() -> UpdateAccountRequest {
        UpdateAccountRequest {
            stellar_account_id: None,
            payala_account_id: None,
            first_name: None,
            middle_name: None,
            last_name: None,
            nickname: None,
            affiliation: None,
            gender: None,
        }
    }

    #[test]
    fn keyed_by_stellar_single_field() {
        let payload = UpdateAccountRequest {
            stellar_account_id: Some("GSTELLAR".to_string()),
            first_name: Some("Ada".to_string()),
            ..empty_payload()
        };
        let qb = build_account_update(&payload, "alice", false).expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE impala_account SET first_name = $1 \
             WHERE stellar_account_id = $2 AND payala_account_id = $3"
        );
    }

    #[test]
    fn keyed_by_stellar_admin_skips_ownership_conjunct() {
        // Admin console path: no `payala_account_id = <caller>` scoping.
        let payload = UpdateAccountRequest {
            stellar_account_id: Some("GSTELLAR".to_string()),
            first_name: Some("Ada".to_string()),
            ..empty_payload()
        };
        let qb = build_account_update(&payload, "alice", true).expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE impala_account SET first_name = $1 WHERE stellar_account_id = $2"
        );
    }

    #[test]
    fn keyed_by_payala_multiple_fields() {
        let payload = UpdateAccountRequest {
            payala_account_id: Some("alice".to_string()),
            nickname: Some("ace".to_string()),
            gender: Some("x".to_string()),
            ..empty_payload()
        };
        let qb = build_account_update(&payload, "alice", false).expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE impala_account SET nickname = $1, gender = $2 \
             WHERE payala_account_id = $3"
        );
    }

    #[test]
    fn keyed_by_stellar_sets_payala_id_first() {
        let payload = UpdateAccountRequest {
            stellar_account_id: Some("GSTELLAR".to_string()),
            payala_account_id: Some("newid".to_string()),
            last_name: Some("Lovelace".to_string()),
            ..empty_payload()
        };
        let qb = build_account_update(&payload, "alice", false).expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE impala_account SET payala_account_id = $1, last_name = $2 \
             WHERE stellar_account_id = $3 AND payala_account_id = $4"
        );
    }

    #[test]
    fn all_profile_fields_in_legacy_order() {
        let payload = UpdateAccountRequest {
            payala_account_id: Some("alice".to_string()),
            first_name: Some("a".to_string()),
            middle_name: Some("b".to_string()),
            last_name: Some("c".to_string()),
            nickname: Some("d".to_string()),
            affiliation: Some("e".to_string()),
            gender: Some("f".to_string()),
            ..empty_payload()
        };
        let qb = build_account_update(&payload, "alice", false).expect("builder");
        assert_eq!(
            qb.sql(),
            "UPDATE impala_account SET first_name = $1, middle_name = $2, last_name = $3, \
             nickname = $4, affiliation = $5, gender = $6 WHERE payala_account_id = $7"
        );
    }

    #[test]
    fn no_set_fields_returns_none() {
        let payload = UpdateAccountRequest {
            payala_account_id: Some("alice".to_string()),
            ..empty_payload()
        };
        assert!(build_account_update(&payload, "alice", false).is_none());
        assert!(build_account_update(&empty_payload(), "alice", false).is_none());
    }

    /// Ownership-WHERE invariant (SECURITY.md / CLAUDE.md): every generated
    /// UPDATE must constrain `payala_account_id` so cross-account writes are
    /// impossible at the SQL layer, for every non-empty field combination.
    #[test]
    fn every_generated_where_clause_pins_the_account() {
        let field_setters: Vec<fn(&mut UpdateAccountRequest)> = vec![
            |p| p.first_name = Some("v".to_string()),
            |p| p.middle_name = Some("v".to_string()),
            |p| p.last_name = Some("v".to_string()),
            |p| p.nickname = Some("v".to_string()),
            |p| p.affiliation = Some("v".to_string()),
            |p| p.gender = Some("v".to_string()),
        ];
        for keyed_by_stellar in [true, false] {
            for mask in 1u32..(1 << field_setters.len()) {
                let mut payload = empty_payload();
                if keyed_by_stellar {
                    payload.stellar_account_id = Some("GSTELLAR".to_string());
                } else {
                    payload.payala_account_id = Some("alice".to_string());
                }
                for (i, setter) in field_setters.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        setter(&mut payload);
                    }
                }
                let qb = build_account_update(&payload, "alice", false).expect("non-empty mask");
                assert!(
                    qb.sql().contains("payala_account_id = "),
                    "WHERE must pin the account: {}",
                    qb.sql()
                );
            }
        }
    }
}

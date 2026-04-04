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
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
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
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
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
pub async fn get_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(params): Query<GetAccountQuery>,
) -> Result<Json<GetAccountResponse>, AppError> {
    debug!(
        "GET /account: lookup stellar_id={}",
        params.stellar_account_id
    );
    let result = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        r#"
        SELECT payala_account_id, first_name, middle_name, last_name,
               nickname, affiliation, gender
        FROM impala_account
        WHERE stellar_account_id = $1 AND payala_account_id = $2
        "#,
    )
    .bind(&params.stellar_account_id)
    .bind(&user.account_id)
    .fetch_optional(&pool)
    .await;

    match result {
        Ok(Some((
            payala_account_id,
            first_name,
            middle_name,
            last_name,
            nickname,
            affiliation,
            gender,
        ))) => Ok(Json(GetAccountResponse {
            payala_account_id,
            first_name,
            middle_name,
            last_name,
            nickname,
            affiliation,
            gender,
        })),
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

/// Update account fields (`PUT /account`).
pub async fn update_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<Arc<String>>>,
    Json(payload): Json<UpdateAccountRequest>,
) -> Result<Json<UpdateAccountResponse>, AppError> {
    info!("PUT /account: updating account");
    let (where_clause, where_value) = if let Some(ref stellar_id) = payload.stellar_account_id {
        ("stellar_account_id = $1", stellar_id.clone())
    } else if let Some(ref payala_id) = payload.payala_account_id {
        crate::auth::require_owner(&user, payala_id)?;
        ("payala_account_id = $1", payala_id.clone())
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

    let mut set_parts = Vec::new();
    let mut param_index = 2;

    if payload.stellar_account_id.is_some() && where_clause.contains("payala_account_id") {
        set_parts.push(format!("stellar_account_id = ${}", param_index));
        param_index += 1;
    }
    if payload.payala_account_id.is_some() && where_clause.contains("stellar_account_id") {
        set_parts.push(format!("payala_account_id = ${}", param_index));
        param_index += 1;
    }
    if payload.first_name.is_some() {
        set_parts.push(format!("first_name = ${}", param_index));
        param_index += 1;
    }
    if payload.middle_name.is_some() {
        set_parts.push(format!("middle_name = ${}", param_index));
        param_index += 1;
    }
    if payload.last_name.is_some() {
        set_parts.push(format!("last_name = ${}", param_index));
        param_index += 1;
    }
    if payload.nickname.is_some() {
        set_parts.push(format!("nickname = ${}", param_index));
        param_index += 1;
    }
    if payload.affiliation.is_some() {
        set_parts.push(format!("affiliation = ${}", param_index));
        param_index += 1;
    }
    if payload.gender.is_some() {
        set_parts.push(format!("gender = ${}", param_index));
        param_index += 1;
    }

    if set_parts.is_empty() {
        warn!("update_account: no fields provided to update");
        return Ok(Json(UpdateAccountResponse {
            success: false,
            message: "No fields provided to update".to_string(),
            rows_affected: 0,
        }));
    }

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

    let needs_ownership_bind = where_clause.contains("stellar_account_id");
    let sql = if needs_ownership_bind {
        format!(
            "UPDATE impala_account SET {} WHERE {} AND payala_account_id = ${}",
            set_parts.join(", "),
            where_clause,
            param_index
        )
    } else {
        format!(
            "UPDATE impala_account SET {} WHERE {}",
            set_parts.join(", "),
            where_clause
        )
    };

    let mut query = sqlx::query(&sql);
    query = query.bind(&where_value);

    if payload.stellar_account_id.is_some() && where_clause.contains("payala_account_id") {
        query = query.bind(&payload.stellar_account_id);
    }
    if payload.payala_account_id.is_some() && where_clause.contains("stellar_account_id") {
        query = query.bind(&payload.payala_account_id);
    }
    if let Some(ref val) = payload.first_name {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.middle_name {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.last_name {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.nickname {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.affiliation {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.gender {
        query = query.bind(val);
    }
    if needs_ownership_bind {
        query = query.bind(&user.account_id);
    }

    let result = query.execute(&pool).await;

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

                // Fire-and-forget notification for profile update
                let sns_c = sns_client.as_ref().map(|e| &e.0);
                let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
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

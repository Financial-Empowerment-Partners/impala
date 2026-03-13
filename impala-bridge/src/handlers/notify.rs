use axum::extract::{Extension, Query};
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{
    CreateNotifyRequest, NotifyListItem, NotifyResponse, PaginatedResponse, PaginationParams,
    UpdateNotifyRequest,
};

/// List notification preferences for the authenticated user (`GET /notify`).
/// Supports pagination via `?page=1&per_page=20` query parameters.
pub async fn list_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<NotifyListItem>>, AppError> {
    let (per_page, offset) = pagination.clamped();

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notify WHERE account_id = $1",
    )
    .bind(&user.account_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("list_notify: count query error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let rows = sqlx::query_as::<_, NotifyListItem>(
        r#"
        SELECT id, account_id, medium::text, active, mobile, wa, signal, tel, email, url, app
        FROM notify
        WHERE account_id = $1
        ORDER BY id
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(&user.account_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("list_notify: database error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    Ok(Json(PaginatedResponse {
        data: rows,
        page: pagination.page.max(1),
        per_page: per_page as u64,
        total: total as u64,
    }))
}

/// Create a notification preference record (`POST /notify`).
pub async fn create_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateNotifyRequest>,
) -> Result<Json<NotifyResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.account_id)?;
    info!(
        "POST /notify: medium={} for account_id={}",
        payload.medium, payload.account_id
    );

    let valid_mediums = ["webhook", "sms", "mobile_push", "to_app", "email"];
    if !valid_mediums.contains(&payload.medium.as_str()) {
        warn!("create_notify: invalid medium '{}'", payload.medium);
        return Ok(Json(NotifyResponse {
            success: false,
            message: format!(
                "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app, email",
                payload.medium
            ),
            id: None,
        }));
    }

    // Validate email format if provided
    if let Some(ref email) = payload.email {
        crate::validate::validate_email(email)?;
    }

    // Validate webhook URL if provided (SSRF prevention)
    if let Some(ref url) = payload.url {
        crate::validate::validate_callback_url(url)?;
    }

    let result = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO notify (account_id, medium, mobile, wa, signal, tel, email, url, app)
        VALUES ($1, $2::notify_medium, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(&payload.account_id)
    .bind(&payload.medium)
    .bind(&payload.mobile)
    .bind(&payload.wa)
    .bind(&payload.signal)
    .bind(&payload.tel)
    .bind(&payload.email)
    .bind(&payload.url)
    .bind(&payload.app)
    .fetch_one(&pool)
    .await;

    match result {
        Ok(id) => {
            info!(
                "create_notify: created notify id={} for account_id={}",
                id, payload.account_id
            );
            Ok(Json(NotifyResponse {
                success: true,
                message: "Notification record created successfully".to_string(),
                id: Some(id),
            }))
        }
        Err(e) => {
            error!("create_notify: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Update an existing notification record by ID (`PUT /notify`).
pub async fn update_notify(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateNotifyRequest>,
) -> Result<Json<NotifyResponse>, AppError> {
    info!("PUT /notify: updating id={}", payload.id);

    if let Some(ref medium) = payload.medium {
        let valid_mediums = ["webhook", "sms", "mobile_push", "to_app", "email"];
        if !valid_mediums.contains(&medium.as_str()) {
            warn!("update_notify: invalid medium '{}'", medium);
            return Ok(Json(NotifyResponse {
                success: false,
                message: format!(
                    "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app, email",
                    medium
                ),
                id: None,
            }));
        }
    }

    // Validate email format if provided
    if let Some(ref email) = payload.email {
        crate::validate::validate_email(email)?;
    }

    // Validate webhook URL if provided (SSRF prevention)
    if let Some(ref url) = payload.url {
        crate::validate::validate_callback_url(url)?;
    }

    let mut set_parts = Vec::new();
    let mut param_index = 2u32;

    if payload.medium.is_some() {
        set_parts.push(format!("medium = ${}::notify_medium", param_index));
        param_index += 1;
    }
    if payload.mobile.is_some() {
        set_parts.push(format!("mobile = ${}", param_index));
        param_index += 1;
    }
    if payload.wa.is_some() {
        set_parts.push(format!("wa = ${}", param_index));
        param_index += 1;
    }
    if payload.signal.is_some() {
        set_parts.push(format!("signal = ${}", param_index));
        param_index += 1;
    }
    if payload.tel.is_some() {
        set_parts.push(format!("tel = ${}", param_index));
        param_index += 1;
    }
    if payload.email.is_some() {
        set_parts.push(format!("email = ${}", param_index));
        param_index += 1;
    }
    if payload.url.is_some() {
        set_parts.push(format!("url = ${}", param_index));
        param_index += 1;
    }
    if payload.app.is_some() {
        set_parts.push(format!("app = ${}", param_index));
        param_index += 1;
    }

    if set_parts.is_empty() {
        warn!(
            "update_notify: no fields provided to update for id={}",
            payload.id
        );
        return Ok(Json(NotifyResponse {
            success: false,
            message: "No fields provided to update".to_string(),
            id: None,
        }));
    }

    let sql = format!(
        "UPDATE notify SET {} WHERE id = $1 AND account_id = ${}",
        set_parts.join(", "),
        param_index
    );

    let mut query = sqlx::query(&sql);
    query = query.bind(payload.id);

    if let Some(ref val) = payload.medium {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.mobile {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.wa {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.signal {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.tel {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.email {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.url {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.app {
        query = query.bind(val);
    }
    query = query.bind(&user.account_id);

    let result = query.execute(&pool).await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                debug!("update_notify: no record found for id={}", payload.id);
                Ok(Json(NotifyResponse {
                    success: false,
                    message: "No notification record found with the provided id".to_string(),
                    id: None,
                }))
            } else {
                info!("update_notify: updated id={}", payload.id);
                Ok(Json(NotifyResponse {
                    success: true,
                    message: "Notification record updated successfully".to_string(),
                    id: Some(payload.id),
                }))
            }
        }
        Err(e) => {
            error!("update_notify: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

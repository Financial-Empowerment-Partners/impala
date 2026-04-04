use axum::extract::{Extension, Path, Query};
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{
    CreateSubscriptionRequest, PaginatedResponse, PaginationParams, SubscriptionListItem,
    SubscriptionResponse, UpdateSubscriptionRequest,
};

const VALID_EVENT_TYPES: &[&str] = &[
    "login_success",
    "login_failure",
    "password_change",
    "transfer_incoming",
    "transfer_outgoing",
    "profile_updated",
];

const VALID_MEDIUMS: &[&str] = &["webhook", "sms", "mobile_push", "to_app", "email"];

/// List all notification subscriptions for the authenticated user (`GET /notification/subscriptions`).
/// Supports pagination via `?page=1&per_page=20` query parameters.
pub async fn list_subscriptions(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<SubscriptionListItem>>, AppError> {
    let (per_page, offset) = pagination.clamped();

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_subscription WHERE account_id = $1")
            .bind(&user.account_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| {
                error!("list_subscriptions: count query error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;

    let rows = sqlx::query_as::<_, SubscriptionListItem>(
        r#"
        SELECT id, event_type::text, medium::text, enabled
        FROM notification_subscription
        WHERE account_id = $1
        ORDER BY event_type, medium
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(&user.account_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("list_subscriptions: database error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    Ok(Json(PaginatedResponse {
        data: rows,
        page: pagination.page.max(1),
        per_page: per_page as u64,
        total: total as u64,
    }))
}

/// Create a notification subscription (`POST /notification/subscriptions`).
pub async fn create_subscription(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    info!(
        "POST /notification/subscriptions: event_type={} medium={} for account_id={}",
        payload.event_type, payload.medium, user.account_id
    );

    if !VALID_EVENT_TYPES.contains(&payload.event_type.as_str()) {
        warn!(
            "create_subscription: invalid event_type '{}'",
            payload.event_type
        );
        return Ok(Json(SubscriptionResponse {
            success: false,
            message: format!(
                "Invalid event_type '{}'. Must be one of: {}",
                payload.event_type,
                VALID_EVENT_TYPES.join(", ")
            ),
            id: None,
        }));
    }

    if !VALID_MEDIUMS.contains(&payload.medium.as_str()) {
        warn!("create_subscription: invalid medium '{}'", payload.medium);
        return Ok(Json(SubscriptionResponse {
            success: false,
            message: format!(
                "Invalid medium '{}'. Must be one of: {}",
                payload.medium,
                VALID_MEDIUMS.join(", ")
            ),
            id: None,
        }));
    }

    let result = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO notification_subscription (account_id, event_type, medium)
        VALUES ($1, $2::event_type, $3::notify_medium)
        ON CONFLICT (account_id, event_type, medium) DO UPDATE SET enabled = true, updated_at = NOW()
        RETURNING id
        "#,
    )
    .bind(&user.account_id)
    .bind(&payload.event_type)
    .bind(&payload.medium)
    .fetch_one(&pool)
    .await;

    match result {
        Ok(id) => {
            info!(
                "create_subscription: created/updated id={} for account_id={}",
                id, user.account_id
            );
            Ok(Json(SubscriptionResponse {
                success: true,
                message: "Subscription created successfully".to_string(),
                id: Some(id),
            }))
        }
        Err(e) => {
            error!("create_subscription: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Update a notification subscription (`PUT /notification/subscriptions/:id`).
pub async fn update_subscription(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    info!(
        "PUT /notification/subscriptions/{}: enabled={} for account_id={}",
        id, payload.enabled, user.account_id
    );

    let result = sqlx::query(
        "UPDATE notification_subscription SET enabled = $1, updated_at = NOW() WHERE id = $2 AND account_id = $3",
    )
    .bind(payload.enabled)
    .bind(id)
    .bind(&user.account_id)
    .execute(&pool)
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                Ok(Json(SubscriptionResponse {
                    success: false,
                    message: "Subscription not found".to_string(),
                    id: None,
                }))
            } else {
                Ok(Json(SubscriptionResponse {
                    success: true,
                    message: "Subscription updated successfully".to_string(),
                    id: Some(id),
                }))
            }
        }
        Err(e) => {
            error!("update_subscription: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Delete a notification subscription (`DELETE /notification/subscriptions/:id`).
pub async fn delete_subscription(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(id): Path<i32>,
) -> Result<Json<SubscriptionResponse>, AppError> {
    info!(
        "DELETE /notification/subscriptions/{}: account_id={}",
        id, user.account_id
    );

    let result =
        sqlx::query("DELETE FROM notification_subscription WHERE id = $1 AND account_id = $2")
            .bind(id)
            .bind(&user.account_id)
            .execute(&pool)
            .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                Ok(Json(SubscriptionResponse {
                    success: false,
                    message: "Subscription not found".to_string(),
                    id: None,
                }))
            } else {
                Ok(Json(SubscriptionResponse {
                    success: true,
                    message: "Subscription deleted successfully".to_string(),
                    id: Some(id),
                }))
            }
        }
        Err(e) => {
            error!("delete_subscription: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_event_types_contains_expected() {
        assert!(VALID_EVENT_TYPES.contains(&"login_success"));
        assert!(VALID_EVENT_TYPES.contains(&"login_failure"));
        assert!(VALID_EVENT_TYPES.contains(&"password_change"));
        assert!(VALID_EVENT_TYPES.contains(&"transfer_incoming"));
        assert!(VALID_EVENT_TYPES.contains(&"transfer_outgoing"));
        assert!(VALID_EVENT_TYPES.contains(&"profile_updated"));
    }

    #[test]
    fn test_valid_event_types_count() {
        assert_eq!(VALID_EVENT_TYPES.len(), 6);
    }

    #[test]
    fn test_valid_mediums_contains_expected() {
        assert!(VALID_MEDIUMS.contains(&"webhook"));
        assert!(VALID_MEDIUMS.contains(&"sms"));
        assert!(VALID_MEDIUMS.contains(&"mobile_push"));
        assert!(VALID_MEDIUMS.contains(&"to_app"));
        assert!(VALID_MEDIUMS.contains(&"email"));
    }

    #[test]
    fn test_valid_mediums_count() {
        assert_eq!(VALID_MEDIUMS.len(), 5);
    }

    #[test]
    fn test_invalid_event_type_not_in_list() {
        assert!(!VALID_EVENT_TYPES.contains(&"invalid_event"));
    }

    #[test]
    fn test_invalid_medium_not_in_list() {
        assert!(!VALID_MEDIUMS.contains(&"carrier_pigeon"));
    }
}

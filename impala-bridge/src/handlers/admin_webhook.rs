//! Admin-only management of the webhook event feed (all routes gated by the
//! [`AdminUser`] extractor) plus a pull/replay endpoint over the event log.

use axum::extract::{Extension, Path, Query};
use axum::Json;
use log::{error, info};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AdminUser;
use crate::constants::{RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS};
use crate::error::AppError;
use crate::models::{
    EventFeedItem, EventFeedQuery, EventFeedResponse, RegisterWebhookRequest,
    RegisterWebhookResponse, WebhookInfo,
};

fn db_err(ctx: &str, e: sqlx::Error) -> AppError {
    error!("admin_webhook: {}: {}", ctx, e);
    AppError::InternalError("Database error".to_string())
}

/// Register an admin webhook (`POST /admin/webhooks`).
pub async fn register_webhook(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<RegisterWebhookRequest>,
) -> Result<Json<RegisterWebhookResponse>, AppError> {
    // Rate-limit registrations per admin (fail-closed via Redis helper).
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "admin_webhook_register",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // SSRF guard at registration (also re-checked at every delivery).
    crate::validate::validate_callback_url(&payload.url)?;

    // 256-bit signing secret (hex).
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let event_types = payload.event_types.filter(|v| !v.is_empty());

    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO admin_webhook (url, secret, event_types, created_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&payload.url)
    .bind(&secret)
    .bind(&event_types)
    .bind(&user.account_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| db_err("register insert", e))?;

    info!(
        "admin_webhook: webhook {} registered by {}",
        id, user.account_id
    );
    Ok(Json(RegisterWebhookResponse {
        id,
        url: payload.url,
        secret,
    }))
}

/// List admin webhooks (`GET /admin/webhooks`). Never returns the signing secret.
pub async fn list_webhooks(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Vec<WebhookInfo>>, AppError> {
    let rows = sqlx::query_as::<_, WebhookInfo>(
        "SELECT id, url, event_types, enabled, failure_count, last_error, \
         last_delivery_at::text AS last_delivery_at, created_at::text AS created_at \
         FROM admin_webhook ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| db_err("list", e))?;
    Ok(Json(rows))
}

/// Delete an admin webhook (`DELETE /admin/webhooks/:id`).
pub async fn delete_webhook(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let res = sqlx::query("DELETE FROM admin_webhook WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| db_err("delete", e))?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }
    Ok(Json(serde_json::json!({ "success": true })))
}

/// Enqueue a signed test event to a specific webhook (`POST /admin/webhooks/:id/test`).
pub async fn test_webhook(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let enabled: Option<(bool,)> =
        sqlx::query_as("SELECT enabled FROM admin_webhook WHERE id = $1")
            .bind(id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| db_err("test lookup", e))?;
    let enabled = enabled
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?
        .0;
    if !enabled {
        return Err(AppError::BadRequest("Webhook is disabled".to_string()));
    }

    // Append a pre-dispatched test event (so the fan-out won't also pick it up)
    // and a single delivery targeting just this webhook.
    let mut tx = pool.begin().await.map_err(|e| db_err("test begin", e))?;
    let (event_id,): (i64,) = sqlx::query_as(
        "INSERT INTO event_outbox (event_type, account_id, payload, dispatched) \
         VALUES ('webhook.test', $1, $2, TRUE) RETURNING id",
    )
    .bind(&user.account_id)
    .bind(serde_json::json!({ "message": "Impala admin webhook test event" }))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| db_err("test event insert", e))?;
    sqlx::query(
        "INSERT INTO admin_webhook_delivery (webhook_id, event_id, status, next_attempt_at) \
         VALUES ($1, $2, 'pending', CURRENT_TIMESTAMP)",
    )
    .bind(id)
    .bind(event_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| db_err("test delivery insert", e))?;
    tx.commit().await.map_err(|e| db_err("test commit", e))?;

    info!(
        "admin_webhook: test event {} enqueued for webhook {}",
        event_id, id
    );
    Ok(Json(
        serde_json::json!({ "success": true, "event_id": event_id }),
    ))
}

/// Pull/replay the event feed (`GET /admin/events?since=<id>&limit=<n>`).
pub async fn list_events(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<EventFeedQuery>,
) -> Result<Json<EventFeedResponse>, AppError> {
    let limit = q.limit.clamp(1, 500);
    let events = sqlx::query_as::<_, EventFeedItem>(
        "SELECT id, event_type, account_id, payload, created_at::text AS created_at \
         FROM event_outbox WHERE id > $1 ORDER BY id LIMIT $2",
    )
    .bind(q.since)
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map_err(|e| db_err("list events", e))?;
    Ok(Json(EventFeedResponse { events }))
}

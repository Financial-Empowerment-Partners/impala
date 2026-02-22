use axum::extract::Extension;
use axum::Json;
use log::error;
use sqlx::PgPool;
use std::sync::Arc;

use crate::error::AppError;
use crate::models::{HealthResponse, VersionResponse};

/// Health check endpoint (`GET /`). Returns a static greeting.
pub async fn default_route() -> &'static str {
    "Hello, World!"
}

/// Return build info and database schema version (`GET /version`).
pub async fn get_version(Extension(pool): Extension<PgPool>) -> Json<VersionResponse> {
    let schema_version = sqlx::query_scalar::<_, String>(
        "SELECT current_version FROM impala_schema LIMIT 1",
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    Json(VersionResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        build_date: env!("BUILD_DATE"),
        rustc_version: env!("RUSTC_VERSION"),
        schema_version,
    })
}

/// Health check that verifies DB and Redis connectivity (`GET /health`).
pub async fn health_check(
    Extension(pool): Extension<PgPool>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
) -> Result<Json<HealthResponse>, AppError> {
    // Check database
    let db_status = match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await
    {
        Ok(_) => "ok".to_string(),
        Err(e) => {
            error!("health_check: database error: {}", e);
            "error".to_string()
        }
    };

    // Check Redis
    let redis_status = match redis_client.get_async_connection().await {
        Ok(mut conn) => {
            let result: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            match result {
                Ok(_) => "ok".to_string(),
                Err(e) => {
                    error!("health_check: Redis PING error: {}", e);
                    "error".to_string()
                }
            }
        }
        Err(e) => {
            error!("health_check: Redis connection error: {}", e);
            "error".to_string()
        }
    };

    let overall = if db_status == "ok" && redis_status == "ok" {
        "healthy"
    } else {
        "degraded"
    };

    Ok(Json(HealthResponse {
        status: overall.to_string(),
        database: db_status,
        redis: redis_status,
    }))
}

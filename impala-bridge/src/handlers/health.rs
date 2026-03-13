use axum::extract::Extension;
use axum::http::StatusCode;
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
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
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
    let redis_status = match redis_pool.get().await {
        Ok(mut conn) => {
            let result: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;
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
        stellar_network: stellar_config.network.as_str().to_string(),
    }))
}

/// Liveness probe (`GET /healthz`). Returns 200 if the process is running.
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe (`GET /readyz`). Returns 200 if DB and Redis are reachable,
/// 503 otherwise.
pub async fn readiness(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
) -> StatusCode {
    // Check database
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await
        .is_ok();

    // Check Redis
    let redis_ok = match redis_pool.get().await {
        Ok(mut conn) => {
            let result: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;
            result.is_ok()
        }
        Err(_) => false,
    };

    if db_ok && redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

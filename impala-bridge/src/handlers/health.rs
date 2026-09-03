use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use log::error;
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::AppError;
use crate::exchange::reserve::{ConversionReserve, ReserveAccountGuard};
use crate::google::GoogleProvider;
use crate::models::{HealthResponse, VersionResponse};
use crate::oidc::ProviderRegistry;
use crate::okta::OktaProvider;

/// `conversion_reserve` values reported by `GET /health`.
pub const RESERVE_STATE_OFF: &str = "off";
pub const RESERVE_STATE_ARMED_INACTIVE: &str = "armed_inactive";
pub const RESERVE_STATE_ACTIVE: &str = "active";

/// `sso_providers` key for the legacy single-provider `/auth/okta` flow
/// (distinct from a registry provider that may also be named `okta`).
pub const SSO_HEALTH_KEY_OKTA_LEGACY: &str = "okta-legacy";
/// `sso_providers` key for Google sign-in (`/auth/google`).
pub const SSO_HEALTH_KEY_GOOGLE: &str = "google";
/// Fallback key for Google sign-in when a registry provider already owns
/// `google`, so neither entry is silently overwritten.
pub const SSO_HEALTH_KEY_GOOGLE_FALLBACK: &str = "google-signin";

/// Pure mapping for the `conversion_reserve` health field.
///
/// `configured` = `RESERVE_ACCOUNT_ID` is set (the `ReserveAccountGuard`
/// view, which reads configuration only); `handle_present` = the live
/// `ConversionReserve` handle exists. Configured without a handle is the
/// "armed but inactive" window documented in the import-keys runbook.
pub fn reserve_state(configured: bool, handle_present: bool) -> &'static str {
    match (configured, handle_present) {
        (_, true) => RESERVE_STATE_ACTIVE,
        (true, false) => RESERVE_STATE_ARMED_INACTIVE,
        (false, false) => RESERVE_STATE_OFF,
    }
}

/// Health check endpoint (`GET /`). Returns a static greeting.
pub async fn default_route() -> &'static str {
    "Hello, World!"
}

/// Return build info and database schema version (`GET /version`).
pub async fn get_version(Extension(pool): Extension<PgPool>) -> Json<VersionResponse> {
    let schema_version =
        sqlx::query_scalar::<_, String>("SELECT current_version FROM impala_schema LIMIT 1")
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
///
/// Also reports two coarse, non-secret readiness facts an operator otherwise
/// has to infer from logs: whether the conversion reserve is off / armed but
/// inactive / active, and which SSO providers are still waiting on their IdP.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an Extension
pub async fn health_check(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(key_runtime): Extension<Arc<crate::keys::store::KeyRuntime>>,
    Extension(reserve_guard): Extension<Arc<ReserveAccountGuard>>,
    Extension(sso_registry): Extension<Arc<ProviderRegistry>>,
    conversion_reserve: Option<Extension<Arc<ConversionReserve>>>,
    okta_provider: Option<Extension<Arc<OktaProvider>>>,
    google_provider: Option<Extension<Arc<GoogleProvider>>>,
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

    // A credential that failed to resolve disables one provider; it does not
    // make the bridge unhealthy, so it is reported beside the overall status
    // rather than folded into it.
    let key_resolution = if key_runtime.degraded() {
        "degraded"
    } else {
        "ok"
    };

    // Same reasoning for the reserve and SSO readiness: informational, never
    // folded into `status` (the orchestrator acts on /readyz, and a pending
    // IdP must not cycle the fleet).
    let conversion_reserve =
        reserve_state(reserve_guard.is_configured(), conversion_reserve.is_some());

    let mut sso_providers: BTreeMap<String, String> = BTreeMap::new();
    for provider in sso_registry.iter() {
        sso_providers.insert(
            provider.name.clone(),
            provider.state_label().await.to_string(),
        );
    }
    if let Some(Extension(provider)) = okta_provider.as_ref() {
        sso_providers.insert(
            SSO_HEALTH_KEY_OKTA_LEGACY.to_string(),
            provider.state_label().await.to_string(),
        );
    }
    if let Some(Extension(provider)) = google_provider.as_ref() {
        let key = if sso_providers.contains_key(SSO_HEALTH_KEY_GOOGLE) {
            SSO_HEALTH_KEY_GOOGLE_FALLBACK
        } else {
            SSO_HEALTH_KEY_GOOGLE
        };
        sso_providers.insert(key.to_string(), provider.state_label().await.to_string());
    }

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
        key_resolution: key_resolution.to_string(),
        conversion_reserve: conversion_reserve.to_string(),
        sso_providers,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_route_returns_hello() {
        let result = default_route().await;
        assert_eq!(result, "Hello, World!");
    }

    #[tokio::test]
    async fn test_liveness_returns_ok() {
        let status = liveness().await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The three states the import-keys runbook promises `/health` reports.
    #[test]
    fn reserve_state_distinguishes_off_armed_inactive_and_active() {
        assert_eq!(reserve_state(false, false), "off");
        assert_eq!(reserve_state(true, false), "armed_inactive");
        assert_eq!(reserve_state(true, true), "active");
        // A live handle always means active, whatever the guard says.
        assert_eq!(reserve_state(false, true), "active");
    }

    /// The guard reads configuration only, so it is what tells "off" from
    /// "armed" when the live handle is absent.
    #[test]
    fn reserve_guard_reports_configured_from_config_alone() {
        let mut config = crate::config::test_config();
        config.reserve_account_id = None;
        assert!(!ReserveAccountGuard::from_config(&config).is_configured());
        config.reserve_account_id = Some(String::new());
        assert!(!ReserveAccountGuard::from_config(&config).is_configured());
        config.reserve_account_id = Some("reserve@impala".to_string());
        assert!(ReserveAccountGuard::from_config(&config).is_configured());
    }
}

//! Browser cookie-session endpoints: `POST /session/login`, `GET /session/me`,
//! `POST /session/logout`.
//!
//! These exist for the impala-ui dashboard so browser credentials live in an
//! HttpOnly cookie (out of reach of XSS) instead of localStorage bearer
//! tokens. Mobile/SDK clients keep the JWT bearer path. CSRF protection is
//! enforced for every cookie-authenticated unsafe-method request inside the
//! shared auth extractor (see `auth.rs`); the synchronizer token is returned
//! by login and re-fetchable via `GET /session/me`.

use axum::extract::Extension;
use axum::http::header::SET_COOKIE;
use axum::response::{AppendHeaders, IntoResponse};
use axum::Json;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::SessionUser;
use crate::client_source::ClientSource;
use crate::constants::{
    LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD, PREAUTH_SOURCE_MAX_REQUESTS,
    PREAUTH_SOURCE_WINDOW_SECS, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::session::{self, SessionConfig};
use crate::telemetry::AppMetrics;

#[derive(Deserialize)]
pub struct SessionLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub success: bool,
    pub message: String,
    pub account_id: String,
    pub is_admin: bool,
    /// CSRF synchronizer token for `X-CSRF-Token` on unsafe-method requests.
    /// Keep it in memory only — never in localStorage.
    pub csrf_token: String,
}

/// `POST /session/login` — establish a cookie session from local credentials.
///
/// Same rate-limit and lockout regime as `/authenticate`, same credential
/// check as `POST /token` flow 2 (shared `verify_local_credentials`).
pub async fn session_login(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(session_config): Extension<Arc<SessionConfig>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<SessionLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Per-source budget before any per-identity budget is spent.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "preauth_src",
        &source,
        PREAUTH_SOURCE_MAX_REQUESTS,
        PREAUTH_SOURCE_WINDOW_SECS,
    )
    .await?;

    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "session_login",
        &payload.username,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    crate::redis_helpers::check_lockout(&redis_pool, &payload.username, &source, LOCKOUT_THRESHOLD)
        .await?;

    match super::token::verify_local_credentials(&pool, &payload.username, &payload.password)
        .await?
    {
        Ok(()) => {
            crate::redis_helpers::clear_lockout(&redis_pool, &payload.username, &source).await;
        }
        // Same 401 for an unknown, federated or wrong-password attempt; only
        // the last is a guess against a stored password and counts.
        Err(failure) => {
            if failure.counts_toward_lockout() {
                crate::redis_helpers::increment_lockout(
                    &redis_pool,
                    &payload.username,
                    &source,
                    LOCKOUT_DURATION_SECS,
                )
                .await;
            }
            warn!(
                "session_login: invalid credentials for username={}",
                payload.username
            );
            return Err(AppError::Unauthorized);
        }
    }

    let is_admin = admin_ids.contains(&payload.username);
    let (cookie, csrf_token) = session::establish_session(
        &redis_pool,
        &payload.username,
        is_admin,
        session_config.cookie_secure,
    )
    .await?;

    metrics.sessions_created.add(1, &[]);
    info!(
        "session_login: session established for account_id={}",
        payload.username
    );

    Ok((
        AppendHeaders([(SET_COOKIE, cookie)]),
        Json(SessionResponse {
            success: true,
            message: "Session established".to_string(),
            account_id: payload.username,
            is_admin,
            csrf_token,
        }),
    ))
}

/// `GET /session/me` — current session identity + CSRF token.
///
/// The UI calls this on page load to rehydrate its in-memory CSRF token
/// (and to learn `is_admin`, which is re-derived from the live allowlist).
pub async fn session_me(user: SessionUser) -> Json<SessionResponse> {
    Json(SessionResponse {
        success: true,
        message: "Session active".to_string(),
        account_id: user.account_id,
        is_admin: user.is_admin,
        csrf_token: user.csrf,
    })
}

/// `POST /session/logout` — destroy the current session.
///
/// CSRF is enforced by the extractor (cookie path, unsafe method). The
/// session delete is fail-closed: a logout that didn't delete must error.
pub async fn session_logout(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(session_config): Extension<Arc<SessionConfig>>,
    user: SessionUser,
) -> Result<impl IntoResponse, AppError> {
    crate::redis_helpers::delete_session(&redis_pool, &user.sid_hash).await?;

    info!(
        "session_logout: session destroyed for account_id={}",
        user.account_id
    );

    let clear = axum::http::HeaderValue::from_str(&session::build_clear_cookie(
        session_config.cookie_secure,
    ))
    .map_err(|_| AppError::InternalError("Internal error".to_string()))?;

    Ok((
        AppendHeaders([(SET_COOKIE, clear)]),
        Json(serde_json::json!({
            "success": true,
            "message": "Session destroyed"
        })),
    ))
}

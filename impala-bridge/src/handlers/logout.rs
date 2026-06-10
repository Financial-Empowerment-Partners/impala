use axum::extract::Extension;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use log::info;
use serde::Serialize;
use std::sync::Arc;

use crate::auth::{AuthContext, AuthSource};
use crate::constants::{REFRESH_TOKEN_TTL_SECS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_TEMPORAL};
use crate::error::AppError;
use crate::jwt::JwtKeys;

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
    pub message: String,
}

/// Revoke the presented JWT token (`POST /logout`).
///
/// Accepts either token type (revoking whatever is presented). The blacklist
/// write is strict: a logout that failed to record the revocation is an
/// error, never a silent success.
pub async fn logout(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(jwt_keys): Extension<Arc<JwtKeys>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<LogoutResponse>, AppError> {
    let token = bearer.token();

    // Validate signature/issuer/audience/expiry; accept either token type.
    let claims = crate::jwt::decode_claims(&jwt_keys, token, TOKEN_TYPE_TEMPORAL)
        .or_else(|_| crate::jwt::decode_claims(&jwt_keys, token, TOKEN_TYPE_REFRESH))?;

    // Add JTI to the Redis blacklist with TTL matching the remaining lifetime.
    let now = chrono::Utc::now().timestamp() as usize;
    let remaining = claims.exp.saturating_sub(now);
    if remaining > 0 {
        crate::redis_helpers::revoke_token_strict(&redis_pool, &claims.jti, remaining).await?;
    }

    info!("logout: token revoked for sub={}", claims.sub);
    Ok(Json(LogoutResponse {
        success: true,
        message: "Token revoked successfully".to_string(),
    }))
}

/// Logout everywhere (`POST /logout/all`).
///
/// Bumps the account's auth epoch in Redis (fail-closed): every JWT issued at
/// or before this moment — refresh and temporal, on any device — and every
/// session created at or before it is rejected from now on. Works from both
/// the bearer and the cookie path; on the cookie path the current session is
/// also deleted so the browser drops out immediately.
pub async fn logout_all(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    context: AuthContext,
) -> Result<Json<LogoutResponse>, AppError> {
    let now = chrono::Utc::now().timestamp() as u64;

    crate::redis_helpers::bump_auth_epoch(
        &redis_pool,
        &context.account_id,
        now,
        REFRESH_TOKEN_TTL_SECS,
    )
    .await?;

    if let AuthSource::Session { ref sid_hash } = context.source {
        crate::redis_helpers::delete_session(&redis_pool, sid_hash).await?;
    }

    info!(
        "logout_all: auth epoch bumped for account_id={}",
        context.account_id
    );
    Ok(Json(LogoutResponse {
        success: true,
        message: "All tokens and sessions revoked".to_string(),
    }))
}

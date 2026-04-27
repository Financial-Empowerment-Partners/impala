use axum::extract::Extension;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use jsonwebtoken::{decode, DecodingKey, Validation};
use log::info;
use serde::Serialize;
use std::sync::Arc;

use crate::constants::JWT_ISSUER;
use crate::error::AppError;
use crate::models::Claims;

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
    pub message: String,
}

/// Revoke the current JWT token (`POST /logout`).
///
/// Adds the token's JTI to a Redis blacklist with TTL matching
/// the token's remaining lifetime.
pub async fn logout(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(jwt_secret): Extension<Arc<String>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<LogoutResponse>, AppError> {
    let token = bearer.token();

    // Decode the token (validates signature and expiry)
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_issuer(&[JWT_ISSUER]);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized)?;

    // Add JTI to Redis blacklist with TTL matching remaining token lifetime
    let now = chrono::Utc::now().timestamp() as usize;
    let remaining = token_data.claims.exp.saturating_sub(now);
    if remaining > 0 {
        crate::redis_helpers::revoke_token(&redis_pool, &token_data.claims.jti, remaining).await;
    }

    info!("logout: token revoked for sub={}", token_data.claims.sub);
    Ok(Json(LogoutResponse {
        success: true,
        message: "Token revoked successfully".to_string(),
    }))
}

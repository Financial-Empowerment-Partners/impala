use axum::extract::Extension;
use axum::Json;
use jsonwebtoken::{decode, DecodingKey, Validation};
use log::{debug, error, info, warn};
use password_auth::verify_password;
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    JWT_ISSUER, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, TOKEN_TYPE_REFRESH,
};
use crate::error::AppError;
use crate::models::{Claims, TokenRequest, TokenResponse};

/// Issue JWT tokens (`POST /token`).
///
/// Two flows:
/// - Refresh token -> temporal token
/// - Username + password -> refresh token
pub async fn token(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_secret): Extension<Arc<String>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    debug!("POST /token: request received");
    let key = jwt_secret.as_bytes();

    // Flow 1: refresh_token provided -> return a short-lived temporal_token
    if let Some(ref refresh_token) = payload.refresh_token {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let token_data =
            decode::<Claims>(refresh_token, &DecodingKey::from_secret(key), &validation).map_err(
                |e| {
                    warn!("token: invalid refresh token presented: {}", e);
                    AppError::Unauthorized
                },
            )?;

        if token_data.claims.token_type != TOKEN_TYPE_REFRESH {
            warn!(
                "token: wrong token type '{}' presented for refresh flow",
                token_data.claims.token_type
            );
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid token type".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }

        // Check if refresh token has been revoked
        if crate::redis_helpers::is_token_revoked(&redis_pool, &token_data.claims.jti).await? {
            warn!("token: revoked refresh token presented");
            return Err(AppError::Unauthorized);
        }

        let now = chrono::Utc::now().timestamp() as usize;
        let sub = token_data.claims.sub.clone();

        // Issue rotated refresh + temporal token pair
        let (new_refresh_token, temporal_token) = crate::jwt::encode_token_pair(key, &sub)?;

        // Revoke the old refresh token
        let remaining = token_data.claims.exp.saturating_sub(now);
        if remaining > 0 {
            crate::redis_helpers::revoke_token(&redis_pool, &token_data.claims.jti, remaining)
                .await;
        }

        info!(
            "token: tokens issued (with refresh rotation) for sub={}",
            sub
        );
        return Ok(Json(TokenResponse {
            success: true,
            message: "Tokens issued".to_string(),
            refresh_token: Some(new_refresh_token),
            temporal_token: Some(temporal_token),
        }));
    }

    // Flow 2: username + password -> refresh_token
    let username = payload.username.as_deref().unwrap_or("");
    let password = payload.password.as_deref().unwrap_or("");

    if username.is_empty() || password.is_empty() {
        warn!("token: missing username or password");
        return Ok(Json(TokenResponse {
            success: false,
            message: "Either username/password or refresh_token must be provided".to_string(),
            refresh_token: None,
            temporal_token: None,
        }));
    }

    // Rate limiting check
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "token",
        username,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let stored = sqlx::query_as::<_, (String, String)>(
        "SELECT password_hash, auth_provider FROM impala_auth WHERE account_id = $1",
    )
    .bind(username)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("token: database error looking up credentials: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let (stored_hash, auth_provider) = match stored {
        Some((hash, provider)) => (hash, provider),
        None => {
            warn!("token: no credentials found for username={}", username);
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }
    };

    if auth_provider != crate::constants::AUTH_PROVIDER_LOCAL {
        warn!(
            "token: external auth user {} attempted password login",
            username
        );
        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    }

    if verify_password(password, &stored_hash).is_err() {
        warn!("token: invalid password for username={}", username);
        return Ok(Json(TokenResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            refresh_token: None,
            temporal_token: None,
        }));
    }

    let refresh_token = crate::jwt::encode_refresh_token(key, username)?;

    info!("token: refresh token issued for username={}", username);
    Ok(Json(TokenResponse {
        success: true,
        message: "Refresh token issued".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: None,
    }))
}

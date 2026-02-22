use axum::extract::Extension;
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error, info, warn};
use password_auth::verify_password;
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, REFRESH_TOKEN_TTL_SECS,
    TEMPORAL_TOKEN_TTL_SECS, TOKEN_TYPE_REFRESH,
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
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    debug!("POST /token: request received");
    let key = jwt_secret.as_bytes();

    // Flow 1: refresh_token provided -> return a short-lived temporal_token
    if let Some(ref refresh_token) = payload.refresh_token {
        let token_data = decode::<Claims>(
            refresh_token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
        .map_err(|e| {
            warn!("token: invalid refresh token presented: {}", e);
            AppError::Unauthorized
        })?;

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

        let now = chrono::Utc::now().timestamp() as usize;
        let temporal_claims = Claims {
            sub: token_data.claims.sub,
            token_type: "temporal".to_string(),
            iat: now,
            exp: now + TEMPORAL_TOKEN_TTL_SECS,
        };

        let temporal_token = encode(
            &Header::default(),
            &temporal_claims,
            &EncodingKey::from_secret(key),
        )
        .map_err(|e| {
            error!("token: failed to encode temporal token: {}", e);
            AppError::InternalError("Failed to generate token".to_string())
        })?;

        info!(
            "token: temporal token issued for sub={}",
            temporal_claims.sub
        );
        return Ok(Json(TokenResponse {
            success: true,
            message: "Temporal token issued".to_string(),
            refresh_token: None,
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
    if let Ok(mut conn) = redis_client.get_async_connection().await {
        let rate_key = format!("rate:token:{}", username);
        let count: u64 = conn.get(&rate_key).await.unwrap_or(0);
        if count >= RATE_LIMIT_MAX_REQUESTS {
            warn!("token: rate limit exceeded for username={}", username);
            return Err(AppError::RateLimited);
        }
        let _: Result<(), _> = conn.incr(&rate_key, 1u64).await;
        let _: Result<(), _> = conn.expire(&rate_key, RATE_LIMIT_WINDOW_SECS).await;
    }

    let stored_hash = sqlx::query_as::<_, (String,)>(
        "SELECT password_hash FROM impala_auth WHERE account_id = $1",
    )
    .bind(username)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("token: database error looking up credentials: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let stored_hash = match stored_hash {
        Some((hash,)) => hash,
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

    if verify_password(password, &stored_hash).is_err() {
        warn!("token: invalid password for username={}", username);
        return Ok(Json(TokenResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            refresh_token: None,
            temporal_token: None,
        }));
    }

    let now = chrono::Utc::now().timestamp() as usize;
    let refresh_claims = Claims {
        sub: username.to_string(),
        token_type: "refresh".to_string(),
        iat: now,
        exp: now + REFRESH_TOKEN_TTL_SECS,
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(key),
    )
    .map_err(|e| {
        error!("token: failed to encode refresh token: {}", e);
        AppError::InternalError("Failed to generate token".to_string())
    })?;

    info!("token: refresh token issued for username={}", username);
    Ok(Json(TokenResponse {
        success: true,
        message: "Refresh token issued".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: None,
    }))
}

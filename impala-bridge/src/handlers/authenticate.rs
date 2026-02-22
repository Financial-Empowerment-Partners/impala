use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info, warn};
use password_auth::{generate_hash, verify_password};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD, MIN_PASSWORD_LENGTH, RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{AuthenticateRequest, AuthenticateResponse};

/// Register or authenticate a user (`POST /authenticate`).
///
/// Includes rate limiting and account lockout via Redis.
/// Returns generic "Invalid credentials" for both missing-account and wrong-password
/// to prevent account enumeration.
pub async fn authenticate(
    Extension(pool): Extension<PgPool>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, AppError> {
    info!("POST /authenticate: account_id={}", payload.account_id);

    // Rate limiting check
    if let Ok(mut conn) = redis_client.get_async_connection().await {
        let rate_key = format!("rate:auth:{}", payload.account_id);
        let count: u64 = conn.get(&rate_key).await.unwrap_or(0);
        if count >= RATE_LIMIT_MAX_REQUESTS {
            warn!(
                "authenticate: rate limit exceeded for account_id={}",
                payload.account_id
            );
            return Err(AppError::RateLimited);
        }
        let _: Result<(), _> = conn.incr(&rate_key, 1u64).await;
        let _: Result<(), _> = conn
            .expire(&rate_key, RATE_LIMIT_WINDOW_SECS)
            .await;
    }

    // Account lockout check
    if let Ok(mut conn) = redis_client.get_async_connection().await {
        let lockout_key = format!("lockout:{}", payload.account_id);
        let failures: u64 = conn.get(&lockout_key).await.unwrap_or(0);
        if failures >= LOCKOUT_THRESHOLD {
            warn!(
                "authenticate: account locked out for account_id={}",
                payload.account_id
            );
            return Ok(Json(AuthenticateResponse {
                success: false,
                message: "Account temporarily locked due to too many failed attempts".to_string(),
                action: "".to_string(),
            }));
        }
    }

    // Validate password strength
    if payload.password.len() < MIN_PASSWORD_LENGTH {
        warn!(
            "authenticate: password too short for account_id={}",
            payload.account_id
        );
        return Ok(Json(AuthenticateResponse {
            success: false,
            message: format!(
                "Password must be at least {} characters",
                MIN_PASSWORD_LENGTH
            ),
            action: "".to_string(),
        }));
    }

    // Verify account exists
    let account_exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM impala_account WHERE payala_account_id = $1",
    )
    .bind(&payload.account_id)
    .fetch_one(&pool)
    .await;

    match account_exists {
        Ok(0) => {
            // Constant-time behavior: run a dummy hash verification so timing
            // does not reveal whether the account exists
            let dummy_hash = generate_hash("dummy-password-for-timing");
            let _ = verify_password("not-the-real-password", &dummy_hash);

            debug!(
                "authenticate: account not found for account_id={} (generic error returned)",
                payload.account_id
            );
            return Ok(Json(AuthenticateResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                action: "".to_string(),
            }));
        }
        Err(e) => {
            error!("authenticate: database error looking up account: {}", e);
            return Err(AppError::InternalError("Database error".to_string()));
        }
        _ => {}
    }

    // Check if auth credentials exist
    let existing_auth = sqlx::query_as::<_, (String,)>(
        "SELECT password_hash FROM impala_auth WHERE account_id = $1",
    )
    .bind(&payload.account_id)
    .fetch_optional(&pool)
    .await;

    match existing_auth {
        Ok(None) => {
            // No credentials exist - register new user
            let password_hash = generate_hash(&payload.password);

            let insert_result = sqlx::query(
                "INSERT INTO impala_auth (account_id, password_hash) VALUES ($1, $2)",
            )
            .bind(&payload.account_id)
            .bind(&password_hash)
            .execute(&pool)
            .await;

            match insert_result {
                Ok(_) => {
                    info!(
                        "authenticate: registered new user account_id={}",
                        payload.account_id
                    );
                    Ok(Json(AuthenticateResponse {
                        success: true,
                        message: "Registration successful".to_string(),
                        action: "registered".to_string(),
                    }))
                }
                Err(e) => {
                    error!("authenticate: failed to insert auth record: {}", e);
                    Err(AppError::InternalError("Database error".to_string()))
                }
            }
        }
        Ok(Some((stored_hash,))) => {
            match verify_password(&payload.password, &stored_hash) {
                Ok(_) => {
                    // Reset failed login counter on success
                    if let Ok(mut conn) = redis_client.get_async_connection().await {
                        let lockout_key = format!("lockout:{}", payload.account_id);
                        let _: Result<(), _> = conn.del(&lockout_key).await;
                    }

                    info!(
                        "authenticate: successful login for account_id={}",
                        payload.account_id
                    );
                    Ok(Json(AuthenticateResponse {
                        success: true,
                        message: "Authentication successful".to_string(),
                        action: "authenticated".to_string(),
                    }))
                }
                Err(_) => {
                    // Increment failed login counter
                    if let Ok(mut conn) = redis_client.get_async_connection().await {
                        let lockout_key = format!("lockout:{}", payload.account_id);
                        let _: Result<(), _> = conn.incr(&lockout_key, 1u64).await;
                        let _: Result<(), _> = conn
                            .expire(&lockout_key, LOCKOUT_DURATION_SECS)
                            .await;
                    }

                    warn!(
                        "authenticate: invalid password for account_id={}",
                        payload.account_id
                    );
                    Ok(Json(AuthenticateResponse {
                        success: false,
                        message: "Invalid credentials".to_string(),
                        action: "".to_string(),
                    }))
                }
            }
        }
        Err(e) => {
            error!("authenticate: database error fetching auth record: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

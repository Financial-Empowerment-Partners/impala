use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info, warn};
use opentelemetry::KeyValue;
use password_auth::{generate_hash, verify_password};
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    AUTH_PROVIDER_LOCAL, LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD, MIN_PASSWORD_LENGTH,
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{AuthenticateRequest, AuthenticateResponse};
use crate::notifications::{self, NotificationEvent};
use crate::telemetry::AppMetrics;

/// Register or authenticate a user (`POST /authenticate`).
///
/// Includes rate limiting and account lockout via Redis.
/// Returns generic "Invalid credentials" for both missing-account and wrong-password
/// to prevent account enumeration.
pub async fn authenticate(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<Arc<String>>>,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, AppError> {
    info!("POST /authenticate: account_id={}", payload.account_id);

    // Rate limiting check
    crate::redis_helpers::check_rate_limit(&redis_pool, "auth", &payload.account_id, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS).await?;

    // Account lockout check
    crate::redis_helpers::check_lockout(&redis_pool, &payload.account_id, LOCKOUT_THRESHOLD).await?;

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
    let existing_auth = sqlx::query_as::<_, (String, String)>(
        "SELECT password_hash, auth_provider FROM impala_auth WHERE account_id = $1",
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
                    metrics.auth_attempts.add(1, &[KeyValue::new("outcome", "registered")]);

                    // Fire-and-forget notification for registration
                    let sns_c = sns_client.as_ref().map(|e| &e.0);
                    let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
                    notifications::dispatch_event(
                        &pool,
                        sns_c,
                        sns_a,
                        NotificationEvent::LoginSuccess {
                            account_id: payload.account_id.clone(),
                        },
                        Some(&metrics),
                    )
                    .await;

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
        Ok(Some((stored_hash, auth_provider))) => {
            // Reject non-local auth provider accounts (e.g. Okta users)
            if auth_provider != AUTH_PROVIDER_LOCAL {
                warn!(
                    "authenticate: non-local auth user {} attempted password login",
                    payload.account_id
                );
                return Ok(Json(AuthenticateResponse {
                    success: false,
                    message: "Invalid credentials".to_string(),
                    action: "".to_string(),
                }));
            }

            match verify_password(&payload.password, &stored_hash) {
                Ok(_) => {
                    // Reset failed login counter on success
                    crate::redis_helpers::clear_lockout(&redis_pool, &payload.account_id).await;

                    info!(
                        "authenticate: successful login for account_id={}",
                        payload.account_id
                    );
                    metrics.auth_attempts.add(1, &[KeyValue::new("outcome", "authenticated")]);

                    // Fire-and-forget notification for login success
                    let sns_c = sns_client.as_ref().map(|e| &e.0);
                    let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
                    notifications::dispatch_event(
                        &pool,
                        sns_c,
                        sns_a,
                        NotificationEvent::LoginSuccess {
                            account_id: payload.account_id.clone(),
                        },
                        Some(&metrics),
                    )
                    .await;

                    Ok(Json(AuthenticateResponse {
                        success: true,
                        message: "Authentication successful".to_string(),
                        action: "authenticated".to_string(),
                    }))
                }
                Err(_) => {
                    // Increment failed login counter
                    crate::redis_helpers::increment_lockout(&redis_pool, &payload.account_id, LOCKOUT_DURATION_SECS).await;

                    warn!(
                        "authenticate: invalid password for account_id={}",
                        payload.account_id
                    );
                    metrics.auth_attempts.add(1, &[KeyValue::new("outcome", "failed")]);

                    // Fire-and-forget notification for login failure
                    let sns_c = sns_client.as_ref().map(|e| &e.0);
                    let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
                    notifications::dispatch_event(
                        &pool,
                        sns_c,
                        sns_a,
                        NotificationEvent::LoginFailure {
                            account_id: payload.account_id.clone(),
                        },
                        Some(&metrics),
                    )
                    .await;

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

use axum::extract::{Extension, Query};
use axum::Json;
use log::{debug, error, info, warn};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{
    EnrollMfaRequest, MfaEnrollment, MfaQuery, MfaResponse, VerifyMfaRequest,
};

/// Enroll or re-enroll an MFA method (`POST /mfa`).
///
/// For TOTP: generates a secret and returns a provisioning URI for QR codes.
/// For SMS: requires a phone_number.
pub async fn enroll_mfa(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<EnrollMfaRequest>,
) -> Result<Json<MfaResponse>, AppError> {
    info!(
        "POST /mfa: enrolling mfa_type={} for account_id={}",
        payload.mfa_type, payload.account_id
    );

    if payload.mfa_type != "totp" && payload.mfa_type != "sms" {
        warn!("enroll_mfa: invalid mfa_type '{}'", payload.mfa_type);
        return Ok(Json(MfaResponse {
            success: false,
            message: "mfa_type must be 'totp' or 'sms'".to_string(),
            provisioning_uri: None,
        }));
    }

    if payload.mfa_type == "sms" && payload.phone_number.is_none() {
        warn!("enroll_mfa: missing phone_number for SMS enrollment");
        return Ok(Json(MfaResponse {
            success: false,
            message: "phone_number is required for SMS enrollment".to_string(),
            provisioning_uri: None,
        }));
    }

    let (secret_value, provisioning_uri) = if payload.mfa_type == "totp" {
        // Generate a TOTP secret
        let secret = Secret::generate_secret();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("Impala".to_string()),
            payload.account_id.clone(),
        )
        .map_err(|e| {
            error!("enroll_mfa: failed to create TOTP: {}", e);
            AppError::InternalError("Failed to generate TOTP".to_string())
        })?;

        let uri = totp.get_url();
        let secret_base32 = secret.to_encoded().to_string();
        (Some(secret_base32), Some(uri))
    } else {
        (None, None)
    };

    let result = sqlx::query(
        "INSERT INTO impala_mfa (account_id, mfa_type, secret, phone_number, enabled)
         VALUES ($1, $2, $3, $4, TRUE)
         ON CONFLICT (account_id, mfa_type)
         DO UPDATE SET secret = EXCLUDED.secret,
                       phone_number = EXCLUDED.phone_number,
                       enabled = TRUE",
    )
    .bind(&payload.account_id)
    .bind(&payload.mfa_type)
    .bind(&secret_value)
    .bind(&payload.phone_number)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!(
                "enroll_mfa: {} enrolled for account_id={}",
                payload.mfa_type, payload.account_id
            );
            Ok(Json(MfaResponse {
                success: true,
                message: "MFA enrolled successfully".to_string(),
                provisioning_uri,
            }))
        }
        Err(e) => {
            error!("enroll_mfa: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// List all MFA enrollments for an account (`GET /mfa?account_id=...`).
pub async fn get_mfa(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(params): Query<MfaQuery>,
) -> Result<Json<Vec<MfaEnrollment>>, AppError> {
    debug!("GET /mfa: account_id={}", params.account_id);
    let rows = sqlx::query_as::<_, MfaEnrollment>(
        "SELECT account_id, mfa_type, secret, phone_number, enabled
         FROM impala_mfa WHERE account_id = $1",
    )
    .bind(&params.account_id)
    .fetch_all(&pool)
    .await;

    match rows {
        Ok(enrollments) => {
            debug!(
                "get_mfa: found {} enrollment(s) for account_id={}",
                enrollments.len(),
                params.account_id
            );
            Ok(Json(enrollments))
        }
        Err(e) => {
            error!("get_mfa: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Verify an MFA code (`POST /mfa/verify`).
///
/// For TOTP: validates the 6-digit code against the stored secret using totp-rs.
/// For SMS: validates the code stored in Redis.
pub async fn verify_mfa(
    Extension(pool): Extension<PgPool>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Json(payload): Json<VerifyMfaRequest>,
) -> Result<Json<MfaResponse>, AppError> {
    info!(
        "POST /mfa/verify: mfa_type={} for account_id={}",
        payload.mfa_type, payload.account_id
    );

    let enrollment = sqlx::query_as::<_, MfaEnrollment>(
        "SELECT account_id, mfa_type, secret, phone_number, enabled
         FROM impala_mfa WHERE account_id = $1 AND mfa_type = $2",
    )
    .bind(&payload.account_id)
    .bind(&payload.mfa_type)
    .fetch_optional(&pool)
    .await;

    match enrollment {
        Ok(None) => {
            warn!(
                "verify_mfa: no enrollment found for account_id={} mfa_type={}",
                payload.account_id, payload.mfa_type
            );
            Ok(Json(MfaResponse {
                success: false,
                message: "MFA not enrolled for this account/type".to_string(),
                provisioning_uri: None,
            }))
        }
        Ok(Some(record)) => {
            if !record.enabled {
                warn!(
                    "verify_mfa: MFA disabled for account_id={} mfa_type={}",
                    payload.account_id, payload.mfa_type
                );
                return Ok(Json(MfaResponse {
                    success: false,
                    message: "MFA is disabled for this enrollment".to_string(),
                    provisioning_uri: None,
                }));
            }

            if payload.code.is_empty() {
                warn!(
                    "verify_mfa: empty code submitted for account_id={}",
                    payload.account_id
                );
                return Ok(Json(MfaResponse {
                    success: false,
                    message: "Code must not be empty".to_string(),
                    provisioning_uri: None,
                }));
            }

            match payload.mfa_type.as_str() {
                "totp" => {
                    let secret_str = match record.secret {
                        Some(ref s) => s.clone(),
                        None => {
                            error!(
                                "verify_mfa: no secret stored for TOTP enrollment account_id={}",
                                payload.account_id
                            );
                            return Ok(Json(MfaResponse {
                                success: false,
                                message: "TOTP not properly configured".to_string(),
                                provisioning_uri: None,
                            }));
                        }
                    };

                    let secret = Secret::Encoded(secret_str)
                        .to_bytes()
                        .map_err(|e| {
                            error!("verify_mfa: invalid TOTP secret: {}", e);
                            AppError::InternalError("Invalid TOTP configuration".to_string())
                        })?;

                    let totp = TOTP::new(
                        Algorithm::SHA1,
                        6,
                        1,
                        30,
                        secret,
                        Some("Impala".to_string()),
                        payload.account_id.clone(),
                    )
                    .map_err(|e| {
                        error!("verify_mfa: failed to create TOTP verifier: {}", e);
                        AppError::InternalError("TOTP verification error".to_string())
                    })?;

                    let is_valid = totp.check_current(&payload.code).map_err(|e| {
                        error!("verify_mfa: TOTP check error: {}", e);
                        AppError::InternalError("TOTP verification error".to_string())
                    })?;

                    if is_valid {
                        info!(
                            "verify_mfa: TOTP verified for account_id={}",
                            payload.account_id
                        );
                        Ok(Json(MfaResponse {
                            success: true,
                            message: "MFA verification successful".to_string(),
                            provisioning_uri: None,
                        }))
                    } else {
                        warn!(
                            "verify_mfa: invalid TOTP code for account_id={}",
                            payload.account_id
                        );
                        Ok(Json(MfaResponse {
                            success: false,
                            message: "Invalid verification code".to_string(),
                            provisioning_uri: None,
                        }))
                    }
                }
                "sms" => {
                    // SMS: verify against code stored in Redis
                    let sms_key = format!("mfa:sms:{}:{}", payload.account_id, payload.mfa_type);
                    if let Ok(mut conn) = redis_client.get_async_connection().await {
                        let stored_code: Option<String> = conn.get(&sms_key).await.unwrap_or(None);
                        match stored_code {
                            Some(ref code) if code == &payload.code => {
                                // Delete the code after successful verification
                                let _: Result<(), _> = conn.del(&sms_key).await;
                                info!(
                                    "verify_mfa: SMS verified for account_id={}",
                                    payload.account_id
                                );
                                Ok(Json(MfaResponse {
                                    success: true,
                                    message: "MFA verification successful".to_string(),
                                    provisioning_uri: None,
                                }))
                            }
                            _ => {
                                warn!(
                                    "verify_mfa: invalid SMS code for account_id={}",
                                    payload.account_id
                                );
                                Ok(Json(MfaResponse {
                                    success: false,
                                    message: "Invalid verification code".to_string(),
                                    provisioning_uri: None,
                                }))
                            }
                        }
                    } else {
                        error!("verify_mfa: Redis connection error");
                        Err(AppError::InternalError("Redis connection error".to_string()))
                    }
                }
                _ => Ok(Json(MfaResponse {
                    success: false,
                    message: "Unsupported MFA type".to_string(),
                    provisioning_uri: None,
                })),
            }
        }
        Err(e) => {
            error!("verify_mfa: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

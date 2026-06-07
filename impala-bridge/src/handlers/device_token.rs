use axum::extract::Extension;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{DeleteDeviceTokenRequest, DeviceTokenResponse, RegisterDeviceTokenRequest};

/// Register or refresh a device token (`POST /device-token`).
pub async fn register_device_token(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<RegisterDeviceTokenRequest>,
) -> Result<Json<DeviceTokenResponse>, AppError> {
    info!(
        "POST /device-token: platform={} for account_id={}",
        payload.platform, user.account_id
    );

    if payload.token.trim().is_empty() {
        warn!("register_device_token: empty token");
        return Ok(Json(DeviceTokenResponse {
            success: false,
            message: "Token must not be empty".to_string(),
        }));
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!("register_device_token: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let result = sqlx::query(
        r#"
        INSERT INTO device_token (account_id, platform, token)
        VALUES ($1, $2, $3)
        ON CONFLICT (account_id, token) DO UPDATE SET updated_at = NOW(), platform = $2
        "#,
    )
    .bind(&user.account_id)
    .bind(&payload.platform)
    .bind(&payload.token)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            // Event carries only the platform — never the raw token.
            crate::events::emit_event(
                &mut tx,
                &crate::events::AccountEvent::DeviceTokenRegistered {
                    account_id: user.account_id.clone(),
                    platform: payload.platform.clone(),
                },
            )
            .await?;
            tx.commit().await.map_err(|e| {
                error!("register_device_token: commit error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;
            info!(
                "register_device_token: registered for account_id={}",
                user.account_id
            );
            Ok(Json(DeviceTokenResponse {
                success: true,
                message: "Device token registered successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("register_device_token: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Remove a device token (`DELETE /device-token`).
pub async fn delete_device_token(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<DeleteDeviceTokenRequest>,
) -> Result<Json<DeviceTokenResponse>, AppError> {
    info!("DELETE /device-token: for account_id={}", user.account_id);

    let mut tx = pool.begin().await.map_err(|e| {
        error!("delete_device_token: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    let result = sqlx::query("DELETE FROM device_token WHERE account_id = $1 AND token = $2")
        .bind(&user.account_id)
        .bind(&payload.token)
        .execute(&mut *tx)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                Ok(Json(DeviceTokenResponse {
                    success: false,
                    message: "Device token not found".to_string(),
                }))
            } else {
                crate::events::emit_event(
                    &mut tx,
                    &crate::events::AccountEvent::DeviceTokenDeleted {
                        account_id: user.account_id.clone(),
                    },
                )
                .await?;
                tx.commit().await.map_err(|e| {
                    error!("delete_device_token: commit error: {}", e);
                    AppError::InternalError("Database error".to_string())
                })?;
                Ok(Json(DeviceTokenResponse {
                    success: true,
                    message: "Device token removed successfully".to_string(),
                }))
            }
        }
        Err(e) => {
            error!("delete_device_token: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

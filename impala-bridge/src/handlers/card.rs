use axum::extract::Extension;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{CardResponse, CreateCardRequest, DeleteCardRequest};

/// Register a hardware smartcard (`POST /card`).
pub async fn create_card(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateCardRequest>,
) -> Result<Json<CardResponse>, AppError> {
    info!(
        "POST /card: registering card_id={} for account_id={}",
        payload.card_id, payload.account_id
    );
    let result = sqlx::query(
        r#"
        INSERT INTO card (account_id, card_id, ec_pubkey, rsa_pubkey)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&payload.account_id)
    .bind(&payload.card_id)
    .bind(&payload.ec_pubkey)
    .bind(&payload.rsa_pubkey)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!("create_card: card_id={} registered", payload.card_id);
            Ok(Json(CardResponse {
                success: true,
                message: "Card created successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("create_card: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// Soft-delete a card (`DELETE /card`).
pub async fn delete_card(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<DeleteCardRequest>,
) -> Result<Json<CardResponse>, AppError> {
    info!("DELETE /card: card_id={}", payload.card_id);
    let result = sqlx::query(
        "UPDATE card SET is_delete = TRUE, updated_at = CURRENT_TIMESTAMP WHERE card_id = $1 AND is_delete = FALSE",
    )
    .bind(&payload.card_id)
    .execute(&pool)
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                warn!(
                    "delete_card: card_id={} not found or already deleted",
                    payload.card_id
                );
                Ok(Json(CardResponse {
                    success: false,
                    message: "Card not found or already deleted".to_string(),
                }))
            } else {
                info!("delete_card: card_id={} soft-deleted", payload.card_id);
                Ok(Json(CardResponse {
                    success: true,
                    message: "Card deleted successfully".to_string(),
                }))
            }
        }
        Err(e) => {
            error!("delete_card: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

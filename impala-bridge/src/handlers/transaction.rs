use axum::extract::Extension;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{CreateTransactionRequest, CreateTransactionResponse};

/// Create a dual-chain transaction record (`POST /transaction`).
pub async fn create_transaction(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateTransactionRequest>,
) -> Result<Json<CreateTransactionResponse>, AppError> {
    info!(
        "POST /transaction: stellar_tx_id={:?} payala_tx_id={:?}",
        payload.stellar_tx_id, payload.payala_tx_id
    );

    if payload.stellar_tx_id.is_none() && payload.payala_tx_id.is_none() {
        warn!("create_transaction: neither stellar_tx_id nor payala_tx_id provided");
        return Ok(Json(CreateTransactionResponse {
            success: false,
            message: "At least one of stellar_tx_id or payala_tx_id must be provided".to_string(),
            btxid: None,
        }));
    }

    let result = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO transaction
            (stellar_tx_id, payala_tx_id, stellar_hash, source_account,
             stellar_fee, stellar_max_fee, memo, signatures, preconditions,
             payala_currency, payala_digest)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING btxid
        "#,
    )
    .bind(&payload.stellar_tx_id)
    .bind(&payload.payala_tx_id)
    .bind(&payload.stellar_hash)
    .bind(&payload.source_account)
    .bind(payload.stellar_fee)
    .bind(payload.stellar_max_fee)
    .bind(&payload.memo)
    .bind(&payload.signatures)
    .bind(&payload.preconditions)
    .bind(&payload.payala_currency)
    .bind(&payload.payala_digest)
    .fetch_one(&pool)
    .await;

    match result {
        Ok(btxid) => {
            info!("create_transaction: created btxid={}", btxid);
            Ok(Json(CreateTransactionResponse {
                success: true,
                message: "Transaction created successfully".to_string(),
                btxid: Some(btxid),
            }))
        }
        Err(e) => {
            error!("create_transaction: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

use axum::extract::Extension;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{CreateTransactionRequest, CreateTransactionResponse};
use crate::notifications::{self, NotificationEvent};
use crate::telemetry::AppMetrics;

/// Create a dual-chain transaction record (`POST /transaction`).
pub async fn create_transaction(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<Arc<String>>>,
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
            metrics.transactions_created.add(1, &[]);

            // Fire-and-forget notification for outgoing transfer
            let sns_c = sns_client.as_ref().map(|e| &e.0);
            let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
            notifications::dispatch_event(
                &pool,
                sns_c,
                sns_a,
                NotificationEvent::TransferOutgoing {
                    account_id: user.account_id.clone(),
                    amount: payload.memo.clone().unwrap_or_default(),
                    to: payload.source_account.clone().unwrap_or_default(),
                },
                Some(&metrics),
            )
            .await;

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

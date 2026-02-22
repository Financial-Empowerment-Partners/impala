use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{SyncRequest, SyncResponse};

/// Record a sync timestamp in Redis and reconcile with Stellar RPC (`POST /sync`).
pub async fn sync_account(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Extension(stellar_rpc_url): Extension<Arc<String>>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, AppError> {
    info!("POST /sync: account_id={}", payload.account_id);

    let mut conn = redis_client.get_async_connection().await.map_err(|e| {
        error!("sync_account: Redis connection error: {}", e);
        AppError::InternalError("Redis connection error".to_string())
    })?;

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string();

    conn.set::<_, _, ()>(&payload.account_id, &timestamp)
        .await
        .map_err(|e| {
            error!("sync_account: Redis set error: {}", e);
            AppError::InternalError("Redis error".to_string())
        })?;

    // Call Stellar Soroban RPC getTransactions and check against local DB
    let client = reqwest::Client::new();
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransactions",
        "params": {}
    });

    match client
        .post(stellar_rpc_url.as_str())
        .json(&rpc_request)
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(body) = response.json::<serde_json::Value>().await {
                if let Some(transactions) = body["result"]["transactions"].as_array() {
                    for tx in transactions {
                        if let Some(tx_id) = tx["id"].as_str() {
                            let exists = sqlx::query_scalar::<_, i64>(
                                "SELECT COUNT(*) FROM transaction WHERE stellar_tx_id = $1",
                            )
                            .bind(tx_id)
                            .fetch_one(&pool)
                            .await;

                            if let Ok(count) = exists {
                                if count > 0 {
                                    debug!("sync_account: matched local tx {}", tx_id);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("sync_account: Stellar RPC getTransactions error: {}", e);
        }
    }

    Ok(Json(SyncResponse {
        success: true,
        message: "Sync timestamp recorded".to_string(),
        timestamp,
    }))
}

use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS;
use crate::error::AppError;
use crate::models::{SyncRequest, SyncResponse};

/// Core sync logic: record a sync timestamp in Redis and reconcile with Stellar RPC.
/// Returns the recorded timestamp on success.
pub async fn sync_account_core(
    pool: &PgPool,
    redis_pool: &deadpool_redis::Pool,
    stellar_rpc_url: &str,
    account_id: &str,
) -> Result<String, String> {
    let mut conn = redis_pool.get().await.map_err(|e| {
        error!("sync_account_core: Redis connection error: {}", e);
        format!("Redis connection error: {}", e)
    })?;

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string();

    conn.set::<_, _, ()>(account_id, &timestamp)
        .await
        .map_err(|e| {
            error!("sync_account_core: Redis set error: {}", e);
            format!("Redis error: {}", e)
        })?;

    // Call Stellar Soroban RPC getTransactions and check against local DB
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(DEFAULT_HTTP_CLIENT_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransactions",
        "params": {}
    });

    match client.post(stellar_rpc_url).json(&rpc_request).send().await {
        Ok(response) => {
            if let Ok(body) = response.json::<serde_json::Value>().await {
                if let Some(transactions) = body["result"]["transactions"].as_array() {
                    for tx in transactions {
                        if let Some(tx_id) = tx["id"].as_str() {
                            let exists = sqlx::query_scalar::<_, i64>(
                                "SELECT COUNT(*) FROM transaction WHERE stellar_tx_id = $1",
                            )
                            .bind(tx_id)
                            .fetch_one(pool)
                            .await;

                            if let Ok(count) = exists {
                                if count > 0 {
                                    debug!("sync_account_core: matched local tx {}", tx_id);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!(
                "sync_account_core: Stellar RPC getTransactions error: {}",
                e
            );
        }
    }

    Ok(timestamp)
}

/// Record a sync timestamp in Redis and reconcile with Stellar RPC (`POST /sync`).
pub async fn sync_account(
    _user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_rpc_url): Extension<Arc<String>>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, AppError> {
    info!("POST /sync: account_id={}", payload.account_id);

    let timestamp =
        sync_account_core(&pool, &redis_pool, &stellar_rpc_url, &payload.account_id)
            .await
            .map_err(AppError::InternalError)?;

    Ok(Json(SyncResponse {
        success: true,
        message: "Sync timestamp recorded".to_string(),
        timestamp,
    }))
}

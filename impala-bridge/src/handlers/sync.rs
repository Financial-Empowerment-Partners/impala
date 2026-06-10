use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info};
use redis::AsyncCommands;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;

use crate::auth::AdminUser;
use crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS;
use crate::error::AppError;
use crate::models::{SyncRequest, SyncResponse};

/// Query shape for the batched local-transaction lookup. Lifted into a const
/// so the test below pins the `= ANY` form (the per-row `SELECT COUNT(*)`
/// N+1 this replaced must not creep back in).
const SYNC_KNOWN_TX_SQL: &str =
    "SELECT stellar_tx_id FROM transaction WHERE stellar_tx_id = ANY($1)";

/// Extract the string transaction ids from a Stellar RPC `getTransactions`
/// result array (non-string / missing ids are skipped).
fn collect_tx_ids(transactions: &[serde_json::Value]) -> Vec<String> {
    transactions
        .iter()
        .filter_map(|tx| tx["id"].as_str().map(str::to_owned))
        .collect()
}

/// Core sync logic: record a sync timestamp in Redis and reconcile with Stellar RPC.
/// Returns the recorded timestamp on success.
///
/// The HTTP client is passed in so the worker's batch loop (N accounts)
/// reuses one connection pool instead of building a client per account.
pub async fn sync_account_core(
    pool: &PgPool,
    redis_pool: &deadpool_redis::Pool,
    client: &reqwest::Client,
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
                    // Deliberately global (admin/worker batch sync): matches by
                    // stellar_tx_id across all accounts, not scoped to
                    // transaction.account_id. One batched round trip via
                    // `= ANY` (served by idx_transaction_stellar_tx_id from
                    // migration 006) instead of a COUNT(*) per transaction.
                    let tx_ids = collect_tx_ids(transactions);
                    if !tx_ids.is_empty() {
                        let known: HashSet<String> =
                            sqlx::query_scalar::<_, String>(SYNC_KNOWN_TX_SQL)
                                .bind(&tx_ids)
                                .fetch_all(pool)
                                .await
                                .map(|v| v.into_iter().collect())
                                .unwrap_or_else(|e| {
                                    error!("sync_account_core: local tx lookup error: {}", e);
                                    HashSet::new()
                                });

                        for id in tx_ids.iter().filter(|id| known.contains(*id)) {
                            debug!("sync_account_core: matched local tx {}", id);
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
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, AppError> {
    info!("POST /sync: account_id={}", payload.account_id);

    // Admin-only, low-traffic endpoint: a per-request client is fine here.
    // The hot path (worker batch_sync over N accounts) passes the shared
    // WorkerContext client instead.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            DEFAULT_HTTP_CLIENT_TIMEOUT_SECS,
        ))
        .build()
        .map_err(|e| {
            error!("sync_account: failed to create HTTP client: {}", e);
            AppError::InternalError("Internal error".to_string())
        })?;

    let timestamp = sync_account_core(
        &pool,
        &redis_pool,
        &client,
        &stellar_config.rpc_url,
        &payload.account_id,
    )
    .await
    .map_err(AppError::InternalError)?;

    Ok(Json(SyncResponse {
        success: true,
        message: "Sync timestamp recorded".to_string(),
        timestamp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_tx_ids_extracts_string_ids_in_order() {
        let txs = vec![
            serde_json::json!({"id": "txa"}),
            serde_json::json!({"noid": true}),
            serde_json::json!({"id": 42}),
            serde_json::json!({"id": "txb"}),
        ];
        assert_eq!(collect_tx_ids(&txs), vec!["txa", "txb"]);
    }

    #[test]
    fn collect_tx_ids_empty_input() {
        // Empty result => the `= ANY` query is skipped entirely.
        assert!(collect_tx_ids(&[]).is_empty());
    }

    /// Pins the batched lookup shape: one `= ANY($1)` round trip, never a
    /// per-transaction COUNT(*) loop.
    #[test]
    fn known_tx_query_is_batched() {
        assert!(SYNC_KNOWN_TX_SQL.contains("= ANY($1)"));
    }
}

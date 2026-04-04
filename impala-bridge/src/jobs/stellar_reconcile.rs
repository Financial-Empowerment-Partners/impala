use log::{debug, info, warn};
use opentelemetry::KeyValue;
use serde::Deserialize;

use crate::worker::{JobError, WorkerContext};

#[derive(Deserialize)]
struct ReconcilePayload {
    #[serde(default)]
    start_ledger: Option<u64>,
    #[serde(default)]
    end_ledger: Option<u64>,
}

/// Reconcile Stellar transactions against the local database.
pub async fn execute(ctx: &WorkerContext, payload: &serde_json::Value) -> Result<(), JobError> {
    let parsed: ReconcilePayload = serde_json::from_value(payload.clone())
        .map_err(|e| JobError::Permanent(format!("Invalid stellar_reconcile payload: {}", e)))?;

    info!(
        "stellar_reconcile: start_ledger={:?} end_ledger={:?}",
        parsed.start_ledger, parsed.end_ledger
    );

    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransactions",
        "params": {}
    });

    let response = ctx
        .http_client
        .post(&ctx.stellar_rpc_url)
        .json(&rpc_request)
        .send()
        .await
        .map_err(|e| JobError::Transient(format!("Stellar RPC request failed: {}", e)))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| JobError::Transient(format!("Failed to parse Stellar RPC response: {}", e)))?;

    let transactions = body["result"]["transactions"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    info!(
        "stellar_reconcile: fetched {} transaction(s) from RPC",
        transactions.len()
    );

    let mut matched = 0u64;
    let mut unmatched = 0u64;

    for tx in &transactions {
        if let Some(tx_id) = tx["id"].as_str() {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM transaction WHERE stellar_tx_id = $1",
            )
            .bind(tx_id)
            .fetch_one(&ctx.pool)
            .await
            .map_err(|e| JobError::Transient(format!("Database query failed: {}", e)))?;

            if count > 0 {
                debug!("stellar_reconcile: matched tx {}", tx_id);
                matched += 1;
                ctx.metrics
                    .stellar_reconcile_txns
                    .add(1, &[KeyValue::new("status", "matched")]);
            } else {
                warn!("stellar_reconcile: unmatched Stellar tx {}", tx_id);
                unmatched += 1;
                ctx.metrics
                    .stellar_reconcile_txns
                    .add(1, &[KeyValue::new("status", "unmatched")]);
            }
        }
    }

    info!(
        "stellar_reconcile: complete — {} matched, {} unmatched",
        matched, unmatched
    );

    // Store reconciliation summary in Redis
    if let Ok(mut conn) = ctx.redis_pool.get().await {
        let summary = serde_json::json!({
            "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            "total": transactions.len(),
            "matched": matched,
            "unmatched": unmatched,
        });
        let _: Result<(), _> = redis::AsyncCommands::set(
            &mut *conn,
            "stellar:reconcile:latest",
            serde_json::to_string(&summary).unwrap_or_default(),
        )
        .await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconcile_payload_deserialize_with_ledgers() {
        let json = serde_json::json!({
            "start_ledger": 1000,
            "end_ledger": 2000
        });
        let parsed: ReconcilePayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.start_ledger, Some(1000));
        assert_eq!(parsed.end_ledger, Some(2000));
    }

    #[test]
    fn test_reconcile_payload_deserialize_defaults() {
        let json = serde_json::json!({});
        let parsed: ReconcilePayload = serde_json::from_value(json).unwrap();
        assert!(parsed.start_ledger.is_none());
        assert!(parsed.end_ledger.is_none());
    }

    #[test]
    fn test_reconcile_payload_partial() {
        let json = serde_json::json!({ "start_ledger": 500 });
        let parsed: ReconcilePayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.start_ledger, Some(500));
        assert!(parsed.end_ledger.is_none());
    }
}

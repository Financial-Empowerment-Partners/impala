use log::{error, info};
use opentelemetry::KeyValue;
use serde::Deserialize;

use crate::handlers::sync::sync_account_core;
use crate::worker::{JobError, WorkerContext};

#[derive(Deserialize)]
struct BatchSyncPayload {
    account_ids: Vec<String>,
}

/// Sync multiple accounts by invoking the core sync logic for each account ID.
pub async fn execute(ctx: &WorkerContext, payload: &serde_json::Value) -> Result<(), JobError> {
    let parsed: BatchSyncPayload = serde_json::from_value(payload.clone())
        .map_err(|e| JobError::Permanent(format!("Invalid batch_sync payload: {}", e)))?;

    if parsed.account_ids.is_empty() {
        info!("batch_sync: empty account_ids list, nothing to do");
        return Ok(());
    }

    info!(
        "batch_sync: processing {} account(s)",
        parsed.account_ids.len()
    );

    let mut errors = Vec::new();
    for account_id in &parsed.account_ids {
        match sync_account_core(&ctx.pool, &ctx.redis_pool, &ctx.stellar_rpc_url, account_id).await
        {
            Ok(ts) => {
                info!("batch_sync: synced {} at {}", account_id, ts);
                ctx.metrics
                    .batch_sync_accounts
                    .add(1, &[KeyValue::new("outcome", "success")]);
            }
            Err(e) => {
                error!("batch_sync: failed to sync {}: {}", account_id, e);
                ctx.metrics
                    .batch_sync_accounts
                    .add(1, &[KeyValue::new("outcome", "failed")]);
                errors.push(format!("{}: {}", account_id, e));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(JobError::Transient(format!(
            "batch_sync: {} of {} failed: {}",
            errors.len(),
            parsed.account_ids.len(),
            errors.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_sync_payload_deserialize() {
        let json = serde_json::json!({
            "account_ids": ["GABCDEF", "GXYZ123"]
        });
        let parsed: BatchSyncPayload = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.account_ids.len(), 2);
        assert_eq!(parsed.account_ids[0], "GABCDEF");
    }

    #[test]
    fn test_batch_sync_payload_empty_ids() {
        let json = serde_json::json!({ "account_ids": [] });
        let parsed: BatchSyncPayload = serde_json::from_value(json).unwrap();
        assert!(parsed.account_ids.is_empty());
    }

    #[test]
    fn test_batch_sync_payload_missing_field() {
        let json = serde_json::json!({});
        let result: Result<BatchSyncPayload, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }
}

use axum::extract::{Extension, Path};
use axum::Json;
use log::{debug, error, info, warn};
use opentelemetry::KeyValue;
use redis::AsyncCommands;
use sqlx::PgPool;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::constants::{
    DEFAULT_HTTP_CLIENT_TIMEOUT_SECS, MAX_SYNC_BATCH_CURRENCIES, MAX_SYNC_BATCH_ITEMS,
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, SYNC_MODE_MIRROR, SYNC_MODE_RESERVE,
    TX_ORIGIN_PAYALA_SYNC,
};
use crate::error::AppError;
use crate::handlers::transaction::TS_FMT;
use crate::models::{
    PayalaSyncItemInput, PayalaSyncRequest, PayalaSyncResponse, ReserveBalance,
    ReserveBalancesResponse, SyncRequest, SyncResponse,
};
use crate::telemetry::AppMetrics;

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

    let redis_key = format!("impala:sync:{}", account_id);
    conn.set::<_, _, ()>(&redis_key, &timestamp)
        .await
        .map_err(|e| {
            error!("sync_account_core: Redis set error: {}", e);
            format!("Redis error: {}", e)
        })?;

    // Call Stellar Soroban RPC getTransactions and check against local DB
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            DEFAULT_HTTP_CLIENT_TIMEOUT_SECS,
        ))
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
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, AppError> {
    info!("POST /sync: account_id={}", payload.account_id);

    crate::validate::validate_stellar_account_id(&payload.account_id)?;

    let timestamp = sync_account_core(
        &pool,
        &redis_pool,
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

// ── Payala sync (reserve / mirror modes) ────────────────────────────────

/// Validate a Payala sync batch: size bounds, per-item field formats, no
/// intra-batch duplicate tx ids (ambiguous under ON CONFLICT), a distinct-
/// currency cap, and per-currency Σ|amount| within i64 — which guarantees that
/// aggregating ANY subset of the batch cannot overflow in Rust.
pub(crate) fn validate_sync_batch(items: &[PayalaSyncItemInput]) -> Result<(), AppError> {
    if items.is_empty() {
        return Err(AppError::BadRequest(
            "transactions must not be empty".to_string(),
        ));
    }
    if items.len() > MAX_SYNC_BATCH_ITEMS {
        return Err(AppError::BadRequest(format!(
            "batch must not exceed {} transactions",
            MAX_SYNC_BATCH_ITEMS
        )));
    }

    let mut seen_ids: HashSet<&str> = HashSet::with_capacity(items.len());
    let mut abs_sums: HashMap<&str, i64> = HashMap::new();
    for item in items {
        crate::validate::validate_transaction_id(&item.payala_tx_id)?;
        crate::validate::validate_payala_currency(&item.currency)?;
        if item.amount == 0 {
            return Err(AppError::BadRequest(format!(
                "amount must not be zero (payala_tx_id {})",
                item.payala_tx_id
            )));
        }
        if let Some(ref memo) = item.memo {
            if memo.len() > 256 {
                return Err(AppError::BadRequest(
                    "memo must not exceed 256 characters".to_string(),
                ));
            }
        }
        if let Some(ref digest) = item.payala_digest {
            if digest.len() > 256 {
                return Err(AppError::BadRequest(
                    "payala_digest must not exceed 256 characters".to_string(),
                ));
            }
        }
        if !seen_ids.insert(item.payala_tx_id.as_str()) {
            return Err(AppError::BadRequest(format!(
                "duplicate payala_tx_id '{}' within batch",
                item.payala_tx_id
            )));
        }
        // checked_abs also rejects i64::MIN, which has no positive counterpart.
        let abs = item.amount.checked_abs().ok_or_else(|| {
            AppError::BadRequest(format!(
                "amount out of range (payala_tx_id {})",
                item.payala_tx_id
            ))
        })?;
        let sum = abs_sums.entry(item.currency.as_str()).or_insert(0);
        *sum = sum.checked_add(abs).ok_or_else(|| {
            AppError::BadRequest(format!(
                "batch amounts overflow for currency {}",
                item.currency
            ))
        })?;
    }

    if abs_sums.len() > MAX_SYNC_BATCH_CURRENCIES {
        return Err(AppError::BadRequest(format!(
            "batch must not exceed {} distinct currencies",
            MAX_SYNC_BATCH_CURRENCIES
        )));
    }
    Ok(())
}

/// Sum signed amounts per currency with checked arithmetic. Input is the
/// (currency, amount) pairs of the FRESH (newly inserted) items. Currencies
/// netting to zero are kept — they belong in the audit record and response.
pub(crate) fn aggregate_net_deltas<'a>(
    pairs: impl IntoIterator<Item = (&'a str, i64)>,
) -> Result<BTreeMap<String, i64>, AppError> {
    let mut deltas: BTreeMap<String, i64> = BTreeMap::new();
    for (currency, amount) in pairs {
        let sum = deltas.entry(currency.to_string()).or_insert(0);
        // Unreachable when the input passed validate_sync_batch (Σ|amount| is
        // bounded per currency), but kept checked for defense in depth.
        *sum = sum.checked_add(amount).ok_or_else(|| {
            AppError::InternalError(format!("net delta overflow for currency {}", currency))
        })?;
    }
    Ok(deltas)
}

/// Map a DB error from the sync path to an AppError, logging the context.
fn sync_db_error(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e| {
        error!("sync_payala: {} error: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// Map a reserve-upsert error: BIGINT overflow (SQLSTATE 22003) is a
/// caller-visible 409 (amounts are caller-controlled), not a poison-batch 500.
fn reserve_upsert_error(e: sqlx::Error, currency: &str) -> AppError {
    if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("22003") {
        AppError::Conflict(format!(
            "reserve balance overflow for currency {}",
            currency
        ))
    } else {
        error!("sync_payala: reserve upsert error: {}", e);
        AppError::InternalError("Database error".to_string())
    }
}

/// Ingest a batch of offline Payala transactions (`POST /sync/payala`).
///
/// Owner-only. The whole batch is applied in ONE database transaction,
/// idempotent per `(payala_account_id, payala_tx_id)`: replayed ids drop out
/// of the fresh set via ON CONFLICT DO NOTHING and are reported as duplicates
/// (an all-duplicate replay is a success with `applied = 0`). Application
/// depends on the account's `sync_mode`:
/// - `reserve`: per-currency net deltas of the fresh items are added to the
///   account's `payala_reserve` balances — one balance update per batch.
/// - `mirror`: each fresh item becomes a `transaction` row
///   (`origin = 'payala_sync'`, `source_account` = the account's Stellar id).
///
/// Amounts are unverified client assertions (see SECURITY.md); nothing is
/// submitted on-chain.
pub async fn sync_payala(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Json(payload): Json<PayalaSyncRequest>,
) -> Result<Json<PayalaSyncResponse>, AppError> {
    info!(
        "POST /sync/payala: account_id={} items={}",
        payload.account_id,
        payload.transactions.len()
    );

    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "sync_payala",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    crate::auth::require_owner(&user, &payload.account_id)?;
    validate_sync_batch(&payload.transactions)?;

    let received = payload.transactions.len();

    // Deterministic insert order — belt-and-braces against deadlocks between
    // concurrent overlapping batches (the advisory lock is the primary guard).
    let mut items: Vec<&PayalaSyncItemInput> = payload.transactions.iter().collect();
    items.sort_by(|a, b| a.payala_tx_id.cmp(&b.payala_tx_id));

    let ids: Vec<String> = items.iter().map(|i| i.payala_tx_id.clone()).collect();
    let amounts: Vec<i64> = items.iter().map(|i| i.amount).collect();
    let currencies: Vec<String> = items.iter().map(|i| i.currency.clone()).collect();
    let by_id: HashMap<&str, &PayalaSyncItemInput> = items
        .iter()
        .map(|i| (i.payala_tx_id.as_str(), *i))
        .collect();

    let mut tx = pool.begin().await.map_err(sync_db_error("begin"))?;

    // Serialize batches per account; released automatically at COMMIT/ROLLBACK.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('payala_sync:' || $1))")
        .bind(&payload.account_id)
        .execute(&mut tx)
        .await
        .map_err(sync_db_error("advisory lock"))?;

    // Read the mode inside the transaction (after the lock) so a concurrent
    // admin flip cannot split a batch across modes. FOR KEY SHARE makes a
    // concurrent delete_account wait for this batch to commit (then cascade)
    // instead of failing our FK inserts mid-batch.
    let (sync_mode, stellar_account_id) = sqlx::query_as::<_, (String, String)>(
        "SELECT sync_mode, stellar_account_id FROM impala_account \
         WHERE payala_account_id = $1 FOR KEY SHARE",
    )
    .bind(&payload.account_id)
    .fetch_optional(&mut tx)
    .await
    .map_err(sync_db_error("account lookup"))?
    .ok_or_else(|| AppError::NotFound("Account not found".to_string()))?;

    // Batch shell first (items FK it); counts are patched before commit.
    let batch_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO payala_sync_batch
            (payala_account_id, sync_mode, item_count, applied_count, duplicate_count, net_deltas)
        VALUES ($1, $2, $3, 0, 0, '{}'::jsonb)
        RETURNING batch_id
        "#,
    )
    .bind(&payload.account_id)
    .bind(&sync_mode)
    .bind(received as i32)
    .fetch_one(&mut tx)
    .await
    .map_err(sync_db_error("batch insert"))?;

    // The RETURNING set — not the request list — is the fresh set: replayed
    // ids hit ON CONFLICT DO NOTHING and drop out here.
    let fresh: Vec<(String, i64, String)> = sqlx::query_as(
        r#"
        INSERT INTO payala_sync_item
            (payala_account_id, payala_tx_id, batch_id, amount, currency)
        SELECT $1, t.tx_id, $2, t.amount, t.currency
        FROM UNNEST($3::varchar[], $4::bigint[], $5::varchar[]) AS t(tx_id, amount, currency)
        ON CONFLICT (payala_account_id, payala_tx_id) DO NOTHING
        RETURNING payala_tx_id, amount, currency
        "#,
    )
    .bind(&payload.account_id)
    .bind(batch_id)
    .bind(&ids)
    .bind(&amounts)
    .bind(&currencies)
    .fetch_all(&mut tx)
    .await
    .map_err(sync_db_error("item insert"))?;

    let applied = fresh.len();
    let duplicates = received - applied;

    // A replayed id whose stored (amount, currency) differs from this
    // submission signals client corruption or tampering — surfaced separately
    // from routine duplicates.
    let mut conflicting = 0usize;
    if duplicates > 0 {
        let fresh_ids: HashSet<&str> = fresh.iter().map(|(id, _, _)| id.as_str()).collect();
        let dup_ids: Vec<String> = ids
            .iter()
            .filter(|id| !fresh_ids.contains(id.as_str()))
            .cloned()
            .collect();
        let stored: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT payala_tx_id, amount, currency FROM payala_sync_item \
             WHERE payala_account_id = $1 AND payala_tx_id = ANY($2)",
        )
        .bind(&payload.account_id)
        .bind(&dup_ids)
        .fetch_all(&mut tx)
        .await
        .map_err(sync_db_error("duplicate lookup"))?;
        for (id, stored_amount, stored_currency) in &stored {
            if let Some(submitted) = by_id.get(id.as_str()) {
                if submitted.amount != *stored_amount || submitted.currency != *stored_currency {
                    warn!(
                        "sync_payala: conflicting replay of {} for {}: stored ({}, {}) vs submitted ({}, {})",
                        id,
                        payload.account_id,
                        stored_amount,
                        stored_currency,
                        submitted.amount,
                        submitted.currency
                    );
                    conflicting += 1;
                }
            }
        }
    }

    let net_deltas = aggregate_net_deltas(fresh.iter().map(|(_, a, c)| (c.as_str(), *a)))?;

    let mut reserve_balances: Vec<ReserveBalance> = Vec::new();
    match sync_mode.as_str() {
        SYNC_MODE_RESERVE => {
            // One net update per currency; BTreeMap iteration keeps the upsert
            // order deterministic. Zero-net currencies stay in the audit only.
            for (currency, delta) in &net_deltas {
                if *delta == 0 {
                    continue;
                }
                sqlx::query(
                    r#"
                    INSERT INTO payala_reserve (payala_account_id, currency, balance, updated_at)
                    VALUES ($1, $2, $3, NOW())
                    ON CONFLICT (payala_account_id, currency)
                    DO UPDATE SET balance = payala_reserve.balance + EXCLUDED.balance,
                                  updated_at = NOW()
                    "#,
                )
                .bind(&payload.account_id)
                .bind(currency)
                .bind(delta)
                .execute(&mut tx)
                .await
                .map_err(|e| reserve_upsert_error(e, currency))?;
            }
            // Balances for every batch currency (not just upserted ones), so an
            // idempotent replay after a timed-out response still reconciles.
            let mut batch_currencies = currencies.clone();
            batch_currencies.sort();
            batch_currencies.dedup();
            reserve_balances = sqlx::query_as::<_, ReserveBalance>(&format!(
                "SELECT currency, balance, \
                 to_char(updated_at AT TIME ZONE 'UTC', '{}') AS updated_at \
                 FROM payala_reserve \
                 WHERE payala_account_id = $1 AND currency = ANY($2) ORDER BY currency",
                TS_FMT
            ))
            .bind(&payload.account_id)
            .bind(&batch_currencies)
            .fetch_all(&mut tx)
            .await
            .map_err(sync_db_error("reserve read"))?;
        }
        SYNC_MODE_MIRROR => {
            for (id, amount, currency) in &fresh {
                let item = by_id.get(id.as_str());
                // ON CONFLICT targets the uq_transaction_payala_sync backstop:
                // if the account was deleted (cascading away the dedupe ledger)
                // and re-created with the same Stellar id, an orphaned mirror
                // row can survive — a replay must not poison the whole batch.
                let res = sqlx::query(
                    r#"
                    INSERT INTO transaction
                        (payala_tx_id, source_account, memo, payala_currency,
                         payala_digest, payala_amount, origin)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (source_account, payala_tx_id)
                        WHERE origin = 'payala_sync' DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(&stellar_account_id)
                .bind(item.and_then(|i| i.memo.as_deref()))
                .bind(currency)
                .bind(item.and_then(|i| i.payala_digest.as_deref()))
                .bind(amount)
                .bind(TX_ORIGIN_PAYALA_SYNC)
                .execute(&mut tx)
                .await
                .map_err(sync_db_error("mirror insert"))?;
                if res.rows_affected() == 0 {
                    warn!(
                        "sync_payala: mirror row for {} ({}, {}) already exists \
                         (orphan from a deleted account?) — counted as conflicting",
                        id, amount, currency
                    );
                    conflicting += 1;
                }
            }
        }
        other => {
            // Unreachable: the DB CHECK constrains sync_mode. Defensive only.
            error!(
                "sync_payala: unknown sync_mode '{}' for {}",
                other, payload.account_id
            );
            return Err(AppError::InternalError("Unknown sync_mode".to_string()));
        }
    }

    // sqlx is built without the `json` feature, so JSONB is bound as a string
    // with a ::jsonb cast (existing convention).
    let net_deltas_json = serde_json::to_string(&net_deltas).map_err(|e| {
        error!("sync_payala: net_deltas serialization error: {}", e);
        AppError::InternalError("Serialization error".to_string())
    })?;
    sqlx::query(
        "UPDATE payala_sync_batch \
         SET applied_count = $1, duplicate_count = $2, conflicting_count = $3, \
             net_deltas = $4::jsonb \
         WHERE batch_id = $5",
    )
    .bind(applied as i32)
    .bind(duplicates as i32)
    .bind(conflicting as i32)
    .bind(&net_deltas_json)
    .bind(batch_id)
    .execute(&mut tx)
    .await
    .map_err(sync_db_error("batch update"))?;

    tx.commit().await.map_err(sync_db_error("commit"))?;

    // Metrics only after commit — nothing may claim state that didn't land.
    metrics.payala_sync_batches.add(
        1,
        &[
            KeyValue::new("mode", sync_mode.clone()),
            KeyValue::new("outcome", "success"),
        ],
    );
    metrics
        .payala_sync_items
        .add(applied as u64, &[KeyValue::new("result", "applied")]);
    metrics
        .payala_sync_items
        .add(duplicates as u64, &[KeyValue::new("result", "duplicate")]);
    metrics.payala_sync_items.add(
        conflicting as u64,
        &[KeyValue::new("result", "conflicting")],
    );

    info!(
        "sync_payala: batch {} for {} mode={} received={} applied={} duplicates={} conflicting={}",
        batch_id, payload.account_id, sync_mode, received, applied, duplicates, conflicting
    );

    Ok(Json(PayalaSyncResponse {
        success: true,
        message: "Sync batch applied".to_string(),
        batch_id,
        sync_mode,
        received,
        applied,
        duplicates,
        conflicting,
        net_deltas,
        reserve_balances,
    }))
}

/// Read an account's Payala reserve balances (`GET /reserves/:account_id`).
/// Owner or admin; the ownership check runs before any database access.
pub async fn get_reserves(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(account_id): Path<String>,
) -> Result<Json<ReserveBalancesResponse>, AppError> {
    if !user.is_admin() {
        crate::auth::require_owner(&user, &account_id)?;
    }

    let sync_mode: String =
        sqlx::query_scalar("SELECT sync_mode FROM impala_account WHERE payala_account_id = $1")
            .bind(&account_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("get_reserves: account lookup error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?
            .ok_or_else(|| AppError::NotFound("Account not found".to_string()))?;

    let reserves = sqlx::query_as::<_, ReserveBalance>(&format!(
        "SELECT currency, balance, \
         to_char(updated_at AT TIME ZONE 'UTC', '{}') AS updated_at \
         FROM payala_reserve WHERE payala_account_id = $1 ORDER BY currency",
        TS_FMT
    ))
    .bind(&account_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("get_reserves: query error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    Ok(Json(ReserveBalancesResponse {
        account_id,
        sync_mode,
        reserves,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::VALID_SYNC_MODES;

    fn item(id: &str, amount: i64, currency: &str) -> PayalaSyncItemInput {
        PayalaSyncItemInput {
            payala_tx_id: id.to_string(),
            amount,
            currency: currency.to_string(),
            memo: None,
            payala_digest: None,
        }
    }

    // ── validate_sync_batch ────────────────────────────────────────────

    #[test]
    fn test_validate_batch_ok() {
        let items = vec![
            item("tx1", 100, "USD"),
            item("tx2", -50, "USD"),
            item("tx3", 7, "XLM"),
        ];
        assert!(validate_sync_batch(&items).is_ok());
    }

    #[test]
    fn test_validate_batch_empty_rejected() {
        assert!(validate_sync_batch(&[]).is_err());
    }

    #[test]
    fn test_validate_batch_over_cap_rejected() {
        let items: Vec<_> = (0..=MAX_SYNC_BATCH_ITEMS)
            .map(|i| item(&format!("tx{}", i), 1, "USD"))
            .collect();
        assert_eq!(items.len(), MAX_SYNC_BATCH_ITEMS + 1);
        assert!(validate_sync_batch(&items).is_err());
    }

    #[test]
    fn test_validate_batch_zero_amount_rejected() {
        assert!(validate_sync_batch(&[item("tx1", 0, "USD")]).is_err());
    }

    #[test]
    fn test_validate_batch_i64_min_rejected() {
        assert!(validate_sync_batch(&[item("tx1", i64::MIN, "USD")]).is_err());
    }

    #[test]
    fn test_validate_batch_duplicate_tx_id_rejected() {
        let items = vec![item("tx1", 100, "USD"), item("tx1", 200, "USD")];
        assert!(validate_sync_batch(&items).is_err());
    }

    #[test]
    fn test_validate_batch_bad_tx_id_rejected() {
        assert!(validate_sync_batch(&[item("tx-1", 100, "USD")]).is_err());
        assert!(validate_sync_batch(&[item("", 100, "USD")]).is_err());
    }

    #[test]
    fn test_validate_batch_bad_currency_rejected() {
        assert!(validate_sync_batch(&[item("tx1", 100, "usd")]).is_err());
        assert!(validate_sync_batch(&[item("tx1", 100, "")]).is_err());
        assert!(validate_sync_batch(&[item("tx1", 100, "ABCDEFGHIJKLMNOPQ")]).is_err());
    }

    #[test]
    fn test_validate_batch_memo_and_digest_length() {
        let mut long_memo = item("tx1", 100, "USD");
        long_memo.memo = Some("m".repeat(257));
        assert!(validate_sync_batch(&[long_memo]).is_err());

        let mut ok_memo = item("tx1", 100, "USD");
        ok_memo.memo = Some("m".repeat(256));
        assert!(validate_sync_batch(&[ok_memo]).is_ok());

        let mut long_digest = item("tx1", 100, "USD");
        long_digest.payala_digest = Some("d".repeat(257));
        assert!(validate_sync_batch(&[long_digest]).is_err());
    }

    #[test]
    fn test_validate_batch_abs_sum_overflow_rejected() {
        // Two near-max same-currency amounts overflow the Σ|amount| bound...
        let items = vec![
            item("tx1", i64::MAX - 1, "USD"),
            item("tx2", i64::MAX - 1, "USD"),
        ];
        assert!(validate_sync_batch(&items).is_err());
        // ...but split across currencies each sum stays in range.
        let items = vec![
            item("tx1", i64::MAX - 1, "USD"),
            item("tx2", i64::MAX - 1, "XLM"),
        ];
        assert!(validate_sync_batch(&items).is_ok());
    }

    #[test]
    fn test_validate_batch_too_many_currencies_rejected() {
        let items: Vec<_> = (0..=MAX_SYNC_BATCH_CURRENCIES)
            .map(|i| item(&format!("tx{}", i), 1, &format!("CUR{}", i)))
            .collect();
        assert!(validate_sync_batch(&items).is_err());
    }

    // ── aggregate_net_deltas ───────────────────────────────────────────

    #[test]
    fn test_aggregate_mixed_currencies() {
        let deltas = aggregate_net_deltas(vec![("USD", -100), ("USD", 30), ("XLM", 5)]).unwrap();
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas["USD"], -70);
        assert_eq!(deltas["XLM"], 5);
    }

    #[test]
    fn test_aggregate_zero_net_currency_kept() {
        let deltas = aggregate_net_deltas(vec![("USD", 100), ("USD", -100)]).unwrap();
        assert_eq!(deltas["USD"], 0);
    }

    #[test]
    fn test_aggregate_empty_is_empty() {
        // The all-duplicate replay path aggregates an empty fresh set.
        let deltas = aggregate_net_deltas(std::iter::empty()).unwrap();
        assert!(deltas.is_empty());
    }

    #[test]
    fn test_aggregate_overflow_is_error() {
        assert!(aggregate_net_deltas(vec![("USD", i64::MAX), ("USD", 1)]).is_err());
    }

    // ── request serde ──────────────────────────────────────────────────

    #[test]
    fn test_payala_sync_request_deserializes() {
        let json = serde_json::json!({
            "account_id": "payala1",
            "transactions": [
                {"payala_tx_id": "tx1", "amount": -1500, "currency": "USD",
                 "memo": "coffee", "payala_digest": "abc123"},
                {"payala_tx_id": "tx2", "amount": 200, "currency": "XLM"}
            ]
        });
        let req: PayalaSyncRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.account_id, "payala1");
        assert_eq!(req.transactions.len(), 2);
        assert_eq!(req.transactions[0].amount, -1500);
        assert!(req.transactions[1].memo.is_none());
    }

    #[test]
    fn test_payala_sync_request_rejects_float_amount() {
        let json = serde_json::json!({
            "account_id": "payala1",
            "transactions": [{"payala_tx_id": "tx1", "amount": 1.5, "currency": "USD"}]
        });
        assert!(serde_json::from_value::<PayalaSyncRequest>(json).is_err());
    }

    #[test]
    fn test_payala_sync_request_rejects_out_of_range_amount() {
        // u64::MAX overflows i64.
        let json = r#"{
            "account_id": "payala1",
            "transactions": [
                {"payala_tx_id": "tx1", "amount": 18446744073709551615, "currency": "USD"}
            ]
        }"#;
        assert!(serde_json::from_str::<PayalaSyncRequest>(json).is_err());
    }

    // ── constants ↔ DDL drift guards ───────────────────────────────────

    #[test]
    fn test_valid_sync_modes_match_ddl() {
        // Mirrors the chk_impala_account_sync_mode DB CHECK in migration 023.
        assert_eq!(VALID_SYNC_MODES.len(), 2);
        for m in ["reserve", "mirror"] {
            assert!(VALID_SYNC_MODES.contains(&m));
        }
    }
}

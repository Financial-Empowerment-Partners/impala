use axum::extract::{Extension, Path, Query};
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::constants::{RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, VALID_REVIEW_STATUSES};
use crate::error::AppError;
use crate::models::{
    CreateTransactionRequest, CreateTransactionResponse, ListTransactionsQuery, PaginatedResponse,
    ReviewTransactionRequest, ReviewTransactionResponse, TransactionDetail, TransactionListItem,
};
use crate::notifications::{self, NotificationEvent};
use crate::telemetry::AppMetrics;

/// Create a dual-chain transaction record (`POST /transaction`).
pub async fn create_transaction(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<Arc<String>>>,
    Json(payload): Json<CreateTransactionRequest>,
) -> Result<Json<CreateTransactionResponse>, AppError> {
    info!(
        "POST /transaction: stellar_tx_id={:?} payala_tx_id={:?}",
        payload.stellar_tx_id, payload.payala_tx_id
    );

    // Per-account rate limiting. Prevents a single compromised token from
    // flooding the transaction table and the downstream notification fanout.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "tx",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    if payload.stellar_tx_id.is_none() && payload.payala_tx_id.is_none() {
        warn!("create_transaction: neither stellar_tx_id nor payala_tx_id provided");
        return Ok(Json(CreateTransactionResponse {
            success: false,
            message: "At least one of stellar_tx_id or payala_tx_id must be provided".to_string(),
            btxid: None,
        }));
    }

    // Validate optional fields that have defined formats
    if let Some(ref tx_id) = payload.stellar_tx_id {
        crate::validate::validate_transaction_id(tx_id)?;
    }
    if let Some(ref tx_id) = payload.payala_tx_id {
        crate::validate::validate_transaction_id(tx_id)?;
    }
    if let Some(ref account) = payload.source_account {
        if !account.is_empty() {
            crate::validate::validate_stellar_account_id(account)?;
        }
    }
    if let Some(ref hash) = payload.stellar_hash {
        if !hash.is_empty() {
            crate::validate::validate_hex_hash(hash, "stellar_hash")?;
        }
    }
    if let Some(ref memo) = payload.memo {
        if memo.len() > 256 {
            return Err(AppError::BadRequest(
                "memo must not exceed 256 characters".to_string(),
            ));
        }
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

/// SQL `to_char` timestamp format producing RFC3339 (UTC). The codebase returns
/// timestamps as text because sqlx has no `chrono` decode feature enabled.
const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

/// A single dynamic filter bind value (heterogeneous String/bool).
enum FilterBind {
    Str(String),
    Bool(bool),
}

/// Pure builder for the dynamic `WHERE` fragment + ordered binds shared by the
/// count and page queries. When `is_admin` is false, the owner-scoping subquery
/// (`source_account IN (... payala_account_id = $sub)`) is appended last so a
/// regular caller only sees transactions sourced from an account they own.
fn build_tx_filters(
    p: &ListTransactionsQuery,
    is_admin: bool,
    account_id: &str,
) -> (String, Vec<FilterBind>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<FilterBind> = Vec::new();
    let mut n = 1;

    if let Some(flagged) = p.flagged {
        clauses.push(format!("COALESCE(r.flagged, FALSE) = ${}", n));
        n += 1;
        binds.push(FilterBind::Bool(flagged));
    }
    if let Some(ref s) = p.status {
        clauses.push(format!("COALESCE(r.status, 'unreviewed') = ${}", n));
        n += 1;
        binds.push(FilterBind::Str(s.clone()));
    }
    if let Some(ref sa) = p.source_account {
        clauses.push(format!("t.source_account = ${}", n));
        n += 1;
        binds.push(FilterBind::Str(sa.clone()));
    }
    if let Some(ref f) = p.from {
        clauses.push(format!("t.created_at >= ${}::timestamptz", n));
        n += 1;
        binds.push(FilterBind::Str(f.clone()));
    }
    if let Some(ref t) = p.to {
        clauses.push(format!("t.created_at < ${}::timestamptz", n));
        n += 1;
        binds.push(FilterBind::Str(t.clone()));
    }
    if let Some(ref q) = p.q {
        clauses.push(format!(
            "(t.memo ILIKE ${0} OR t.stellar_tx_id ILIKE ${0} OR t.payala_tx_id ILIKE ${0} \
             OR t.stellar_hash ILIKE ${0} OR t.source_account ILIKE ${0})",
            n
        ));
        n += 1;
        binds.push(FilterBind::Str(format!("%{}%", q)));
    }
    if !is_admin {
        clauses.push(format!(
            "t.source_account IN (SELECT stellar_account_id FROM impala_account \
             WHERE payala_account_id = ${})",
            n
        ));
        binds.push(FilterBind::Str(account_id.to_string()));
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" AND {}", clauses.join(" AND "))
    };
    (where_sql, binds)
}

/// Derive the stored review status when not explicitly provided.
fn derive_status(flagged: bool, status: Option<&str>) -> String {
    match status {
        Some(s) => s.to_string(),
        None => {
            if flagged {
                "flagged".to_string()
            } else {
                "unreviewed".to_string()
            }
        }
    }
}

/// List transactions with review state (`GET /transactions`). Admins see all;
/// a regular caller is scoped to transactions sourced from accounts they own.
pub async fn list_transactions(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Query(params): Query<ListTransactionsQuery>,
) -> Result<Json<PaginatedResponse<TransactionListItem>>, AppError> {
    if let Some(ref s) = params.status {
        if !VALID_REVIEW_STATUSES.contains(&s.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid status '{}'. Must be one of: {}",
                s,
                VALID_REVIEW_STATUSES.join(", ")
            )));
        }
    }
    if let Some(ref f) = params.from {
        crate::validate::validate_rfc3339_timestamp(f, "from")?;
    }
    if let Some(ref t) = params.to {
        crate::validate::validate_rfc3339_timestamp(t, "to")?;
    }

    let per_page = params.per_page.clamp(1, 100) as i64;
    let offset = (params.page.max(1) - 1) as i64 * per_page;

    let (where_sql, binds) = build_tx_filters(&params, user.is_admin(), &user.account_id);
    let n_limit = binds.len() + 1;
    let n_offset = binds.len() + 2;

    let count_sql = format!(
        "SELECT COUNT(*) FROM transaction t \
         LEFT JOIN transaction_review r ON r.btxid = t.btxid WHERE 1=1{}",
        where_sql
    );
    let select_sql = format!(
        "SELECT t.btxid, t.stellar_tx_id, t.payala_tx_id, t.stellar_hash, t.source_account, \
         t.stellar_fee, t.stellar_max_fee, t.memo, t.payala_currency, \
         to_char(t.created_at AT TIME ZONE 'UTC', '{ts}') AS created_at, \
         COALESCE(r.flagged, FALSE) AS flagged, COALESCE(r.status, 'unreviewed') AS status, \
         r.note, r.reviewed_by, \
         to_char(r.reviewed_at AT TIME ZONE 'UTC', '{ts}') AS reviewed_at \
         FROM transaction t LEFT JOIN transaction_review r ON r.btxid = t.btxid \
         WHERE 1=1{where_sql} ORDER BY t.created_at DESC LIMIT ${n_limit} OFFSET ${n_offset}",
        ts = TS_FMT,
        where_sql = where_sql,
        n_limit = n_limit,
        n_offset = n_offset
    );

    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        cq = match b {
            FilterBind::Str(s) => cq.bind(s.clone()),
            FilterBind::Bool(v) => cq.bind(*v),
        };
    }
    let total = cq.fetch_one(&pool).await.map_err(|e| {
        error!("list_transactions: count error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let mut sq = sqlx::query_as::<_, TransactionListItem>(&select_sql);
    for b in &binds {
        sq = match b {
            FilterBind::Str(s) => sq.bind(s.clone()),
            FilterBind::Bool(v) => sq.bind(*v),
        };
    }
    let rows = sq
        .bind(per_page)
        .bind(offset)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("list_transactions: query error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

    Ok(Json(PaginatedResponse {
        data: rows,
        page: params.page.max(1),
        per_page: per_page as u64,
        total: total as u64,
    }))
}

/// Fetch a single transaction with review state (`GET /transaction/:btxid`).
/// Admin or owner; a non-owned existing tx returns 404 (no existence leak).
pub async fn get_transaction(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(btxid): Path<Uuid>,
) -> Result<Json<TransactionDetail>, AppError> {
    let mut sql = format!(
        "SELECT t.btxid, t.stellar_tx_id, t.payala_tx_id, t.stellar_hash, t.source_account, \
         t.stellar_fee, t.stellar_max_fee, t.memo, t.signatures, t.preconditions, \
         t.payala_currency, t.payala_digest, \
         to_char(t.created_at AT TIME ZONE 'UTC', '{ts}') AS created_at, \
         COALESCE(r.flagged, FALSE) AS flagged, COALESCE(r.status, 'unreviewed') AS status, \
         r.note, r.reviewed_by, \
         to_char(r.reviewed_at AT TIME ZONE 'UTC', '{ts}') AS reviewed_at \
         FROM transaction t LEFT JOIN transaction_review r ON r.btxid = t.btxid \
         WHERE t.btxid = $1",
        ts = TS_FMT
    );
    if !user.is_admin() {
        sql.push_str(
            " AND t.source_account IN (SELECT stellar_account_id FROM impala_account \
             WHERE payala_account_id = $2)",
        );
    }

    let mut q = sqlx::query_as::<_, TransactionDetail>(&sql).bind(btxid);
    if !user.is_admin() {
        q = q.bind(&user.account_id);
    }

    q.fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("get_transaction: db error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?
        .map(Json)
        .ok_or_else(|| AppError::NotFound("Transaction not found".to_string()))
}

/// Set a transaction's review/flag/annotation state (`PUT /transaction/:btxid/review`).
/// Admin only. PUT replaces the full review state (omitted fields reset).
pub async fn review_transaction(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Path(btxid): Path<Uuid>,
    Json(payload): Json<ReviewTransactionRequest>,
) -> Result<Json<ReviewTransactionResponse>, AppError> {
    crate::auth::require_admin(&user)?;

    if let Some(ref s) = payload.status {
        if !VALID_REVIEW_STATUSES.contains(&s.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid status '{}'. Must be one of: {}",
                s,
                VALID_REVIEW_STATUSES.join(", ")
            )));
        }
    }
    if let Some(ref note) = payload.note {
        if note.len() > 2000 {
            return Err(AppError::BadRequest(
                "note must not exceed 2000 characters".to_string(),
            ));
        }
    }

    let flagged = payload.flagged.unwrap_or(false);
    let status = derive_status(flagged, payload.status.as_deref());

    // Explicit existence check → clean 404 instead of an FK-violation 500.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT btxid FROM transaction WHERE btxid = $1")
        .bind(btxid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("review_transaction: lookup error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
    if exists.is_none() {
        return Err(AppError::NotFound("Transaction not found".to_string()));
    }

    sqlx::query(
        r#"
        INSERT INTO transaction_review
            (btxid, flagged, status, note, reviewed_by, reviewed_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ON CONFLICT (btxid) DO UPDATE SET
            flagged = EXCLUDED.flagged,
            status = EXCLUDED.status,
            note = EXCLUDED.note,
            reviewed_by = EXCLUDED.reviewed_by,
            reviewed_at = EXCLUDED.reviewed_at,
            updated_at = NOW()
        "#,
    )
    .bind(btxid)
    .bind(flagged)
    .bind(&status)
    .bind(&payload.note)
    .bind(&user.account_id)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("review_transaction: upsert error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    info!(
        "review_transaction: btxid={} status={} flagged={} by={}",
        btxid, status, flagged, user.account_id
    );
    Ok(Json(ReviewTransactionResponse {
        success: true,
        message: "Review updated successfully".to_string(),
        btxid,
        flagged,
        status,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ListTransactionsQuery;

    fn empty_query() -> ListTransactionsQuery {
        ListTransactionsQuery {
            page: 1,
            per_page: 20,
            status: None,
            flagged: None,
            source_account: None,
            from: None,
            to: None,
            q: None,
        }
    }

    #[test]
    fn test_build_tx_filters_admin_no_filters_is_empty() {
        let (where_sql, binds) = build_tx_filters(&empty_query(), true, "alice");
        assert!(where_sql.is_empty());
        assert!(binds.is_empty());
    }

    #[test]
    fn test_build_tx_filters_owner_appends_ownership_subquery() {
        let (where_sql, binds) = build_tx_filters(&empty_query(), false, "alice");
        assert!(where_sql.contains("payala_account_id = $1"));
        assert!(where_sql.contains("SELECT stellar_account_id FROM impala_account"));
        assert_eq!(binds.len(), 1);
        match &binds[0] {
            FilterBind::Str(s) => assert_eq!(s, "alice"),
            _ => panic!("expected the account id bind"),
        }
    }

    #[test]
    fn test_build_tx_filters_numbering_and_owner_last() {
        let mut q = empty_query();
        q.flagged = Some(true);
        q.status = Some("escalated".to_string());
        q.q = Some("abc".to_string());
        let (where_sql, binds) = build_tx_filters(&q, false, "bob");
        // flagged=$1, status=$2, q=$3 (reused 5x), owner=$4
        assert!(where_sql.contains("COALESCE(r.flagged, FALSE) = $1"));
        assert!(where_sql.contains("COALESCE(r.status, 'unreviewed') = $2"));
        assert!(where_sql.contains("t.memo ILIKE $3"));
        assert!(where_sql.contains("payala_account_id = $4"));
        assert_eq!(binds.len(), 4);
        // the q bind is wrapped with % wildcards
        match &binds[2] {
            FilterBind::Str(s) => assert_eq!(s, "%abc%"),
            _ => panic!("expected the q bind"),
        }
    }

    #[test]
    fn test_derive_status() {
        assert_eq!(derive_status(true, None), "flagged");
        assert_eq!(derive_status(false, None), "unreviewed");
        assert_eq!(derive_status(false, Some("cleared")), "cleared");
        assert_eq!(derive_status(true, Some("escalated")), "escalated");
    }

    #[test]
    fn test_valid_review_statuses_match_ddl() {
        assert_eq!(VALID_REVIEW_STATUSES.len(), 4);
        for s in ["unreviewed", "cleared", "flagged", "escalated"] {
            assert!(VALID_REVIEW_STATUSES.contains(&s));
        }
    }
}

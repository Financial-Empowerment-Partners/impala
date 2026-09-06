//! Reconciliation reads and snapshots (`/admin/reconciliation/*`, 037 part C).
//!
//! `get_positions`, `list_snapshots` and `get_snapshot` take
//! `Privileged<ReadCustody>` (admin, treasurer, auditor); `create_snapshot`
//! takes `Privileged<ManageCustody>` because a manual snapshot is an
//! attributable attestation that walks every custodial address.

use axum::extract::{Path, Query};
use axum::{Extension, Json};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{ManageCustody, Privileged, ReadCustody};
use crate::constants::RECONCILIATION_SNAPSHOT_MANUAL;
use crate::error::AppError;
use crate::models::{
    PaginatedResponse, PaginationParams, PositionsQuery, ReconciliationSnapshotListItem,
    SnapshotListQuery,
};
use crate::reconciliation::compute::PositionsResponse;
use crate::reconciliation::{build_positions, record_snapshot, CustodialScope, ReconcileDeps};

const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        log::error!("admin_reconciliation: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// `POST /admin/reconciliation/snapshots` response.
#[derive(Debug, serde::Serialize)]
pub struct CreateSnapshotResponse {
    pub success: bool,
    pub snapshot_id: Uuid,
    pub kind: String,
    pub as_of: String,
    pub horizon_fresh: bool,
    pub complete: bool,
    pub drift_detected: bool,
    pub invariants_ok: bool,
    pub attested: bool,
    pub warnings: Vec<String>,
}

/// `GET /admin/reconciliation/positions?page&per_page` — the live report
/// over one custodial page.
pub async fn get_positions(
    _user: Privileged<ReadCustody>,
    Extension(deps): Extension<Arc<ReconcileDeps>>,
    Query(q): Query<PositionsQuery>,
) -> Result<Json<PositionsResponse>, AppError> {
    let report = build_positions(
        &deps,
        CustodialScope::Page {
            page: q.page,
            per_page: q.per_page,
        },
    )
    .await?;
    Ok(Json(report.response))
}

/// `POST /admin/reconciliation/snapshots` — a manual, attributable snapshot
/// over EVERY custodial address (same budgets as the daily job).
pub async fn create_snapshot(
    user: Privileged<ManageCustody>,
    Extension(deps): Extension<Arc<ReconcileDeps>>,
) -> Result<Json<CreateSnapshotResponse>, AppError> {
    let report = build_positions(&deps, CustodialScope::All).await?;
    let snapshot_id = record_snapshot(
        &deps,
        RECONCILIATION_SNAPSHOT_MANUAL,
        Some(&user.account_id),
        &report,
    )
    .await?
    .ok_or_else(|| AppError::InternalError("snapshot was not recorded".to_string()))?;
    let invariants_ok = report.invariants_ok();
    let fresh = report.response.horizon.fresh;
    let complete = report.response.complete;
    log::info!(
        "reconciliation: manual snapshot {} by {} (attested={})",
        snapshot_id,
        user.account_id,
        fresh && complete && invariants_ok
    );
    Ok(Json(CreateSnapshotResponse {
        success: true,
        snapshot_id,
        kind: RECONCILIATION_SNAPSHOT_MANUAL.to_string(),
        as_of: report.response.as_of.clone(),
        horizon_fresh: fresh,
        complete,
        drift_detected: report.drift_detected(),
        invariants_ok,
        attested: fresh && complete && invariants_ok,
        warnings: report.response.warnings.clone(),
    }))
}

/// `GET /admin/reconciliation/snapshots?page&per_page` — newest first,
/// payloads omitted. `attested` = fresh AND complete AND invariants ok.
pub async fn list_snapshots(
    _user: Privileged<ReadCustody>,
    Extension(pool): Extension<PgPool>,
    Query(q): Query<SnapshotListQuery>,
) -> Result<Json<PaginatedResponse<ReconciliationSnapshotListItem>>, AppError> {
    let (per_page, offset) = PaginationParams {
        page: q.page,
        per_page: q.per_page,
    }
    .clamped();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reconciliation_snapshot")
        .fetch_one(&pool)
        .await
        .map_err(db_err("snapshot count"))?;
    let rows: Vec<ReconciliationSnapshotListItem> = sqlx::query_as(&format!(
        "SELECT snapshot_id, to_char(snapshot_date, 'YYYY-MM-DD') AS snapshot_date, kind, \
                to_char(as_of AT TIME ZONE 'UTC', '{ts}') AS as_of, horizon_fresh, complete, \
                drift_detected, invariants_ok, created_by \
         FROM reconciliation_snapshot \
         ORDER BY created_at DESC, snapshot_id DESC LIMIT $1 OFFSET $2",
        ts = TS_FMT
    ))
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(db_err("snapshot list"))?;
    let data = rows
        .into_iter()
        .map(|mut r| {
            r.attested = r.horizon_fresh && r.complete && r.invariants_ok;
            r
        })
        .collect();
    Ok(Json(PaginatedResponse {
        data,
        page: ((offset / per_page) + 1) as u64,
        per_page: per_page as u64,
        total: total.max(0) as u64,
    }))
}

/// `GET /admin/reconciliation/snapshots/{snapshot_id}` — the stored payload,
/// verbatim (the report exactly as it was computed).
pub async fn get_snapshot(
    _user: Privileged<ReadCustody>,
    Extension(pool): Extension<PgPool>,
    Path(snapshot_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let payload: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT payload FROM reconciliation_snapshot WHERE snapshot_id = $1")
            .bind(snapshot_id)
            .fetch_optional(&pool)
            .await
            .map_err(db_err("snapshot read"))?;
    payload
        .map(Json)
        .ok_or_else(|| AppError::NotFound("No such snapshot".to_string()))
}

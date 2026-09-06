//! Custodial payment intents: the write-ahead row behind
//! `POST /managed-account/sign` (037 part A).
//!
//! Life of a user payment:
//!
//! 1. **Claim** (`claim_user_payment`, ONE transaction under a per-account
//!    advisory lock): replay lookup by `(account, idempotency_key)`, policy
//!    (pause + caps), and the `INSERT` of a `prepared` row. Replays never
//!    re-check policy and never count spend — the recorded outcome is the
//!    answer. The partial unique index `uq_custodial_intent_one_inflight`
//!    admits ONE unresolved `sign` intent per account.
//! 2. **Submit** (`submit_intent`): load the seed, build and sign the
//!    payment, persist its hash on the row (`INTENT_ARM_SQL`: exactly one
//!    row, else NO submit), zeroize the seed, then submit. A row with no hash
//!    has provably never been submitted; a row with a hash may have been.
//! 3. **Settle** (`record_settlement`, shared with the sweep and admin
//!    resolve): the `transaction` row and the intent's terminal status commit
//!    together with the `custodial.payment_settled` event.
//!
//! An ambiguous submit freezes the row (`ambiguous`) and is only ever resolved
//! by hash — by the sweep (`custody::sweep`) or an admin — never resubmitted.
//! Every state change is a compare-and-swap on `(status, stellar_hash)`, so
//! two resolvers can never both settle or both reject one intent.
//!
//! No cache or throttle is consulted anywhere on this path: the pause switch
//! and the caps are rows read inside the claim transaction.

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::constants::{
    CUSTODIAL_DAILY_WINDOW_SECS, CUSTODIAL_IDEMPOTENCY_KEY_MAX_LEN,
    CUSTODIAL_IDEMPOTENCY_KEY_MIN_LEN, CUSTODIAL_INTENT_ORIGIN_REDEMPTION,
    CUSTODIAL_INTENT_ORIGIN_SIGN, CUSTODIAL_KEY_SOURCE_SERVER, RESERVE_SCALE_STELLAR,
    TX_ORIGIN_CUSTODIAL_SIGN, TX_ORIGIN_OFFLINE_REDEMPTION,
};
use crate::custody::policy::{
    evaluate_policy, PolicyRow, Refusal, ACCOUNT_LIMIT_SQL, DAILY_SPEND_SQL, POLICY_READ_SQL,
};
use crate::error::AppError;
use crate::events::{emit_event, AccountEvent};
use crate::exchange::reserve::minor_to_decimal_string;
use crate::exchange::reserve_watch::{classify_submit, SubmitOutcome};
use crate::models::SignSubmitResponse;
use crate::seed_protect::SeedProtector;
use crate::stellar::{Asset, PaymentParams, StellarSigner};

// ── SQL (string-pinned by the tests below) ─────────────────────────────

/// Replay lookup, locked so a concurrent claim with the same key waits.
pub(crate) const INTENT_LOOKUP_SQL: &str = "SELECT intent_id, request_fingerprint, status, \
        resolution, stellar_hash, btxid, last_error, amount_minor \
     FROM custodial_payment_intent \
     WHERE payala_account_id = $1 AND idempotency_key = $2 FOR UPDATE";

/// The source address the row is claimed against (asserted again by
/// `load_protected_seed` when the seed is opened).
pub(crate) const SOURCE_ACCOUNT_SQL: &str = "SELECT stellar_account_id FROM managed_seed \
     WHERE payala_account_id = $1 FOR KEY SHARE";

/// 13 binds. `redemption_id` is always NULL for `sign` rows (038 fills it
/// for redemption payouts through the same statement).
pub(crate) const INTENT_INSERT_SQL: &str = "INSERT INTO custodial_payment_intent \
     (payala_account_id, source_account, origin, idempotency_key, key_source, \
      request_fingerprint, destination, asset_code, asset_issuer, amount_minor, memo, \
      fee_stroops, redemption_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING intent_id";

/// Persist the signed envelope's hash BEFORE submission. Exactly one row
/// must change; anything else means the row moved under us (abandoned by
/// the sweep, or armed by a racing task) and the submit must not happen.
pub(crate) const INTENT_ARM_SQL: &str = "UPDATE custodial_payment_intent \
     SET stellar_hash = $2, status = 'submitted', armed_at = CURRENT_TIMESTAMP \
     WHERE intent_id = $1 AND status = 'prepared' AND stellar_hash IS NULL";

/// Terminal rejection of a row that was never armed (no hash => no submit).
pub(crate) const INTENT_REJECT_PREPARED_SQL: &str = "UPDATE custodial_payment_intent \
     SET status = 'rejected', resolution = $2, last_error = $3, resolved_at = CURRENT_TIMESTAMP \
     WHERE intent_id = $1 AND status = 'prepared'";

/// Terminal rejection after a DEFINITIVE Horizon rejection of this hash.
pub(crate) const INTENT_REJECT_SUBMITTED_SQL: &str = "UPDATE custodial_payment_intent \
     SET status = 'rejected', resolution = $2, last_error = $3, resolved_at = CURRENT_TIMESTAMP \
     WHERE intent_id = $1 AND status = 'submitted' AND stellar_hash = $4";

/// Terminal rejection by hash after the chain proved the transaction failed
/// or expired (sweep / admin only).
pub(crate) const INTENT_REJECT_BY_HASH_SQL: &str = "UPDATE custodial_payment_intent \
     SET status = 'rejected', resolution = $2, last_error = $3, resolved_at = CURRENT_TIMESTAMP \
     WHERE intent_id = $1 AND status IN ('submitted', 'ambiguous') AND stellar_hash = $4";

/// Freeze after an ambiguous submit. Only a `submitted` row can become
/// ambiguous; the hash guard keeps it tied to the envelope that was sent.
pub(crate) const INTENT_AMBIGUOUS_SQL: &str = "UPDATE custodial_payment_intent \
     SET status = 'ambiguous', last_error = $2 \
     WHERE intent_id = $1 AND status = 'submitted' AND stellar_hash = $3";

/// Settle: the CAS every resolver shares. Zero rows = someone else already
/// resolved this hash; the caller rolls back its duplicate ledger row.
pub(crate) const INTENT_SETTLE_SQL: &str = "UPDATE custodial_payment_intent \
     SET status = 'settled', btxid = $2, resolution = $3, resolved_at = CURRENT_TIMESTAMP \
     WHERE intent_id = $1 AND status IN ('submitted', 'ambiguous') AND stellar_hash = $4";

/// The settlement row. 10 binds — the four settlement columns are 037's
/// nullable additions, so the older shared INSERTs keep their bind lists.
pub(crate) const SETTLEMENT_TX_INSERT_SQL: &str = "INSERT INTO transaction \
     (stellar_tx_id, stellar_hash, source_account, memo, account_id, origin, \
      stellar_amount_minor, stellar_destination, stellar_asset_code, stellar_asset_issuer) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING btxid";

/// The live `sign` intent blocking a second claim (the 23505 explanation).
pub(crate) const LIVE_INTENT_SQL: &str = "SELECT intent_id FROM custodial_payment_intent \
     WHERE payala_account_id = $1 AND origin = 'sign' \
       AND status IN ('prepared', 'submitted', 'ambiguous')";

/// Columns of an open row, as the sweep and admin resolve read them
/// (pinned into both statements by tests).
#[allow(dead_code)]
pub(crate) const OPEN_INTENT_COLUMNS: &str = "intent_id, payala_account_id, origin, \
        source_account, destination, asset_code, asset_issuer, amount_minor, memo, \
        stellar_hash, status, armed_at";

/// One open row by id (admin resolve).
pub(crate) const OPEN_INTENT_BY_ID_SQL: &str = "SELECT intent_id, payala_account_id, origin, \
        source_account, destination, asset_code, asset_issuer, amount_minor, memo, \
        stellar_hash, status, armed_at \
     FROM custodial_payment_intent WHERE intent_id = $1";

/// UTC RFC3339 rendering used by every intent view.
pub(crate) const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

/// The `CustodialIntentView` projection (owner and admin reads).
pub(crate) fn intent_view_columns() -> String {
    format!(
        "intent_id, payala_account_id, origin, status, resolution, key_source, \
         idempotency_key, destination, asset_code, asset_issuer, amount_minor, memo, \
         fee_stroops, stellar_hash, btxid, last_error, \
         to_char(created_at AT TIME ZONE 'UTC', '{ts}') AS created_at, \
         to_char(armed_at AT TIME ZONE 'UTC', '{ts}') AS armed_at, \
         to_char(resolved_at AT TIME ZONE 'UTC', '{ts}') AS resolved_at",
        ts = TS_FMT
    )
}

/// Fill the derived `amount` string on a fetched view.
pub(crate) fn finish_view(
    mut v: crate::models::CustodialIntentView,
) -> crate::models::CustodialIntentView {
    v.amount = minor_to_decimal_string(v.amount_minor, RESERVE_SCALE_STELLAR);
    v
}

/// The message on every 202 for an ambiguous submit.
pub(crate) const AMBIGUOUS_MESSAGE: &str = "Outcome unknown: the signed transaction may still \
     land within 300s. Do NOT resubmit; resend with the same idempotency_key or poll \
     GET /managed-account/intents/{id}.";

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("custodial intent: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.code().as_deref() == Some("23505"))
}

/// `last_error` is VARCHAR(200): truncate on a char boundary.
pub(crate) fn truncate_error(msg: &str) -> String {
    msg.chars().take(200).collect()
}

/// Client idempotency keys: 1-64 chars of `[A-Za-z0-9._:-]`.
pub(crate) fn validate_idempotency_key(key: &str) -> Result<(), AppError> {
    let ok_len = (CUSTODIAL_IDEMPOTENCY_KEY_MIN_LEN..=CUSTODIAL_IDEMPOTENCY_KEY_MAX_LEN)
        .contains(&key.len());
    let ok_chars = key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if !ok_len || !ok_chars {
        return Err(AppError::BadRequest(format!(
            "idempotency_key must be {}-{} characters of [A-Za-z0-9._:-]",
            CUSTODIAL_IDEMPOTENCY_KEY_MIN_LEN, CUSTODIAL_IDEMPOTENCY_KEY_MAX_LEN
        )));
    }
    Ok(())
}

// ── Rows ───────────────────────────────────────────────────────────────

/// A row as seen by the replay lookup.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct IntentSnapshot {
    pub intent_id: Uuid,
    pub request_fingerprint: String,
    pub status: String,
    pub resolution: Option<String>,
    pub stellar_hash: Option<String>,
    pub btxid: Option<Uuid>,
    pub last_error: Option<String>,
    pub amount_minor: i64,
}

/// An open (or any) row with everything a hash resolver needs.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct OpenIntentRow {
    pub intent_id: Uuid,
    pub payala_account_id: String,
    pub origin: String,
    pub source_account: String,
    pub destination: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub amount_minor: i64,
    pub memo: Option<String>,
    pub stellar_hash: Option<String>,
    pub status: String,
    pub armed_at: Option<DateTime<Utc>>,
}

impl OpenIntentRow {
    /// The asset the row was signed in (issuer-pinned for credit assets).
    pub(crate) fn asset(&self) -> Asset {
        match &self.asset_issuer {
            None => Asset::Native,
            Some(issuer) => Asset::Credit {
                code: self.asset_code.clone(),
                issuer: issuer.clone(),
            },
        }
    }

    /// Settlement parameters for this row under `resolution`. The Horizon
    /// transaction id of a landed payment IS its hash.
    pub(crate) fn settlement<'a>(
        &'a self,
        stellar_hash: &'a str,
        resolution: &'a str,
    ) -> SettlementParams<'a> {
        SettlementParams {
            intent_id: self.intent_id,
            payala_account_id: &self.payala_account_id,
            origin: &self.origin,
            source_account: &self.source_account,
            destination: &self.destination,
            asset_code: &self.asset_code,
            asset_issuer: self.asset_issuer.as_deref(),
            amount_minor: self.amount_minor,
            memo: self.memo.as_deref(),
            stellar_hash,
            stellar_tx_id: Some(stellar_hash),
            resolution,
        }
    }
}

// ── Claim ──────────────────────────────────────────────────────────────

/// What the owner asked for, already validated and canonicalized.
pub(crate) struct UserPaymentClaim<'a> {
    pub payala_account_id: &'a str,
    pub idempotency_key: &'a str,
    /// `CUSTODIAL_KEY_SOURCE_CLIENT` | `CUSTODIAL_KEY_SOURCE_SERVER`.
    pub key_source: &'static str,
    pub fingerprint: &'a str,
    pub destination: &'a str,
    pub amount_minor: i64,
    pub memo: Option<&'a str>,
    pub fee: Option<u32>,
}

pub(crate) enum ClaimOutcome {
    /// A fresh `prepared` row exists; submit it.
    Claimed {
        intent_id: Uuid,
        source_account: String,
    },
    /// The key was seen before with the same request: report what happened.
    Replay(IntentSnapshot),
}

/// Same key, different request: the recorded intent is not this one.
pub(crate) fn check_fingerprint(
    existing: &IntentSnapshot,
    fingerprint: &str,
) -> Result<(), AppError> {
    if existing.request_fingerprint.trim_end() != fingerprint {
        return Err(AppError::coded(
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "This idempotency_key was already used for a different payment",
        )
        .with_details(json!({ "intent_id": existing.intent_id })));
    }
    Ok(())
}

/// The 409 for a second live `sign` intent on the account.
pub(crate) fn in_flight_error(
    intent_id: Uuid,
    status: &str,
    stellar_hash: Option<&str>,
) -> AppError {
    let mut details = json!({ "intent_id": intent_id, "status": status });
    if let Some(h) = stellar_hash {
        details["stellar_hash"] = json!(h);
    }
    AppError::coded(
        StatusCode::CONFLICT,
        "payment_in_flight",
        "A custodial payment from this account is still unresolved; wait for it to settle or poll GET /managed-account/intents/{id}",
    )
    .with_details(details)
}

/// Claim a `prepared` intent for the owner's payment, or find the recorded
/// outcome for a replayed key. Nothing is signed here.
pub(crate) async fn claim_user_payment(
    pool: &PgPool,
    claim: &UserPaymentClaim<'_>,
) -> Result<ClaimOutcome, AppError> {
    let mut tx = pool.begin().await.map_err(db_err("claim begin"))?;
    // Serialize claims per account so the replay lookup, the spend sum and
    // the insert form one decision (the one-in-flight index is the backstop).
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('custodial_sign:' || $1))")
        .bind(claim.payala_account_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err("claim lock"))?;

    let existing: Option<IntentSnapshot> = sqlx::query_as(INTENT_LOOKUP_SQL)
        .bind(claim.payala_account_id)
        .bind(claim.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("replay lookup"))?;
    if let Some(snapshot) = existing {
        // Nothing written: dropping the transaction rolls it back. Replays
        // never re-check policy and never count spend.
        drop(tx);
        check_fingerprint(&snapshot, claim.fingerprint)?;
        return Ok(ClaimOutcome::Replay(snapshot));
    }

    let policy: Option<PolicyRow> = sqlx::query_as(POLICY_READ_SQL)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("policy read"))?;
    let policy = policy.ok_or_else(|| {
        error!("custodial_policy row is missing; refusing to sign (run migration 037)");
        Refusal::Unconfigured.into_error()
    })?;
    if policy.require_idempotency_key && claim.key_source == CUSTODIAL_KEY_SOURCE_SERVER {
        return Err(AppError::coded(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "This bridge requires a client idempotency_key on custodial payments",
        ));
    }
    // The brake is checked before any spend query and long before any seed
    // access.
    if policy.paused {
        return Err(Refusal::Paused.into_error());
    }

    let account_override: Option<Option<i64>> = sqlx::query_scalar(ACCOUNT_LIMIT_SQL)
        .bind(claim.payala_account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("account limit"))?;
    let (spent, window_start): (i64, Option<DateTime<Utc>>) = sqlx::query_as(DAILY_SPEND_SQL)
        .bind(claim.payala_account_id)
        .bind(CUSTODIAL_DAILY_WINDOW_SECS as f64)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("daily spend"))?;
    evaluate_policy(
        &policy,
        account_override.flatten(),
        spent,
        window_start,
        claim.amount_minor,
    )
    .map_err(Refusal::into_error)?;

    let source_account: Option<String> = sqlx::query_scalar(SOURCE_ACCOUNT_SQL)
        .bind(claim.payala_account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("source account"))?;
    let source_account = source_account
        .ok_or_else(|| AppError::NotFound("No managed seed for this account".to_string()))?;

    let inserted = sqlx::query_scalar::<_, Uuid>(INTENT_INSERT_SQL)
        .bind(claim.payala_account_id)
        .bind(&source_account)
        .bind(CUSTODIAL_INTENT_ORIGIN_SIGN)
        .bind(claim.idempotency_key)
        .bind(claim.key_source)
        .bind(claim.fingerprint)
        .bind(claim.destination)
        .bind("XLM")
        .bind(None::<String>)
        .bind(claim.amount_minor)
        .bind(claim.memo)
        .bind(claim.fee.map(i64::from))
        .bind(None::<Uuid>)
        .fetch_one(&mut *tx)
        .await;
    let intent_id = match inserted {
        Ok(id) => id,
        Err(e) if is_unique_violation(&e) => {
            drop(tx);
            let live: Option<(Uuid,)> = sqlx::query_as(LIVE_INTENT_SQL)
                .bind(claim.payala_account_id)
                .fetch_optional(pool)
                .await
                .map_err(db_err("live intent lookup"))?;
            return Err(match live {
                Some((id,)) => in_flight_error(id, "unresolved", None),
                None => AppError::Conflict(
                    "A custodial payment from this account is still unresolved".to_string(),
                ),
            });
        }
        Err(e) => return Err(db_err("intent insert")(e)),
    };
    tx.commit().await.map_err(db_err("claim commit"))?;
    info!(
        "custodial intent {} claimed: account={} key_source={} amount_minor={}",
        intent_id, claim.payala_account_id, claim.key_source, claim.amount_minor
    );
    Ok(ClaimOutcome::Claimed {
        intent_id,
        source_account,
    })
}

// ── Submit ─────────────────────────────────────────────────────────────

/// Everything the submit phase needs, owned so it can run on a tracked task
/// that outlives the request.
pub(crate) struct SubmitDeps {
    pub pool: PgPool,
    pub protector: Arc<dyn SeedProtector>,
    pub signer: Arc<dyn StellarSigner>,
    pub cancel: CancellationToken,
}

pub(crate) struct SubmitParams {
    pub intent_id: Uuid,
    pub payala_account_id: String,
    pub source_account: String,
    pub destination: String,
    pub amount_minor: i64,
    pub memo: Option<String>,
    pub fee: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SubmitResult {
    /// Landed and recorded.
    Settled {
        stellar_hash: String,
        btxid: Uuid,
        resolution: String,
    },
    /// Landed on-chain but the settle transaction failed: the sweep records
    /// it by hash. Never reported as a 200 with `btxid: null`.
    SettledUnrecorded { stellar_hash: String },
    /// Outcome unknown; frozen for resolution by hash.
    Ambiguous { stellar_hash: String },
    /// Definitively did not and cannot land.
    Rejected {
        resolution: &'static str,
        last_error: String,
    },
}

async fn reject_prepared(pool: &PgPool, intent_id: Uuid, resolution: &str, last_error: &str) {
    match sqlx::query(INTENT_REJECT_PREPARED_SQL)
        .bind(intent_id)
        .bind(resolution)
        .bind(truncate_error(last_error))
        .execute(pool)
        .await
    {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => warn!(
            "custodial intent {}: not rejected as {} (row already moved)",
            intent_id, resolution
        ),
        Err(e) => error!(
            "custodial intent {}: reject ({}) failed: {} — the sweep will abandon it",
            intent_id, resolution, e
        ),
    }
}

/// Sign, arm, submit, record. Runs detached from the request on the task
/// tracker; the handler awaits its handle.
pub(crate) async fn submit_intent(
    deps: SubmitDeps,
    p: SubmitParams,
) -> Result<SubmitResult, AppError> {
    if deps.cancel.is_cancelled() {
        // Nothing signed: the row stays `prepared` and the sweep abandons it.
        return Err(AppError::Retryable(
            "bridge is shutting down; the payment was not signed".to_string(),
        ));
    }

    let seed = match crate::handlers::managed_seed::load_protected_seed(
        &deps.pool,
        &deps.protector,
        &deps.signer,
        &p.payala_account_id,
    )
    .await
    {
        Ok(seed) => seed,
        Err(e) => {
            reject_prepared(
                &deps.pool,
                p.intent_id,
                "prepare_rejected",
                "seed unavailable",
            )
            .await;
            return Err(e);
        }
    };
    // Row == transaction: the amount signed is the canonical rendering of
    // the minor units the row carries.
    let params = PaymentParams {
        destination: p.destination.clone(),
        amount: minor_to_decimal_string(p.amount_minor, RESERVE_SCALE_STELLAR),
        asset: Asset::Native,
        memo: p.memo.clone(),
        fee: p.fee,
    };
    let prepared = match deps.signer.prepare_payment(seed.as_slice(), &params).await {
        Ok(prepared) => prepared,
        Err(AppError::BadRequest(msg)) => {
            reject_prepared(&deps.pool, p.intent_id, "prepare_rejected", &msg).await;
            return Ok(SubmitResult::Rejected {
                resolution: "prepare_rejected",
                last_error: msg,
            });
        }
        Err(e) => {
            reject_prepared(&deps.pool, p.intent_id, "prepare_rejected", &e.to_string()).await;
            return Err(AppError::Retryable(
                "transaction preparation failed before submission".to_string(),
            ));
        }
    };
    if prepared.source_account != p.source_account {
        // Cannot happen after load_protected_seed's derivation assertion,
        // but a row that disagrees with its signature is never submitted.
        error!(
            "custodial intent {}: prepared source {} != claimed source {}",
            p.intent_id, prepared.source_account, p.source_account
        );
        reject_prepared(
            &deps.pool,
            p.intent_id,
            "prepare_rejected",
            "source mismatch",
        )
        .await;
        return Err(AppError::InternalError(
            "seed does not match its account record".to_string(),
        ));
    }

    // Hash before submit: exactly one row armed, or no submit at all.
    let armed = sqlx::query(INTENT_ARM_SQL)
        .bind(p.intent_id)
        .bind(&prepared.stellar_hash)
        .execute(&deps.pool)
        .await;
    match armed {
        Ok(r) if r.rows_affected() == 1 => {}
        other => {
            match other {
                Ok(r) => error!(
                    "custodial intent {}: arm affected {} rows; NOT submitting",
                    p.intent_id,
                    r.rows_affected()
                ),
                Err(e) => error!(
                    "custodial intent {}: arm failed ({}); NOT submitting",
                    p.intent_id, e
                ),
            }
            reject_prepared(
                &deps.pool,
                p.intent_id,
                "arm_failed",
                "intent hash not recorded",
            )
            .await;
            return Err(AppError::Retryable(
                "intent hash not recorded; not submitting".to_string(),
            ));
        }
    }
    // The seed is zeroized before the network call.
    drop(seed);

    let submitted = deps.signer.submit_prepared(&prepared).await;
    let stellar_hash = prepared.stellar_hash.clone();
    match classify_submit(&submitted) {
        SubmitOutcome::Settled => {
            let tx_result = submitted.expect("Settled implies Ok");
            let settlement = SettlementParams {
                intent_id: p.intent_id,
                payala_account_id: &p.payala_account_id,
                origin: CUSTODIAL_INTENT_ORIGIN_SIGN,
                source_account: &p.source_account,
                destination: &p.destination,
                asset_code: "XLM",
                asset_issuer: None,
                amount_minor: p.amount_minor,
                memo: p.memo.as_deref(),
                stellar_hash: &stellar_hash,
                stellar_tx_id: tx_result.stellar_tx_id.as_deref(),
                resolution: "submit_ok",
            };
            match record_settlement(&deps.pool, &settlement, None).await {
                Ok(SettleOutcome::Settled { btxid }) => Ok(SubmitResult::Settled {
                    stellar_hash,
                    btxid,
                    resolution: "submit_ok".to_string(),
                }),
                Ok(SettleOutcome::AlreadySettled) => {
                    // A resolver beat us to it; report its record.
                    let row: Option<(String, Option<Uuid>, Option<String>)> = sqlx::query_as(
                        "SELECT status, btxid, resolution FROM custodial_payment_intent \
                         WHERE intent_id = $1",
                    )
                    .bind(p.intent_id)
                    .fetch_optional(&deps.pool)
                    .await
                    .unwrap_or(None);
                    match row {
                        Some((status, Some(btxid), resolution)) if status == "settled" => {
                            Ok(SubmitResult::Settled {
                                stellar_hash,
                                btxid,
                                resolution: resolution.unwrap_or_default(),
                            })
                        }
                        _ => Ok(SubmitResult::SettledUnrecorded { stellar_hash }),
                    }
                }
                Err(e) => {
                    error!(
                        "custodial intent {}: SETTLED PAYMENT NOT YET RECORDED (hash {}): {:?} — \
                         the sweep records it by hash",
                        p.intent_id, stellar_hash, e
                    );
                    Ok(SubmitResult::SettledUnrecorded { stellar_hash })
                }
            }
        }
        SubmitOutcome::Rejected { msg, .. } => {
            let last_error = truncate_error(&msg);
            match sqlx::query(INTENT_REJECT_SUBMITTED_SQL)
                .bind(p.intent_id)
                .bind("submit_rejected")
                .bind(&last_error)
                .bind(&stellar_hash)
                .execute(&deps.pool)
                .await
            {
                Ok(r) if r.rows_affected() == 1 => {}
                Ok(_) => warn!(
                    "custodial intent {}: rejection not recorded (row moved)",
                    p.intent_id
                ),
                Err(e) => error!(
                    "custodial intent {}: rejection not recorded: {} — the sweep resolves by hash",
                    p.intent_id, e
                ),
            }
            Ok(SubmitResult::Rejected {
                resolution: "submit_rejected",
                last_error,
            })
        }
        SubmitOutcome::Ambiguous => {
            let why = submitted
                .err()
                .map(|e| truncate_error(&e.to_string()))
                .unwrap_or_else(|| "ambiguous submit".to_string());
            if let Err(e) = mark_ambiguous(&deps.pool, &p, &stellar_hash, &why).await {
                error!(
                    "custodial intent {}: ambiguous mark failed: {:?} — the sweep resolves by hash",
                    p.intent_id, e
                );
            }
            Ok(SubmitResult::Ambiguous { stellar_hash })
        }
    }
}

async fn mark_ambiguous(
    pool: &PgPool,
    p: &SubmitParams,
    stellar_hash: &str,
    why: &str,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(db_err("ambiguous begin"))?;
    let updated = sqlx::query(INTENT_AMBIGUOUS_SQL)
        .bind(p.intent_id)
        .bind(why)
        .bind(stellar_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_err("ambiguous update"))?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    emit_event(
        &mut tx,
        &AccountEvent::CustodialPaymentAmbiguous {
            account_id: p.payala_account_id.clone(),
            intent_id: p.intent_id.to_string(),
            origin: CUSTODIAL_INTENT_ORIGIN_SIGN.to_string(),
            amount_minor: p.amount_minor,
            asset_code: "XLM".to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("ambiguous commit"))?;
    warn!(
        "custodial intent {} is AMBIGUOUS (hash {}); frozen for resolution by hash",
        p.intent_id, stellar_hash
    );
    Ok(())
}

// ── Settle / reject by hash ────────────────────────────────────────────

pub(crate) struct SettlementParams<'a> {
    pub intent_id: Uuid,
    /// Beneficiary: the owner for `sign`, the card owner for `redemption`.
    pub payala_account_id: &'a str,
    pub origin: &'a str,
    pub source_account: &'a str,
    pub destination: &'a str,
    pub asset_code: &'a str,
    pub asset_issuer: Option<&'a str>,
    pub amount_minor: i64,
    pub memo: Option<&'a str>,
    pub stellar_hash: &'a str,
    pub stellar_tx_id: Option<&'a str>,
    pub resolution: &'a str,
}

#[derive(Debug, PartialEq)]
pub(crate) enum SettleOutcome {
    Settled {
        btxid: Uuid,
    },
    /// Another resolver already settled this hash; nothing was written.
    AlreadySettled,
}

/// One transaction: the `transaction` row, the intent CAS, the event. Shared
/// by the submit path, the sweep and admin resolve so the three can never
/// disagree about what a settlement writes.
pub(crate) async fn record_settlement(
    pool: &PgPool,
    p: &SettlementParams<'_>,
    audit: Option<&AccountEvent>,
) -> Result<SettleOutcome, AppError> {
    let tx_origin = if p.origin == CUSTODIAL_INTENT_ORIGIN_REDEMPTION {
        TX_ORIGIN_OFFLINE_REDEMPTION
    } else {
        TX_ORIGIN_CUSTODIAL_SIGN
    };
    let mut tx = pool.begin().await.map_err(db_err("settle begin"))?;
    let btxid: Uuid = sqlx::query_scalar(SETTLEMENT_TX_INSERT_SQL)
        .bind(p.stellar_tx_id.unwrap_or(p.stellar_hash))
        .bind(p.stellar_hash)
        .bind(p.source_account)
        .bind(p.memo)
        .bind(p.payala_account_id)
        .bind(tx_origin)
        .bind(p.amount_minor)
        .bind(p.destination)
        .bind(p.asset_code)
        .bind(p.asset_issuer)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("settlement row"))?;
    let updated = sqlx::query(INTENT_SETTLE_SQL)
        .bind(p.intent_id)
        .bind(btxid)
        .bind(p.resolution)
        .bind(p.stellar_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_err("settle cas"))?;
    if updated.rows_affected() == 0 {
        // Someone else resolved it first: discard our duplicate ledger row.
        drop(tx);
        return Ok(SettleOutcome::AlreadySettled);
    }
    emit_event(
        &mut tx,
        &AccountEvent::CustodialPaymentSettled {
            account_id: p.payala_account_id.to_string(),
            intent_id: p.intent_id.to_string(),
            btxid: btxid.to_string(),
            origin: p.origin.to_string(),
            amount_minor: p.amount_minor,
            asset_code: p.asset_code.to_string(),
            resolution: p.resolution.to_string(),
        },
    )
    .await?;
    // An admin resolution is audited in the same transaction as the change.
    if let Some(event) = audit {
        emit_event(&mut tx, event).await?;
    }
    tx.commit().await.map_err(db_err("settle commit"))?;
    info!(
        "custodial intent {} settled: btxid={} resolution={}",
        p.intent_id, btxid, p.resolution
    );
    Ok(SettleOutcome::Settled { btxid })
}

/// Terminal rejection of an open row by hash (sweep / admin). `true` when
/// this call made the change.
pub(crate) async fn reject_by_hash(
    pool: &PgPool,
    intent_id: Uuid,
    stellar_hash: &str,
    resolution: &str,
    last_error: &str,
    audit: Option<&AccountEvent>,
) -> Result<bool, AppError> {
    let mut tx = pool.begin().await.map_err(db_err("reject begin"))?;
    let updated = sqlx::query(INTENT_REJECT_BY_HASH_SQL)
        .bind(intent_id)
        .bind(resolution)
        .bind(truncate_error(last_error))
        .bind(stellar_hash)
        .execute(&mut *tx)
        .await
        .map_err(db_err("reject by hash"))?;
    if updated.rows_affected() == 0 {
        drop(tx);
        return Ok(false);
    }
    if let Some(event) = audit {
        emit_event(&mut tx, event).await?;
    }
    tx.commit().await.map_err(db_err("reject commit"))?;
    Ok(true)
}

// ── Responses (pure) ───────────────────────────────────────────────────

fn base_response(intent_id: Uuid, key: &str, replayed: bool) -> SignSubmitResponse {
    SignSubmitResponse {
        success: false,
        message: String::new(),
        stellar_hash: None,
        btxid: None,
        intent_id: Some(intent_id),
        idempotency_key: Some(key.to_string()),
        status: None,
        resolution: None,
        replayed: Some(replayed),
        amount_minor: None,
    }
}

fn rejected_error(
    intent_id: Uuid,
    resolution: Option<&str>,
    last_error: Option<&str>,
    replayed: bool,
) -> AppError {
    AppError::coded(
        StatusCode::BAD_REQUEST,
        "payment_rejected",
        last_error.unwrap_or("Payment rejected"),
    )
    .with_details(json!({
        "intent_id": intent_id,
        "status": "rejected",
        "resolution": resolution,
        "replayed": replayed,
    }))
}

/// The response for a replayed key (same request): the recorded outcome,
/// with nothing signed or submitted again.
pub(crate) fn replay_response(
    snap: &IntentSnapshot,
    key: &str,
) -> Result<(StatusCode, SignSubmitResponse), AppError> {
    let mut r = base_response(snap.intent_id, key, true);
    r.amount_minor = Some(snap.amount_minor);
    match snap.status.as_str() {
        "settled" => {
            r.success = true;
            r.message = "Payment signed and submitted".to_string();
            r.status = Some("settled".to_string());
            r.stellar_hash = snap.stellar_hash.clone();
            r.btxid = snap.btxid;
            r.resolution = snap.resolution.clone();
            Ok((StatusCode::OK, r))
        }
        "ambiguous" => {
            r.message = AMBIGUOUS_MESSAGE.to_string();
            r.status = Some("ambiguous".to_string());
            r.stellar_hash = snap.stellar_hash.clone();
            Ok((StatusCode::ACCEPTED, r))
        }
        "prepared" | "submitted" => Err(in_flight_error(
            snap.intent_id,
            &snap.status,
            snap.stellar_hash.as_deref(),
        )),
        "rejected" => Err(rejected_error(
            snap.intent_id,
            snap.resolution.as_deref(),
            snap.last_error.as_deref(),
            true,
        )),
        other => {
            error!(
                "custodial intent {}: unknown status {}",
                snap.intent_id, other
            );
            Err(AppError::InternalError("Corrupt intent record".to_string()))
        }
    }
}

/// The response for a first-time submit outcome.
pub(crate) fn outcome_response(
    intent_id: Uuid,
    key: &str,
    amount_minor: i64,
    outcome: SubmitResult,
) -> Result<(StatusCode, SignSubmitResponse), AppError> {
    let mut r = base_response(intent_id, key, false);
    r.amount_minor = Some(amount_minor);
    match outcome {
        SubmitResult::Settled {
            stellar_hash,
            btxid,
            resolution,
        } => {
            r.success = true;
            r.message = "Payment signed and submitted".to_string();
            r.status = Some("settled".to_string());
            r.stellar_hash = Some(stellar_hash);
            r.btxid = Some(btxid);
            r.resolution = Some(resolution);
            Ok((StatusCode::OK, r))
        }
        SubmitResult::SettledUnrecorded { stellar_hash } => {
            r.message = "Payment settled on-chain; the ledger row is still being recorded. \
                         Poll GET /managed-account/intents/{id} for the btxid; do NOT resubmit."
                .to_string();
            r.status = Some("submitted".to_string());
            r.stellar_hash = Some(stellar_hash);
            Ok((StatusCode::ACCEPTED, r))
        }
        SubmitResult::Ambiguous { stellar_hash } => {
            r.message = AMBIGUOUS_MESSAGE.to_string();
            r.status = Some("ambiguous".to_string());
            r.stellar_hash = Some(stellar_hash);
            Ok((StatusCode::ACCEPTED, r))
        }
        SubmitResult::Rejected {
            resolution,
            last_error,
        } => Err(rejected_error(
            intent_id,
            Some(resolution),
            Some(&last_error),
            false,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(status: &str) -> IntentSnapshot {
        IntentSnapshot {
            intent_id: Uuid::nil(),
            request_fingerprint: "f".repeat(64),
            status: status.to_string(),
            resolution: Some("submit_ok".to_string()),
            stellar_hash: Some("ab".repeat(32)),
            btxid: Some(Uuid::max()),
            last_error: Some("op_underfunded".to_string()),
            amount_minor: 42,
        }
    }

    fn code_of(err: &AppError) -> (&'static str, StatusCode) {
        match err {
            AppError::Coded { code, status, .. } => (code, *status),
            other => panic!("expected Coded, got {:?}", other),
        }
    }

    #[test]
    fn replay_decision_table() {
        // settled -> 200 with the recorded ids, replayed:true
        let (status, body) = replay_response(&snap("settled"), "k").unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(body.success);
        assert_eq!(body.status.as_deref(), Some("settled"));
        assert_eq!(body.replayed, Some(true));
        assert_eq!(body.btxid, Some(Uuid::max()));
        assert_eq!(body.stellar_hash.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(body.amount_minor, Some(42));
        assert_eq!(body.idempotency_key.as_deref(), Some("k"));
        // ambiguous -> 202, success:false
        let (status, body) = replay_response(&snap("ambiguous"), "k").unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(!body.success);
        assert_eq!(body.status.as_deref(), Some("ambiguous"));
        assert_eq!(body.message, AMBIGUOUS_MESSAGE);
        // prepared / submitted -> 409 payment_in_flight
        for st in ["prepared", "submitted"] {
            let err = replay_response(&snap(st), "k").unwrap_err();
            assert_eq!(code_of(&err), ("payment_in_flight", StatusCode::CONFLICT));
            match err {
                AppError::Coded { details, .. } => {
                    let d = details.unwrap();
                    assert_eq!(d["status"], st);
                    assert_eq!(d["intent_id"], Uuid::nil().to_string());
                    assert!(d.get("stellar_hash").is_some());
                }
                _ => unreachable!(),
            }
        }
        // rejected -> 400 payment_rejected carrying last_error and replayed:true
        let err = replay_response(&snap("rejected"), "k").unwrap_err();
        assert_eq!(code_of(&err), ("payment_rejected", StatusCode::BAD_REQUEST));
        match err {
            AppError::Coded {
                message, details, ..
            } => {
                assert_eq!(message, "op_underfunded");
                let d = details.unwrap();
                assert_eq!(d["replayed"], true);
                assert_eq!(d["resolution"], "submit_ok");
            }
            _ => unreachable!(),
        }
        // anything else is corrupt, never silently a success
        assert!(matches!(
            replay_response(&snap("weird"), "k"),
            Err(AppError::InternalError(_))
        ));
    }

    #[test]
    fn ambiguous_maps_to_202_and_is_never_resubmitted() {
        let (status, body) = outcome_response(
            Uuid::nil(),
            "k",
            7,
            SubmitResult::Ambiguous {
                stellar_hash: "cd".repeat(32),
            },
        )
        .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(!body.success);
        assert_eq!(body.status.as_deref(), Some("ambiguous"));
        assert!(body.message.contains("Do NOT resubmit"));
        assert_eq!(body.replayed, Some(false));
        // The freeze is a CAS from `submitted` on the exact hash, so a late
        // duplicate resolver cannot re-freeze a settled row...
        assert!(INTENT_AMBIGUOUS_SQL.contains("status = 'submitted' AND stellar_hash = $3"));
        // ...and there is no statement anywhere that moves a row back to
        // `prepared` or clears a hash (the only way to sign again).
        // (needles are split so this test's own text cannot match them.)
        let src = include_str!("intent.rs");
        assert!(!src.contains(concat!("SET stellar_hash", " = NULL")));
        assert!(!src.contains(concat!("status = 'prepared'", ",")));
        assert!(!src.contains(concat!("SET status", " = 'prepared'")));
    }

    #[test]
    fn settled_unrecorded_is_202_never_200_with_null_btxid() {
        let (status, body) = outcome_response(
            Uuid::nil(),
            "k",
            7,
            SubmitResult::SettledUnrecorded {
                stellar_hash: "cd".repeat(32),
            },
        )
        .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body.status.as_deref(), Some("submitted"));
        assert!(body.btxid.is_none());
        let (status, body) = outcome_response(
            Uuid::nil(),
            "k",
            7,
            SubmitResult::Settled {
                stellar_hash: "cd".repeat(32),
                btxid: Uuid::max(),
                resolution: "submit_ok".into(),
            },
        )
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(body.success);
        assert_eq!(body.btxid, Some(Uuid::max()));
        let err = outcome_response(
            Uuid::nil(),
            "k",
            7,
            SubmitResult::Rejected {
                resolution: "submit_rejected",
                last_error: "tx_bad_seq".into(),
            },
        )
        .unwrap_err();
        assert_eq!(code_of(&err), ("payment_rejected", StatusCode::BAD_REQUEST));
    }

    #[test]
    fn same_key_different_fingerprint_is_conflict() {
        let s = snap("settled");
        assert!(check_fingerprint(&s, &"f".repeat(64)).is_ok());
        // CHAR(64) may come back space-padded on some drivers; trailing
        // whitespace is not a different request.
        let mut padded = s.clone();
        padded.request_fingerprint = format!("{}  ", "f".repeat(64));
        assert!(check_fingerprint(&padded, &"f".repeat(64)).is_ok());
        let err = check_fingerprint(&s, &"0".repeat(64)).unwrap_err();
        assert_eq!(
            code_of(&err),
            ("idempotency_conflict", StatusCode::CONFLICT)
        );
    }

    #[test]
    fn idempotency_key_charset_and_length() {
        assert!(validate_idempotency_key("a").is_ok());
        assert!(validate_idempotency_key("order-42_v1.0:retry").is_ok());
        assert!(validate_idempotency_key(&"x".repeat(64)).is_ok());
        assert!(validate_idempotency_key("").is_err());
        assert!(validate_idempotency_key(&"x".repeat(65)).is_err());
        assert!(validate_idempotency_key("has space").is_err());
        assert!(validate_idempotency_key("slash/").is_err());
        assert!(validate_idempotency_key("ünïcode").is_err());
        // A UUIDv4 (the server-minted form) always passes.
        assert!(validate_idempotency_key(&Uuid::new_v4().to_string()).is_ok());
    }

    #[test]
    fn intent_insert_binds_thirteen_and_matches_ddl() {
        let cols = &INTENT_INSERT_SQL
            [INTENT_INSERT_SQL.find('(').unwrap() + 1..INTENT_INSERT_SQL.find(')').unwrap()];
        let names: Vec<&str> = cols.split(',').map(str::trim).collect();
        assert_eq!(names.len(), 13);
        assert!(INTENT_INSERT_SQL.contains("$13)"));
        assert!(!INTENT_INSERT_SQL.contains("$14"));
        let ddl = include_str!("../../migrations/037_custodial_conservation.sql");
        let table = &ddl[ddl
            .find("CREATE TABLE IF NOT EXISTS custodial_payment_intent")
            .unwrap()..];
        let table = &table[..table.find(");").unwrap()];
        for name in &names {
            assert!(
                table.lines().any(|l| l.trim_start().starts_with(name)),
                "column {} not in 037 DDL",
                name
            );
        }
    }

    #[test]
    fn settlement_transaction_insert_binds_ten() {
        let cols = &SETTLEMENT_TX_INSERT_SQL[SETTLEMENT_TX_INSERT_SQL.find('(').unwrap() + 1
            ..SETTLEMENT_TX_INSERT_SQL.find(')').unwrap()];
        assert_eq!(cols.split(',').count(), 10);
        assert!(SETTLEMENT_TX_INSERT_SQL.contains("$10)"));
        assert!(!SETTLEMENT_TX_INSERT_SQL.contains("$11"));
        for c in [
            "stellar_amount_minor",
            "stellar_destination",
            "stellar_asset_code",
            "stellar_asset_issuer",
        ] {
            assert!(SETTLEMENT_TX_INSERT_SQL.contains(c));
        }
        assert!(SETTLEMENT_TX_INSERT_SQL.contains("RETURNING btxid"));
    }

    #[test]
    fn arm_sql_requires_prepared_and_null_hash() {
        assert!(INTENT_ARM_SQL
            .contains("WHERE intent_id = $1 AND status = 'prepared' AND stellar_hash IS NULL"));
        assert!(INTENT_ARM_SQL.contains("status = 'submitted'"));
        assert!(INTENT_ARM_SQL.contains("armed_at = CURRENT_TIMESTAMP"));
    }

    #[test]
    fn settle_sql_requires_hash_and_open_status() {
        assert!(INTENT_SETTLE_SQL
            .contains("status IN ('submitted', 'ambiguous') AND stellar_hash = $4"));
        assert!(INTENT_SETTLE_SQL.contains("SET status = 'settled', btxid = $2"));
        assert!(INTENT_REJECT_BY_HASH_SQL
            .contains("status IN ('submitted', 'ambiguous') AND stellar_hash = $4"));
        assert!(INTENT_REJECT_SUBMITTED_SQL.contains("status = 'submitted' AND stellar_hash = $4"));
        assert!(INTENT_REJECT_PREPARED_SQL.contains("AND status = 'prepared'"));
    }

    #[test]
    fn ambiguous_sql_only_leaves_submitted() {
        assert!(INTENT_AMBIGUOUS_SQL
            .starts_with("UPDATE custodial_payment_intent SET status = 'ambiguous'"));
        assert!(INTENT_AMBIGUOUS_SQL.contains("AND status = 'submitted' AND stellar_hash = $3"));
    }

    #[test]
    fn open_row_sql_carries_every_column_the_resolvers_read() {
        assert!(
            OPEN_INTENT_BY_ID_SQL.contains(OPEN_INTENT_COLUMNS.split_whitespace().next().unwrap())
        );
        for col in OPEN_INTENT_COLUMNS.split(',').map(str::trim) {
            assert!(OPEN_INTENT_BY_ID_SQL.contains(col), "missing {}", col);
        }
    }

    #[test]
    fn open_row_asset_is_issuer_pinned() {
        let mut row = OpenIntentRow {
            intent_id: Uuid::nil(),
            payala_account_id: "a".into(),
            origin: "sign".into(),
            source_account: "GSRC".into(),
            destination: "GDEST".into(),
            asset_code: "XLM".into(),
            asset_issuer: None,
            amount_minor: 1,
            memo: None,
            stellar_hash: None,
            status: "submitted".into(),
            armed_at: None,
        };
        assert_eq!(row.asset(), Asset::Native);
        row.asset_code = "USDC".into();
        row.asset_issuer = Some("GISS".into());
        assert_eq!(
            row.asset(),
            Asset::Credit {
                code: "USDC".into(),
                issuer: "GISS".into()
            }
        );
        let s = row.settlement("h", "sweep_settled");
        assert_eq!(s.stellar_tx_id, Some("h"));
        assert_eq!(s.resolution, "sweep_settled");
    }

    #[test]
    fn truncate_error_is_char_safe_and_bounded() {
        assert_eq!(truncate_error("ok"), "ok");
        let long = "é".repeat(300);
        let t = truncate_error(&long);
        assert_eq!(t.chars().count(), 200);
        assert!(t.len() <= 400);
    }
}

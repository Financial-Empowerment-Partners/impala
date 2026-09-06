//! Custodial Stellar account handlers: generate/import a protected seed and
//! sign+submit payments server-side.
//!
//! Security invariants (see SECURITY.md):
//! - `require_owner()` is the first check on every endpoint.
//! - Seeds are protected by the configured [`SeedProtector`] and only ever
//!   materialise inside a zeroizing [`SecretBytes`] for the duration of one call.
//! - All protector/signer failures fail closed (`AppError::InternalError`); seed
//!   material is never logged or returned.
//! - Signing/submission is server-only (never the SQS worker) and idempotent
//!   through a write-ahead intent row (`custody::intent`): a retry replays the
//!   recorded outcome, and a second live payment per account is refused by a
//!   partial unique index, so an at-least-once retry cannot double-submit.

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::Json;
use log::{error, info};
use sqlx::PgPool;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::AuthenticatedUser;
use crate::constants::{
    CUSTODIAL_KEY_SOURCE_CLIENT, CUSTODIAL_KEY_SOURCE_SERVER, MAX_NAME_LENGTH, MEMO_TEXT_MAX_BYTES,
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, RESERVE_SCALE_STELLAR, SEED_FORMAT_BOUND,
    SIGN_RATE_LIMIT_MAX_REQUESTS, SIGN_RATE_LIMIT_WINDOW_SECS, VALID_CUSTODIAL_INTENT_STATUSES,
};
use crate::custody::fingerprint::intent_fingerprint;
use crate::custody::intent::{
    claim_user_payment, finish_view, intent_view_columns, outcome_response, replay_response,
    submit_intent, validate_idempotency_key, ClaimOutcome, SubmitDeps, SubmitParams, SubmitResult,
    UserPaymentClaim,
};
use crate::error::AppError;
use crate::exchange::reserve::{minor_to_decimal_string, parse_decimal_to_minor};
use crate::models::{
    CustodialIntentListQuery, CustodialIntentView, GenerateManagedAccountRequest,
    ImportManagedAccountRequest, ManagedAccountResponse, PaginatedResponse, PaginationParams,
    SignSubmitRequest, SignSubmitResponse,
};
use crate::notifications::{self, NotificationEvent};
use crate::seed_protect::{ProtectedSeed, ProtectorBackend, SeedProtector};
use crate::stellar::StellarSigner;
use crate::telemetry::AppMetrics;

/// The configured conversion-reserve account is quarantined from user-facing
/// custodial endpoints: its seed signs payouts from the bridge's own pool, so
/// whoever holds that one account's *user* credential must not be able to
/// drain it through /managed-account/sign (5/min, no reserve ledger entry —
/// the pool would silently overstate available), nor rebind/overwrite its
/// seed via generate/import. Ops movements go through the audited
/// /admin/exchange-reserve flows instead. Fail closed on a match.
///
/// The guard reads the CONFIGURED account id, not the live `ConversionReserve`
/// handle. The handle is absent whenever the reserve failed to initialize —
/// including the bootstrap window in which `RESERVE_ACCOUNT_ID` is set but its
/// seed has not been provisioned yet — and keying off it would disarm this
/// check at exactly the moment the reserve account is claimable.
fn require_not_reserve_account(
    guard: &crate::exchange::reserve::ReserveAccountGuard,
    payala_account_id: &str,
) -> Result<(), AppError> {
    if guard.matches(payala_account_id) {
        error!(
            "managed-account endpoint refused for the conversion-reserve account '{}'",
            payala_account_id
        );
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Validate the profile name fields shared by generate/import.
fn validate_names(first_name: &str, last_name: &str) -> Result<(), AppError> {
    if first_name.trim().is_empty() || last_name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "first_name and last_name must not be empty".to_string(),
        ));
    }
    if first_name.len() > MAX_NAME_LENGTH || last_name.len() > MAX_NAME_LENGTH {
        return Err(AppError::BadRequest(format!(
            "Name fields must not exceed {} characters",
            MAX_NAME_LENGTH
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn store_managed_account(
    pool: &PgPool,
    payala_account_id: &str,
    stellar_account_id: &str,
    protected: &ProtectedSeed,
    origin: &str,
    first_name: &str,
    middle_name: &Option<String>,
    last_name: &str,
    nickname: &Option<String>,
    affiliation: &Option<String>,
    gender: &Option<String>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|e| {
        error!("store_managed_account: begin failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let seed_result = sqlx::query(
        r#"
        INSERT INTO managed_seed
            (payala_account_id, stellar_account_id, backend, ciphertext,
             wrapped_data_key, nonce, key_id, key_version, origin, format_version)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(payala_account_id)
    .bind(stellar_account_id)
    .bind(protected.backend.as_str())
    .bind(&protected.ciphertext)
    .bind(&protected.wrapped_data_key)
    .bind(&protected.nonce)
    .bind(&protected.key_id)
    .bind(&protected.key_version)
    .bind(origin)
    // Every new row is written bound. `seal_seed` is the only producer of the
    // ciphertext handed in here, so this constant and that call must move
    // together; `bound_writes_are_marked_bound` pins them.
    .bind(SEED_FORMAT_BOUND)
    .execute(&mut *tx)
    .await;

    if let Err(e) = seed_result {
        let err = e.to_string();
        if err.contains("duplicate key") || err.contains("unique constraint") {
            return Err(AppError::Conflict(
                "A managed account already exists for this identifier".to_string(),
            ));
        }
        error!("store_managed_account: seed insert failed: {}", e);
        return Err(AppError::InternalError("Database error".to_string()));
    }

    let account_result = sqlx::query(
        r#"
        INSERT INTO impala_account
            (stellar_account_id, payala_account_id, first_name, middle_name,
             last_name, nickname, affiliation, gender)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(stellar_account_id)
    .bind(payala_account_id)
    .bind(first_name)
    .bind(middle_name)
    .bind(last_name)
    .bind(nickname)
    .bind(affiliation)
    .bind(gender)
    .execute(&mut *tx)
    .await;

    if let Err(e) = account_result {
        let err = e.to_string();
        if err.contains("duplicate key") || err.contains("unique constraint") {
            return Err(AppError::Conflict(
                "An account with this identifier already exists".to_string(),
            ));
        }
        error!("store_managed_account: account insert failed: {}", e);
        return Err(AppError::InternalError("Database error".to_string()));
    }

    tx.commit().await.map_err(|e| {
        error!("store_managed_account: commit failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    Ok(())
}

/// Generate a fresh custodial Stellar account (`POST /managed-account/generate`).
/// The seed is created server-side, protected, and stored; only the public
/// `G...` address is returned.
pub async fn generate_managed_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(signer): Extension<Arc<dyn StellarSigner>>,
    Extension(reserve_guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Json(payload): Json<GenerateManagedAccountRequest>,
) -> Result<Json<ManagedAccountResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
    require_not_reserve_account(&reserve_guard, &payload.payala_account_id)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "seedgen",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    validate_names(&payload.first_name, &payload.last_name)?;

    info!(
        "POST /managed-account/generate: account={}",
        user.account_id
    );

    let (stellar_account_id, seed) = signer.generate_keypair()?;
    let protected = protector
        .encrypt_seed(&seal_seed(&payload.payala_account_id, seed.as_slice()))
        .await?;
    // `seed` (SecretBytes) zeroizes on drop at the end of this function.

    store_managed_account(
        &pool,
        &payload.payala_account_id,
        &stellar_account_id,
        &protected,
        "generated",
        &payload.first_name,
        &payload.middle_name,
        &payload.last_name,
        &payload.nickname,
        &payload.affiliation,
        &payload.gender,
    )
    .await?;

    info!(
        "generate_managed_account: created managed account stellar_id={}",
        stellar_account_id
    );
    Ok(Json(ManagedAccountResponse {
        success: true,
        message: "Managed account created successfully".to_string(),
        stellar_account_id: Some(stellar_account_id),
    }))
}

/// Import an existing Stellar secret seed under custody (`POST /managed-account/import`).
pub async fn import_managed_account(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(signer): Extension<Arc<dyn StellarSigner>>,
    Extension(reserve_guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Json(mut payload): Json<ImportManagedAccountRequest>,
) -> Result<Json<ManagedAccountResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
    require_not_reserve_account(&reserve_guard, &payload.payala_account_id)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "seedimport",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    validate_names(&payload.first_name, &payload.last_name)?;

    info!("POST /managed-account/import: account={}", user.account_id);

    // Move the seed into a zeroizing buffer and scrub the original in place.
    //
    // `payload.secret_seed` is a plain `String` on a struct with no
    // ZeroizeOnDrop, so taking only a clone (as this did) left the plaintext
    // strkey sitting in a heap allocation that was freed unscrubbed — visible
    // afterwards in a core dump, in swap, or to any memory-disclosure bug.
    // `mem::take` + `zeroize` overwrites it rather than merely dropping it.
    //
    // This narrows the window; it cannot close it entirely, because axum's
    // buffered request body and serde's unescape scratch space also hold the
    // seed transiently and are not reachable from here.
    let secret_seed = Zeroizing::new(std::mem::take(&mut payload.secret_seed));
    payload.secret_seed.zeroize();
    crate::validate::validate_stellar_secret_seed(&secret_seed)?;
    let seed = signer.seed_from_strkey(&secret_seed)?;
    let stellar_account_id = signer.public_address(seed.as_slice())?;
    let protected = protector
        .encrypt_seed(&seal_seed(&payload.payala_account_id, seed.as_slice()))
        .await?;

    store_managed_account(
        &pool,
        &payload.payala_account_id,
        &stellar_account_id,
        &protected,
        "imported",
        &payload.first_name,
        &payload.middle_name,
        &payload.last_name,
        &payload.nickname,
        &payload.affiliation,
        &payload.gender,
    )
    .await?;

    info!(
        "import_managed_account: imported managed account stellar_id={}",
        stellar_account_id
    );
    Ok(Json(ManagedAccountResponse {
        success: true,
        message: "Managed account imported successfully".to_string(),
        stellar_account_id: Some(stellar_account_id),
    }))
}

/// Load and decrypt the protected seed for an account. Shared by the sign
/// endpoint and the conversion-reserve payout driver so the backend check
/// and fail-closed behavior can never diverge between them. The returned
/// [`SecretBytes`](crate::seed_protect::SecretBytes) zeroizes on drop.
pub(crate) async fn load_protected_seed(
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    signer: &Arc<dyn StellarSigner>,
    payala_account_id: &str,
) -> Result<crate::seed_protect::SecretBytes, AppError> {
    #[allow(clippy::type_complexity)]
    let row = sqlx::query_as::<
        _,
        (
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            String,
            Option<String>,
            String,
            i16,
        ),
    >(
        r#"
        SELECT backend, ciphertext, wrapped_data_key, nonce, key_id, key_version,
               stellar_account_id, format_version
        FROM managed_seed
        WHERE payala_account_id = $1
        "#,
    )
    .bind(payala_account_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("load_protected_seed: seed lookup failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let (
        backend_tag,
        ciphertext,
        wrapped_data_key,
        nonce,
        key_id,
        key_version,
        stellar_account_id,
        format_version,
    ) = row.ok_or_else(|| AppError::NotFound("No managed seed for this account".to_string()))?;

    let backend = ProtectorBackend::from_tag(&backend_tag)
        .ok_or_else(|| AppError::InternalError("Corrupt seed record".to_string()))?;
    // Refuse to use a seed protected by a different backend than is configured.
    if backend != protector.backend() {
        error!(
            "load_protected_seed: seed backend '{}' != configured backend '{}'",
            backend.as_str(),
            protector.backend().as_str()
        );
        return Err(AppError::InternalError(
            "seed protection backend mismatch".to_string(),
        ));
    }

    let protected = ProtectedSeed {
        backend,
        ciphertext,
        wrapped_data_key,
        nonce,
        key_id,
        key_version,
    };

    let raw = protector.decrypt_seed(&protected).await?;
    let seed = unseal_seed(payala_account_id, format_version, raw)?;

    // The identity check. Neither protector backend binds an encryption
    // context, so a ciphertext is byte-portable between rows: an adversary
    // with database write access (but no KMS/Vault access) could copy the
    // conversion reserve's ciphertext into an ordinary account's row and sign
    // payments FROM the reserve through /managed-account/sign, because the
    // quarantine there keys off the account id the transplanted row no longer
    // matches, and `prepare_payment` derives the source account from the
    // SEED rather than from the row.
    //
    // Asserting the decrypted seed derives the address the row claims closes
    // that for every row, including legacy ones written before the bound
    // header existed. Failing closed here costs one public-key derivation.
    let derived = signer.public_address(seed.as_slice())?;
    if derived != stellar_account_id {
        error!(
            "load_protected_seed: seed for account '{}' derives a different Stellar address \
             than its row claims — REFUSING to sign. This means the row was tampered with or \
             the seed was replaced out of band.",
            payala_account_id
        );
        return Err(AppError::InternalError(
            "seed does not match its account record".to_string(),
        ));
    }

    // Opportunistic upgrade: a legacy row that just proved it decrypts and
    // derives the right address is re-sealed with the bound header. Guarded on
    // `format_version = 0`, so it is idempotent and cannot race a replacement.
    // Best-effort by design — a read-only replica or a revoked KMS encrypt
    // grant must never break signing.
    if format_version < SEED_FORMAT_BOUND {
        upgrade_seed_binding(pool, protector, payala_account_id, seed.as_slice()).await;
    }

    Ok(seed)
}

/// Strip and verify the bound header on a decrypted seed blob.
///
/// `format_version = 0` rows predate the header and carry the bare strkey;
/// they are accepted (the derived-address assertion in the caller is what
/// protects them) and upgraded on the way past.
fn unseal_seed(
    payala_account_id: &str,
    format_version: i16,
    raw: crate::seed_protect::SecretBytes,
) -> Result<crate::seed_protect::SecretBytes, AppError> {
    if format_version < SEED_FORMAT_BOUND {
        return Ok(raw);
    }
    let header = crate::keys::seed_header(payala_account_id);
    if !raw.as_slice().starts_with(header.as_bytes()) {
        // Fixed string: on a transplanted blob the leading plaintext bytes are
        // another account's secret seed, and `AppError` messages are returned
        // to the caller verbatim.
        error!(
            "load_protected_seed: seed blob for account '{}' failed its binding check",
            payala_account_id
        );
        return Err(AppError::InternalError(
            "seed blob failed the binding check".to_string(),
        ));
    }
    Ok(crate::seed_protect::SecretBytes::new(
        raw.as_slice()[header.len()..].to_vec(),
    ))
}

/// Seal a seed under its account-bound header, ready for the protector.
pub(crate) fn seal_seed(payala_account_id: &str, seed: &[u8]) -> Zeroizing<Vec<u8>> {
    let header = crate::keys::seed_header(payala_account_id);
    let mut buf = Zeroizing::new(Vec::with_capacity(header.len() + seed.len()));
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(seed);
    buf
}

/// Re-seal a legacy (unbound) row in place. Never fatal.
async fn upgrade_seed_binding(
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    payala_account_id: &str,
    seed: &[u8],
) {
    let sealed = seal_seed(payala_account_id, seed);
    let protected = match protector.encrypt_seed(&sealed).await {
        Ok(p) => p,
        Err(_) => {
            info!(
                "load_protected_seed: could not re-seal legacy seed for '{}'; leaving it unbound",
                payala_account_id
            );
            return;
        }
    };
    let result = sqlx::query(
        r#"
        UPDATE managed_seed
        SET ciphertext = $2, wrapped_data_key = $3, nonce = $4, key_id = $5,
            key_version = $6, backend = $7, format_version = $8,
            updated_at = CURRENT_TIMESTAMP
        WHERE payala_account_id = $1 AND format_version = 0
        "#,
    )
    .bind(payala_account_id)
    .bind(&protected.ciphertext)
    .bind(&protected.wrapped_data_key)
    .bind(&protected.nonce)
    .bind(&protected.key_id)
    .bind(&protected.key_version)
    .bind(protected.backend.as_str())
    .bind(SEED_FORMAT_BOUND)
    .execute(pool)
    .await;
    match result {
        Ok(r) if r.rows_affected() > 0 => info!(
            "load_protected_seed: upgraded '{}' to a bound seed ciphertext",
            payala_account_id
        ),
        Ok(_) => {}
        Err(e) => info!(
            "load_protected_seed: bound-seed upgrade for '{}' did not apply: {}",
            payala_account_id, e
        ),
    }
}

/// Sign and submit a payment from a custodial account (`POST /managed-account/sign`).
///
/// Idempotent and write-ahead (037): the request is claimed as a
/// `custodial_payment_intent` row under the pause switch and the spend caps
/// BEFORE the seed is opened; the signed envelope's hash is persisted BEFORE
/// it is submitted; the ledger row and the intent's terminal status commit
/// together. A replayed `idempotency_key` returns the recorded outcome and
/// never signs again. The submit phase runs on the shutdown task tracker so
/// a client timeout cannot tear it down between submit and record — and
/// even then the sweep (`custody::sweep`) resolves the row by hash.
#[allow(clippy::too_many_arguments)]
pub async fn sign_and_submit(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(signer): Extension<Arc<dyn StellarSigner>>,
    Extension(tracker): Extension<Arc<TaskTracker>>,
    Extension(cancel): Extension<CancellationToken>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<Arc<String>>>,
    Extension(reserve_guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Json(payload): Json<SignSubmitRequest>,
) -> Result<(StatusCode, Json<SignSubmitResponse>), AppError> {
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
    require_not_reserve_account(&reserve_guard, &payload.payala_account_id)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "sign",
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // ── Validate + canonicalize (nothing touches the database yet) ──────
    crate::validate::validate_stellar_account_id(&payload.destination)?;
    let amount_minor = parse_decimal_to_minor(payload.amount.trim(), RESERVE_SCALE_STELLAR)
        .filter(|m| *m > 0)
        .ok_or_else(|| {
            AppError::BadRequest(
                "amount must be a positive decimal with at most 7 fraction digits".to_string(),
            )
        })?;
    if let Some(memo) = payload.memo.as_deref() {
        if memo.len() > MEMO_TEXT_MAX_BYTES {
            return Err(AppError::BadRequest(format!(
                "memo must be at most {} bytes",
                MEMO_TEXT_MAX_BYTES
            )));
        }
    }
    if payload.fee == Some(0) {
        return Err(AppError::BadRequest("fee must be positive".to_string()));
    }
    let (idempotency_key, key_source) = match payload.idempotency_key.as_deref() {
        Some(key) => {
            validate_idempotency_key(key)?;
            (key.to_string(), CUSTODIAL_KEY_SOURCE_CLIENT)
        }
        None => (Uuid::new_v4().to_string(), CUSTODIAL_KEY_SOURCE_SERVER),
    };
    let fingerprint = intent_fingerprint(
        &payload.destination,
        "XLM",
        None,
        amount_minor,
        payload.memo.as_deref(),
        payload.fee,
    );

    info!(
        "POST /managed-account/sign: account={} key_source={}",
        user.account_id, key_source
    );

    // ── Claim: replay lookup + policy + write-ahead row, one transaction ──
    let claim = UserPaymentClaim {
        payala_account_id: &payload.payala_account_id,
        idempotency_key: &idempotency_key,
        key_source,
        fingerprint: &fingerprint,
        destination: &payload.destination,
        amount_minor,
        memo: payload.memo.as_deref(),
        fee: payload.fee,
    };
    let (intent_id, source_account) = match claim_user_payment(&pool, &claim).await {
        Ok(ClaimOutcome::Claimed {
            intent_id,
            source_account,
        }) => (intent_id, source_account),
        Ok(ClaimOutcome::Replay(snapshot)) => {
            metrics.record_custodial_payment("replayed");
            let (status, body) = replay_response(&snapshot, &idempotency_key)?;
            return Ok((status, Json(body)));
        }
        Err(e) => {
            metrics.record_custodial_payment("refused");
            return Err(e);
        }
    };

    // ── Submit on the tracker: a dropped request future detaches the task
    // (a JoinHandle never aborts on drop) and shutdown drains it. ──────────
    let deps = SubmitDeps {
        pool: pool.clone(),
        protector: protector.clone(),
        signer: signer.clone(),
        cancel: cancel.clone(),
    };
    let params = SubmitParams {
        intent_id,
        payala_account_id: payload.payala_account_id.clone(),
        source_account,
        destination: payload.destination.clone(),
        amount_minor,
        memo: payload.memo.clone(),
        fee: payload.fee,
    };
    let outcome = match tracker.spawn(submit_intent(deps, params)).await {
        Ok(result) => result?,
        Err(e) => {
            error!(
                "sign_and_submit: submit task for intent {} failed to join: {} — the sweep \
                 resolves the row",
                intent_id, e
            );
            return Err(AppError::InternalError("submit task failed".to_string()));
        }
    };

    let settled = matches!(outcome, SubmitResult::Settled { .. });
    if matches!(outcome, SubmitResult::SettledUnrecorded { .. }) {
        // Landed on-chain, ledger row pending: the sweep records it by hash,
        // and this counter says how often that safety net had to catch it.
        metrics.unrecorded_settled_payments.add(1, &[]);
    }
    metrics.record_custodial_payment(match &outcome {
        SubmitResult::Settled { .. } => "settled",
        SubmitResult::SettledUnrecorded { .. } => "settled_unrecorded",
        SubmitResult::Ambiguous { .. } => "ambiguous",
        SubmitResult::Rejected { .. } => "rejected",
    });
    let (status, body) = outcome_response(intent_id, &idempotency_key, amount_minor, outcome)?;

    // Bookkeeping side effects fire only once the settle transaction has
    // committed: a notification for a payment the ledger does not carry
    // was the old behaviour and is gone.
    if settled {
        metrics.transactions_created.add(1, &[]);
        let sns_c = sns_client.as_ref().map(|e| &e.0);
        let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
        notifications::dispatch_event(
            &pool,
            sns_c,
            sns_a,
            NotificationEvent::TransferOutgoing {
                account_id: user.account_id.clone(),
                amount: minor_to_decimal_string(amount_minor, RESERVE_SCALE_STELLAR),
                to: payload.destination.clone(),
            },
            Some(&metrics),
        )
        .await;
    }

    info!(
        "sign_and_submit: intent={} status={:?} hash={:?} btxid={:?}",
        intent_id, body.status, body.stellar_hash, body.btxid
    );
    Ok((status, Json(body)))
}

/// `GET /managed-account/intents/{intent_id}` — one intent, owner-scoped.
/// A non-owner and a missing row are the same 404: ids are not enumerable.
pub async fn get_intent(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(reserve_guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Path(intent_id): Path<Uuid>,
) -> Result<Json<CustodialIntentView>, AppError> {
    require_not_reserve_account(&reserve_guard, &user.account_id)?;
    let sql = format!(
        "SELECT {} FROM custodial_payment_intent WHERE intent_id = $1",
        intent_view_columns()
    );
    let row: Option<CustodialIntentView> = sqlx::query_as(&sql)
        .bind(intent_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("get_intent: lookup failed: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
    match row {
        Some(v) if crate::auth::require_owner(&user, &v.payala_account_id).is_ok() => {
            Ok(Json(finish_view(v)))
        }
        _ => Err(AppError::NotFound("No such intent".to_string())),
    }
}

/// `GET /managed-account/intents?payala_account_id=&idempotency_key=&status=`
/// — the owner's intents, newest first. `idempotency_key` lets a client that
/// lost the response of a server-minted-key request find its intent.
pub async fn list_intents(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(reserve_guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Query(q): Query<CustodialIntentListQuery>,
) -> Result<Json<PaginatedResponse<CustodialIntentView>>, AppError> {
    crate::auth::require_owner(&user, &q.payala_account_id)?;
    require_not_reserve_account(&reserve_guard, &q.payala_account_id)?;
    if let Some(st) = &q.status {
        if !VALID_CUSTODIAL_INTENT_STATUSES.contains(&st.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid status '{}'. Must be one of: {}",
                st,
                VALID_CUSTODIAL_INTENT_STATUSES.join(", ")
            )));
        }
    }
    if let Some(key) = &q.idempotency_key {
        validate_idempotency_key(key)?;
    }
    let (per_page, offset) = PaginationParams {
        page: q.page,
        per_page: q.per_page,
    }
    .clamped();
    // Optional filters bind as NULL-able params so one statement serves
    // every combination (no string-built WHERE clauses).
    let filter = "WHERE payala_account_id = $1 \
         AND ($2::text IS NULL OR idempotency_key = $2) \
         AND ($3::text IS NULL OR status = $3)";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM custodial_payment_intent {}",
        filter
    ))
    .bind(&q.payala_account_id)
    .bind(&q.idempotency_key)
    .bind(&q.status)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("list_intents: count failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    let rows: Vec<CustodialIntentView> = sqlx::query_as(&format!(
        "SELECT {} FROM custodial_payment_intent {} \
         ORDER BY created_at DESC, intent_id DESC LIMIT $4 OFFSET $5",
        intent_view_columns(),
        filter
    ))
    .bind(&q.payala_account_id)
    .bind(&q.idempotency_key)
    .bind(&q.status)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("list_intents: list failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    Ok(Json(PaginatedResponse {
        data: rows.into_iter().map(finish_view).collect(),
        page: ((offset / per_page) + 1) as u64,
        per_page: per_page as u64,
        total: total.max(0) as u64,
    }))
}

#[cfg(test)]
mod tests {
    use crate::auth::AuthenticatedUser;

    // The ownership gate is the first check on every custodial endpoint; verify
    // it rejects a token whose account does not own the target before any
    // seed decryption or signing can occur.
    #[test]
    fn test_require_owner_rejects_mismatch() {
        let user = AuthenticatedUser {
            account_id: "alice".to_string(),
            role: "view-only".to_string(),
        };
        assert!(crate::auth::require_owner(&user, "bob").is_err());
        assert!(crate::auth::require_owner(&user, "alice").is_ok());
    }

    #[test]
    fn test_validate_names() {
        assert!(super::validate_names("John", "Doe").is_ok());
        assert!(super::validate_names("", "Doe").is_err());
        assert!(super::validate_names("John", "  ").is_err());
        let long = "a".repeat(100);
        assert!(super::validate_names(&long, "Doe").is_err());
    }

    // ── Seed binding ──────────────────────────────────────────────────
    //
    // Neither protector backend binds an encryption context, so a ciphertext
    // is byte-portable between rows. Without the bound header, an adversary
    // with database write access (but no KMS/Vault access) could copy the
    // conversion reserve's ciphertext into an ordinary account's row and sign
    // payments FROM the reserve: `prepare_payment` derives the source
    // account from the SEED, and the reserve quarantine keys off the account
    // id the transplanted row no longer matches.

    #[test]
    fn a_sealed_seed_round_trips_under_its_own_account() {
        let seed = b"SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        let sealed = super::seal_seed("acct-1", seed);
        let opened = super::unseal_seed(
            "acct-1",
            crate::constants::SEED_FORMAT_BOUND,
            crate::seed_protect::SecretBytes::new(sealed.to_vec()),
        )
        .expect("bound seed should open under its own account");
        assert_eq!(opened.as_slice(), seed);
    }

    #[test]
    fn a_sealed_seed_does_not_open_under_another_account() {
        let seed = b"SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        let sealed = super::seal_seed("reserve-acct", seed);
        let err = super::unseal_seed(
            "victim-acct",
            crate::constants::SEED_FORMAT_BOUND,
            crate::seed_protect::SecretBytes::new(sealed.to_vec()),
        );
        assert!(err.is_err(), "a transplanted seed blob must not open");
    }

    // `AppError` messages are serialized into the response body verbatim, and
    // a transplanted blob's leading plaintext bytes are another account's
    // secret seed.
    #[test]
    fn a_binding_failure_never_echoes_seed_material() {
        let seed = "SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        let sealed = super::seal_seed("reserve-acct", seed.as_bytes());
        let err = super::unseal_seed(
            "victim-acct",
            crate::constants::SEED_FORMAT_BOUND,
            crate::seed_protect::SecretBytes::new(sealed.to_vec()),
        )
        .unwrap_err();
        let rendered = format!("{:?}", err);
        assert!(!rendered.contains(seed));
        assert!(!rendered.contains("SABCDE"));
        // The account being READ is safe to name; the one sealed in is not.
        assert!(!rendered.contains("reserve-acct"));
    }

    // Rows written before the header existed carry the bare strkey. They must
    // keep opening — the derived-address assertion in `load_protected_seed` is
    // what protects them until the opportunistic upgrade rewrites them.
    #[test]
    fn legacy_unbound_seeds_still_open() {
        let seed = b"SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        let opened = super::unseal_seed(
            "acct-1",
            0,
            crate::seed_protect::SecretBytes::new(seed.to_vec()),
        )
        .expect("legacy seeds must keep opening");
        assert_eq!(opened.as_slice(), seed);
    }

    // A bound seed blob must not be mistakable for a bound credential blob.
    #[test]
    fn seed_and_credential_headers_are_distinct() {
        let sealed = super::seal_seed("acct-1", b"seed");
        assert!(sealed.starts_with(crate::constants::SEED_HEADER_MAGIC.as_bytes()));
        assert!(!sealed.starts_with(crate::constants::CREDENTIAL_HEADER_MAGIC.as_bytes()));
    }

    // The quarantine must read configuration, not the live reserve handle:
    // the handle is absent exactly during the bootstrap window in which the
    // reserve account has no seed and is therefore claimable.
    #[test]
    fn the_reserve_quarantine_is_armed_without_a_live_reserve() {
        let mut config = crate::config::test_config();
        config.reserve_account_id = Some("reserve-acct".to_string());
        let guard = crate::exchange::reserve::ReserveAccountGuard::from_config(&config);
        assert!(super::require_not_reserve_account(&guard, "reserve-acct").is_err());
        assert!(super::require_not_reserve_account(&guard, "someone-else").is_ok());
    }

    #[test]
    fn no_reserve_configured_quarantines_nothing() {
        let config = crate::config::test_config();
        let guard = crate::exchange::reserve::ReserveAccountGuard::from_config(&config);
        assert!(super::require_not_reserve_account(&guard, "anyone").is_ok());
        // An empty string is "unset", not "an account called empty".
        let mut empty = crate::config::test_config();
        empty.reserve_account_id = Some(String::new());
        let guard = crate::exchange::reserve::ReserveAccountGuard::from_config(&empty);
        assert!(super::require_not_reserve_account(&guard, "").is_ok());
    }
}

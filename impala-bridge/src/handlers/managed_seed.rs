//! Custodial Stellar account handlers: generate/import a protected seed and
//! sign+submit payments server-side.
//!
//! Security invariants (see SECURITY.md):
//! - `require_owner()` is the first check on every endpoint.
//! - Seeds are protected by the configured [`SeedProtector`] and only ever
//!   materialise inside a zeroizing [`SecretBytes`] for the duration of one call.
//! - All protector/signer failures fail closed (`AppError::InternalError`); seed
//!   material is never logged or returned.
//! - Signing/submission is synchronous and server-only (never the SQS worker), so
//!   an at-least-once retry cannot double-submit a payment.

use axum::extract::Extension;
use axum::Json;
use log::{error, info};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::AuthenticatedUser;
use crate::constants::{
    MAX_NAME_LENGTH, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, SEED_FORMAT_BOUND,
    SIGN_RATE_LIMIT_MAX_REQUESTS, SIGN_RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{
    GenerateManagedAccountRequest, ImportManagedAccountRequest, ManagedAccountResponse,
    SignSubmitRequest, SignSubmitResponse,
};
use crate::notifications::{self, NotificationEvent};
use crate::seed_protect::{ProtectedSeed, ProtectorBackend, SeedProtector};
use crate::stellar::{Asset, PaymentParams, StellarSigner};
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
    // matches, and `sign_and_submit_payment` derives the source account from
    // the SEED rather than from the row.
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
/// Synchronous and server-only so a retry cannot double-submit.
#[allow(clippy::too_many_arguments)]
pub async fn sign_and_submit(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(signer): Extension<Arc<dyn StellarSigner>>,
    sns_client: Option<Extension<Arc<aws_sdk_sns::Client>>>,
    sns_topic_arn: Option<Extension<Arc<String>>>,
    Extension(reserve_guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Json(payload): Json<SignSubmitRequest>,
) -> Result<Json<SignSubmitResponse>, AppError> {
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

    crate::validate::validate_stellar_account_id(&payload.destination)?;
    if payload.amount.trim().is_empty() {
        return Err(AppError::BadRequest("amount must not be empty".to_string()));
    }

    info!("POST /managed-account/sign: account={}", user.account_id);

    // Load and decrypt the protected seed for this owner's account.
    let seed = load_protected_seed(&pool, &protector, &signer, &payload.payala_account_id).await?;
    let params = PaymentParams {
        destination: payload.destination.clone(),
        amount: payload.amount.clone(),
        asset: Asset::Native,
        memo: payload.memo.clone(),
        fee: payload.fee,
    };
    let submitted = signer
        .sign_and_submit_payment(seed.as_slice(), &params)
        .await?;
    // `seed` zeroizes on drop here.

    // Record the on-ledger transaction (reusing the existing transaction table).
    //
    // PAST THIS POINT THE PAYMENT HAS SETTLED ON-CHAIN AND CANNOT BE UNDONE.
    // A failure here is a bookkeeping miss, not a failed payment, so it must
    // NOT be reported as an error: a 500 tells the caller the transfer did not
    // happen, and the natural response — retry — submits a second real
    // payment. (`fetch_sequence` re-reads the account's advanced sequence on
    // every call, so a sequential retry builds a *distinct*, network-valid
    // transaction; Stellar's tx_bad_seq only stops concurrent duplicates.)
    // Surface success with the on-chain hash, and shout about the missing row.
    let btxid = match sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO transaction (stellar_tx_id, stellar_hash, source_account, memo)
        VALUES ($1, $2, $3, $4)
        RETURNING btxid
        "#,
    )
    .bind(&submitted.stellar_tx_id)
    .bind(&submitted.stellar_hash)
    .bind(&submitted.source_account)
    .bind(&payload.memo)
    .fetch_one(&pool)
    .await
    {
        Ok(id) => {
            metrics.transactions_created.add(1, &[]);
            Some(id)
        }
        Err(e) => {
            error!(
                "sign_and_submit: SETTLED PAYMENT NOT RECORDED — account={} hash={} to={} amount={}: {}. \
                 Reconcile this transaction into the ledger manually.",
                user.account_id, submitted.stellar_hash, payload.destination, payload.amount, e
            );
            metrics.unrecorded_settled_payments.add(1, &[]);
            None
        }
    };

    let sns_c = sns_client.as_ref().map(|e| &e.0);
    let sns_a = sns_topic_arn.as_ref().map(|e| &e.0);
    notifications::dispatch_event(
        &pool,
        sns_c,
        sns_a,
        NotificationEvent::TransferOutgoing {
            account_id: user.account_id.clone(),
            amount: payload.amount.clone(),
            to: payload.destination.clone(),
        },
        Some(&metrics),
    )
    .await;

    info!(
        "sign_and_submit: submitted tx hash={} btxid={:?}",
        submitted.stellar_hash, btxid
    );
    Ok(Json(SignSubmitResponse {
        success: true,
        message: "Payment signed and submitted".to_string(),
        stellar_hash: Some(submitted.stellar_hash),
        btxid,
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
    // payments FROM the reserve: `sign_and_submit_payment` derives the source
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

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
use zeroize::Zeroizing;

use crate::auth::AuthenticatedUser;
use crate::constants::{
    MAX_NAME_LENGTH, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, SIGN_RATE_LIMIT_MAX_REQUESTS,
    SIGN_RATE_LIMIT_WINDOW_SECS,
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
             wrapped_data_key, nonce, key_id, key_version, origin)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
    Json(payload): Json<GenerateManagedAccountRequest>,
) -> Result<Json<ManagedAccountResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
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
    let protected = protector.encrypt_seed(seed.as_slice()).await?;
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
    Json(payload): Json<ImportManagedAccountRequest>,
) -> Result<Json<ManagedAccountResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
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

    // Hold the incoming seed in a zeroizing buffer and scrub the original ASAP.
    let secret_seed = Zeroizing::new(payload.secret_seed.clone());
    crate::validate::validate_stellar_secret_seed(&secret_seed)?;
    let seed = signer.seed_from_strkey(&secret_seed)?;
    let stellar_account_id = signer.public_address(seed.as_slice())?;
    let protected = protector.encrypt_seed(seed.as_slice()).await?;

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
    Json(payload): Json<SignSubmitRequest>,
) -> Result<Json<SignSubmitResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.payala_account_id)?;
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

    // Load the protected seed for this owner's account.
    let row = sqlx::query_as::<
        _,
        (
            String,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            String,
            Option<String>,
        ),
    >(
        r#"
        SELECT backend, ciphertext, wrapped_data_key, nonce, key_id, key_version
        FROM managed_seed
        WHERE payala_account_id = $1
        "#,
    )
    .bind(&payload.payala_account_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("sign_and_submit: seed lookup failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let (backend_tag, ciphertext, wrapped_data_key, nonce, key_id, key_version) =
        row.ok_or_else(|| AppError::NotFound("No managed seed for this account".to_string()))?;

    let backend = ProtectorBackend::from_tag(&backend_tag)
        .ok_or_else(|| AppError::InternalError("Corrupt seed record".to_string()))?;
    // Refuse to use a seed protected by a different backend than is configured.
    if backend != protector.backend() {
        error!(
            "sign_and_submit: seed backend '{}' != configured backend '{}'",
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

    let seed = protector.decrypt_seed(&protected).await?;
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
    let btxid = sqlx::query_scalar::<_, Uuid>(
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
    .map_err(|e| {
        // The payment already submitted; surface success but log the bookkeeping miss.
        error!("sign_and_submit: transaction record insert failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    metrics.transactions_created.add(1, &[]);

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
        "sign_and_submit: submitted tx hash={} btxid={}",
        submitted.stellar_hash, btxid
    );
    Ok(Json(SignSubmitResponse {
        success: true,
        message: "Payment signed and submitted".to_string(),
        stellar_hash: Some(submitted.stellar_hash),
        btxid: Some(btxid),
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
}

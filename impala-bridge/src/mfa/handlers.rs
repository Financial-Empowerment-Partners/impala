//! MFA HTTP surface: step-up, the step-up challenge, session status, device
//! keys, and the per-account policy (`docs/mfa-card-pin-biometrics.md` §5).
//!
//! The step-up, challenge and status routes take [`AuthContext`] (ungated), so
//! a session that is required-but-not-yet-multi-factor can reach them to step
//! up; every other route in the bridge is gated by the extractors in
//! `auth.rs`. The factor-change routes (device keys, policy) apply the §6.3
//! re-auth gate themselves, so a required account must be freshly multi-factor
//! to change its own factors.

use std::sync::Arc;

use axum::extract::{Extension, Json, Path};
use axum::http::StatusCode;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use crate::auth::{AdminUser, AuthContext, AuthSource, Privileged, ReadAccounts};
use crate::client_source::ClientSource;
use crate::constants::{
    AMR_CARD, AMR_CARD_PIN, AMR_MFA, AMR_TOTP, DEVICE_KEY_PURPOSE_ENROLL,
    DEVICE_KEY_PURPOSE_STEP_UP, DEVICE_SIGNATURE_MAX_BYTES, DEVICE_USER_VERIFICATION_BIOMETRIC,
    DEVICE_USER_VERIFICATION_NONE, MFA_CHALLENGE_BYTES, MFA_CHALLENGE_MAX_OUTSTANDING,
    MFA_CHALLENGE_TTL_SECS, MFA_CODE_REPLAY_WINDOW_SECS, MFA_REAUTH_MAX_AGE_SECS, MFA_STEP_UP_CARD,
    MFA_STEP_UP_DEVICE, MFA_STEP_UP_TOTP, PREAUTH_SOURCE_MAX_REQUESTS, PREAUTH_SOURCE_WINDOW_SECS,
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, REFRESH_TOKEN_TTL_SECS,
};
use crate::error::AppError;
use crate::handlers::card_auth::{
    decode_challenge_entry, encode_challenge_entry, live_challenges, verify_card_signature,
};
use crate::jwt::{JwtKeys, SessionAssurance};
use crate::mfa::{
    account_requires_mfa, collect_device_factor, is_session_multi_factor, verify_pin_proof,
    MfaConfig,
};
use crate::models::TokenResponse;

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn forbidden(code: &'static str, msg: &'static str) -> AppError {
    AppError::coded(StatusCode::FORBIDDEN, code, msg)
}

/// Decode a hex DER signature argument, bounding its size (a bad encoding is a
/// generic 401 — a presented factor is never silently dropped).
fn decode_sig(hex_str: &str) -> Result<Vec<u8>, AppError> {
    let bytes = hex::decode(hex_str).map_err(|_| AppError::Unauthorized)?;
    if bytes.is_empty() || bytes.len() > DEVICE_SIGNATURE_MAX_BYTES {
        return Err(AppError::Unauthorized);
    }
    Ok(bytes)
}

// ── GET /mfa/status ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MfaStatusResponse {
    /// Finalized `amr` for this session (includes `mfa` when multi-factor).
    pub amr: Vec<String>,
    pub auth_time: usize,
    /// Whether the session is multi-factor *and* fresh.
    pub mfa: bool,
    /// Whether this account must be multi-factor.
    pub required: bool,
    /// Whether the mandate came from the account's role (vs its own flag).
    pub required_by_role: bool,
    /// `satisfied == !required || mfa` — the gate the rest of the API enforces.
    pub satisfied: bool,
    pub max_age_secs: i64,
}

/// `GET /mfa/status` — the current session's assurance and whether it
/// satisfies the account's MFA requirement. Ungated.
pub async fn mfa_status(
    Extension(mfa_cfg): Extension<Arc<MfaConfig>>,
    context: AuthContext,
) -> Json<MfaStatusResponse> {
    let now = unix_now();
    let mfa = is_session_multi_factor(&context.amr, context.auth_time, now, mfa_cfg.max_age_secs);
    let required_by_role = mfa_cfg.required_roles.contains(&context.role);
    let required =
        account_requires_mfa(context.mfa_required, &context.role, &mfa_cfg.required_roles);
    Json(MfaStatusResponse {
        amr: context.amr,
        auth_time: context.auth_time,
        mfa,
        required,
        required_by_role,
        satisfied: !required || mfa,
        max_age_secs: mfa_cfg.max_age_secs,
    })
}

// ── POST /mfa/challenge ────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MfaChallengeResponse {
    pub challenge: String,
    pub expires_in: u64,
}

/// `POST /mfa/challenge` — a single-use, short-lived challenge for a step-up
/// or a device-key enrollment, bound to the caller's own account.
pub async fn mfa_challenge(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    context: AuthContext,
) -> Result<Json<MfaChallengeResponse>, AppError> {
    let mut challenge = [0u8; MFA_CHALLENGE_BYTES];
    aws_lc_rs::rand::fill(&mut challenge)
        .map_err(|_| AppError::InternalError("Failed to generate challenge".to_string()))?;
    let challenge_hex = hex::encode(challenge);
    let expires_at = (unix_now().max(0) as u64) + MFA_CHALLENGE_TTL_SECS as u64;
    crate::redis_helpers::push_mfa_challenge(
        &redis_pool,
        &context.account_id,
        &encode_challenge_entry(expires_at, &challenge_hex),
        MFA_CHALLENGE_MAX_OUTSTANDING,
        MFA_CHALLENGE_TTL_SECS,
    )
    .await?;
    Ok(Json(MfaChallengeResponse {
        challenge: challenge_hex,
        expires_in: MFA_CHALLENGE_TTL_SECS as u64,
    }))
}

/// Consume one of the caller's outstanding step-up challenges by its hex,
/// returning its bytes. Anything not live is a generic 401.
async fn take_challenge(
    redis_pool: &Arc<deadpool_redis::Pool>,
    account_id: &str,
    challenge_hex: &str,
) -> Result<Vec<u8>, AppError> {
    if challenge_hex.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let entries = crate::redis_helpers::list_mfa_challenges(redis_pool, account_id).await?;
    let now = unix_now().max(0) as u64;
    for (entry, bytes) in live_challenges(&entries, now) {
        if decode_challenge_entry(entry)
            .map(|(_, h)| h == challenge_hex)
            .unwrap_or(false)
            && crate::redis_helpers::consume_mfa_challenge(redis_pool, account_id, entry).await?
        {
            return Ok(bytes);
        }
    }
    Err(AppError::Unauthorized)
}

// ── POST /mfa/step-up ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StepUpRequest {
    pub mfa_type: String,
    #[serde(default)]
    pub code: Option<String>, // totp
    #[serde(default)]
    pub challenge: Option<String>, // card / device
    #[serde(default)]
    pub card_id: Option<String>, // card
    #[serde(default)]
    pub signature: Option<String>, // card
    #[serde(default)]
    pub pin_proof: Option<String>, // card
    #[serde(default)]
    pub key_id: Option<String>, // device
    #[serde(default)]
    pub device_signature: Option<String>, // device
}

#[derive(Serialize)]
pub struct StepUpResponse {
    pub success: bool,
    pub amr: Vec<String>,
    /// The upgraded token pair (bearer sessions only; a cookie session is
    /// upgraded in place and these are absent).
    #[serde(flatten)]
    pub tokens: TokenResponse,
}

/// `POST /mfa/step-up` — add a factor to the current session. Ungated.
#[allow(clippy::too_many_arguments)]
pub async fn mfa_step_up(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(jwt_keys): Extension<Arc<JwtKeys>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(mfa_cfg): Extension<Arc<MfaConfig>>,
    ClientSource(source): ClientSource,
    context: AuthContext,
    Json(payload): Json<StepUpRequest>,
) -> Result<Json<StepUpResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "preauth_src",
        &source,
        PREAUTH_SOURCE_MAX_REQUESTS,
        PREAUTH_SOURCE_WINDOW_SECS,
    )
    .await?;

    let account_id = context.account_id.clone();
    let mut new_methods: Vec<String> = Vec::new();

    match payload.mfa_type.as_str() {
        MFA_STEP_UP_TOTP => {
            let code = payload.code.as_deref().unwrap_or("");
            if code.is_empty()
                || !verify_totp(&pool, &redis_pool, &account_id, code, &source).await?
            {
                return Err(AppError::Unauthorized);
            }
            new_methods.push(AMR_TOTP.to_string());
        }
        MFA_STEP_UP_CARD => {
            let challenge = take_challenge(
                &redis_pool,
                &account_id,
                payload.challenge.as_deref().unwrap_or(""),
            )
            .await?;
            step_up_card(
                &pool,
                &mfa_cfg,
                &account_id,
                &challenge,
                &payload,
                &mut new_methods,
            )
            .await?;
        }
        MFA_STEP_UP_DEVICE => {
            let challenge = take_challenge(
                &redis_pool,
                &account_id,
                payload.challenge.as_deref().unwrap_or(""),
            )
            .await?;
            let key_id = payload.key_id.as_deref().ok_or(AppError::Unauthorized)?;
            let sig = decode_sig(payload.device_signature.as_deref().unwrap_or(""))?;
            collect_device_factor(
                &pool,
                &mfa_cfg,
                &account_id,
                key_id,
                DEVICE_KEY_PURPOSE_STEP_UP,
                &challenge,
                &sig,
                &mut new_methods,
            )
            .await?;
        }
        _ => {
            return Err(AppError::BadRequest(
                "mfa_type must be 'totp', 'card' or 'device'".to_string(),
            ))
        }
    }

    // Merge with what the session already had (drop the derived marker, it is
    // recomputed), re-resolve role and `mfr`, refresh `auth_time`.
    let mut merged = context.amr.clone();
    merged.retain(|m| m != AMR_MFA);
    merged.extend(new_methods);
    let (role, assurance) =
        crate::auth::issue_session(&pool, &admin_ids, &account_id, merged).await;

    info!(
        "mfa: step-up ({}) for account_id={}",
        payload.mfa_type, account_id
    );
    reissue(&redis_pool, &jwt_keys, &context, &role, &assurance).await
}

/// Verify a card step-up: the caller's own card signed the challenge
/// (`SIGN_AUTH` → `sc`), optionally with a PIN proof (`pin`).
async fn step_up_card(
    pool: &PgPool,
    cfg: &MfaConfig,
    account_id: &str,
    challenge: &[u8],
    payload: &StepUpRequest,
    methods: &mut Vec<String>,
) -> Result<(), AppError> {
    let card_id = payload.card_id.as_deref().ok_or(AppError::Unauthorized)?;
    crate::validate::validate_card_id(card_id)?;
    let sig = decode_sig(payload.signature.as_deref().unwrap_or(""))?;
    let account_uuid = Uuid::parse_str(account_id).map_err(|_| AppError::Unauthorized)?;

    let row = sqlx::query_as::<_, (String,)>(
        "SELECT ec_pubkey FROM card WHERE card_id = $1 AND account_id = $2 AND is_delete = FALSE",
    )
    .bind(card_id)
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        warn!("mfa: step-up card lookup error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    let Some((ec_pubkey_hex,)) = row else {
        return Err(AppError::Unauthorized);
    };
    let ec_pubkey = hex::decode(ec_pubkey_hex.trim()).map_err(|_| AppError::Unauthorized)?;

    if !verify_card_signature(&ec_pubkey, &account_uuid, challenge, &sig) {
        return Err(AppError::Unauthorized);
    }
    methods.push(AMR_CARD.to_string());

    if let Some(proof_hex) = payload.pin_proof.as_deref().filter(|s| !s.is_empty()) {
        let der = decode_sig(proof_hex)?;
        if !verify_pin_proof(&ec_pubkey, &account_uuid, challenge, &der) {
            return Err(AppError::Unauthorized);
        }
        if cfg.card_pin_trust_certified && !crate::mfa::card_pin_trusted(pool, card_id).await? {
            return Err(AppError::Unauthorized);
        }
        methods.push(AMR_CARD_PIN.to_string());
    }
    Ok(())
}

/// TOTP verification shared shape with the pre-auth `/mfa/verify`: look up the
/// enrolled secret, check the current code, and claim it single-use. Lockout
/// is keyed on `(account, "totp", source)`.
async fn verify_totp(
    pool: &PgPool,
    redis_pool: &Arc<deadpool_redis::Pool>,
    account_id: &str,
    code: &str,
    source: &str,
) -> Result<bool, AppError> {
    crate::redis_helpers::check_mfa_lockout(
        redis_pool,
        account_id,
        MFA_STEP_UP_TOTP,
        source,
        crate::constants::LOCKOUT_THRESHOLD,
    )
    .await?;
    crate::redis_helpers::check_rate_limit(
        redis_pool,
        "mfa",
        &format!("{account_id}:totp"),
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let secret: Option<Option<String>> = sqlx::query_scalar(
        "SELECT secret FROM impala_mfa WHERE account_id = $1 AND mfa_type = 'totp' AND enabled = TRUE",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        warn!("mfa: step-up TOTP lookup error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    let Some(Some(secret_str)) = secret else {
        return Ok(false);
    };
    let secret_bytes = Secret::Encoded(secret_str)
        .to_bytes()
        .map_err(|_| AppError::InternalError("Invalid TOTP configuration".to_string()))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Impala".to_string()),
        account_id.to_string(),
    )
    .map_err(|_| AppError::InternalError("TOTP verification error".to_string()))?;
    let ok = totp
        .check_current(code)
        .map_err(|_| AppError::InternalError("TOTP verification error".to_string()))?;
    if !ok {
        crate::redis_helpers::increment_mfa_attempts(
            redis_pool,
            account_id,
            MFA_STEP_UP_TOTP,
            source,
            crate::constants::LOCKOUT_DURATION_SECS,
        )
        .await;
        return Ok(false);
    }
    // Single-use within the acceptance window (same claim the pre-auth path uses).
    let first_use = crate::redis_helpers::claim_mfa_code(
        redis_pool,
        account_id,
        MFA_STEP_UP_TOTP,
        code,
        MFA_CODE_REPLAY_WINDOW_SECS,
    )
    .await?;
    if !first_use {
        return Ok(false);
    }
    crate::redis_helpers::clear_mfa_attempts(redis_pool, account_id, MFA_STEP_UP_TOTP, source)
        .await;
    Ok(true)
}

/// Re-issue a session at its new assurance: for a bearer session, a fresh
/// token family (the old one revoked so the pre-step-up token cannot linger);
/// for a cookie session, the record's factors upgraded in place.
async fn reissue(
    redis_pool: &Arc<deadpool_redis::Pool>,
    jwt_keys: &JwtKeys,
    context: &AuthContext,
    role: &str,
    assurance: &SessionAssurance,
) -> Result<Json<StepUpResponse>, AppError> {
    match &context.source {
        AuthSource::Bearer { fid, .. } => {
            crate::redis_helpers::revoke_token_family(redis_pool, fid, REFRESH_TOKEN_TTL_SECS)
                .await?;
            let (refresh, temporal) =
                crate::jwt::encode_token_pair(jwt_keys, &context.account_id, role, assurance)?;
            Ok(Json(StepUpResponse {
                success: true,
                amr: assurance.amr.clone(),
                tokens: TokenResponse {
                    success: true,
                    message: "Step-up complete".to_string(),
                    refresh_token: Some(refresh),
                    temporal_token: Some(temporal),
                },
            }))
        }
        AuthSource::Session { sid_hash } => {
            crate::redis_helpers::upgrade_session_factors(
                redis_pool,
                sid_hash,
                &assurance.amr,
                assurance.auth_time as u64,
            )
            .await?;
            Ok(Json(StepUpResponse {
                success: true,
                amr: assurance.amr.clone(),
                tokens: TokenResponse {
                    success: true,
                    message: "Step-up complete".to_string(),
                    refresh_token: None,
                    temporal_token: None,
                },
            }))
        }
    }
}

// ── Device keys ────────────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceKeyView {
    pub key_id: Uuid,
    pub label: Option<String>,
    pub platform: Option<String>,
    pub user_verification: String,
    /// Unix seconds (serialized as a plain integer — the chrono/serde bridge
    /// is not enabled in this crate).
    pub created_at_unix: i64,
}

/// The column list every device-key read projects (the epoch cast keeps the
/// timestamp a plain integer on the wire).
const DEVICE_KEY_COLUMNS: &str = "key_id, label, platform, user_verification, \
     EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix";

/// `GET /mfa/device-keys` — the caller's active device keys (public data).
pub async fn list_device_keys(
    Extension(pool): Extension<PgPool>,
    context: AuthContext,
) -> Result<Json<Vec<DeviceKeyView>>, AppError> {
    let rows = sqlx::query_as::<_, DeviceKeyView>(&device_keys_query())
        .bind(&context.account_id)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            warn!("mfa: list device keys error: {e}");
            AppError::InternalError("Database error".to_string())
        })?;
    Ok(Json(rows))
}

/// The active-device-keys-by-account query (shared by the owner list and the
/// admin summary).
fn device_keys_query() -> String {
    format!(
        "SELECT {DEVICE_KEY_COLUMNS} FROM mfa_device_key \
         WHERE account_id = $1 AND is_delete = FALSE ORDER BY created_at"
    )
}

#[derive(Deserialize)]
pub struct EnrollDeviceKeyRequest {
    pub public_key: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub user_verification: Option<String>,
    pub challenge: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct EnrollDeviceKeyResponse {
    pub success: bool,
    pub key_id: Uuid,
}

/// `POST /mfa/device-keys` — enroll a phone device key. The client proves
/// possession by signing a fresh `/mfa/challenge` with the new key (purpose
/// `enroll`). For a required account, this is a factor change and needs a
/// fresh multi-factor session (§6.3).
pub async fn enroll_device_key(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(mfa_cfg): Extension<Arc<MfaConfig>>,
    context: AuthContext,
    Json(payload): Json<EnrollDeviceKeyRequest>,
) -> Result<Json<EnrollDeviceKeyResponse>, AppError> {
    require_fresh_mfa(&mfa_cfg, &context)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "card",
        &context.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let pubkey = hex::decode(payload.public_key.trim())
        .map_err(|_| AppError::BadRequest("public_key must be hex".to_string()))?;
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return Err(AppError::BadRequest(
            "public_key must be a 65-byte uncompressed P-256 point".to_string(),
        ));
    }
    let uv = match payload.user_verification.as_deref() {
        None | Some(DEVICE_USER_VERIFICATION_NONE) => DEVICE_USER_VERIFICATION_NONE,
        Some(DEVICE_USER_VERIFICATION_BIOMETRIC) => DEVICE_USER_VERIFICATION_BIOMETRIC,
        Some(_) => {
            return Err(AppError::BadRequest(
                "user_verification must be 'biometric' or 'none'".to_string(),
            ))
        }
    };

    // Proof of possession: the new key signs a fresh challenge (purpose enroll).
    let challenge = take_challenge(&redis_pool, &context.account_id, &payload.challenge).await?;
    let sig = decode_sig(&payload.signature)?;
    if !crate::mfa::verify_device_assertion(
        &pubkey,
        DEVICE_KEY_PURPOSE_ENROLL,
        &context.account_id,
        &challenge,
        &sig,
    ) {
        warn!("mfa: device-key enroll assertion did not verify");
        return Err(AppError::Unauthorized);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        warn!("mfa: enroll begin tx error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    let key_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mfa_device_key (account_id, public_key_hex, label, platform, user_verification) \
         VALUES ($1, $2, $3, $4, $5) RETURNING key_id",
    )
    .bind(&context.account_id)
    .bind(payload.public_key.trim())
    .bind(payload.label.as_deref())
    .bind(payload.platform.as_deref())
    .bind(uv)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db) = &e {
            if db.code().as_deref() == Some("23505") {
                return AppError::coded(
                    StatusCode::CONFLICT,
                    "device_key_in_use",
                    "This device key is already registered",
                );
            }
        }
        warn!("mfa: enroll insert error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    crate::events::emit_event(
        &mut tx,
        &crate::events::AccountEvent::MfaDeviceKeyRegistered {
            account_id: context.account_id.clone(),
            key_id: key_id.to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(|e| {
        warn!("mfa: enroll commit error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    info!(
        "mfa: device key {} enrolled for account_id={}",
        key_id, context.account_id
    );
    Ok(Json(EnrollDeviceKeyResponse {
        success: true,
        key_id,
    }))
}

/// `DELETE /mfa/device-keys/{key_id}` — revoke the caller's own device key.
pub async fn delete_device_key(
    Extension(pool): Extension<PgPool>,
    Extension(mfa_cfg): Extension<Arc<MfaConfig>>,
    context: AuthContext,
    Path(key_id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    require_fresh_mfa(&mfa_cfg, &context)?;
    revoke_device_key(&pool, &context.account_id, key_id).await
}

/// The soft-delete + event shared by the owner and admin-recovery paths.
async fn revoke_device_key(
    pool: &PgPool,
    account_id: &str,
    key_id: Uuid,
) -> Result<Json<Value>, AppError> {
    let mut tx = pool.begin().await.map_err(|e| {
        warn!("mfa: revoke begin tx error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    let affected = sqlx::query(
        "UPDATE mfa_device_key SET is_delete = TRUE, updated_at = CURRENT_TIMESTAMP \
         WHERE account_id = $1 AND key_id = $2 AND is_delete = FALSE",
    )
    .bind(account_id)
    .bind(key_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        warn!("mfa: revoke error: {e}");
        AppError::InternalError("Database error".to_string())
    })?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound("Device key not found".to_string()));
    }
    crate::events::emit_event(
        &mut tx,
        &crate::events::AccountEvent::MfaDeviceKeyRevoked {
            account_id: account_id.to_string(),
            key_id: key_id.to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(|e| {
        warn!("mfa: revoke commit error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    Ok(Json(json!({ "success": true })))
}

// ── Policy ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct MfaPolicyRequest {
    pub required: bool,
}

/// `PUT /mfa/policy` — the owner turns their own MFA mandate on or off.
/// Turning it on requires a multi-factor session now (you may not lock
/// yourself out), and signs the account out everywhere so the next sign-in
/// must satisfy it. Turning it off is itself a factor change (§6.3).
pub async fn set_mfa_policy(
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(mfa_cfg): Extension<Arc<MfaConfig>>,
    context: AuthContext,
    Json(payload): Json<MfaPolicyRequest>,
) -> Result<Json<Value>, AppError> {
    let now = unix_now();
    let session_is_mfa =
        is_session_multi_factor(&context.amr, context.auth_time, now, mfa_cfg.max_age_secs);
    if payload.required && !session_is_mfa {
        return Err(forbidden(
            "mfa_reauth_required",
            "Turning on the MFA requirement needs a multi-factor session",
        ));
    }
    if !payload.required {
        require_fresh_mfa(&mfa_cfg, &context)?;
    }
    write_mfa_required(&pool, &context.account_id, payload.required).await?;
    if payload.required {
        // Force every existing session to re-satisfy the mandate.
        let epoch = now.max(0) as u64;
        crate::redis_helpers::bump_auth_epoch(
            &redis_pool,
            &context.account_id,
            epoch,
            REFRESH_TOKEN_TTL_SECS,
        )
        .await?;
    }
    Ok(Json(
        json!({ "success": true, "required": payload.required }),
    ))
}

/// The §6.3 gate for a factor change: a required account must be freshly
/// multi-factor. A non-required account may change factors freely.
fn require_fresh_mfa(cfg: &MfaConfig, context: &AuthContext) -> Result<(), AppError> {
    let required = account_requires_mfa(context.mfa_required, &context.role, &cfg.required_roles);
    if !required {
        return Ok(());
    }
    let now = unix_now();
    if is_session_multi_factor(
        &context.amr,
        context.auth_time,
        now,
        MFA_REAUTH_MAX_AGE_SECS,
    ) {
        Ok(())
    } else {
        Err(forbidden(
            "mfa_reauth_required",
            "Changing factors needs a recent multi-factor sign-in",
        ))
    }
}

async fn write_mfa_required(
    pool: &PgPool,
    account_id: &str,
    required: bool,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await.map_err(|e| {
        warn!("mfa: policy begin tx error: {e}");
        AppError::InternalError("Database error".to_string())
    })?;
    let affected =
        sqlx::query("UPDATE impala_account SET mfa_required = $2 WHERE payala_account_id = $1")
            .bind(account_id)
            .bind(required)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                warn!("mfa: policy update error: {e}");
                AppError::InternalError("Database error".to_string())
            })?
            .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound("Account not found".to_string()));
    }
    crate::events::emit_event(
        &mut tx,
        &crate::events::AccountEvent::MfaPolicyChanged {
            account_id: account_id.to_string(),
            required,
        },
    )
    .await?;
    tx.commit().await.map_err(|e| {
        warn!("mfa: policy commit error: {e}");
        AppError::InternalError("Database error".to_string())
    })
}

// ── Admin ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminMfaView {
    pub account_id: String,
    pub mfa_required: bool,
    pub totp_enrolled: bool,
    pub device_keys: Vec<DeviceKeyView>,
    pub cards: i64,
}

/// `GET /admin/accounts/{id}/mfa` — an account's MFA factor summary (no
/// secrets). Reserved to the accounts-read capability.
pub async fn admin_get_account_mfa(
    _admin: Privileged<ReadAccounts>,
    Extension(pool): Extension<PgPool>,
    Path(account_id): Path<String>,
) -> Result<Json<AdminMfaView>, AppError> {
    let mfa_required: Option<Option<bool>> =
        sqlx::query_scalar("SELECT mfa_required FROM impala_account WHERE payala_account_id = $1")
            .bind(&account_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                warn!("mfa: admin read error: {e}");
                AppError::InternalError("Database error".to_string())
            })?;
    let mfa_required = match mfa_required {
        Some(v) => v.unwrap_or(false),
        None => return Err(AppError::NotFound("Account not found".to_string())),
    };
    let totp_enrolled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM impala_mfa WHERE account_id = $1 AND mfa_type = 'totp' AND enabled = TRUE)",
    )
    .bind(&account_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(false);
    let device_keys = sqlx::query_as::<_, DeviceKeyView>(&device_keys_query())
        .bind(&account_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
    let cards: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM card WHERE account_id = $1 AND is_delete = FALSE")
            .bind(&account_id)
            .fetch_one(&pool)
            .await
            .unwrap_or(0);
    Ok(Json(AdminMfaView {
        account_id,
        mfa_required,
        totp_enrolled,
        device_keys,
        cards,
    }))
}

/// `PUT /admin/accounts/{id}/mfa-policy` — an admin mandates (or lifts) MFA for
/// an account. Mandating signs that account out everywhere.
pub async fn admin_set_account_mfa_policy(
    _admin: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Path(account_id): Path<String>,
    Json(payload): Json<MfaPolicyRequest>,
) -> Result<Json<Value>, AppError> {
    write_mfa_required(&pool, &account_id, payload.required).await?;
    if payload.required {
        let epoch = unix_now().max(0) as u64;
        crate::redis_helpers::bump_auth_epoch(
            &redis_pool,
            &account_id,
            epoch,
            REFRESH_TOKEN_TTL_SECS,
        )
        .await?;
    }
    info!(
        "mfa: admin set mfa_required={} for account_id={}",
        payload.required, account_id
    );
    Ok(Json(
        json!({ "success": true, "required": payload.required }),
    ))
}

/// `DELETE /admin/accounts/{id}/mfa/device-keys/{key_id}` — admin recovery for
/// a lost phone.
pub async fn admin_delete_device_key(
    _admin: AdminUser,
    Extension(pool): Extension<PgPool>,
    Path((account_id, key_id)): Path<(String, Uuid)>,
) -> Result<Json<Value>, AppError> {
    revoke_device_key(&pool, &account_id, key_id).await
}

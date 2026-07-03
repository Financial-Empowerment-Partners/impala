//! Card challenge-response authentication (`POST /auth/card/challenge` +
//! `POST /auth/card`).
//!
//! Implements the pinned cross-stream card-auth contract (see
//! `CARD_AUTH_DOMAIN_PREFIX` in `constants.rs` and `AUTH_DOMAIN_TAG` in
//! `ImpalaApplet.java`): the bridge issues a random 32-byte challenge, the
//! card signs `"IMPALA-AUTH:" || accountId(16, RFC-4122 big-endian) ||
//! challenge` with ECDSA-SHA256 (secp256r1, ASN.1 DER), and the bridge
//! verifies against the registered card's 65-byte uncompressed SEC1 public
//! key. Challenges are single-use (Redis GETDEL), expire after 60 seconds,
//! and are issued unconditionally so the endpoint never reveals whether a
//! card is registered. There is NO auto-provisioning: a registered card
//! implies an existing account (migration 017 FK).

use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    CARD_AUTH_DOMAIN_PREFIX, CARD_CHALLENGE_BYTES, CARD_CHALLENGE_TTL_SECS,
    CARD_SIGNATURE_MAX_BYTES, LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD, RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{
    CardChallengeRequest, CardChallengeResponse, CardTokenExchangeRequest, TokenResponse,
};
use crate::telemetry::{token_exchange_outcome, AppMetrics};

/// Applet-enforced challenge length bounds (bytes); the verifier mirrors them.
const MIN_CHALLENGE_LEN: usize = 8;
const MAX_CHALLENGE_LEN: usize = 64;

/// Uncompressed SEC1 P-256 public key: 0x04 || X(32) || Y(32).
const UNCOMPRESSED_POINT_LEN: usize = 65;
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// Build the exact byte string the card signs:
/// `CARD_AUTH_DOMAIN_PREFIX || accountId(16, RFC-4122 big-endian) || challenge`.
pub(crate) fn build_card_auth_message(account_id: &uuid::Uuid, challenge: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CARD_AUTH_DOMAIN_PREFIX.len() + 16 + challenge.len());
    msg.extend_from_slice(CARD_AUTH_DOMAIN_PREFIX);
    msg.extend_from_slice(account_id.as_bytes());
    msg.extend_from_slice(challenge);
    msg
}

/// Verify a card's ECDSA-SHA256 signature over the pinned card-auth message.
///
/// Pure function (unit-testable without Redis/Postgres). Rejects anything
/// that is not a 65-byte uncompressed SEC1 point (compressed keys included —
/// the card table stores 130-hex uncompressed keys per the contract), an
/// out-of-bounds challenge, or an oversized DER signature.
pub(crate) fn verify_card_signature(
    ec_pubkey: &[u8],
    account_id: &uuid::Uuid,
    challenge: &[u8],
    signature_der: &[u8],
) -> bool {
    if ec_pubkey.len() != UNCOMPRESSED_POINT_LEN || ec_pubkey[0] != UNCOMPRESSED_POINT_TAG {
        return false;
    }
    if challenge.len() < MIN_CHALLENGE_LEN || challenge.len() > MAX_CHALLENGE_LEN {
        return false;
    }
    if signature_der.is_empty() || signature_der.len() > CARD_SIGNATURE_MAX_BYTES {
        return false;
    }

    let msg = build_card_auth_message(account_id, challenge);
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        ec_pubkey,
    )
    .verify(&msg, signature_der)
    .is_ok()
}

/// `POST /auth/card/challenge` — Issue a single-use signing challenge.
///
/// Issued **unconditionally** (no card lookup) so the response never reveals
/// whether a card is registered. The challenge is stored fail-closed in Redis
/// under `impala:card_challenge:{card_id}` with a 60s TTL and consumed
/// atomically (GETDEL) by `POST /auth/card`.
pub async fn card_challenge(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<CardChallengeRequest>,
) -> Result<Json<CardChallengeResponse>, AppError> {
    debug!("POST /auth/card/challenge: challenge requested");

    crate::validate::validate_card_id(&payload.card_id)?;

    // Rate-limit issuance per card id (fail-closed)
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "card_challenge",
        &payload.card_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let mut challenge = [0u8; CARD_CHALLENGE_BYTES];
    aws_lc_rs::rand::fill(&mut challenge).map_err(|_| {
        error!("card_challenge: CSPRNG failure");
        AppError::InternalError("Failed to generate challenge".to_string())
    })?;
    let challenge_hex = hex::encode(challenge);

    crate::redis_helpers::store_card_challenge(
        &redis_pool,
        &payload.card_id,
        &challenge_hex,
        CARD_CHALLENGE_TTL_SECS,
    )
    .await?;

    Ok(Json(CardChallengeResponse {
        success: true,
        challenge: challenge_hex,
        expires_in: CARD_CHALLENGE_TTL_SECS as u64,
    }))
}

/// `POST /auth/card` — Exchange a card signature for local JWT tokens.
///
/// Looks up the active registered card, reconstructs the pinned message from
/// the consumed challenge, and verifies the DER signature against the card's
/// EC public key. All failure modes (unknown card, missing/expired/replayed
/// challenge, bad signature) return the same generic 401 and count toward the
/// per-card lockout.
pub async fn card_token_exchange(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<crate::jwt::JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    Json(payload): Json<CardTokenExchangeRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let result = card_token_exchange_inner(pool, jwt_keys, redis_pool, admin_ids, payload).await;
    metrics.record_token_exchange("card", token_exchange_outcome(&result));
    result
}

async fn card_token_exchange_inner(
    pool: PgPool,
    jwt_keys: Arc<crate::jwt::JwtKeys>,
    redis_pool: Arc<deadpool_redis::Pool>,
    admin_ids: Arc<std::collections::HashSet<String>>,
    payload: CardTokenExchangeRequest,
) -> Result<Json<TokenResponse>, AppError> {
    debug!("POST /auth/card: token exchange request received");

    crate::validate::validate_card_id(&payload.card_id)?;
    crate::validate::validate_hex_signature(&payload.signature)?;

    let card_id = payload.card_id;
    let lockout_id = format!("card:{card_id}");

    // Lockout + rate limit (fail-closed on Redis errors)
    crate::redis_helpers::check_lockout(&redis_pool, &lockout_id, LOCKOUT_THRESHOLD).await?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "card",
        &card_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Consume the outstanding challenge FIRST (GETDEL — single use), so even
    // a valid signature can only ever be presented once per challenge.
    let challenge_hex = match crate::redis_helpers::consume_card_challenge(&redis_pool, &card_id)
        .await?
    {
        Some(c) => c,
        None => {
            warn!(
                "card_auth: no outstanding challenge for card_id={} (expired, replayed, or never issued)",
                card_id
            );
            crate::redis_helpers::increment_lockout(
                &redis_pool,
                &lockout_id,
                LOCKOUT_DURATION_SECS,
            )
            .await;
            return Err(AppError::Unauthorized);
        }
    };

    let challenge = hex::decode(&challenge_hex).map_err(|e| {
        // The bridge wrote this value itself; failure here is server-side corruption.
        error!("card_auth: stored challenge is not valid hex: {}", e);
        AppError::Unauthorized
    })?;

    // Look up the active registered card (unique per migration 021)
    let card_row = sqlx::query_as::<_, (String, String)>(
        "SELECT account_id, ec_pubkey FROM card WHERE card_id = $1 AND is_delete = FALSE",
    )
    .bind(&card_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("card_auth: database error looking up card: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let (account_id, ec_pubkey_hex) = match card_row {
        Some(row) => row,
        None => {
            warn!("card_auth: unknown or deleted card_id={}", card_id);
            crate::redis_helpers::increment_lockout(
                &redis_pool,
                &lockout_id,
                LOCKOUT_DURATION_SECS,
            )
            .await;
            return Err(AppError::Unauthorized);
        }
    };

    // The signed message embeds the account id as 16 raw RFC-4122 big-endian
    // bytes (the on-card value from INS_GET_ACCOUNT_ID), so card-auth accounts
    // must use UUID account ids. Non-UUID account ids can never verify.
    let account_uuid = uuid::Uuid::parse_str(&account_id).map_err(|_| {
        error!(
            "card_auth: account_id for card_id={} is not a UUID; card auth unavailable",
            card_id
        );
        AppError::Unauthorized
    })?;

    let ec_pubkey = hex::decode(&ec_pubkey_hex).map_err(|_| {
        error!(
            "card_auth: registered ec_pubkey for card_id={} is not valid hex",
            card_id
        );
        AppError::Unauthorized
    })?;

    let signature = hex::decode(&payload.signature)
        .map_err(|_| AppError::BadRequest("Invalid signature encoding".to_string()))?;

    if !verify_card_signature(&ec_pubkey, &account_uuid, &challenge, &signature) {
        warn!(
            "card_auth: signature verification failed for card_id={}",
            card_id
        );
        crate::redis_helpers::increment_lockout(&redis_pool, &lockout_id, LOCKOUT_DURATION_SECS)
            .await;
        return Err(AppError::Unauthorized);
    }

    // Success — reset the failure counter
    crate::redis_helpers::clear_lockout(&redis_pool, &lockout_id).await;

    info!(
        "card_auth: signature verified for card_id={} account_id={}",
        card_id, account_id
    );

    // Issue local JWT tokens (role derived from DB + allowlist at issuance).
    // No auto-provisioning: the card FK guarantees the account exists.
    let role = crate::auth::issuance_role(&pool, &admin_ids, &account_id).await;
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(&jwt_keys, &account_id, &role)?;

    info!("card_auth: tokens issued for account_id={}", account_id);

    Ok(Json(TokenResponse {
        success: true,
        message: "Card authentication successful".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn test_uuid() -> uuid::Uuid {
        uuid::Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap()
    }

    /// Golden byte-layout test — pins the same bytes as the applet-side
    /// golden test (`AppletInteropTest.kt`: "sign auth signature verifies
    /// host-side over the pinned domain-tagged message").
    #[test]
    fn golden_domain_prefix_bytes() {
        let pinned: [u8; 12] = [
            0x49, 0x4D, 0x50, 0x41, // "IMPA"
            0x4C, 0x41, 0x2D, 0x41, // "LA-A"
            0x55, 0x54, 0x48, 0x3A, // "UTH:"
        ];
        assert_eq!(CARD_AUTH_DOMAIN_PREFIX, &pinned);
        assert_eq!(CARD_AUTH_DOMAIN_PREFIX, b"IMPALA-AUTH:");
    }

    #[test]
    fn golden_message_layout() {
        let challenge: Vec<u8> = (0u8..32).collect();
        let msg = build_card_auth_message(&test_uuid(), &challenge);

        assert_eq!(msg.len(), 12 + 16 + 32);
        assert_eq!(
            hex::encode(&msg),
            // "IMPALA-AUTH:"            account uuid (RFC-4122 big-endian)
            format!(
                "494d50414c412d415554483a00112233445566778899aabbccddeeff{}",
                hex::encode(&challenge)
            )
        );
    }

    fn keypair() -> (EcdsaKeyPair, Vec<u8>) {
        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("P-256 keypair generation");
        let pubkey = key_pair.public_key().as_ref().to_vec();
        assert_eq!(pubkey.len(), 65, "expected uncompressed SEC1 point");
        (key_pair, pubkey)
    }

    fn sign(key_pair: &EcdsaKeyPair, msg: &[u8]) -> Vec<u8> {
        key_pair
            .sign(&SystemRandom::new(), msg)
            .expect("signing")
            .as_ref()
            .to_vec()
    }

    #[test]
    fn round_trip_signature_verifies() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let challenge = [0xA5u8; 32];

        let sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenge));
        assert!(verify_card_signature(&pubkey, &uuid, &challenge, &sig));
    }

    #[test]
    fn untagged_message_fails() {
        // A signature over the pre-contract format (no domain prefix) must not verify
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let challenge = [0x42u8; 32];

        let mut untagged = uuid.as_bytes().to_vec();
        untagged.extend_from_slice(&challenge);
        let sig = sign(&key_pair, &untagged);

        assert!(!verify_card_signature(&pubkey, &uuid, &challenge, &sig));
    }

    #[test]
    fn wrong_account_uuid_fails() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let challenge = [0x42u8; 32];
        let sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenge));

        let other = uuid::Uuid::parse_str("ffeeddcc-bbaa-9988-7766-554433221100").unwrap();
        assert!(!verify_card_signature(&pubkey, &other, &challenge, &sig));
    }

    #[test]
    fn wrong_challenge_fails() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let sig = sign(&key_pair, &build_card_auth_message(&uuid, &[0x42u8; 32]));

        assert!(!verify_card_signature(&pubkey, &uuid, &[0x43u8; 32], &sig));
    }

    #[test]
    fn mutated_signature_fails() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let challenge = [0x42u8; 32];
        let mut sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenge));

        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert!(!verify_card_signature(&pubkey, &uuid, &challenge, &sig));
    }

    #[test]
    fn compressed_public_key_is_rejected() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let challenge = [0x42u8; 32];
        let sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenge));

        // Compressed SEC1 form of the same point: parity prefix || X
        let mut compressed = Vec::with_capacity(33);
        compressed.push(if pubkey[64] & 1 == 1 { 0x03 } else { 0x02 });
        compressed.extend_from_slice(&pubkey[1..33]);

        assert!(!verify_card_signature(&compressed, &uuid, &challenge, &sig));
    }

    #[test]
    fn challenge_length_bounds_enforced() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();

        for len in [7usize, 65] {
            let challenge = vec![0x11u8; len];
            let sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenge));
            assert!(
                !verify_card_signature(&pubkey, &uuid, &challenge, &sig),
                "challenge of {} bytes must be rejected",
                len
            );
        }

        for len in [8usize, 64] {
            let challenge = vec![0x11u8; len];
            let sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenge));
            assert!(
                verify_card_signature(&pubkey, &uuid, &challenge, &sig),
                "challenge of {} bytes must verify",
                len
            );
        }
    }
}

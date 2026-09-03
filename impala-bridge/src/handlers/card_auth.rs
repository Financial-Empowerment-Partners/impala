//! Card challenge-response authentication (`POST /auth/card/challenge` +
//! `POST /auth/card`).
//!
//! Implements the pinned cross-stream card-auth contract (see
//! `CARD_AUTH_DOMAIN_PREFIX` in `constants.rs` and `AUTH_DOMAIN_TAG` in
//! `ImpalaApplet.java`): the bridge issues a random 32-byte challenge, the
//! card signs `"IMPALA-AUTH:" || accountId(16, RFC-4122 big-endian) ||
//! challenge` with ECDSA-SHA256 (secp256r1, ASN.1 DER), and the bridge
//! verifies against the registered card's 65-byte uncompressed SEC1 public
//! key. Each card keeps a SMALL set of outstanding challenges (a card UID is
//! public over NFC, so a single overwritable slot let anyone who knew one
//! clobber or consume the holder's challenge); each expires after 60
//! seconds, the matching one is consumed atomically (Redis `LREM`) exactly
//! once, and challenges are issued unconditionally so the endpoint never
//! reveals whether a card is registered. There is NO auto-provisioning: a
//! registered card implies an existing account (migration 017 FK).

use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::client_source::ClientSource;
use crate::constants::{
    CARD_AUTH_DOMAIN_PREFIX, CARD_CHALLENGE_BYTES, CARD_CHALLENGE_MAX_OUTSTANDING,
    CARD_CHALLENGE_TTL_SECS, CARD_SIGNATURE_MAX_BYTES, LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD,
    PREAUTH_SOURCE_MAX_REQUESTS, PREAUTH_SOURCE_WINDOW_SECS, RATE_LIMIT_MAX_REQUESTS,
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

/// Outstanding-challenge entry as stored in the card's Redis list:
/// `{expires_at_unix}:{challenge_hex}`. Expiry rides on the entry because
/// the list key holds several challenges with different issue times.
pub(crate) fn encode_challenge_entry(expires_at: u64, challenge_hex: &str) -> String {
    format!("{expires_at}:{challenge_hex}")
}

/// Parse an entry back into `(expires_at, challenge_hex)`. `None` for
/// anything the bridge did not write (server-side corruption, never input).
pub(crate) fn decode_challenge_entry(entry: &str) -> Option<(u64, &str)> {
    let (expires_at, challenge_hex) = entry.split_once(':')?;
    let expires_at = expires_at.parse::<u64>().ok()?;
    Some((expires_at, challenge_hex))
}

/// The entries still live at `now`, newest first, each with its decoded
/// challenge bytes. Expired or unparseable entries are skipped; they lapse
/// with the list key's TTL.
pub(crate) fn live_challenges(entries: &[String], now: u64) -> Vec<(&str, Vec<u8>)> {
    entries
        .iter()
        .rev()
        .filter_map(|entry| {
            let (expires_at, challenge_hex) = decode_challenge_entry(entry)?;
            if expires_at <= now {
                return None;
            }
            let challenge = hex::decode(challenge_hex).ok()?;
            Some((entry.as_str(), challenge))
        })
        .collect()
}

fn unix_now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// `POST /auth/card/challenge` — Issue a single-use signing challenge.
///
/// Issued **unconditionally** (no card lookup) so the response never reveals
/// whether a card is registered. The challenge joins the card's bounded
/// outstanding set in Redis (`impala:card_challenges:{card_id}`, at most
/// `CARD_CHALLENGE_MAX_OUTSTANDING`, oldest evicted, 60s TTL each), stored
/// fail-closed, and is consumed atomically by `POST /auth/card`.
pub async fn card_challenge(
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<CardChallengeRequest>,
) -> Result<Json<CardChallengeResponse>, AppError> {
    debug!("POST /auth/card/challenge: challenge requested");

    crate::validate::validate_card_id(&payload.card_id)?;

    // Per-source budget before any per-card budget is spent, then
    // rate-limit issuance per card id (both fail-closed).
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "preauth_src",
        &source,
        PREAUTH_SOURCE_MAX_REQUESTS,
        PREAUTH_SOURCE_WINDOW_SECS,
    )
    .await?;
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

    let entry = encode_challenge_entry(unix_now() + CARD_CHALLENGE_TTL_SECS as u64, &challenge_hex);
    crate::redis_helpers::push_card_challenge(
        &redis_pool,
        &payload.card_id,
        &entry,
        CARD_CHALLENGE_MAX_OUTSTANDING,
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
/// Looks up the active registered card, reconstructs the pinned message for
/// each live outstanding challenge, and verifies the DER signature against
/// the card's EC public key; the challenge that verifies is consumed
/// atomically (exactly once). Every failure mode (unknown card, no live
/// challenge, bad signature, replay) returns the same generic 401, but only
/// a bad signature over a live challenge — a real guess — counts toward the
/// `(card, source)` lockout. An empty submission against a card whose UID
/// anyone can read must not be able to spend the holder's budget.
pub async fn card_token_exchange(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<crate::jwt::JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<CardTokenExchangeRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let result =
        card_token_exchange_inner(pool, jwt_keys, redis_pool, admin_ids, &source, payload).await;
    metrics.record_token_exchange("card", token_exchange_outcome(&result));
    result
}

async fn card_token_exchange_inner(
    pool: PgPool,
    jwt_keys: Arc<crate::jwt::JwtKeys>,
    redis_pool: Arc<deadpool_redis::Pool>,
    admin_ids: Arc<std::collections::HashSet<String>>,
    source: &str,
    payload: CardTokenExchangeRequest,
) -> Result<Json<TokenResponse>, AppError> {
    debug!("POST /auth/card: token exchange request received");

    crate::validate::validate_card_id(&payload.card_id)?;
    crate::validate::validate_hex_signature(&payload.signature)?;

    let card_id = payload.card_id;
    let lockout_id = format!("card:{card_id}");

    // Per-source budget, (card, source) lockout, per-card rate limit — all
    // fail-closed on Redis errors.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "preauth_src",
        source,
        PREAUTH_SOURCE_MAX_REQUESTS,
        PREAUTH_SOURCE_WINDOW_SECS,
    )
    .await?;
    crate::redis_helpers::check_lockout(&redis_pool, &lockout_id, source, LOCKOUT_THRESHOLD)
        .await?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "card",
        &card_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Read the outstanding set WITHOUT consuming anything: nothing is
    // removed until a signature has verified against it, so a stranger's
    // submission can no longer burn the holder's challenge.
    let entries = crate::redis_helpers::list_card_challenges(&redis_pool, &card_id).await?;
    let candidates = live_challenges(&entries, unix_now());
    if candidates.is_empty() {
        // Not a guess — there was nothing to sign against — so no lockout
        // increment: counting this let anyone who knew a card UID lock the
        // holder out with empty submissions.
        warn!(
            "card_auth: no live challenge for card_id={} (expired, consumed, or never issued)",
            card_id
        );
        return Err(AppError::Unauthorized);
    }

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
            // Unknown identity: no key to guess against, not counted (same
            // rule as an unknown username on the password paths).
            warn!("card_auth: unknown or deleted card_id={}", card_id);
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

    // The card signed exactly one of the live challenges (newest first — the
    // one it was most likely just handed). One signature can verify against
    // at most one 32-byte random challenge, so the match is unambiguous.
    let matched = candidates
        .iter()
        .find(|(_, challenge)| {
            verify_card_signature(&ec_pubkey, &account_uuid, challenge, &signature)
        })
        .map(|(entry, _)| *entry);

    let Some(entry) = matched else {
        // A real guess: a signature that verifies against no live challenge.
        // This is the ONLY card-path failure that counts toward lockout.
        warn!(
            "card_auth: signature verification failed for card_id={}",
            card_id
        );
        crate::redis_helpers::increment_lockout(
            &redis_pool,
            &lockout_id,
            source,
            LOCKOUT_DURATION_SECS,
        )
        .await;
        return Err(AppError::Unauthorized);
    };

    // Consume exactly the challenge that verified, atomically: of two
    // concurrent presentations of the same valid signature, exactly one
    // removes the entry; the other finds it gone and is a replay.
    if !crate::redis_helpers::consume_card_challenge(&redis_pool, &card_id, entry).await? {
        warn!(
            "card_auth: challenge for card_id={} was already consumed (replay)",
            card_id
        );
        return Err(AppError::Unauthorized);
    }

    // Success — reset the failure counter for this source
    crate::redis_helpers::clear_lockout(&redis_pool, &lockout_id, source).await;

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

    // ── Outstanding-challenge set ──────────────────────────────────────

    #[test]
    fn challenge_entry_round_trips() {
        let hex = hex::encode([0xA5u8; 32]);
        let entry = encode_challenge_entry(1_700_000_060, &hex);
        assert_eq!(entry, format!("1700000060:{hex}"));
        assert_eq!(
            decode_challenge_entry(&entry),
            Some((1_700_000_060, hex.as_str()))
        );
    }

    #[test]
    fn decode_rejects_anything_the_bridge_did_not_write() {
        assert!(decode_challenge_entry("").is_none());
        assert!(decode_challenge_entry("deadbeef").is_none());
        assert!(decode_challenge_entry("soon:deadbeef").is_none());
        assert!(decode_challenge_entry("-5:deadbeef").is_none());
    }

    /// Expired entries are invisible, live ones come newest-first, and an
    /// entry that will not parse is skipped rather than failing the lot.
    #[test]
    fn live_challenges_filters_expired_and_orders_newest_first() {
        let old = hex::encode([0x01u8; 32]);
        let mid = hex::encode([0x02u8; 32]);
        let new = hex::encode([0x03u8; 32]);
        let entries = vec![
            encode_challenge_entry(100, &old), // expired at now=100 (<=)
            encode_challenge_entry(150, &mid),
            "garbage".to_string(),
            encode_challenge_entry(160, &new),
        ];
        let live = live_challenges(&entries, 100);
        let order: Vec<&str> = live.iter().map(|(e, _)| *e).collect();
        assert_eq!(order, vec![entries[3].as_str(), entries[1].as_str()]);
        assert_eq!(live[0].1, vec![0x03u8; 32]);
        assert!(live_challenges(&entries, 160).is_empty());
    }

    /// With several challenges outstanding, the signature verifies against
    /// exactly the one the card signed — never a neighbour — so the handler
    /// consumes the right entry and leaves the rest for their holders.
    #[test]
    fn signature_matches_exactly_one_live_challenge() {
        let (key_pair, pubkey) = keypair();
        let uuid = test_uuid();
        let challenges: Vec<[u8; 32]> = (1u8..=5).map(|i| [i; 32]).collect();
        let entries: Vec<String> = challenges
            .iter()
            .enumerate()
            .map(|(i, c)| encode_challenge_entry(1_000 + i as u64, &hex::encode(c)))
            .collect();
        let sig = sign(&key_pair, &build_card_auth_message(&uuid, &challenges[2]));

        let live = live_challenges(&entries, 0);
        let matched: Vec<&str> = live
            .iter()
            .filter(|(_, c)| verify_card_signature(&pubkey, &uuid, c, &sig))
            .map(|(e, _)| *e)
            .collect();
        assert_eq!(matched, vec![entries[2].as_str()]);
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

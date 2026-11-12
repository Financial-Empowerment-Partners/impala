//! Multi-factor sign-in: the factor model shared by the sign-in paths, the
//! step-up route and request enforcement (`docs/mfa-card-pin-biometrics.md`).
//!
//! The bridge never takes a factor on a client's word. This module holds the
//! verification each factor's evidence must pass before it is added to a
//! session's `amr`:
//! - a **card PIN proof**: a P-256 signature the applet makes under the
//!   `IMPALA-APIN:` tag only while the user PIN is verified (`sc` is already
//!   proven by the sign-in signature; this adds `pin`);
//! - a **device-key assertion**: a P-256 signature by a key registered to the
//!   account, over a bridge challenge (`dev`, plus `bio` when the operator
//!   opted to trust a client's biometric declaration).
//!
//! `amr` finalization and the kind-based multi-factor test live in
//! `constants.rs` ([`crate::constants::finalize_amr`]); enforcement
//! (`is_session_multi_factor`, `account_requires_mfa`) is here.

use std::collections::HashSet;

use log::warn;
use sqlx::PgPool;
use uuid::Uuid;

use crate::constants::{
    amr_has_mfa, AMR_BIOMETRIC, AMR_CARD_PIN, AMR_DEVICE_KEY, CARD_PIN_PROOF_DOMAIN_PREFIX,
    DEVICE_KEY_DOMAIN_PREFIX, DEVICE_KEY_VERSION, DEVICE_SIGNATURE_MAX_BYTES,
    DEVICE_USER_VERIFICATION_BIOMETRIC, MFA_CARD_PIN_TRUST_ANY, MFA_DEVICE_BIOMETRIC_CLAIMED,
};
use crate::error::AppError;

pub mod handlers;

/// Uncompressed SEC1 P-256 public key: `0x04 || X(32) || Y(32)`.
const UNCOMPRESSED_POINT_LEN: usize = 65;
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// A card is trusted for the `pin` factor only when its certificate still
/// verifies: it is certified and the issuer key version that signed it has not
/// been revoked.
const CARD_PIN_TRUST_SQL: &str = "SELECT (c.certified_at IS NOT NULL \
     AND k.state IS NOT NULL AND k.state <> 'revoked') \
     FROM card c LEFT JOIN card_issuer_key k ON k.version = c.cert_issuer_version \
     WHERE c.card_id = $1 AND c.is_delete = FALSE";

/// An active device key by `(account, key_id)`: its public key and the
/// biometric declaration. One row (the active-key index is unique).
const DEVICE_KEY_LOOKUP_SQL: &str = "SELECT public_key_hex, user_verification \
     FROM mfa_device_key WHERE account_id = $1 AND key_id = $2 AND is_delete = FALSE";

/// Resolved MFA policy, carried as shared state (like the admin allowlist).
#[derive(Debug, Clone)]
pub struct MfaConfig {
    /// Roles whose sessions must be multi-factor (`MFA_REQUIRED_ROLES`).
    pub required_roles: HashSet<String>,
    /// How long a multi-factor verification lasts before a step-up is needed.
    pub max_age_secs: i64,
    /// Trust a card PIN proof only from an issuer-certified card.
    pub card_pin_trust_certified: bool,
    /// Credit `bio` for a device key the client declared biometric-bound.
    pub device_biometric_claimed: bool,
}

impl MfaConfig {
    pub fn from_config(config: &crate::config::Config) -> Self {
        MfaConfig {
            required_roles: config.mfa_required_roles.clone(),
            max_age_secs: config.mfa_max_age_secs,
            card_pin_trust_certified: config.mfa_card_pin_trust != MFA_CARD_PIN_TRUST_ANY,
            device_biometric_claimed: config.mfa_device_biometric == MFA_DEVICE_BIOMETRIC_CLAIMED,
        }
    }
}

// ── Factor verification (pure) ─────────────────────────────────────────────

/// Build the card PIN-proof message: `"IMPALA-APIN:" || accountId(16) ||
/// challenge`. The same layout as the sign-in message with a different tag, so
/// a sign-in signature can never pass as a PIN proof and vice versa.
pub fn build_pin_proof_message(account_id: &Uuid, challenge: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CARD_PIN_PROOF_DOMAIN_PREFIX.len() + 16 + challenge.len());
    msg.extend_from_slice(CARD_PIN_PROOF_DOMAIN_PREFIX);
    msg.extend_from_slice(account_id.as_bytes());
    msg.extend_from_slice(challenge);
    msg
}

/// Verify a card PIN proof: an ECDSA-SHA256 (P-256, DER) signature over the
/// PIN-proof message under the card's registered EC public key. Same strict
/// input checks as the sign-in verifier.
pub fn verify_pin_proof(
    ec_pubkey: &[u8],
    account_id: &Uuid,
    challenge: &[u8],
    signature_der: &[u8],
) -> bool {
    if ec_pubkey.len() != UNCOMPRESSED_POINT_LEN || ec_pubkey[0] != UNCOMPRESSED_POINT_TAG {
        return false;
    }
    if signature_der.is_empty() || signature_der.len() > DEVICE_SIGNATURE_MAX_BYTES {
        return false;
    }
    let msg = build_pin_proof_message(account_id, challenge);
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        ec_pubkey,
    )
    .verify(&msg, signature_der)
    .is_ok()
}

/// Build the device-key assertion message: `"IMPALA-DKEY:" || 0x01 ||
/// purpose(1) || sha256(account_id UTF-8)(32) || challenge(32)`.
pub fn build_device_assertion_message(purpose: u8, account_id: &str, challenge: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let account_hash = Sha256::digest(account_id.as_bytes());
    let mut msg = Vec::with_capacity(DEVICE_KEY_DOMAIN_PREFIX.len() + 2 + 32 + challenge.len());
    msg.extend_from_slice(DEVICE_KEY_DOMAIN_PREFIX);
    msg.push(DEVICE_KEY_VERSION);
    msg.push(purpose);
    msg.extend_from_slice(&account_hash);
    msg.extend_from_slice(challenge);
    msg
}

/// Verify a device-key assertion (P-256 ECDSA-SHA256, DER) under `pubkey`.
pub fn verify_device_assertion(
    pubkey: &[u8],
    purpose: u8,
    account_id: &str,
    challenge: &[u8],
    signature_der: &[u8],
) -> bool {
    if pubkey.len() != UNCOMPRESSED_POINT_LEN || pubkey[0] != UNCOMPRESSED_POINT_TAG {
        return false;
    }
    if signature_der.is_empty() || signature_der.len() > DEVICE_SIGNATURE_MAX_BYTES {
        return false;
    }
    let msg = build_device_assertion_message(purpose, account_id, challenge);
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        pubkey,
    )
    .verify(&msg, signature_der)
    .is_ok()
}

// ── Enforcement (pure) ─────────────────────────────────────────────────────

/// True when a session is multi-factor *now*: its `amr` carries the derived
/// `mfa` marker and the last verification is within `max_age_secs`.
pub fn is_session_multi_factor(
    amr: &[String],
    auth_time: usize,
    now: i64,
    max_age_secs: i64,
) -> bool {
    amr_has_mfa(amr) && now.saturating_sub(auth_time as i64) <= max_age_secs
}

/// True when the account must be multi-factor: its stamped `mfr` claim, or its
/// role being one the operator requires (`MFA_REQUIRED_ROLES`).
pub fn account_requires_mfa(mfr_claim: bool, role: &str, required_roles: &HashSet<String>) -> bool {
    mfr_claim || required_roles.contains(role)
}

// ── Factor collection for a sign-in (DB-backed) ─────────────────────────────

/// Decode a hex DER signature argument, bounding its size. A present-but-bad
/// encoding is a hard 401: a factor the client claimed must not be silently
/// dropped.
fn decode_signature(hex_str: &str) -> Result<Vec<u8>, AppError> {
    let bytes = hex::decode(hex_str).map_err(|_| AppError::Unauthorized)?;
    if bytes.is_empty() || bytes.len() > DEVICE_SIGNATURE_MAX_BYTES {
        return Err(AppError::Unauthorized);
    }
    Ok(bytes)
}

/// Verify the optional MFA extras that ride a card / SEP-10 sign-in and append
/// the factors they prove (`pin`, `dev`, and `bio` when configured) to
/// `methods`. The challenge is the value the card signed (the card challenge,
/// or the SEP-10 transaction hash): the PIN proof covers it directly, and the
/// device assertion covers it under `purpose`.
///
/// Any extra that is present and does not verify is a hard failure (401): the
/// whole sign-in is refused, never downgraded to one without that factor.
#[allow(clippy::too_many_arguments)]
pub async fn collect_card_extras(
    pool: &PgPool,
    cfg: &MfaConfig,
    account_uuid: &Uuid,
    account_id: &str,
    card_id: &str,
    ec_pubkey: &[u8],
    challenge: &[u8],
    device_purpose: u8,
    pin_proof: Option<&str>,
    device_key_id: Option<&str>,
    device_signature: Option<&str>,
    methods: &mut Vec<String>,
) -> Result<(), AppError> {
    if let Some(proof_hex) = pin_proof.filter(|s| !s.is_empty()) {
        let der = decode_signature(proof_hex)?;
        if !verify_pin_proof(ec_pubkey, account_uuid, challenge, &der) {
            warn!("mfa: card PIN proof present but did not verify for card_id={card_id}");
            return Err(AppError::Unauthorized);
        }
        if cfg.card_pin_trust_certified && !card_pin_trusted(pool, card_id).await? {
            warn!("mfa: card PIN proof verified but card_id={card_id} is not issuer-certified");
            return Err(AppError::Unauthorized);
        }
        methods.push(AMR_CARD_PIN.to_string());
    }

    if let Some(key_id) = device_key_id.filter(|s| !s.is_empty()) {
        let sig_hex = device_signature
            .filter(|s| !s.is_empty())
            .ok_or(AppError::Unauthorized)?;
        let der = decode_signature(sig_hex)?;
        collect_device_factor(
            pool,
            cfg,
            account_id,
            key_id,
            device_purpose,
            challenge,
            &der,
            methods,
        )
        .await?;
    }
    Ok(())
}

/// Verify a device-key assertion for one sign-in and append `dev` (+ `bio`).
#[allow(clippy::too_many_arguments)]
pub async fn collect_device_factor(
    pool: &PgPool,
    cfg: &MfaConfig,
    account_id: &str,
    key_id: &str,
    purpose: u8,
    challenge: &[u8],
    signature_der: &[u8],
    methods: &mut Vec<String>,
) -> Result<(), AppError> {
    let key_uuid = Uuid::parse_str(key_id).map_err(|_| AppError::Unauthorized)?;
    let row = sqlx::query_as::<_, (String, String)>(DEVICE_KEY_LOOKUP_SQL)
        .bind(account_id)
        .bind(key_uuid)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            warn!("mfa: device-key lookup error: {e}");
            AppError::InternalError("Database error".to_string())
        })?;
    let Some((public_key_hex, user_verification)) = row else {
        warn!("mfa: device key not found for account (key_id={key_id})");
        return Err(AppError::Unauthorized);
    };
    let pubkey = hex::decode(public_key_hex.trim()).map_err(|_| AppError::Unauthorized)?;
    if !verify_device_assertion(&pubkey, purpose, account_id, challenge, signature_der) {
        warn!("mfa: device-key assertion did not verify (key_id={key_id})");
        return Err(AppError::Unauthorized);
    }
    methods.push(AMR_DEVICE_KEY.to_string());
    if cfg.device_biometric_claimed && user_verification == DEVICE_USER_VERIFICATION_BIOMETRIC {
        methods.push(AMR_BIOMETRIC.to_string());
    }
    Ok(())
}

/// Whether a card's PIN proof may be trusted as the `pin` factor: the card is
/// issuer-certified and the issuer key version is not revoked.
pub(crate) async fn card_pin_trusted(pool: &PgPool, card_id: &str) -> Result<bool, AppError> {
    let trusted: Option<Option<bool>> = sqlx::query_scalar(CARD_PIN_TRUST_SQL)
        .bind(card_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            warn!("mfa: card certification lookup error: {e}");
            AppError::InternalError("Database error".to_string())
        })?;
    Ok(trusted.flatten().unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        DEVICE_KEY_PURPOSE_CARD_SIGN_IN, DEVICE_KEY_PURPOSE_STEP_UP, MFA_MAX_AGE_SECS_DEFAULT,
    };

    #[test]
    fn pin_proof_and_sign_in_messages_differ_only_in_the_tag() {
        let acct = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let challenge: Vec<u8> = (0u8..32).collect();
        let pin = build_pin_proof_message(&acct, &challenge);
        let auth = crate::handlers::card_auth::build_card_auth_message(&acct, &challenge);
        assert_eq!(pin.len(), auth.len());
        assert_eq!(&pin[..7], &auth[..7]); // "IMPALA-"
        assert_ne!(&pin[7..11], &auth[7..11]); // "APIN" vs "AUTH"
        assert_eq!(&pin[12..], &auth[12..]); // same account id + challenge
    }

    #[test]
    fn device_assertion_message_is_fixed_layout() {
        let msg = build_device_assertion_message(DEVICE_KEY_PURPOSE_STEP_UP, "acct-1", &[7u8; 32]);
        assert_eq!(msg.len(), 12 + 1 + 1 + 32 + 32);
        assert_eq!(&msg[..12], DEVICE_KEY_DOMAIN_PREFIX);
        assert_eq!(msg[12], DEVICE_KEY_VERSION);
        assert_eq!(msg[13], DEVICE_KEY_PURPOSE_STEP_UP);
        // The purpose is bound into the signed bytes: a step-up assertion is
        // not a card-sign-in assertion.
        let other =
            build_device_assertion_message(DEVICE_KEY_PURPOSE_CARD_SIGN_IN, "acct-1", &[7u8; 32]);
        assert_ne!(msg, other);
    }

    #[test]
    fn session_multi_factor_respects_mfa_marker_and_freshness() {
        let now = 1_000_000i64;
        let mfa = vec!["pin".to_string(), "sc".to_string(), "mfa".to_string()];
        assert!(is_session_multi_factor(
            &mfa,
            now as usize,
            now,
            MFA_MAX_AGE_SECS_DEFAULT
        ));
        // Stale: older than max age.
        assert!(!is_session_multi_factor(
            &mfa,
            (now - MFA_MAX_AGE_SECS_DEFAULT - 1) as usize,
            now,
            MFA_MAX_AGE_SECS_DEFAULT
        ));
        // Not multi-factor: no `mfa` marker.
        assert!(!is_session_multi_factor(
            &["sc".to_string()],
            now as usize,
            now,
            MFA_MAX_AGE_SECS_DEFAULT
        ));
    }

    #[test]
    fn required_mfa_from_claim_or_role() {
        let mut roles = HashSet::new();
        roles.insert("treasurer".to_string());
        assert!(account_requires_mfa(true, "view-only", &roles));
        assert!(account_requires_mfa(false, "treasurer", &roles));
        assert!(!account_requires_mfa(false, "view-only", &roles));
    }
}

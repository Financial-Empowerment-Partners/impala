use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, decode_header, encode, DecodingKey, EncodingKey, Header, Validation};
use log::{error, warn};
use sha2::{Digest, Sha256};

use crate::constants::{
    JWT_AUDIENCE, JWT_ISSUER, JWT_KID_LEN, JWT_SECRET_MIN_LENGTH, REFRESH_TOKEN_TTL_SECS,
    TEMPORAL_TOKEN_TTL_SECS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_TEMPORAL,
};
use crate::error::AppError;
use crate::models::Claims;

/// JWT signing/verification key set with zero-downtime secret rotation.
///
/// The primary secret signs every new token; the optional previous secret is
/// verify-only, covering the rotation window (set `JWT_SECRET_PREVIOUS` to the
/// old secret while live tokens signed with it age out — at most the 14-day
/// refresh TTL — then unset it). Every minted token carries a `kid` header
/// (`hex(sha256(secret))[..16]`) so verification selects the key
/// deterministically; kid-less tokens fall back to try-primary-then-previous,
/// retrying only on an invalid-signature error.
///
/// Also a deliberate newtype: the JWT secret used to ride the router as
/// `Extension<Arc<String>>`, the same type as the SNS topic ARN extension,
/// and the inner jwt layer silently overwrote the ARN for every handler.
pub struct JwtKeys {
    primary: Vec<u8>,
    primary_kid: String,
    previous: Option<(Vec<u8>, String)>,
}

impl JwtKeys {
    /// Build the key set, validating both secrets. Errors are fatal at startup.
    pub fn new(primary: String, previous: Option<String>) -> Result<Self, String> {
        if primary.len() < JWT_SECRET_MIN_LENGTH {
            return Err(format!(
                "JWT_SECRET must be at least {JWT_SECRET_MIN_LENGTH} characters for security"
            ));
        }
        let previous = match previous {
            Some(prev) => {
                if prev.len() < JWT_SECRET_MIN_LENGTH {
                    return Err(format!(
                        "JWT_SECRET_PREVIOUS must be at least {JWT_SECRET_MIN_LENGTH} characters"
                    ));
                }
                if prev == primary {
                    return Err(
                        "JWT_SECRET_PREVIOUS must differ from JWT_SECRET (unset it once rotation completes)"
                            .to_string(),
                    );
                }
                let prev = prev.into_bytes();
                let kid = kid_of(&prev);
                Some((prev, kid))
            }
            None => None,
        };
        let primary = primary.into_bytes();
        let primary_kid = kid_of(&primary);
        Ok(JwtKeys {
            primary,
            primary_kid,
            previous,
        })
    }

    fn signing_header(&self) -> Header {
        Header {
            kid: Some(self.primary_kid.clone()),
            ..Header::default()
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(&self.primary)
    }
}

/// Key fingerprint used as the JWT `kid` header.
fn kid_of(secret: &[u8]) -> String {
    hex::encode(Sha256::digest(secret))[..JWT_KID_LEN].to_string()
}

fn base_validation() -> Validation {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_issuer(&[JWT_ISSUER]);
    validation.set_audience(&[JWT_AUDIENCE]);
    validation
}

/// Decode and validate a locally-issued JWT: HS256, issuer, audience, expiry,
/// key selection by `kid`, and the expected token type. Any failure maps to
/// `Unauthorized` (no detail leaks to the caller; specifics go to the log).
pub fn decode_claims(keys: &JwtKeys, token: &str, expected_type: &str) -> Result<Claims, AppError> {
    let validation = base_validation();
    let header = decode_header(token).map_err(|_| AppError::Unauthorized)?;

    let result = match header.kid.as_deref() {
        Some(kid) if kid == keys.primary_kid => {
            decode::<Claims>(token, &DecodingKey::from_secret(&keys.primary), &validation)
        }
        Some(kid) => match &keys.previous {
            Some((secret, prev_kid)) if kid == prev_kid => {
                decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
            }
            _ => {
                warn!("decode_claims: token presented with unknown kid");
                return Err(AppError::Unauthorized);
            }
        },
        // kid-less token (minted before kid stamping): try the primary secret,
        // falling back to the previous one only when the signature itself is
        // what failed — any other error (expiry, claims) is final.
        None => {
            match decode::<Claims>(token, &DecodingKey::from_secret(&keys.primary), &validation) {
                Err(e) if matches!(e.kind(), ErrorKind::InvalidSignature) => {
                    if let Some((secret, _)) = &keys.previous {
                        decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
                    } else {
                        Err(e)
                    }
                }
                other => other,
            }
        }
    };

    let token_data = result.map_err(|_| AppError::Unauthorized)?;

    if token_data.claims.token_type != expected_type {
        return Err(AppError::Unauthorized);
    }

    Ok(token_data.claims)
}

fn encode_with_claims(keys: &JwtKeys, claims: &Claims, what: &str) -> Result<String, AppError> {
    encode(&keys.signing_header(), claims, &keys.encoding_key()).map_err(|e| {
        error!("{what}: failed to encode JWT: {e}");
        AppError::InternalError("Failed to generate token".to_string())
    })
}

fn build_claims(subject: &str, token_type: &str, ttl: usize, role: &str, fid: &str) -> Claims {
    let now = chrono::Utc::now().timestamp() as usize;
    Claims {
        sub: subject.to_string(),
        token_type: token_type.to_string(),
        iat: now,
        exp: now + ttl,
        jti: uuid::Uuid::new_v4().to_string(),
        iss: JWT_ISSUER.to_string(),
        aud: JWT_AUDIENCE.to_string(),
        fid: fid.to_string(),
        role: role.to_string(),
    }
}

/// Encode a long-lived refresh token for the given subject, role, and token
/// family.
///
/// `role` is stamped from the caller's DB lookup (with the ADMIN_ACCOUNT_IDS
/// allowlist overriding to admin) at issuance time; it is re-derived (never
/// trusted from a presented token), bounding privilege staleness to the
/// temporal-token TTL.
pub fn encode_refresh_token(
    keys: &JwtKeys,
    subject: &str,
    role: &str,
    fid: &str,
) -> Result<String, AppError> {
    let claims = build_claims(
        subject,
        TOKEN_TYPE_REFRESH,
        REFRESH_TOKEN_TTL_SECS,
        role,
        fid,
    );
    encode_with_claims(keys, &claims, "encode_refresh_token")
}

/// Encode a short-lived temporal token for the given subject, role, and token
/// family.
pub fn encode_temporal_token(
    keys: &JwtKeys,
    subject: &str,
    role: &str,
    fid: &str,
) -> Result<String, AppError> {
    let claims = build_claims(
        subject,
        TOKEN_TYPE_TEMPORAL,
        TEMPORAL_TOKEN_TTL_SECS,
        role,
        fid,
    );
    encode_with_claims(keys, &claims, "encode_temporal_token")
}

/// Encode a refresh + temporal token pair, minting a fresh token family.
///
/// Returns `(refresh_token, temporal_token)`.
pub fn encode_token_pair(
    keys: &JwtKeys,
    subject: &str,
    role: &str,
) -> Result<(String, String), AppError> {
    let fid = uuid::Uuid::new_v4().to_string();
    encode_token_pair_with_family(keys, subject, role, &fid)
}

/// Encode a refresh + temporal token pair inside an existing token family
/// (the refresh-rotation path: the new pair inherits the presented token's
/// `fid` so reuse detection can revoke the whole lineage).
pub fn encode_token_pair_with_family(
    keys: &JwtKeys,
    subject: &str,
    role: &str,
    fid: &str,
) -> Result<(String, String), AppError> {
    let refresh = encode_refresh_token(keys, subject, role, fid)?;
    let temporal = encode_temporal_token(keys, subject, role, fid)?;
    Ok((refresh, temporal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        JWT_ISSUER, ROLE_ADMIN, ROLE_TOKEN, ROLE_VIEW_ONLY, TOKEN_TYPE_REFRESH, TOKEN_TYPE_TEMPORAL,
    };

    const TEST_SECRET: &str = "test-secret-key-for-jwt-unit-tests";
    const OTHER_SECRET: &str = "other-secret-key-for-jwt-unit-tests";

    fn keys() -> JwtKeys {
        JwtKeys::new(TEST_SECRET.to_string(), None).expect("primary-only keys")
    }

    fn keys_with_previous() -> JwtKeys {
        JwtKeys::new(OTHER_SECRET.to_string(), Some(TEST_SECRET.to_string())).expect("rotated keys")
    }

    #[test]
    fn test_encode_token_pair_returns_two_different_tokens() {
        let (refresh, temporal) =
            encode_token_pair(&keys(), "alice", ROLE_VIEW_ONLY).expect("token pair should succeed");

        assert_ne!(refresh, temporal, "refresh and temporal tokens must differ");
        assert!(!refresh.is_empty());
        assert!(!temporal.is_empty());
    }

    #[test]
    fn test_tokens_decode_and_carry_correct_claims() {
        let k = keys();
        let (refresh, temporal) =
            encode_token_pair(&k, "carol", ROLE_TOKEN).expect("token pair should succeed");

        let refresh_claims =
            decode_claims(&k, &refresh, TOKEN_TYPE_REFRESH).expect("refresh should decode");
        let temporal_claims =
            decode_claims(&k, &temporal, TOKEN_TYPE_TEMPORAL).expect("temporal should decode");

        assert_eq!(refresh_claims.sub, "carol");
        assert_eq!(temporal_claims.sub, "carol");
        assert_eq!(refresh_claims.token_type, TOKEN_TYPE_REFRESH);
        assert_eq!(temporal_claims.token_type, TOKEN_TYPE_TEMPORAL);
        assert_eq!(refresh_claims.iss, JWT_ISSUER);
        assert_eq!(refresh_claims.aud, JWT_AUDIENCE);
        assert_eq!(temporal_claims.aud, JWT_AUDIENCE);

        // Role stamped into both tokens of the pair.
        assert_eq!(refresh_claims.role, ROLE_TOKEN);
        assert_eq!(temporal_claims.role, ROLE_TOKEN);

        // JTI unique per token; fid shared across the pair.
        assert!(!refresh_claims.jti.is_empty());
        assert_ne!(refresh_claims.jti, temporal_claims.jti);
        assert!(!refresh_claims.fid.is_empty());
        assert_eq!(refresh_claims.fid, temporal_claims.fid);

        let now = chrono::Utc::now().timestamp() as usize;
        assert!(refresh_claims.exp > now);
        assert!(temporal_claims.exp > now);
    }

    #[test]
    fn test_pair_with_family_inherits_fid() {
        let k = keys();
        let (refresh, temporal) =
            encode_token_pair_with_family(&k, "dave", ROLE_VIEW_ONLY, "family-1").expect("pair");
        let r = decode_claims(&k, &refresh, TOKEN_TYPE_REFRESH).unwrap();
        let t = decode_claims(&k, &temporal, TOKEN_TYPE_TEMPORAL).unwrap();
        assert_eq!(r.fid, "family-1");
        assert_eq!(t.fid, "family-1");
    }

    #[test]
    fn test_wrong_token_type_rejected() {
        let k = keys();
        let (refresh, temporal) = encode_token_pair(&k, "erin", ROLE_VIEW_ONLY).expect("pair");
        assert!(decode_claims(&k, &refresh, TOKEN_TYPE_TEMPORAL).is_err());
        assert!(decode_claims(&k, &temporal, TOKEN_TYPE_REFRESH).is_err());
    }

    #[test]
    fn test_admin_role_propagates_into_both_tokens() {
        let k = keys();
        let (refresh, temporal) =
            encode_token_pair(&k, "root", ROLE_ADMIN).expect("token pair should succeed");
        for (tok, ty) in [
            (&refresh, TOKEN_TYPE_REFRESH),
            (&temporal, TOKEN_TYPE_TEMPORAL),
        ] {
            let claims = decode_claims(&k, tok, ty).expect("token should decode");
            assert_eq!(
                claims.role, ROLE_ADMIN,
                "admin role must be stamped when requested"
            );
        }
    }

    #[test]
    fn test_kid_header_present_and_matches_fingerprint() {
        let k = keys();
        let (refresh, _) = encode_token_pair(&k, "alice", ROLE_VIEW_ONLY).expect("pair");
        let header = decode_header(&refresh).expect("header decodes");
        let kid = header.kid.expect("kid header must be stamped");
        assert_eq!(kid.len(), JWT_KID_LEN);
        assert_eq!(kid, kid_of(TEST_SECRET.as_bytes()));
    }

    #[test]
    fn test_token_signed_with_previous_secret_decodes_during_rotation() {
        // Token minted under the old secret (carrying its kid)...
        let old = keys();
        let (refresh, _) = encode_token_pair(&old, "alice", ROLE_VIEW_ONLY).expect("pair");
        // ...still verifies once the old secret moves to JWT_SECRET_PREVIOUS.
        let rotated = keys_with_previous();
        let claims = decode_claims(&rotated, &refresh, TOKEN_TYPE_REFRESH)
            .expect("token from previous secret must verify during rotation window");
        assert_eq!(claims.sub, "alice");
    }

    #[test]
    fn test_token_with_unknown_kid_rejected() {
        let minted_by =
            JwtKeys::new("a-third-secret-key-no-longer-active!".to_string(), None).expect("keys");
        let (refresh, _) = encode_token_pair(&minted_by, "alice", ROLE_VIEW_ONLY).expect("pair");
        // Verifier knows primary+previous, neither matches the token's kid.
        assert!(decode_claims(&keys_with_previous(), &refresh, TOKEN_TYPE_REFRESH).is_err());
    }

    #[test]
    fn test_wrong_secret_rejected_without_previous() {
        let minted_by = keys();
        let (refresh, _) = encode_token_pair(&minted_by, "alice", ROLE_VIEW_ONLY).expect("pair");
        let other = JwtKeys::new(OTHER_SECRET.to_string(), None).expect("keys");
        assert!(decode_claims(&other, &refresh, TOKEN_TYPE_REFRESH).is_err());
    }

    #[test]
    fn test_legacy_token_without_aud_fid_rejected() {
        // Hard-cutover regression test: a pre-rollout token body (no aud/fid,
        // no kid header) must fail to decode rather than skip aud validation.
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct LegacyClaims<'a> {
            sub: &'a str,
            token_type: &'a str,
            exp: usize,
            iat: usize,
            jti: &'a str,
            iss: &'a str,
        }
        let now = chrono::Utc::now().timestamp() as usize;
        let legacy = LegacyClaims {
            sub: "alice",
            token_type: TOKEN_TYPE_REFRESH,
            exp: now + 3600,
            iat: now,
            jti: "legacy-jti",
            iss: JWT_ISSUER,
        };
        let token = encode(
            &Header::default(),
            &legacy,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("legacy token encodes");
        assert!(decode_claims(&keys(), &token, TOKEN_TYPE_REFRESH).is_err());
    }

    #[test]
    fn test_jwt_keys_validation() {
        assert!(JwtKeys::new("short".to_string(), None).is_err());
        assert!(JwtKeys::new(TEST_SECRET.to_string(), Some("short".to_string())).is_err());
        assert!(
            JwtKeys::new(TEST_SECRET.to_string(), Some(TEST_SECRET.to_string())).is_err(),
            "previous == primary must be rejected"
        );
        assert!(JwtKeys::new(TEST_SECRET.to_string(), Some(OTHER_SECRET.to_string())).is_ok());
    }

    #[test]
    fn test_expired_token_rejected() {
        // Manually build an already-expired token with full new-format claims.
        use jsonwebtoken::{encode, EncodingKey};
        let k = keys();
        let claims = Claims {
            sub: "alice".to_string(),
            token_type: TOKEN_TYPE_TEMPORAL.to_string(),
            iat: 1000,
            exp: 1001,
            jti: "expired-jti".to_string(),
            iss: JWT_ISSUER.to_string(),
            aud: JWT_AUDIENCE.to_string(),
            fid: "f".to_string(),
            role: ROLE_VIEW_ONLY.to_string(),
        };
        let token = encode(
            &k.signing_header(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("encodes");
        assert!(decode_claims(&k, &token, TOKEN_TYPE_TEMPORAL).is_err());
    }
}

use jsonwebtoken::{encode, EncodingKey, Header};
use log::error;

use crate::constants::{
    JWT_ISSUER, REFRESH_TOKEN_TTL_SECS, TEMPORAL_TOKEN_TTL_SECS, TOKEN_TYPE_REFRESH,
    TOKEN_TYPE_TEMPORAL,
};
use crate::error::AppError;
use crate::models::Claims;

/// Encode a long-lived refresh token for the given subject.
pub fn encode_refresh_token(secret: &[u8], subject: &str) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp() as usize;

    let claims = Claims {
        sub: subject.to_string(),
        token_type: TOKEN_TYPE_REFRESH.to_string(),
        iat: now,
        exp: now + REFRESH_TOKEN_TTL_SECS,
        jti: uuid::Uuid::new_v4().to_string(),
        iss: JWT_ISSUER.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| {
        error!("encode_refresh_token: failed to encode JWT: {}", e);
        AppError::InternalError("Failed to generate token".to_string())
    })
}

/// Encode a short-lived temporal token for the given subject.
pub fn encode_temporal_token(secret: &[u8], subject: &str) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp() as usize;

    let claims = Claims {
        sub: subject.to_string(),
        token_type: TOKEN_TYPE_TEMPORAL.to_string(),
        iat: now,
        exp: now + TEMPORAL_TOKEN_TTL_SECS,
        jti: uuid::Uuid::new_v4().to_string(),
        iss: JWT_ISSUER.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| {
        error!("encode_temporal_token: failed to encode JWT: {}", e);
        AppError::InternalError("Failed to generate token".to_string())
    })
}

/// Encode both a refresh and a temporal token for the given subject.
///
/// Returns `(refresh_token, temporal_token)`.
pub fn encode_token_pair(secret: &[u8], subject: &str) -> Result<(String, String), AppError> {
    let refresh = encode_refresh_token(secret, subject)?;
    let temporal = encode_temporal_token(secret, subject)?;
    Ok((refresh, temporal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{JWT_ISSUER, TOKEN_TYPE_REFRESH, TOKEN_TYPE_TEMPORAL};
    use crate::models::Claims;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    const TEST_SECRET: &[u8] = b"test-secret-key-for-jwt-unit-tests";

    #[test]
    fn test_encode_token_pair_returns_two_different_tokens() {
        let (refresh, temporal) =
            encode_token_pair(TEST_SECRET, "alice").expect("token pair should succeed");

        assert_ne!(refresh, temporal, "refresh and temporal tokens must differ");
        assert!(!refresh.is_empty());
        assert!(!temporal.is_empty());
    }

    #[test]
    fn test_tokens_decode_with_same_secret() {
        let (refresh, temporal) =
            encode_token_pair(TEST_SECRET, "bob").expect("token pair should succeed");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let refresh_data = decode::<Claims>(
            &refresh,
            &DecodingKey::from_secret(TEST_SECRET),
            &validation,
        )
        .expect("refresh token should decode");

        let temporal_data = decode::<Claims>(
            &temporal,
            &DecodingKey::from_secret(TEST_SECRET),
            &validation,
        )
        .expect("temporal token should decode");

        assert_eq!(refresh_data.claims.sub, "bob");
        assert_eq!(temporal_data.claims.sub, "bob");
    }

    #[test]
    fn test_tokens_contain_correct_claims() {
        let (refresh, temporal) =
            encode_token_pair(TEST_SECRET, "carol").expect("token pair should succeed");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let refresh_claims = decode::<Claims>(
            &refresh,
            &DecodingKey::from_secret(TEST_SECRET),
            &validation,
        )
        .expect("refresh token should decode")
        .claims;

        let temporal_claims = decode::<Claims>(
            &temporal,
            &DecodingKey::from_secret(TEST_SECRET),
            &validation,
        )
        .expect("temporal token should decode")
        .claims;

        // Subject
        assert_eq!(refresh_claims.sub, "carol");
        assert_eq!(temporal_claims.sub, "carol");

        // Token types
        assert_eq!(refresh_claims.token_type, TOKEN_TYPE_REFRESH);
        assert_eq!(temporal_claims.token_type, TOKEN_TYPE_TEMPORAL);

        // Issuer
        assert_eq!(refresh_claims.iss, JWT_ISSUER);
        assert_eq!(temporal_claims.iss, JWT_ISSUER);

        // JTI must be non-empty and unique
        assert!(!refresh_claims.jti.is_empty());
        assert!(!temporal_claims.jti.is_empty());
        assert_ne!(refresh_claims.jti, temporal_claims.jti);

        // Expiry must be in the future
        let now = chrono::Utc::now().timestamp() as usize;
        assert!(refresh_claims.exp > now);
        assert!(temporal_claims.exp > now);
    }
}

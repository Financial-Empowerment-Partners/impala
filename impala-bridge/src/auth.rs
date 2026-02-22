use crate::constants::TOKEN_TYPE_TEMPORAL;
use crate::error::AppError;
use crate::models::Claims;
use axum::extract::{Extension, FromRequest, RequestParts};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;

/// Represents an authenticated user extracted from a valid JWT temporal token.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub account_id: String,
}

#[axum::async_trait]
impl<B> FromRequest<B> for AuthenticatedUser
where
    B: Send,
{
    type Rejection = AppError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the JWT secret from extensions
        let Extension(jwt_secret) = Extension::<Arc<String>>::from_request(req)
            .await
            .map_err(|_| AppError::InternalError("JWT secret not configured".to_string()))?;

        // Extract Authorization header
        let headers = req.headers().ok_or(AppError::Unauthorized)?;
        let auth_header = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        // Expect "Bearer <token>"
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        // Decode and validate the JWT
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Unauthorized)?;

        // Must be a temporal token
        if token_data.claims.token_type != TOKEN_TYPE_TEMPORAL {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthenticatedUser {
            account_id: token_data.claims.sub,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::{REFRESH_TOKEN_TTL_SECS, TEMPORAL_TOKEN_TTL_SECS};
    use crate::models::Claims;
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

    const TEST_SECRET: &str = "test-secret-key-for-unit-tests";

    #[test]
    fn test_jwt_encode_decode_temporal() {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "testuser".to_string(),
            token_type: "temporal".to_string(),
            iat: now,
            exp: now + TEMPORAL_TOKEN_TTL_SECS,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &Validation::default(),
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.sub, "testuser");
        assert_eq!(decoded.claims.token_type, "temporal");
    }

    #[test]
    fn test_jwt_encode_decode_refresh() {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "testuser".to_string(),
            token_type: "refresh".to_string(),
            iat: now,
            exp: now + REFRESH_TOKEN_TTL_SECS,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &Validation::default(),
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.sub, "testuser");
        assert_eq!(decoded.claims.token_type, "refresh");
    }

    #[test]
    fn test_jwt_expired_token_rejected() {
        let claims = Claims {
            sub: "testuser".to_string(),
            token_type: "temporal".to_string(),
            iat: 1000,
            exp: 1001, // Already expired
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &Validation::default(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_wrong_secret_rejected() {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "testuser".to_string(),
            token_type: "temporal".to_string(),
            iat: now,
            exp: now + TEMPORAL_TOKEN_TTL_SECS,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(b"wrong-secret"),
            &Validation::default(),
        );

        assert!(result.is_err());
    }
}

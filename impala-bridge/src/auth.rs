use crate::constants::{JWT_ISSUER, TOKEN_TYPE_TEMPORAL};
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

/// Verify that the authenticated user owns the specified account.
/// Returns `Err(AppError::Forbidden)` if `user.account_id` does not match.
pub fn require_owner(user: &AuthenticatedUser, account_id: &str) -> Result<(), AppError> {
    if user.account_id != account_id {
        return Err(AppError::Forbidden);
    }
    Ok(())
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

        // Decode and validate the JWT with explicit HS256 and issuer check
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized)?;

        // Must be a temporal token
        if token_data.claims.token_type != TOKEN_TYPE_TEMPORAL {
            return Err(AppError::Unauthorized);
        }

        // Check if token has been revoked (via /logout)
        let Extension(redis_pool) = Extension::<Arc<deadpool_redis::Pool>>::from_request(req)
            .await
            .map_err(|_| AppError::Unauthorized)?;

        if crate::redis_helpers::is_token_revoked(&redis_pool, &token_data.claims.jti).await? {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthenticatedUser {
            account_id: token_data.claims.sub,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::{JWT_ISSUER, REFRESH_TOKEN_TTL_SECS, TEMPORAL_TOKEN_TTL_SECS};
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
            jti: uuid::Uuid::new_v4().to_string(),
            iss: JWT_ISSUER.to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &validation,
        )
        .expect("Failed to decode JWT");

        assert_eq!(decoded.claims.sub, "testuser");
        assert_eq!(decoded.claims.token_type, "temporal");
        assert_eq!(decoded.claims.iss, JWT_ISSUER);
        assert!(!decoded.claims.jti.is_empty());
    }

    #[test]
    fn test_jwt_encode_decode_refresh() {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "testuser".to_string(),
            token_type: "refresh".to_string(),
            iat: now,
            exp: now + REFRESH_TOKEN_TTL_SECS,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: JWT_ISSUER.to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &validation,
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
            jti: uuid::Uuid::new_v4().to_string(),
            iss: JWT_ISSUER.to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &validation,
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
            jti: uuid::Uuid::new_v4().to_string(),
            iss: JWT_ISSUER.to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(b"wrong-secret"),
            &validation,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_wrong_issuer_rejected() {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "testuser".to_string(),
            token_type: "temporal".to_string(),
            iat: now,
            exp: now + TEMPORAL_TOKEN_TTL_SECS,
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "wrong-issuer".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .expect("Failed to encode JWT");

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.iss = Some(JWT_ISSUER.to_string());

        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(TEST_SECRET.as_bytes()),
            &validation,
        );

        assert!(result.is_err());
    }
}

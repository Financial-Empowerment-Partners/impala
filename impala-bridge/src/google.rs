//! Google ID-token validation (mirrors `okta.rs`, reusing its
//! provider-agnostic JWKS types).
//!
//! Google publishes its RS256 signing keys at a fixed JWKS endpoint
//! (`GOOGLE_JWKS_URL`), so no OIDC discovery round-trip is needed. Tokens are
//! validated for signature, expiry, audience (`GOOGLE_CLIENT_ID`) and issuer
//! (both `https://accounts.google.com` and `accounts.google.com` — Google
//! emits either form).

use log::{debug, info, warn};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::constants::{GOOGLE_JWKS_URL, GOOGLE_TOKEN_ISSUERS};
use crate::error::AppError;
use crate::okta::{fetch_jwks, JwksResponse};

/// Claims from a validated Google ID token.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // claims validated by the JWT library during decode; not all read here
pub struct GoogleIdTokenClaims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: usize,
    pub iat: usize,
    pub email: Option<String>,
    /// Google asserts this only for emails it has verified; the bridge uses
    /// the email as account id ONLY when this is `true`.
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Shared Google provider state.
///
/// Same boot semantics as the OIDC registry: constructed without network
/// I/O, PENDING until [`provider_task`] loads the JWKS (immediately, with
/// retries), 503 on token exchange and `enabled: false, pending: true` on
/// `/config` meanwhile.
pub struct GoogleProvider {
    pub client_id: String,
    pub http_client: reqwest::Client,
    /// Debounce for the unauthenticated on-demand JWKS refetch path.
    pub refresh_cooldown: crate::oidc::RefreshCooldown,
    jwks: RwLock<Option<JwksResponse>>,
}

impl GoogleProvider {
    pub async fn is_ready(&self) -> bool {
        self.jwks.read().await.is_some()
    }

    /// Readiness as reported by `GET /health`.
    pub async fn state_label(&self) -> &'static str {
        if self.is_ready().await {
            crate::oidc::PROVIDER_STATE_READY
        } else {
            crate::oidc::PROVIDER_STATE_PENDING
        }
    }

    /// One JWKS fetch; the first success makes the provider READY.
    pub async fn sync_from_idp(&self) -> Result<(), AppError> {
        let jwks = fetch_jwks(&self.http_client, GOOGLE_JWKS_URL).await?;
        *self.jwks.write().await = Some(jwks);
        Ok(())
    }
}

/// Construct the Google provider (PENDING) if `GOOGLE_CLIENT_ID` is set.
/// No network I/O happens here; see [`provider_task`].
pub fn init_google_provider(config: &Config) -> Option<Arc<GoogleProvider>> {
    let client_id = config.google_client_id.as_ref()?;
    if client_id.trim().is_empty() {
        return None;
    }

    info!(
        "google: provider configured for client_id={} (pending JWKS)",
        client_id
    );

    Some(Arc::new(GoogleProvider {
        client_id: client_id.clone(),
        http_client: crate::oidc::build_idp_client(config.http_client_timeout_secs),
        refresh_cooldown: crate::oidc::RefreshCooldown::new(),
        jwks: RwLock::new(None),
    }))
}

/// Background task: initial JWKS fetch with immediate retries, then periodic
/// refresh (see `crate::oidc::drive_provider`).
pub async fn provider_task(
    provider: Arc<GoogleProvider>,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    crate::oidc::drive_provider("google".to_string(), interval_secs, cancel, move || {
        let p = provider.clone();
        Box::pin(async move { p.sync_from_idp().await })
    })
    .await;
}

/// Validate a Google ID token and return its claims.
///
/// Same flow as `okta::validate_okta_token`: cached JWKS first, then a
/// one-shot refresh when the `kid` is unknown (key rotation).
pub async fn validate_google_id_token(
    provider: &GoogleProvider,
    token: &str,
) -> Result<GoogleIdTokenClaims, AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        warn!("google: failed to decode token header: {}", e);
        AppError::Unauthorized
    })?;

    let kid = header.kid.as_deref().unwrap_or("");

    // Try to find the key in the cached JWKS. PENDING (no keys yet) is a
    // 503, not a 401: the token has not been judged at all.
    let claims = {
        let jwks = provider.jwks.read().await;
        let Some(jwks) = jwks.as_ref() else {
            warn!("google: token exchange refused: provider still PENDING (JWKS not loaded)");
            return Err(crate::oidc::pending_error("google"));
        };
        try_validate_with_jwks(jwks, token, kid, provider)
    };

    match claims {
        Ok(c) => Ok(c),
        Err(_) if !kid.is_empty() => {
            // Key not found or validation failed — try refreshing JWKS once,
            // subject to the cooldown (see crate::oidc::RefreshCooldown): this
            // path is reachable unauthenticated with an attacker-chosen kid.
            if !provider
                .refresh_cooldown
                .try_acquire(std::time::Duration::from_secs(
                    crate::constants::JWKS_ON_DEMAND_COOLDOWN_SECS,
                ))
            {
                debug!("google: skipping JWKS refresh for kid={} (cooldown)", kid);
                return Err(AppError::Unauthorized);
            }
            debug!(
                "google: key kid={} not found in cache, refreshing JWKS",
                kid
            );
            match fetch_jwks(&provider.http_client, GOOGLE_JWKS_URL).await {
                Ok(new_jwks) => {
                    let result = try_validate_with_jwks(&new_jwks, token, kid, provider);
                    // Update the cache with the refreshed keys
                    *provider.jwks.write().await = Some(new_jwks);
                    result
                }
                Err(_) => {
                    warn!("google: JWKS refresh failed during token validation");
                    Err(AppError::Unauthorized)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Attempt to validate a token against a JWKS key set.
/// Requires exact `kid` match with `kty == "RSA"`, compatible `alg`, and `use == "sig"`.
fn try_validate_with_jwks(
    jwks: &JwksResponse,
    token: &str,
    kid: &str,
    provider: &GoogleProvider,
) -> Result<GoogleIdTokenClaims, AppError> {
    let jwk = jwks
        .keys
        .iter()
        .find(|k| {
            k.kid.as_deref() == Some(kid)
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        })
        .ok_or_else(|| {
            warn!("google: no matching JWK found for kid={}", kid);
            AppError::Unauthorized
        })?;

    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            warn!("google: failed to construct decoding key: {}", e);
            AppError::Unauthorized
        })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&GOOGLE_TOKEN_ISSUERS);
    validation.set_audience(&[&provider.client_id]);

    let token_data = jsonwebtoken::decode::<GoogleIdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| {
            warn!("google: token validation failed: {}", e);
            AppError::Unauthorized
        })?;

    debug!("google: token validated for sub={}", token_data.claims.sub);
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_claims_deserialize_verified_email() {
        let json = r#"{
            "sub": "110169484474386276334",
            "iss": "https://accounts.google.com",
            "aud": "1234567890-abc.apps.googleusercontent.com",
            "exp": 1700000000,
            "iat": 1699996400,
            "email": "User@Example.com",
            "email_verified": true,
            "name": "Test User"
        }"#;

        let claims: GoogleIdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "110169484474386276334");
        assert!(claims.email_verified);
        assert_eq!(claims.email.as_deref(), Some("User@Example.com"));
    }

    #[test]
    fn test_google_claims_email_verified_defaults_false() {
        // A token without the email_verified claim must never be treated as
        // verified (the email would otherwise become the account id).
        let json = r#"{
            "sub": "s",
            "iss": "accounts.google.com",
            "exp": 1700000000,
            "iat": 1699996400,
            "email": "user@example.com"
        }"#;

        let claims: GoogleIdTokenClaims = serde_json::from_str(json).unwrap();
        assert!(!claims.email_verified);
    }

    #[tokio::test]
    async fn configured_provider_starts_pending_and_refuses_with_503() {
        let mut config = crate::config::test_config();
        config.google_client_id = Some("1234567890-abc.apps.googleusercontent.com".to_string());
        let provider = init_google_provider(&config).expect("configured");
        assert!(!provider.is_ready().await);
        assert_eq!(
            provider.state_label().await,
            crate::oidc::PROVIDER_STATE_PENDING
        );
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.c2ln";
        assert!(matches!(
            validate_google_id_token(&provider, token).await,
            Err(AppError::Retryable(_))
        ));

        config.google_client_id = Some("  ".to_string());
        assert!(init_google_provider(&config).is_none());
    }

    #[test]
    fn test_google_issuer_list_pins_both_forms() {
        assert_eq!(
            GOOGLE_TOKEN_ISSUERS,
            ["https://accounts.google.com", "accounts.google.com"]
        );
    }
}

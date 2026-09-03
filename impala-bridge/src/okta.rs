use log::{debug, error, info, warn};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::AppError;

/// OIDC discovery document from the authorization server.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // full discovery doc deserialized; not every field is read
pub struct OidcDiscovery {
    #[allow(dead_code)] // part of the OIDC discovery document; retained for completeness
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// JWKS key set response.
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// Individual JSON Web Key (RSA public key).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub n: String,
    pub e: String,
}

/// Claims from a validated Okta access token.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // claims validated by the JWT library during decode; not all read here
pub struct OktaAccessTokenClaims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: usize,
    pub iat: usize,
    pub uid: Option<String>,
    pub email: Option<String>,
    /// Whether the IdP asserts the email is verified. Load-bearing: the bridge
    /// shares one account namespace across every configured IdP, so an
    /// unverified (or absent) email must NOT key an account — see the
    /// `derive_sso_account_id`/`derive_google_account_id` guards this mirrors.
    #[serde(default)]
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
}

/// Discovery + keys learned from Okta; absent while the provider is PENDING.
#[derive(Debug, Clone)]
pub struct OktaReady {
    pub discovery: OidcDiscovery,
    pub jwks: JwksResponse,
}

/// Shared Okta provider state (legacy single-provider `/auth/okta` flow).
///
/// Same boot semantics as the OIDC registry (`crate::oidc::OidcProvider`):
/// constructed from config without network I/O, brought to READY by
/// [`provider_task`] with immediate retries, 503 on token exchange and
/// `enabled: false, pending: true` on `/config` until then.
pub struct OktaProvider {
    pub client_id: String,
    pub issuer_url: String,
    pub http_client: reqwest::Client,
    /// Debounce for the unauthenticated on-demand JWKS refetch path.
    pub refresh_cooldown: crate::oidc::RefreshCooldown,
    state: RwLock<Option<OktaReady>>,
}

impl OktaProvider {
    pub async fn is_ready(&self) -> bool {
        self.state.read().await.is_some()
    }

    /// Readiness as reported by `GET /health`.
    pub async fn state_label(&self) -> &'static str {
        if self.is_ready().await {
            crate::oidc::PROVIDER_STATE_READY
        } else {
            crate::oidc::PROVIDER_STATE_PENDING
        }
    }

    /// Discovery endpoints for `/config`; `None` while pending.
    pub async fn discovery(&self) -> Option<OidcDiscovery> {
        self.state
            .read()
            .await
            .as_ref()
            .map(|r| r.discovery.clone())
    }

    /// One attempt to (re)load IdP state: discovery + JWKS while pending,
    /// JWKS refresh once ready.
    pub async fn sync_from_idp(&self) -> Result<(), AppError> {
        let jwks_uri = self
            .state
            .read()
            .await
            .as_ref()
            .map(|r| r.discovery.jwks_uri.clone());
        match jwks_uri {
            Some(uri) => {
                let jwks = fetch_jwks(&self.http_client, &uri).await?;
                if let Some(ready) = self.state.write().await.as_mut() {
                    ready.jwks = jwks;
                }
                Ok(())
            }
            None => {
                let discovery = fetch_discovery(&self.http_client, &self.issuer_url).await?;
                let jwks = fetch_jwks(&self.http_client, &discovery.jwks_uri).await?;
                *self.state.write().await = Some(OktaReady { discovery, jwks });
                Ok(())
            }
        }
    }
}

/// Fetch the OIDC discovery document from the authorization server.
/// Tries `.well-known/oauth-authorization-server` first, then falls back
/// to `.well-known/openid-configuration`.
pub async fn fetch_discovery(
    client: &reqwest::Client,
    issuer_url: &str,
) -> Result<OidcDiscovery, AppError> {
    let base = issuer_url.trim_end_matches('/');

    let oauth_url = format!("{}/.well-known/oauth-authorization-server", base);
    debug!("okta: fetching discovery from {}", oauth_url);

    match client.get(&oauth_url).send().await {
        Ok(res) if res.status().is_success() => {
            let discovery: OidcDiscovery = res.json().await.map_err(|e| {
                error!("okta: failed to parse discovery document: {}", e);
                AppError::InternalError("Failed to parse Okta discovery document".to_string())
            })?;
            info!("okta: discovery loaded from oauth-authorization-server");
            return Ok(discovery);
        }
        _ => {
            debug!("okta: oauth-authorization-server not found, trying openid-configuration");
        }
    }

    let oidc_url = format!("{}/.well-known/openid-configuration", base);
    let res = client.get(&oidc_url).send().await.map_err(|e| {
        error!("okta: failed to fetch openid-configuration: {}", e);
        AppError::InternalError("Failed to fetch Okta discovery document".to_string())
    })?;

    if !res.status().is_success() {
        error!("okta: discovery endpoint returned {}", res.status());
        return Err(AppError::InternalError(
            "Okta discovery endpoint returned an error".to_string(),
        ));
    }

    let discovery: OidcDiscovery = res.json().await.map_err(|e| {
        error!("okta: failed to parse openid-configuration: {}", e);
        AppError::InternalError("Failed to parse Okta discovery document".to_string())
    })?;

    info!("okta: discovery loaded from openid-configuration");
    Ok(discovery)
}

/// Fetch the JWKS key set from the provider.
pub async fn fetch_jwks(
    client: &reqwest::Client,
    jwks_uri: &str,
) -> Result<JwksResponse, AppError> {
    debug!("okta: fetching JWKS from {}", jwks_uri);
    let res = client.get(jwks_uri).send().await.map_err(|e| {
        error!("okta: failed to fetch JWKS: {}", e);
        AppError::InternalError("Failed to fetch JWKS".to_string())
    })?;

    if !res.status().is_success() {
        error!("okta: JWKS endpoint returned {}", res.status());
        return Err(AppError::InternalError(
            "JWKS endpoint returned an error".to_string(),
        ));
    }

    let jwks: JwksResponse = res.json().await.map_err(|e| {
        error!("okta: failed to parse JWKS: {}", e);
        AppError::InternalError("Failed to parse JWKS".to_string())
    })?;

    info!("okta: loaded {} keys from JWKS", jwks.keys.len());
    Ok(jwks)
}

/// Construct the legacy Okta provider (PENDING) if configured.
///
/// `Ok(None)` = `OKTA_ISSUER_URL` unset/empty. `Err` = the issuer is not
/// HTTPS, which is fatal at startup like any other invalid configuration.
/// No network I/O happens here; see [`provider_task`].
pub fn init_okta_provider(config: &Config) -> Result<Option<Arc<OktaProvider>>, String> {
    let Some(issuer_url) = config.okta_issuer_url.as_ref() else {
        return Ok(None);
    };
    if issuer_url.trim().is_empty() {
        return Ok(None);
    }
    let client_id = config.okta_client_id.clone().unwrap_or_default();

    // Validate that issuer URL uses HTTPS
    if !issuer_url.starts_with("https://") {
        return Err(format!("okta: issuer URL must use HTTPS: {}", issuer_url));
    }

    info!(
        "okta: provider configured for issuer {} (pending IdP discovery)",
        issuer_url
    );

    Ok(Some(Arc::new(OktaProvider {
        client_id,
        issuer_url: issuer_url.clone(),
        http_client: crate::oidc::build_idp_client(config.http_client_timeout_secs),
        refresh_cooldown: crate::oidc::RefreshCooldown::new(),
        state: RwLock::new(None),
    })))
}

/// Background task: initial discovery + JWKS with immediate retries, then
/// periodic JWKS refresh (see `crate::oidc::drive_provider`).
pub async fn provider_task(
    provider: Arc<OktaProvider>,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    crate::oidc::drive_provider("okta".to_string(), interval_secs, cancel, move || {
        let p = provider.clone();
        Box::pin(async move { p.sync_from_idp().await })
    })
    .await;
}

/// Validate an Okta access token and return its claims.
///
/// 1. Decodes the JWT header to extract the `kid`.
/// 2. Finds the matching key in the cached JWKS.
/// 3. If not found, triggers a one-shot JWKS refresh before failing.
/// 4. Validates the token signature (RS256), issuer, and audience.
pub async fn validate_okta_token(
    provider: &OktaProvider,
    token: &str,
) -> Result<OktaAccessTokenClaims, AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        warn!("okta: failed to decode token header: {}", e);
        AppError::Unauthorized
    })?;

    let kid = header.kid.as_deref().unwrap_or("");

    // Try to find the key in the cached JWKS. PENDING (no keys yet) is a
    // 503, not a 401: the token has not been judged at all.
    let (claims, jwks_uri) = {
        let state = provider.state.read().await;
        let Some(ready) = state.as_ref() else {
            warn!(
                "okta: token exchange refused: provider still PENDING (discovery/JWKS not loaded)"
            );
            return Err(crate::oidc::pending_error("okta"));
        };
        (
            try_validate_with_jwks(&ready.jwks, token, kid, provider),
            ready.discovery.jwks_uri.clone(),
        )
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
                debug!("okta: skipping JWKS refresh for kid={} (cooldown)", kid);
                return Err(AppError::Unauthorized);
            }
            debug!("okta: key kid={} not found in cache, refreshing JWKS", kid);
            match fetch_jwks(&provider.http_client, &jwks_uri).await {
                Ok(new_jwks) => {
                    let result = try_validate_with_jwks(&new_jwks, token, kid, provider);
                    // Update the cache with the refreshed keys
                    if let Some(ready) = provider.state.write().await.as_mut() {
                        ready.jwks = new_jwks;
                    }
                    result
                }
                Err(_) => {
                    warn!("okta: JWKS refresh failed during token validation");
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
    provider: &OktaProvider,
) -> Result<OktaAccessTokenClaims, AppError> {
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
            warn!("okta: no matching JWK found for kid={}", kid);
            AppError::Unauthorized
        })?;

    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            warn!("okta: failed to construct decoding key: {}", e);
            AppError::Unauthorized
        })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[provider.issuer_url.as_str()]);
    validation.set_audience(&[&provider.client_id]);

    let token_data =
        jsonwebtoken::decode::<OktaAccessTokenClaims>(token, &decoding_key, &validation).map_err(
            |e| {
                warn!("okta: token validation failed: {}", e);
                AppError::Unauthorized
            },
        )?;

    debug!("okta: token validated for sub={}", token_data.claims.sub);
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_discovery_deserialize() {
        let json = r#"{
            "issuer": "https://dev-12345.okta.com/oauth2/default",
            "authorization_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/authorize",
            "token_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/token",
            "jwks_uri": "https://dev-12345.okta.com/oauth2/default/v1/keys",
            "scopes_supported": ["openid", "profile", "email"]
        }"#;

        let discovery: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(
            discovery.issuer,
            "https://dev-12345.okta.com/oauth2/default"
        );
        assert_eq!(discovery.scopes_supported.len(), 3);
    }

    #[test]
    fn test_jwks_deserialize() {
        let json = r#"{
            "keys": [{
                "kty": "RSA",
                "kid": "test-key-id",
                "alg": "RS256",
                "use": "sig",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }]
        }"#;

        let jwks: JwksResponse = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("test-key-id"));
        assert_eq!(jwks.keys[0].kty, "RSA");
    }

    #[tokio::test]
    async fn configured_provider_starts_pending_and_refuses_with_503() {
        let mut config = crate::config::test_config();
        config.okta_issuer_url = Some("https://dev-12345.okta.com/oauth2/default".to_string());
        config.okta_client_id = Some("0oa1234567890".to_string());
        let provider = init_okta_provider(&config).unwrap().expect("configured");
        assert!(!provider.is_ready().await);
        assert!(provider.discovery().await.is_none());
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.c2ln";
        assert!(matches!(
            validate_okta_token(&provider, token).await,
            Err(AppError::Retryable(_))
        ));
    }

    #[test]
    fn unset_issuer_is_not_configured_and_plain_http_is_fatal() {
        let mut config = crate::config::test_config();
        config.okta_issuer_url = None;
        assert!(init_okta_provider(&config).unwrap().is_none());
        config.okta_issuer_url = Some("".to_string());
        assert!(init_okta_provider(&config).unwrap().is_none());
        config.okta_issuer_url = Some("http://dev-12345.okta.com".to_string());
        assert!(init_okta_provider(&config).is_err());
    }

    #[test]
    fn test_okta_claims_deserialize() {
        let json = r#"{
            "sub": "user123",
            "iss": "https://dev-12345.okta.com/oauth2/default",
            "aud": "0oa1234567890",
            "exp": 1700000000,
            "iat": 1699996400,
            "uid": "00u1234",
            "email": "user@example.com",
            "preferred_username": "user@example.com"
        }"#;

        let claims: OktaAccessTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_jwk_key_lookup_exact_kid() {
        let jwks = JwksResponse {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                    n: "test_n".to_string(),
                    e: "test_e".to_string(),
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key2".to_string()),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                    n: "test_n2".to_string(),
                    e: "test_e2".to_string(),
                },
            ],
        };

        // Exact kid match works
        let found = jwks.keys.iter().find(|k| {
            k.kid.as_deref() == Some("key2")
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        });
        assert!(found.is_some());
        assert_eq!(found.unwrap().n, "test_n2");

        // Non-existent kid returns None (no fallback)
        let not_found = jwks.keys.iter().find(|k| {
            k.kid.as_deref() == Some("key3")
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        });
        assert!(not_found.is_none());
    }

    #[test]
    fn test_jwk_rejects_enc_key() {
        let jwks = JwksResponse {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: Some("enc-key".to_string()),
                alg: Some("RS256".to_string()),
                use_: Some("enc".to_string()),
                n: "test_n".to_string(),
                e: "test_e".to_string(),
            }],
        };

        let found = jwks.keys.iter().find(|k| {
            k.kid.as_deref() == Some("enc-key")
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        });
        assert!(found.is_none());
    }
}

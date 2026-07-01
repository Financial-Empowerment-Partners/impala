use log::{debug, error, info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{Config, ProviderConfig, TokenKind};
use crate::error::AppError;

/// OIDC discovery document from the authorization server.
#[derive(Debug, Clone, Deserialize)]
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

/// Claims from a validated OIDC token (access or id token).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // claims document the token wire format; only some are read
pub struct OidcTokenClaims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: usize,
    pub iat: usize,
    pub uid: Option<String>,
    pub email: Option<String>,
    /// Present on id tokens (and access tokens that add the claim). Used to
    /// decide whether an email may be trusted to key a shared account across
    /// providers — see `handlers::sso`.
    #[serde(default)]
    pub email_verified: Option<bool>,
    pub preferred_username: Option<String>,
}

/// Shared per-provider OIDC state (one per configured IdP).
pub struct OidcProvider {
    /// Provider name (`okta` | `auth0` | `duo` | …). Drives `profile_source`,
    /// `auth_provider`, the rate-limit scope, and log context.
    pub name: String,
    pub discovery: OidcDiscovery,
    pub jwks: Arc<RwLock<JwksResponse>>,
    pub client_id: String,
    /// The value validated as the JWT `aud`. Defaults to `client_id`.
    pub audience: String,
    /// Stored verbatim from config/discovery — must match the token `iss`
    /// exactly (e.g. Auth0 issuers carry a trailing slash).
    pub issuer_url: String,
    /// Which token the browser sends for validation (access vs id).
    pub token_kind: TokenKind,
    pub jwks_refresh_secs: u64,
    pub http_client: reqwest::Client,
}

/// Registry of all configured OIDC providers, shared as a single Axum extension.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<OidcProvider>>,
}

impl ProviderRegistry {
    /// Look up a provider by name.
    pub fn get(&self, name: &str) -> Option<Arc<OidcProvider>> {
        self.providers.get(name).cloned()
    }

    /// Iterate over all configured providers.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<OidcProvider>> {
        self.providers.values()
    }

    /// Sorted list of configured provider names (for `GET /auth/providers`).
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.providers.keys().cloned().collect();
        names.sort();
        names
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

/// Fetch the OIDC discovery document from the authorization server.
/// Tries `.well-known/oauth-authorization-server` first, then falls back
/// to `.well-known/openid-configuration` (which covers Auth0/Duo/Okta).
pub async fn fetch_discovery(
    client: &reqwest::Client,
    name: &str,
    issuer_url: &str,
) -> Result<OidcDiscovery, AppError> {
    let base = issuer_url.trim_end_matches('/');

    let oauth_url = format!("{}/.well-known/oauth-authorization-server", base);
    debug!("oidc[{}]: fetching discovery from {}", name, oauth_url);

    match client.get(&oauth_url).send().await {
        Ok(res) if res.status().is_success() => {
            let discovery: OidcDiscovery = res.json().await.map_err(|e| {
                error!("oidc[{}]: failed to parse discovery document: {}", name, e);
                AppError::InternalError("Failed to parse OIDC discovery document".to_string())
            })?;
            info!("oidc[{}]: discovery loaded from oauth-authorization-server", name);
            return Ok(discovery);
        }
        _ => {
            debug!(
                "oidc[{}]: oauth-authorization-server not found, trying openid-configuration",
                name
            );
        }
    }

    let oidc_url = format!("{}/.well-known/openid-configuration", base);
    let res = client.get(&oidc_url).send().await.map_err(|e| {
        error!("oidc[{}]: failed to fetch openid-configuration: {}", name, e);
        AppError::InternalError("Failed to fetch OIDC discovery document".to_string())
    })?;

    if !res.status().is_success() {
        error!("oidc[{}]: discovery endpoint returned {}", name, res.status());
        return Err(AppError::InternalError(
            "OIDC discovery endpoint returned an error".to_string(),
        ));
    }

    let discovery: OidcDiscovery = res.json().await.map_err(|e| {
        error!("oidc[{}]: failed to parse openid-configuration: {}", name, e);
        AppError::InternalError("Failed to parse OIDC discovery document".to_string())
    })?;

    info!("oidc[{}]: discovery loaded from openid-configuration", name);
    Ok(discovery)
}

/// Fetch the JWKS key set from the provider.
pub async fn fetch_jwks(
    client: &reqwest::Client,
    name: &str,
    jwks_uri: &str,
) -> Result<JwksResponse, AppError> {
    debug!("oidc[{}]: fetching JWKS from {}", name, jwks_uri);
    let res = client.get(jwks_uri).send().await.map_err(|e| {
        error!("oidc[{}]: failed to fetch JWKS: {}", name, e);
        AppError::InternalError("Failed to fetch JWKS".to_string())
    })?;

    if !res.status().is_success() {
        error!("oidc[{}]: JWKS endpoint returned {}", name, res.status());
        return Err(AppError::InternalError(
            "JWKS endpoint returned an error".to_string(),
        ));
    }

    let jwks: JwksResponse = res.json().await.map_err(|e| {
        error!("oidc[{}]: failed to parse JWKS: {}", name, e);
        AppError::InternalError("Failed to parse JWKS".to_string())
    })?;

    info!("oidc[{}]: loaded {} keys from JWKS", name, jwks.keys.len());
    Ok(jwks)
}

/// Initialize a single OIDC provider from its config. Returns `None`
/// (logging the reason) if the issuer is non-HTTPS or discovery/JWKS fails.
pub async fn init_provider(
    cfg: &ProviderConfig,
    http_client_timeout_secs: u64,
) -> Option<Arc<OidcProvider>> {
    if cfg.issuer_url.trim().is_empty() {
        return None;
    }

    // Validate that the issuer URL uses HTTPS.
    if !cfg.issuer_url.starts_with("https://") {
        error!("oidc[{}]: issuer URL must use HTTPS: {}", cfg.name, cfg.issuer_url);
        return None;
    }

    info!("oidc[{}]: initializing provider for issuer {}", cfg.name, cfg.issuer_url);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(http_client_timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("Failed to create HTTP client");

    let discovery = match fetch_discovery(&http_client, &cfg.name, &cfg.issuer_url).await {
        Ok(d) => d,
        Err(e) => {
            error!("oidc[{}]: failed to initialize provider: {}", cfg.name, e);
            return None;
        }
    };

    let jwks = match fetch_jwks(&http_client, &cfg.name, &discovery.jwks_uri).await {
        Ok(j) => j,
        Err(e) => {
            error!("oidc[{}]: failed to fetch initial JWKS: {}", cfg.name, e);
            return None;
        }
    };

    Some(Arc::new(OidcProvider {
        name: cfg.name.clone(),
        discovery,
        jwks: Arc::new(RwLock::new(jwks)),
        client_id: cfg.client_id.clone(),
        audience: cfg.audience.clone(),
        issuer_url: cfg.issuer_url.clone(),
        token_kind: cfg.token_kind,
        jwks_refresh_secs: cfg.jwks_refresh_secs,
        http_client,
    }))
}

/// Build the provider registry from config. Providers that fail to initialize
/// are logged and skipped so one bad IdP doesn't take down the others.
pub async fn init_registry(config: &Config) -> ProviderRegistry {
    let mut providers: HashMap<String, Arc<OidcProvider>> = HashMap::new();
    for cfg in &config.sso_providers {
        match init_provider(cfg, config.http_client_timeout_secs).await {
            Some(provider) => {
                providers.insert(cfg.name.clone(), provider);
            }
            None => {
                error!("oidc[{}]: provider failed to initialize; skipping", cfg.name);
            }
        }
    }
    if !providers.is_empty() {
        info!("oidc: {} provider(s) initialized", providers.len());
    }
    ProviderRegistry { providers }
}

/// Background task that periodically refreshes a provider's JWKS key set.
/// Uses exponential backoff on failure (capped at 5 minutes).
/// Respects cancellation for graceful shutdown.
pub async fn jwks_refresh_task(
    provider: Arc<OidcProvider>,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    use tokio::time::{Duration, Instant};

    let mut consecutive_failures: u32 = 0;
    let mut last_success = Instant::now();

    // Skip the first immediate tick since we already fetched during init
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
        _ = cancel.cancelled() => {
            info!("oidc[{}]: jwks_refresh_task shutting down", provider.name);
            return;
        }
    }

    loop {
        debug!("oidc[{}]: refreshing JWKS keys", provider.name);
        match fetch_jwks(&provider.http_client, &provider.name, &provider.discovery.jwks_uri).await {
            Ok(new_jwks) => {
                consecutive_failures = 0;
                last_success = Instant::now();
                let mut jwks = provider.jwks.write().await;
                *jwks = new_jwks;
                info!("oidc[{}]: JWKS keys refreshed successfully", provider.name);
            }
            Err(e) => {
                consecutive_failures += 1;
                let stale_secs = last_success.elapsed().as_secs();
                if stale_secs > interval_secs * 2 {
                    error!("oidc[{}]: JWKS keys are {} seconds stale", provider.name, stale_secs);
                } else {
                    warn!("oidc[{}]: failed to refresh JWKS keys: {}", provider.name, e);
                }
            }
        }

        let wait_secs = if consecutive_failures > 0 {
            std::cmp::min(
                interval_secs.saturating_mul(2u64.saturating_pow(consecutive_failures)),
                300,
            )
        } else {
            interval_secs
        };
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
            _ = cancel.cancelled() => {
                info!("oidc[{}]: jwks_refresh_task shutting down", provider.name);
                return;
            }
        }
    }
}

/// Validate an OIDC token (access or id) and return its claims.
///
/// 1. Decodes the JWT header to extract the `kid`.
/// 2. Finds the matching key in the cached JWKS.
/// 3. If not found, triggers a one-shot JWKS refresh before failing.
/// 4. Validates the token signature (RS256), issuer, and audience.
pub async fn validate_token(
    provider: &OidcProvider,
    token: &str,
) -> Result<OidcTokenClaims, AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        warn!("oidc[{}]: failed to decode token header: {}", provider.name, e);
        AppError::Unauthorized
    })?;

    let kid = header.kid.as_deref().unwrap_or("");

    // Try to find the key in the cached JWKS
    let claims = {
        let jwks = provider.jwks.read().await;
        try_validate_with_jwks(&jwks, token, kid, provider)
    };

    match claims {
        Ok(c) => Ok(c),
        Err(_) if !kid.is_empty() => {
            // Key not found or validation failed — try refreshing JWKS once
            debug!("oidc[{}]: key kid={} not found in cache, refreshing JWKS", provider.name, kid);
            match fetch_jwks(&provider.http_client, &provider.name, &provider.discovery.jwks_uri)
                .await
            {
                Ok(new_jwks) => {
                    let result = try_validate_with_jwks(&new_jwks, token, kid, provider);
                    // Update the cache with the refreshed keys
                    let mut cached = provider.jwks.write().await;
                    *cached = new_jwks;
                    result
                }
                Err(_) => {
                    warn!("oidc[{}]: JWKS refresh failed during token validation", provider.name);
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
    provider: &OidcProvider,
) -> Result<OidcTokenClaims, AppError> {
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
            warn!("oidc[{}]: no matching JWK found for kid={}", provider.name, kid);
            AppError::Unauthorized
        })?;

    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e);

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.iss = Some(provider.issuer_url.clone());
    validation.set_audience(&[&provider.audience]);

    let token_data =
        jsonwebtoken::decode::<OidcTokenClaims>(token, &decoding_key, &validation).map_err(|e| {
            warn!("oidc[{}]: token validation failed: {}", provider.name, e);
            AppError::Unauthorized
        })?;

    debug!("oidc[{}]: token validated for sub={}", provider.name, token_data.claims.sub);
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
        assert_eq!(discovery.issuer, "https://dev-12345.okta.com/oauth2/default");
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

    #[test]
    fn test_oidc_claims_deserialize() {
        let json = r#"{
            "sub": "user123",
            "iss": "https://dev-12345.okta.com/oauth2/default",
            "aud": "0oa1234567890",
            "exp": 1700000000,
            "iat": 1699996400,
            "uid": "00u1234",
            "email": "user@example.com",
            "email_verified": true,
            "preferred_username": "user@example.com"
        }"#;

        let claims: OidcTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[test]
    fn test_oidc_claims_missing_email_verified_defaults_none() {
        let json = r#"{
            "sub": "user123",
            "iss": "https://issuer.example.com/",
            "aud": "api://x",
            "exp": 1700000000,
            "iat": 1699996400
        }"#;

        let claims: OidcTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.email_verified, None);
        assert_eq!(claims.email, None);
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

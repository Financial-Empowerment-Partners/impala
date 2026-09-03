use log::{debug, error, info, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::{Config, ProviderConfig, TokenKind};
use crate::constants::SSO_PENDING_RETRY_MAX_SECS;
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

/// Debounces on-demand JWKS refetches so a burst of unverifiable tokens cannot
/// be amplified into a burst of outbound requests to the IdP.
///
/// Shared by the OIDC registry, the legacy Okta provider and the Google
/// provider, all of which have the same unauthenticated "unknown kid" path.
/// Uses a std mutex deliberately: the critical section is a timestamp compare
/// with no `.await` inside it.
#[derive(Debug, Default)]
pub struct RefreshCooldown {
    last: std::sync::Mutex<Option<std::time::Instant>>,
}

impl RefreshCooldown {
    pub fn new() -> Self {
        Self {
            last: std::sync::Mutex::new(None),
        }
    }

    /// Claim the right to perform a refresh, returning false when one happened
    /// within `cooldown`. Records the attempt when it returns true, so
    /// concurrent callers cannot all pass.
    pub fn try_acquire(&self, cooldown: std::time::Duration) -> bool {
        let now = std::time::Instant::now();
        // A poisoned lock only guards a timestamp; recover rather than fail
        // token validation over it.
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        match *last {
            Some(prev) if now.duration_since(prev) < cooldown => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }
}

/// Everything learned from the IdP. Absent until BOTH discovery and the first
/// JWKS fetch have succeeded — the provider is PENDING meanwhile.
#[derive(Debug, Clone)]
pub struct ProviderReady {
    pub discovery: OidcDiscovery,
    /// URL used for ALL server-side JWKS fetches (background refresh,
    /// on-kid-miss). Equals `discovery.jwks_uri` unless an internal issuer is
    /// configured, in which case the public issuer prefix is rewritten so the
    /// bridge can reach the IdP on its internal address (split-horizon dev
    /// setups, e.g. the docker-compose OpenBao test IdP).
    pub jwks_fetch_uri: String,
    pub jwks: JwksResponse,
}

/// Coarse readiness string for `GET /health` (`sso_providers` map).
pub const PROVIDER_STATE_READY: &str = "ready";
pub const PROVIDER_STATE_PENDING: &str = "pending";

/// Shared per-provider OIDC state (one per configured IdP).
///
/// Constructed synchronously from configuration — nothing here touches the
/// network — and brought to READY by [`provider_task`], which fetches
/// discovery and JWKS immediately and keeps retrying with backoff. Until then
/// the token-exchange handler answers 503 (`AppError::Retryable`) and
/// `/config` reports `enabled: false, pending: true`. A transient IdP blip at
/// boot therefore delays SSO instead of disabling it for the life of the
/// process, and a rolling deploy cannot leave instances inconsistent.
pub struct OidcProvider {
    /// Provider name (`okta` | `auth0` | `duo` | …). Drives `profile_source`,
    /// `auth_provider`, the rate-limit scope, and log context.
    pub name: String,
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
    /// Debounce for the unauthenticated on-demand JWKS refetch path.
    pub refresh_cooldown: RefreshCooldown,
    /// Base URL discovery is fetched from: the internal issuer when configured
    /// (the public one may only be reachable by browsers). The document
    /// itself still carries the public endpoints handed to clients.
    discovery_base: String,
    internal_issuer_url: Option<String>,
    state: RwLock<Option<ProviderReady>>,
}

impl OidcProvider {
    /// True once discovery and JWKS are loaded.
    pub async fn is_ready(&self) -> bool {
        self.state.read().await.is_some()
    }

    /// Readiness as reported by `GET /health`.
    pub async fn state_label(&self) -> &'static str {
        if self.is_ready().await {
            PROVIDER_STATE_READY
        } else {
            PROVIDER_STATE_PENDING
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

    /// One attempt to (re)load IdP state. While pending: discovery, then JWKS,
    /// then READY. Once ready: a JWKS refresh only. Discovery is re-fetched on
    /// every pending attempt rather than cached across a JWKS failure — it is
    /// one cheap GET and keeps the state machine two-valued.
    pub async fn sync_from_idp(&self) -> Result<(), AppError> {
        let jwks_uri = self
            .state
            .read()
            .await
            .as_ref()
            .map(|r| r.jwks_fetch_uri.clone());
        match jwks_uri {
            Some(uri) => {
                let jwks = fetch_jwks(&self.http_client, &self.name, &uri).await?;
                if let Some(ready) = self.state.write().await.as_mut() {
                    ready.jwks = jwks;
                }
                Ok(())
            }
            None => {
                let discovery =
                    fetch_discovery(&self.http_client, &self.name, &self.discovery_base).await?;
                let jwks_fetch_uri = match &self.internal_issuer_url {
                    Some(internal) => {
                        let rewritten =
                            rewrite_url_base(&discovery.jwks_uri, &self.issuer_url, internal);
                        if rewritten == discovery.jwks_uri {
                            warn!(
                                "oidc[{}]: jwks_uri {} is not under the public issuer {}; fetching it verbatim",
                                self.name, discovery.jwks_uri, self.issuer_url
                            );
                        }
                        rewritten
                    }
                    None => discovery.jwks_uri.clone(),
                };
                let jwks = fetch_jwks(&self.http_client, &self.name, &jwks_fetch_uri).await?;
                *self.state.write().await = Some(ProviderReady {
                    discovery,
                    jwks_fetch_uri,
                    jwks,
                });
                Ok(())
            }
        }
    }
}

/// The 503 a token exchange gets while its provider is pending. Retryable by
/// contract: nothing was validated, provisioned, or issued.
pub fn pending_error(provider_name: &str) -> AppError {
    AppError::Retryable(format!(
        "SSO provider '{}' is still initializing: the identity provider could not be reached \
         yet; retry shortly",
        provider_name
    ))
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
            info!(
                "oidc[{}]: discovery loaded from oauth-authorization-server",
                name
            );
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
        error!(
            "oidc[{}]: failed to fetch openid-configuration: {}",
            name, e
        );
        AppError::InternalError("Failed to fetch OIDC discovery document".to_string())
    })?;

    if !res.status().is_success() {
        error!(
            "oidc[{}]: discovery endpoint returned {}",
            name,
            res.status()
        );
        return Err(AppError::InternalError(
            "OIDC discovery endpoint returned an error".to_string(),
        ));
    }

    let discovery: OidcDiscovery = res.json().await.map_err(|e| {
        error!(
            "oidc[{}]: failed to parse openid-configuration: {}",
            name, e
        );
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

/// Issuer scheme policy: HTTPS always allowed; plain HTTP only with the
/// per-provider dev opt-in (`{NAME}_ALLOW_HTTP`).
fn issuer_scheme_allowed(url: &str, allow_http: bool) -> bool {
    url.starts_with("https://") || (allow_http && url.starts_with("http://"))
}

/// Rewrite `url`'s `public_base` prefix to `internal_base` (both compared with
/// trailing slashes trimmed). Returns `url` unchanged when the prefix does not
/// match. The remainder must be empty or start with `/` so a base of
/// `https://idp.example.com` never rewrites `https://idp.example.com-evil/…`.
fn rewrite_url_base(url: &str, public_base: &str, internal_base: &str) -> String {
    let public = public_base.trim_end_matches('/');
    let internal = internal_base.trim_end_matches('/');
    if public == internal {
        return url.to_string();
    }
    match url.strip_prefix(public) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            format!("{}{}", internal, rest)
        }
        _ => url.to_string(),
    }
}

/// Build the shared HTTP client used for discovery/JWKS fetches.
pub fn build_idp_client(http_client_timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(http_client_timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("Failed to create HTTP client")
}

/// Construct a single OIDC provider from its config in the PENDING state.
///
/// No network I/O happens here. Genuinely invalid configuration — an empty
/// issuer, a non-HTTPS issuer without the dev opt-in — is an `Err` and
/// fatal at startup: it is a mistake a human is watching for, unlike an IdP
/// that happens to be unreachable at the moment the process boots.
pub fn init_provider(
    cfg: &ProviderConfig,
    http_client_timeout_secs: u64,
) -> Result<Arc<OidcProvider>, String> {
    if cfg.issuer_url.trim().is_empty() {
        return Err("issuer URL is empty".to_string());
    }

    // Issuers must use HTTPS unless the dev-only escape hatch is set.
    if !issuer_scheme_allowed(&cfg.issuer_url, cfg.allow_http) {
        return Err(format!("issuer URL must use HTTPS: {}", cfg.issuer_url));
    }
    if let Some(internal) = &cfg.internal_issuer_url {
        if !issuer_scheme_allowed(internal, cfg.allow_http) {
            return Err(format!("internal issuer URL must use HTTPS: {}", internal));
        }
    }
    if cfg.allow_http
        && (cfg.issuer_url.starts_with("http://")
            || cfg
                .internal_issuer_url
                .as_deref()
                .is_some_and(|u| u.starts_with("http://")))
    {
        warn!(
            "oidc[{}]: ALLOW_HTTP enabled — accepting plain-HTTP issuer {} (LOCAL DEVELOPMENT ONLY)",
            cfg.name, cfg.issuer_url
        );
    }

    info!(
        "oidc[{}]: provider configured for issuer {} (pending IdP discovery)",
        cfg.name, cfg.issuer_url
    );

    // Discovery is fetched from the internal issuer when configured (the
    // public issuer may only be reachable by browsers); the document itself
    // still carries the public endpoints, which is what we hand to clients.
    let discovery_base = cfg
        .internal_issuer_url
        .clone()
        .unwrap_or_else(|| cfg.issuer_url.clone());

    Ok(Arc::new(OidcProvider {
        name: cfg.name.clone(),
        client_id: cfg.client_id.clone(),
        audience: cfg.audience.clone(),
        issuer_url: cfg.issuer_url.clone(),
        token_kind: cfg.token_kind,
        jwks_refresh_secs: cfg.jwks_refresh_secs,
        http_client: build_idp_client(http_client_timeout_secs),
        refresh_cooldown: RefreshCooldown::new(),
        discovery_base,
        internal_issuer_url: cfg.internal_issuer_url.clone(),
        state: RwLock::new(None),
    }))
}

/// Build the provider registry from config (all providers PENDING; no
/// network). `Err` = invalid configuration, which the caller treats as fatal.
pub fn init_registry(config: &Config) -> Result<ProviderRegistry, String> {
    let mut providers: HashMap<String, Arc<OidcProvider>> = HashMap::new();
    for cfg in &config.sso_providers {
        let provider = init_provider(cfg, config.http_client_timeout_secs)
            .map_err(|e| format!("oidc[{}]: invalid configuration: {}", cfg.name, e))?;
        providers.insert(cfg.name.clone(), provider);
    }
    if !providers.is_empty() {
        info!(
            "oidc: {} provider(s) configured; discovery and JWKS load in the background",
            providers.len()
        );
    }
    Ok(ProviderRegistry { providers })
}

/// One fetch attempt handed to [`drive_provider`].
pub type AttemptFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send>>;

/// Wait policy for [`drive_provider`] (pure, tested).
///
/// While PENDING the first attempt has already run immediately; failures back
/// off 1s, 2s, 4s, … up to `SSO_PENDING_RETRY_MAX_SECS`. Once READY the
/// refresh cadence is `interval_secs`, with exponential backoff capped at
/// five minutes on failure — the pre-existing refresh behaviour.
pub fn next_wait_secs(ready: bool, consecutive_failures: u32, interval_secs: u64) -> u64 {
    if !ready {
        let exp = consecutive_failures.saturating_sub(1).min(30);
        std::cmp::min(2u64.saturating_pow(exp), SSO_PENDING_RETRY_MAX_SECS)
    } else if consecutive_failures > 0 {
        std::cmp::min(
            interval_secs.saturating_mul(2u64.saturating_pow(consecutive_failures)),
            300,
        )
    } else {
        interval_secs
    }
}

/// Drive a provider from PENDING to READY, then keep its JWKS fresh.
///
/// `attempt` is one fetch: while pending it must load everything the provider
/// needs (discovery + JWKS); once ready it refreshes JWKS. The first attempt
/// runs IMMEDIATELY — never after `interval_secs`. Every pending failure logs
/// at ERROR so a provider that never comes up is loud rather than silently
/// absent; once ready, refresh failures warn and escalate to ERROR past two
/// intervals of staleness. Respects cancellation for graceful shutdown.
///
/// Shared by the OIDC registry, the legacy Okta provider and the Google
/// provider so all three have identical boot semantics.
pub async fn drive_provider<F>(
    label: String,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
    mut attempt: F,
) where
    F: FnMut() -> AttemptFuture,
{
    use tokio::time::{Duration, Instant};

    let mut ready = false;
    let mut consecutive_failures: u32 = 0;
    let mut last_success = Instant::now();

    loop {
        debug!("{}: fetching IdP state", label);
        match attempt().await {
            Ok(()) => {
                consecutive_failures = 0;
                last_success = Instant::now();
                if ready {
                    info!("{}: JWKS keys refreshed successfully", label);
                } else {
                    ready = true;
                    info!("{}: provider READY (discovery and JWKS loaded)", label);
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                if !ready {
                    error!(
                        "{}: provider PENDING — {} (attempt {}); token exchanges through this \
                         provider answer 503 until the identity provider is reachable",
                        label, e, consecutive_failures
                    );
                } else {
                    let stale_secs = last_success.elapsed().as_secs();
                    if stale_secs > interval_secs * 2 {
                        error!("{}: JWKS keys are {} seconds stale", label, stale_secs);
                    } else {
                        warn!("{}: failed to refresh JWKS keys: {}", label, e);
                    }
                }
            }
        }

        let wait_secs = next_wait_secs(ready, consecutive_failures, interval_secs);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
            _ = cancel.cancelled() => {
                info!("{}: provider task shutting down", label);
                return;
            }
        }
    }
}

/// Background task for one registry provider: initial discovery + JWKS with
/// immediate retries, then periodic JWKS refresh.
pub async fn provider_task(
    provider: Arc<OidcProvider>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let label = format!("oidc[{}]", provider.name);
    let interval = provider.jwks_refresh_secs;
    drive_provider(label, interval, cancel, move || {
        let p = provider.clone();
        Box::pin(async move { p.sync_from_idp().await })
    })
    .await;
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
        warn!(
            "oidc[{}]: failed to decode token header: {}",
            provider.name, e
        );
        AppError::Unauthorized
    })?;

    let kid = header.kid.as_deref().unwrap_or("");

    // Try to find the key in the cached JWKS. A provider still PENDING has
    // no keys at all: refuse with 503 rather than 401, because nothing about
    // the token has been judged — the bridge simply cannot judge it yet.
    let (claims, jwks_fetch_uri) = {
        let state = provider.state.read().await;
        let Some(ready) = state.as_ref() else {
            warn!(
                "oidc[{}]: token exchange refused: provider still PENDING (discovery/JWKS not loaded)",
                provider.name
            );
            return Err(pending_error(&provider.name));
        };
        (
            try_validate_with_jwks(&ready.jwks, token, kid, provider),
            ready.jwks_fetch_uri.clone(),
        )
    };

    match claims {
        Ok(c) => Ok(c),
        Err(_) if !kid.is_empty() => {
            // Key not found or validation failed — try refreshing JWKS once,
            // but only if we have not just done so. `kid` comes from an
            // unverified token header on an unauthenticated endpoint, so
            // without this every junk token would force an outbound fetch.
            if !provider
                .refresh_cooldown
                .try_acquire(std::time::Duration::from_secs(
                    crate::constants::JWKS_ON_DEMAND_COOLDOWN_SECS,
                ))
            {
                debug!(
                    "oidc[{}]: skipping JWKS refresh for kid={} (cooldown)",
                    provider.name, kid
                );
                return Err(AppError::Unauthorized);
            }
            debug!(
                "oidc[{}]: key kid={} not found in cache, refreshing JWKS",
                provider.name, kid
            );
            match fetch_jwks(&provider.http_client, &provider.name, &jwks_fetch_uri).await {
                Ok(new_jwks) => {
                    let result = try_validate_with_jwks(&new_jwks, token, kid, provider);
                    // Update the cache with the refreshed keys
                    if let Some(ready) = provider.state.write().await.as_mut() {
                        ready.jwks = new_jwks;
                    }
                    result
                }
                Err(_) => {
                    warn!(
                        "oidc[{}]: JWKS refresh failed during token validation",
                        provider.name
                    );
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
            warn!(
                "oidc[{}]: no matching JWK found for kid={}",
                provider.name, kid
            );
            AppError::Unauthorized
        })?;

    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            warn!(
                "oidc[{}]: invalid RSA components in JWK kid={}: {}",
                provider.name, kid, e
            );
            AppError::Unauthorized
        })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[&provider.issuer_url]);
    validation.set_audience(&[&provider.audience]);

    let token_data = jsonwebtoken::decode::<OidcTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| {
            warn!("oidc[{}]: token validation failed: {}", provider.name, e);
            AppError::Unauthorized
        })?;

    debug!(
        "oidc[{}]: token validated for sub={}",
        provider.name, token_data.claims.sub
    );
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The on-demand JWKS refetch is reachable unauthenticated with an
    /// attacker-chosen `kid`, so a burst of junk tokens must collapse to a
    /// single outbound fetch rather than one per request.
    #[test]
    fn refresh_cooldown_admits_one_then_blocks() {
        let cooldown = RefreshCooldown::new();
        let window = std::time::Duration::from_secs(60);

        assert!(cooldown.try_acquire(window), "first refresh must proceed");
        for _ in 0..100 {
            assert!(
                !cooldown.try_acquire(window),
                "a burst must not amplify into repeated outbound fetches"
            );
        }
    }

    #[test]
    fn refresh_cooldown_admits_again_once_the_window_passes() {
        let cooldown = RefreshCooldown::new();
        // A zero-length window is always elapsed, standing in for "later".
        assert!(cooldown.try_acquire(std::time::Duration::from_secs(60)));
        assert!(
            cooldown.try_acquire(std::time::Duration::ZERO),
            "a genuine key rotation must still be fetchable after the window"
        );
    }

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

    fn test_provider_cfg(issuer: &str, internal: Option<&str>, allow_http: bool) -> ProviderConfig {
        ProviderConfig {
            name: "okta".to_string(),
            issuer_url: issuer.to_string(),
            client_id: "client".to_string(),
            audience: "client".to_string(),
            jwks_refresh_secs: 3600,
            token_kind: TokenKind::Access,
            internal_issuer_url: internal.map(str::to_string),
            allow_http,
        }
    }

    /// Construction is synchronous and network-free: a freshly built provider
    /// is PENDING, refuses token validation with a 503, and reports no
    /// discovery for `/config`.
    #[tokio::test]
    async fn new_provider_is_pending_and_refuses_with_503() {
        let provider = init_provider(
            &test_provider_cfg("https://idp.example.com", None, false),
            5,
        )
        .unwrap();
        assert!(!provider.is_ready().await);
        assert_eq!(provider.state_label().await, PROVIDER_STATE_PENDING);
        assert!(provider.discovery().await.is_none());

        // Any token shape: the pending check comes before key lookup.
        let header = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0";
        let token = format!("{}.e30.c2ln", header);
        match validate_token(&provider, &token).await {
            Err(AppError::Retryable(msg)) => assert!(msg.contains("okta")),
            other => panic!("expected Retryable (503), got {:?}", other.map(|_| ())),
        }
    }

    /// Bad configuration is fatal at startup (an `Err`), unlike an
    /// unreachable IdP, which only delays readiness.
    #[test]
    fn invalid_configuration_is_an_error_not_a_skip() {
        assert!(init_provider(&test_provider_cfg("", None, false), 5).is_err());
        assert!(init_provider(&test_provider_cfg("   ", None, false), 5).is_err());
        assert!(
            init_provider(&test_provider_cfg("http://idp.example.com", None, false), 5).is_err()
        );
        assert!(init_provider(
            &test_provider_cfg(
                "https://idp.example.com",
                Some("http://internal:8200"),
                false
            ),
            5
        )
        .is_err());
        // The dev opt-in keeps plain HTTP valid.
        assert!(init_provider(
            &test_provider_cfg("http://openbao:8200", Some("http://internal:8200"), true),
            5
        )
        .is_ok());
    }

    #[test]
    fn init_registry_fails_closed_on_one_bad_provider() {
        let mut config = crate::config::test_config();
        config.sso_providers = vec![
            test_provider_cfg("https://idp.example.com", None, false),
            ProviderConfig {
                name: "duo".to_string(),
                ..test_provider_cfg("http://duo.example.com", None, false)
            },
        ];
        let err = init_registry(&config)
            .err()
            .expect("a plain-HTTP issuer without ALLOW_HTTP must be rejected");
        assert!(err.contains("oidc[duo]"), "{}", err);

        config.sso_providers.pop();
        let registry = init_registry(&config).unwrap();
        assert_eq!(registry.names(), vec!["okta".to_string()]);
    }

    /// The first fetch runs immediately; while pending, retries are short and
    /// capped; once ready the old refresh cadence applies.
    #[test]
    fn pending_backoff_is_short_and_capped_then_refresh_cadence_resumes() {
        // Pending: 1, 2, 4, 8, 16, 32, then capped.
        assert_eq!(next_wait_secs(false, 1, 3600), 1);
        assert_eq!(next_wait_secs(false, 2, 3600), 2);
        assert_eq!(next_wait_secs(false, 3, 3600), 4);
        assert_eq!(next_wait_secs(false, 6, 3600), 32);
        assert_eq!(next_wait_secs(false, 7, 3600), SSO_PENDING_RETRY_MAX_SECS);
        assert_eq!(next_wait_secs(false, 40, 3600), SSO_PENDING_RETRY_MAX_SECS);
        assert!(
            next_wait_secs(false, 1, 3600) < 3600,
            "a pending provider must never wait a full refresh interval"
        );
        // Ready: interval on success, capped exponential backoff on failure.
        assert_eq!(next_wait_secs(true, 0, 3600), 3600);
        assert_eq!(next_wait_secs(true, 1, 100), 200);
        assert_eq!(next_wait_secs(true, 3, 3600), 300);
    }

    #[test]
    fn test_issuer_scheme_allowed() {
        assert!(issuer_scheme_allowed("https://idp.example.com", false));
        assert!(issuer_scheme_allowed("https://idp.example.com", true));
        assert!(!issuer_scheme_allowed("http://openbao:8200", false));
        assert!(issuer_scheme_allowed("http://openbao:8200", true));
        assert!(!issuer_scheme_allowed("ftp://idp.example.com", true));
        assert!(!issuer_scheme_allowed("idp.example.com", true));
        assert!(!issuer_scheme_allowed("", true));
    }

    #[test]
    fn test_rewrite_url_base_happy_path() {
        assert_eq!(
            rewrite_url_base(
                "http://localhost:8200/v1/identity/oidc/provider/openbao/.well-known/keys",
                "http://localhost:8200/v1/identity/oidc/provider/openbao",
                "http://openbao:8200/v1/identity/oidc/provider/openbao",
            ),
            "http://openbao:8200/v1/identity/oidc/provider/openbao/.well-known/keys"
        );
    }

    #[test]
    fn test_rewrite_url_base_trailing_slashes_trimmed() {
        // Trailing slash on the public base.
        assert_eq!(
            rewrite_url_base(
                "https://idp.example.com/keys",
                "https://idp.example.com/",
                "http://internal:8200",
            ),
            "http://internal:8200/keys"
        );
        // Trailing slash on the internal base.
        assert_eq!(
            rewrite_url_base(
                "https://idp.example.com/keys",
                "https://idp.example.com",
                "http://internal:8200/",
            ),
            "http://internal:8200/keys"
        );
    }

    #[test]
    fn test_rewrite_url_base_exact_base_url() {
        assert_eq!(
            rewrite_url_base(
                "https://idp.example.com",
                "https://idp.example.com",
                "http://internal:8200",
            ),
            "http://internal:8200"
        );
    }

    #[test]
    fn test_rewrite_url_base_mismatch_unchanged() {
        assert_eq!(
            rewrite_url_base(
                "https://other-idp.example.com/keys",
                "https://idp.example.com",
                "http://internal:8200",
            ),
            "https://other-idp.example.com/keys"
        );
    }

    #[test]
    fn test_rewrite_url_base_false_prefix_not_rewritten() {
        // `example.com-evil` shares the string prefix but is a different host.
        assert_eq!(
            rewrite_url_base(
                "https://idp.example.com-evil/keys",
                "https://idp.example.com",
                "http://internal:8200",
            ),
            "https://idp.example.com-evil/keys"
        );
    }

    #[test]
    fn test_rewrite_url_base_identical_bases_unchanged() {
        assert_eq!(
            rewrite_url_base(
                "https://idp.example.com/keys",
                "https://idp.example.com",
                "https://idp.example.com/",
            ),
            "https://idp.example.com/keys"
        );
    }
}

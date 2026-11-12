use crate::constants::*;
use std::collections::HashSet;
use std::env;
use std::fs;

#[derive(Debug, Clone, PartialEq)]
pub enum StellarNetwork {
    Testnet,
    Pubnet,
}

impl StellarNetwork {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pubnet" | "mainnet" | "public" => StellarNetwork::Pubnet,
            _ => StellarNetwork::Testnet,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StellarNetwork::Testnet => "testnet",
            StellarNetwork::Pubnet => "pubnet",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StellarConfig {
    pub network: StellarNetwork,
    pub horizon_url: String,
    pub rpc_url: String,
    pub network_passphrase: String,
    pub contract_id: Option<String>,
    /// Per-operation fee bid in stroops (see `Config::stellar_max_fee_stroops`).
    pub max_fee_stroops: u32,
}

/// Which token the bridge JWKS-validates for an OIDC provider.
///
/// Most providers (Okta, Auth0) hand the browser a JWT **access token** that
/// carries the identity claims. Some (e.g. Duo SSO) reliably carry the identity
/// only in the **id token**, so those are configured with `TokenKind::Id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Id,
}

impl TokenKind {
    pub fn from_str_opt(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "id" | "id_token" | "idtoken" => TokenKind::Id,
            _ => TokenKind::Access,
        }
    }
}

/// Configuration for a single OIDC SSO provider (Okta / Auth0 / Duo / …).
///
/// Providers are declared via `SSO_PROVIDERS=okta,auth0,duo` (or the
/// `sso_providers` config-file key — a comma-list *string*, not an array) and
/// each is configured through prefixed env vars: `{NAME}_ISSUER_URL`,
/// `{NAME}_CLIENT_ID`, `{NAME}_AUDIENCE`, `{NAME}_JWKS_REFRESH_SECS`,
/// `{NAME}_TOKEN_KIND`, `{NAME}_INTERNAL_ISSUER_URL`, `{NAME}_ALLOW_HTTP`.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    /// Validated as the JWT `aud`. Defaults to `client_id` when unset (Okta);
    /// set to the API identifier for Auth0.
    pub audience: String,
    pub jwks_refresh_secs: u64,
    pub token_kind: TokenKind,
    /// Optional server-side base URL used ONLY for discovery/JWKS fetches when
    /// the public issuer is not reachable from the bridge (split-horizon dev
    /// setups, e.g. the docker-compose OpenBao test IdP). `iss` validation and
    /// the `/auth/sso/:provider/config` passthrough always use `issuer_url`.
    pub internal_issuer_url: Option<String>,
    /// Dev-only opt-in permitting plain-HTTP issuer URLs. Default false.
    pub allow_http: bool,
}

/// Build the SSO provider list from a lookup function mapping
/// `(provider name, KEY)` to a configured value (env var or config file).
/// Extracted from `load_config` so tests can drive it with a plain closure
/// instead of mutating process-wide env vars.
pub(crate) fn parse_sso_providers<F>(names: &[String], provider_var: F) -> Vec<ProviderConfig>
where
    F: Fn(&str, &str) -> Option<String>,
{
    names
        .iter()
        .filter_map(|name| {
            let issuer_url = provider_var(name, "ISSUER_URL")?;
            if issuer_url.trim().is_empty() {
                return None;
            }
            let client_id = provider_var(name, "CLIENT_ID").unwrap_or_default();
            let audience = provider_var(name, "AUDIENCE")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| client_id.clone());
            let jwks_refresh_secs = provider_var(name, "JWKS_REFRESH_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(crate::constants::DEFAULT_JWKS_REFRESH_SECS);
            let token_kind = provider_var(name, "TOKEN_KIND")
                .map(|v| TokenKind::from_str_opt(&v))
                .unwrap_or(TokenKind::Access);
            let internal_issuer_url =
                provider_var(name, "INTERNAL_ISSUER_URL").filter(|s| !s.trim().is_empty());
            let allow_http = provider_var(name, "ALLOW_HTTP")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            Some(ProviderConfig {
                name: name.clone(),
                issuer_url,
                client_id,
                audience,
                jwks_refresh_secs,
                token_kind,
                internal_issuer_url,
                allow_http,
            })
        })
        .collect()
}

#[derive(Clone)]
#[allow(dead_code)] // config surface; several fields are populated from env but not yet read
pub struct Config {
    #[allow(dead_code)] // loaded config, not currently read in code paths
    pub public_endpoint: String,
    pub service_address: String,
    #[allow(dead_code)] // loaded config, not currently read in code paths
    pub log_file: String,
    pub debug_mode: bool,
    pub twilio_sid: Option<String>,
    pub twilio_token: Option<String>,
    pub twilio_number: Option<String>,
    pub ldap_url: Option<String>,
    pub ldap_bind_dn: Option<String>,
    pub ldap_bind_password: Option<String>,
    pub ldap_base_dn: Option<String>,
    pub ldap_search_filter: Option<String>,
    pub db_max_connections: u32,
    pub cors_allowed_origins: String,
    pub http_client_timeout_secs: u64,
    /// Legacy single-provider Okta config (the `/auth/okta` cookie-capable
    /// flow); the multi-provider SSO registry below supersedes it for bearer
    /// clients but the UI cookie flow still rides this provider.
    pub okta_issuer_url: Option<String>,
    pub okta_client_id: Option<String>,
    pub okta_jwks_refresh_secs: u64,
    /// OAuth client ID accepted as `aud` on Google ID tokens; enables /auth/google.
    pub google_client_id: Option<String>,
    pub google_jwks_refresh_secs: u64,
    /// Enables /auth/github (GitHub access-token exchange).
    pub github_auth_enabled: bool,
    /// GitHub REST API base URL (override for GitHub Enterprise Server).
    pub github_api_url: String,
    /// OAuth app client id for the server-side code→token exchange.
    pub github_client_id: Option<String>,
    /// OAuth app client secret (server-side only — never ships in clients).
    pub github_client_secret: Option<String>,
    /// GitHub OAuth token endpoint (override for GHES/tests).
    pub github_oauth_token_url: String,
    /// Configured OIDC SSO providers (Okta / Auth0 / Duo / …). Empty when SSO is off.
    pub sso_providers: Vec<ProviderConfig>,
    pub sqs_queue_url: Option<String>,
    pub sns_topic_arn: Option<String>,
    pub worker_concurrency: usize,
    pub sqs_wait_time_seconds: i32,
    pub sqs_visibility_timeout: i32,
    pub ses_from_address: Option<String>,
    pub fcm_project_id: Option<String>,
    /// Path to the Firebase service-account JSON; read by the worker at
    /// startup to mint FCM access tokens (`crate::fcm`). The path is not a
    /// secret, but the file it names is.
    pub fcm_service_account_key: Option<String>,
    pub otel_exporter_endpoint: Option<String>,
    pub otel_service_name: Option<String>,
    pub otel_environment: Option<String>,
    pub stellar_network: StellarNetwork,
    pub stellar_horizon_url: String,
    /// Per-operation fee BID (stroops) for every bridge-signed transaction.
    /// A bid is a maximum — the network charges the ledger's effective fee —
    /// so it is set high enough to ride through surge pricing. Clamped.
    pub stellar_max_fee_stroops: u32,
    pub stellar_rpc_url: String,
    pub stellar_network_passphrase: String,
    pub soroban_contract_id: Option<String>,
    /// Account IDs (JWT `sub`) granted admin; overrides the DB role to `admin`
    /// when the `role` claim is stamped at token issuance.
    pub admin_account_ids: HashSet<String>,
    /// Roles whose sessions must be multi-factor to use the API
    /// (`MFA_REQUIRED_ROLES`, comma-separated; empty by default).
    pub mfa_required_roles: HashSet<String>,
    /// How long a multi-factor verification keeps a session multi-factor
    /// before a step-up is needed (`MFA_MAX_AGE_SECS`, default 12 h).
    pub mfa_max_age_secs: i64,
    /// Whether to trust a card PIN proof only from an issuer-certified card
    /// (`MFA_CARD_PIN_TRUST` = `certified`, default) or any registered card
    /// (`any`, test rigs).
    pub mfa_card_pin_trust: String,
    /// Whether to credit the `bio` factor for a device key the client declared
    /// biometric-bound (`MFA_DEVICE_BIOMETRIC` = `claimed`) or never (`off`,
    /// default — the bridge does not verify platform key attestation).
    pub mfa_device_biometric: String,
    /// Max delivery attempts before an admin-webhook delivery is marked failed.
    pub admin_webhook_max_attempts: u32,
    /// Consecutive-failure count after which a webhook is auto-disabled.
    pub admin_webhook_disable_threshold: i64,
    /// Poll interval (seconds) for the admin-webhook delivery worker.
    pub admin_webhook_poll_secs: u64,
    /// Mark session cookies `Secure` (+ `__Host-` name prefix). Default true;
    /// the plain-HTTP local compose stack sets SESSION_COOKIE_SECURE=false.
    pub session_cookie_secure: bool,
    /// Whether `POST /authenticate` may set a password on an existing account
    /// that has no credentials yet. Default **false** (fail closed) — see the
    /// account-claiming note in `handlers::authenticate`.
    pub allow_open_registration: bool,
    /// Number of trusted reverse proxies in front of the bridge
    /// (TRUSTED_PROXY_HOPS). Selects which `X-Forwarded-For` entry, counted
    /// from the right, is the client for per-source throttling; 0 ignores the
    /// header and uses the TCP peer. Default 1 (the ALB). See `client_source.rs`.
    pub trusted_proxy_hops: u32,
    /// deadpool-redis pool size (REDIS_POOL_SIZE).
    pub redis_pool_size: usize,
    /// Global HTTP request timeout in seconds (REQUEST_TIMEOUT_SECS).
    pub request_timeout_secs: u64,
    /// Postgres pool acquire timeout in seconds (DB_ACQUIRE_TIMEOUT_SECS).
    pub db_acquire_timeout_secs: u64,
    // Custodial Stellar seed protection. Non-secret config only — auth secrets
    // (VAULT_TOKEN / VAULT_SECRET_ID) are read directly from the environment so
    // they never land in this `Debug`-logged struct.
    pub seed_protection_backend: String,
    pub kms_seed_key_id: Option<String>,
    /// Whether admins may import bridge credentials through `/admin/keys/*`,
    /// and whether stored credentials are consulted at startup at all.
    ///
    /// Default **false**: with it off, provider secrets resolve from the
    /// environment exactly as they always have and the admin endpoints refuse.
    /// It doubles as the break-glass switch — flipping it off and restarting
    /// reverts the whole fleet to environment credentials, which is why
    /// `GET /admin/keys` reports any environment variable a stored credential
    /// is shadowing.
    pub key_import_enabled: bool,
    pub vault_addr: Option<String>,
    pub vault_transit_key: Option<String>,
    // Exchange providers (OwlPay / Changelly). Non-secret config only — API
    // keys and signing keys (OWLPAY_API_KEY, CHANGELLY_PRIVATE_KEY, …) are read
    // directly from the environment by the provider init fns so they never
    // land in this `Debug`-logged struct.
    /// OwlPay Harbor API base URL (sandbox default; production is per-tenant).
    pub owlpay_api_url: String,
    /// Changelly Exchange API v2 (crypto swap) base URL.
    pub changelly_api_url: String,
    /// Changelly Fiat API base URL.
    pub changelly_fiat_api_url: String,
    /// Poll interval (seconds) for the exchange-order reconcile loop.
    pub exchange_poll_secs: u64,

    // Conversion reserve (bridge service reserve for small exchange orders).
    // None of these are secrets — the reserve's signing seed stays in
    // managed_seed behind the seed protector; thresholds/enablement live in
    // the conversion_reserve_policy DB table (admin-editable at runtime).
    /// payala_account_id of the managed-seed account designated as the
    /// reserve. Presence enables the subsystem (init fails closed if the
    /// account has no seed). This account is quarantined from user-facing
    /// custodial endpoints.
    pub reserve_account_id: Option<String>,
    /// Stellar issuer (`G...`) of the USDC asset the reserve pays out and
    /// recognizes as deposits. Required when the reserve is enabled.
    pub reserve_usdc_issuer: Option<String>,
    /// Asset code of that asset. ["USDC"]
    pub reserve_usdc_code: String,
    /// Stellar issuer (`G...`) of the USDT0 asset. Optional: when unset the
    /// USDT0 bucket exists but is inert (nothing classifies to it, nothing
    /// pays out of it). Validated with a strkey checksum at startup.
    pub reserve_usdt0_issuer: Option<String>,
    /// Asset code of the USDT0 asset. ["USDT0"]
    pub reserve_usdt0_code: String,
    /// Exchange-provider tickers (lowercased) that mean "USDT0 on Stellar" —
    /// AutoSwap `to_currency` and Disburse `from_currency` values that make an
    /// order divert to the USDT0 leg. Empty by default: provider ticker
    /// strings are provider-specific and must be verified by the operator
    /// against the provider's own currency list, never guessed.
    pub reserve_usdt0_tickers: Vec<String>,
    /// Deposit window for reserve orders (seconds) — also the price-validity
    /// window (a long TTL is a free price option on the pool). Clamped to
    /// [300, 7200]. [1800]
    pub reserve_deposit_ttl_secs: u64,
    /// Reserve deposit-watcher cadence (seconds), clamped to >= 5. [30]
    pub reserve_watch_secs: u64,
    /// How long a bridge-issued price lock stays valid (seconds), clamped to
    /// [60, 900]. Short by design: a quote hold delivers nothing to the
    /// customer while it waits, so it is pure optionality against the pool.
    /// [300]
    pub reserve_quote_ttl_secs: u64,
    /// UTC hour (0..=23) after which the daily reconciliation snapshot is
    /// due (`RECONCILIATION_SNAPSHOT_UTC_HOUR`). [0]
    pub reconciliation_snapshot_utc_hour: u32,
    /// Most custodial addresses a full reconciliation walk reads
    /// (`RECONCILIATION_MAX_ACCOUNTS`); beyond it the snapshot records
    /// `complete = false`. [10000]
    pub reconciliation_max_accounts: i64,
    /// Wall-clock budget (seconds) for a full reconciliation walk
    /// (`RECONCILIATION_DEADLINE_SECS`). [600]
    pub reconciliation_deadline_secs: u64,
    /// SEP-10 web authentication (raw; validated by [`validate_sep10_policy`]
    /// only when enabled, so a disabled bridge behaves exactly as before).
    pub sep10: Sep10Settings,
}

/// SEP-10 configuration as read from the environment / config file. Values
/// stay raw strings so a bad knob is a boot error when SEP-10 is enabled and
/// no error at all when it is not.
#[derive(Debug, Clone, Default)]
pub struct Sep10Settings {
    /// `SEP10_ENABLED` (`true`/`1`). [false]
    pub enabled: bool,
    /// `SEP10_WEB_AUTH_ENDPOINT`, mandatory when enabled, no default.
    pub web_auth_endpoint: Option<String>,
    /// `SEP10_CHALLENGE_TTL_SECS` (60..=900). [300]
    pub challenge_ttl_secs: Option<String>,
    /// `SEP10_CHALLENGE_GLOBAL_MAX` challenges per 60 s, all sources. [600]
    pub challenge_global_max: Option<String>,
    /// `SEP10_KEY_ACTIVATION_DELAY_SECS` (120..=86400). [120]
    pub key_activation_delay_secs: Option<String>,
    /// `STELLAR_NETWORK` exactly as set (the enum maps unset to testnet, so
    /// the testnet-only gate needs to know whether it was explicit).
    pub stellar_network_raw: Option<String>,
    /// `PUBLIC_ENDPOINT` exactly as set (unset → no authority check).
    pub public_endpoint_raw: Option<String>,
}

/// Validated SEP-10 policy (present only when `SEP10_ENABLED=true`).
#[derive(Debug, Clone)]
pub struct Sep10Policy {
    /// The canonical `scheme://authority/auth/sep10`.
    pub web_auth_endpoint: String,
    /// `host[:port]`: home_domain = web_auth_domain.
    pub home_domain: String,
    pub network_passphrase: String,
    pub network_id: [u8; 32],
    pub challenge_ttl_secs: u64,
    pub challenge_global_max: u64,
    pub activation_delay_secs: u64,
}

/// What the always-mounted admin signing-key routes need. With SEP-10
/// disabled the values are derived leniently (an invalid knob falls back to
/// its default, an invalid endpoint reads as unconfigured) — a disabled
/// bridge never fails boot over SEP-10.
#[derive(Debug, Clone)]
pub struct Sep10AdminSettings {
    pub enabled: bool,
    pub home_domain: Option<String>,
    pub web_auth_endpoint: Option<String>,
    pub network_passphrase: String,
    pub challenge_ttl_secs: u64,
    pub activation_delay_secs: u64,
}

impl Sep10AdminSettings {
    pub fn from_config(config: &Config, policy: Option<&Sep10Policy>) -> Self {
        if let Some(p) = policy {
            return Sep10AdminSettings {
                enabled: true,
                home_domain: Some(p.home_domain.clone()),
                web_auth_endpoint: Some(p.web_auth_endpoint.clone()),
                network_passphrase: p.network_passphrase.clone(),
                challenge_ttl_secs: p.challenge_ttl_secs,
                activation_delay_secs: p.activation_delay_secs,
            };
        }
        let s = &config.sep10;
        let lenient = |raw: Option<&str>, default: u64, range: std::ops::RangeInclusive<u64>| {
            raw.and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|v| range.contains(v))
                .unwrap_or(default)
        };
        let endpoint = s
            .web_auth_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .and_then(|raw| sep10_endpoint(raw).ok());
        Sep10AdminSettings {
            enabled: false,
            home_domain: endpoint.as_ref().map(|(h, _)| h.clone()),
            web_auth_endpoint: endpoint.map(|(_, e)| e),
            network_passphrase: config.stellar_network_passphrase.clone(),
            challenge_ttl_secs: lenient(
                s.challenge_ttl_secs.as_deref(),
                DEFAULT_SEP10_CHALLENGE_TTL_SECS,
                SEP10_CHALLENGE_TTL_MIN_SECS..=SEP10_CHALLENGE_TTL_MAX_SECS,
            ),
            activation_delay_secs: lenient(
                s.key_activation_delay_secs.as_deref(),
                DEFAULT_SEP10_KEY_ACTIVATION_DELAY_SECS,
                SEP10_KEY_ACTIVATION_DELAY_MIN_SECS..=SEP10_KEY_ACTIVATION_DELAY_MAX_SECS,
            ),
        }
    }
}

fn sep10_knob(
    raw: Option<&str>,
    name: &str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(default);
    };
    let v: u64 = raw
        .parse()
        .map_err(|_| format!("{name}={raw:?} is not a whole number of seconds/requests"))?;
    if !range.contains(&v) {
        return Err(format!(
            "{name}={v} is out of range ({}..={})",
            range.start(),
            range.end()
        ));
    }
    Ok(v)
}

/// The authority (`host[:port]`) of a validated SEP-10 endpoint, and the
/// canonical endpoint string.
fn sep10_endpoint(raw: &str) -> Result<(String, String), String> {
    let url = url::Url::parse(raw.trim())
        .map_err(|e| format!("SEP10_WEB_AUTH_ENDPOINT={raw:?} is not a URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("SEP10_WEB_AUTH_ENDPOINT={raw:?} has no host"))?;
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        || host.is_empty()
    {
        return Err(format!(
            "SEP10_WEB_AUTH_ENDPOINT host {host:?} must be lowercase [a-z0-9.-]"
        ));
    }
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    match url.scheme() {
        "https" => {}
        "http" if SEP10_LOOPBACK_HOSTS.contains(&host) => {}
        other => {
            return Err(format!(
                "SEP10_WEB_AUTH_ENDPOINT must be https (http only for {}), got {other}",
                SEP10_LOOPBACK_HOSTS.join(", ")
            ))
        }
    }
    if url.path() != SEP10_AUTH_PATH
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(format!(
            "SEP10_WEB_AUTH_ENDPOINT path must be exactly {SEP10_AUTH_PATH} (no query, fragment \
             or credentials)"
        ));
    }
    if authority.len() > SEP10_HOME_DOMAIN_MAX_LEN {
        return Err(format!(
            "SEP10_WEB_AUTH_ENDPOINT authority {authority:?} is longer than \
             {SEP10_HOME_DOMAIN_MAX_LEN} bytes (\"<home> auth\" must fit in 64)"
        ));
    }
    let canonical = format!("{}://{}{}", url.scheme(), authority, SEP10_AUTH_PATH);
    if raw.trim() != canonical {
        return Err(format!(
            "SEP10_WEB_AUTH_ENDPOINT must be written canonically as {canonical:?} (lowercase, no \
             default port, no trailing slash)"
        ));
    }
    Ok((authority, canonical))
}

/// Boot gate for SEP-10 (beside [`validate_cors_policy`]). `Ok(None)` when
/// disabled — nothing is checked and nothing changes. When enabled, refuses
/// to start unless the endpoint is well formed (`https`, path exactly
/// `/auth/sep10`, lowercase host ≤ 59 bytes, matching `PUBLIC_ENDPOINT` when
/// that is set), seed protection is real, no SSO provider name collides with
/// the `sep10*` scopes, and — this phase only — the network is explicitly
/// testnet with the testnet passphrase.
pub fn validate_sep10_policy(config: &Config) -> Result<Option<Sep10Policy>, String> {
    let s = &config.sep10;
    if !s.enabled {
        return Ok(None);
    }
    let raw = s
        .web_auth_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or("SEP10_ENABLED=true requires SEP10_WEB_AUTH_ENDPOINT (there is no default)")?;
    let (home_domain, web_auth_endpoint) = sep10_endpoint(raw)?;

    if let Some(public) = s
        .public_endpoint_raw
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let public_url = url::Url::parse(public)
            .map_err(|e| format!("PUBLIC_ENDPOINT={public:?} is not a URL: {e}"))?;
        let public_authority = match (public_url.host_str(), public_url.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            (None, _) => String::new(),
        };
        if public_authority != home_domain {
            return Err(format!(
                "SEP10_WEB_AUTH_ENDPOINT authority {home_domain:?} differs from PUBLIC_ENDPOINT \
                 authority {public_authority:?}; SEP-10 needs a dedicated per-network host"
            ));
        }
    }

    let backend = config.seed_protection_backend.trim();
    if backend.is_empty() || backend == "none" {
        return Err(
            "SEP10_ENABLED=true requires SEED_PROTECTION_BACKEND to be kms, vault or openbao \
             (the signing key is sealed; there is no plaintext path)"
                .to_string(),
        );
    }

    if let Some(p) = config
        .sso_providers
        .iter()
        .find(|p| p.name.starts_with("sep10"))
    {
        return Err(format!(
            "SSO provider name {:?} collides with the reserved sep10* rate-limit scopes",
            p.name
        ));
    }

    // Phase gate (card-key SEP-10 is testnet-only for now). The enum maps an
    // unset or unknown STELLAR_NETWORK to testnet, so test the raw value and
    // the passphrase itself.
    let explicit_testnet = s
        .stellar_network_raw
        .as_deref()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("testnet"));
    if !explicit_testnet || config.stellar_network_passphrase != STELLAR_TESTNET_PASSPHRASE {
        return Err(
            "SEP10_ENABLED=true is refused unless STELLAR_NETWORK=testnet is set explicitly and \
             the network passphrase is the testnet passphrase (pubnet is a later phase)"
                .to_string(),
        );
    }

    let challenge_ttl_secs = sep10_knob(
        s.challenge_ttl_secs.as_deref(),
        "SEP10_CHALLENGE_TTL_SECS",
        DEFAULT_SEP10_CHALLENGE_TTL_SECS,
        SEP10_CHALLENGE_TTL_MIN_SECS..=SEP10_CHALLENGE_TTL_MAX_SECS,
    )?;
    let challenge_global_max = sep10_knob(
        s.challenge_global_max.as_deref(),
        "SEP10_CHALLENGE_GLOBAL_MAX",
        DEFAULT_SEP10_CHALLENGE_GLOBAL_MAX,
        1..=1_000_000,
    )?;
    let activation_delay_secs = sep10_knob(
        s.key_activation_delay_secs.as_deref(),
        "SEP10_KEY_ACTIVATION_DELAY_SECS",
        DEFAULT_SEP10_KEY_ACTIVATION_DELAY_SECS,
        SEP10_KEY_ACTIVATION_DELAY_MIN_SECS..=SEP10_KEY_ACTIVATION_DELAY_MAX_SECS,
    )?;

    Ok(Some(Sep10Policy {
        web_auth_endpoint,
        home_domain,
        network_passphrase: config.stellar_network_passphrase.clone(),
        network_id: crate::sep10::network_id(&config.stellar_network_passphrase),
        challenge_ttl_secs,
        challenge_global_max,
        activation_delay_secs,
    }))
}

/// Render an optional secret as its presence, never its value.
fn secret_state(value: &Option<String>) -> &'static str {
    match value {
        Some(_) => "<set:redacted>",
        None => "<unset>",
    }
}

/// Hand-written so that `{:?}` on a `Config` can never print a credential.
///
/// This was a derive, and `main.rs` logs `Config: {:?}` at startup under
/// `DEBUG_MODE` — which wrote `ldap_bind_password`, `twilio_token`,
/// `github_client_secret` and `fcm_service_account_key` verbatim into syslog
/// and, when OTEL is configured, into a centrally-readable trace pipeline.
/// Seed-protection and exchange credentials were already kept out of this
/// struct for exactly that reason; these four had been left in.
///
/// Listing fields explicitly also makes the safe direction the default: a
/// secret added to `Config` later is invisible here until someone opts it in,
/// rather than being logged the moment it is introduced.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("public_endpoint", &self.public_endpoint)
            .field("service_address", &self.service_address)
            .field("debug_mode", &self.debug_mode)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("stellar_network", &self.stellar_network)
            .field("stellar_horizon_url", &self.stellar_horizon_url)
            .field("stellar_max_fee_stroops", &self.stellar_max_fee_stroops)
            .field("stellar_rpc_url", &self.stellar_rpc_url)
            .field("soroban_contract_id", &self.soroban_contract_id)
            .field("db_max_connections", &self.db_max_connections)
            .field("db_acquire_timeout_secs", &self.db_acquire_timeout_secs)
            .field("redis_pool_size", &self.redis_pool_size)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("http_client_timeout_secs", &self.http_client_timeout_secs)
            .field("session_cookie_secure", &self.session_cookie_secure)
            .field("trusted_proxy_hops", &self.trusted_proxy_hops)
            .field("admin_account_ids", &self.admin_account_ids.len())
            .field("seed_protection_backend", &self.seed_protection_backend)
            .field("key_import_enabled", &self.key_import_enabled)
            .field("sso_providers", &self.sso_providers.len())
            .field("okta_issuer_url", &self.okta_issuer_url)
            .field("github_auth_enabled", &self.github_auth_enabled)
            .field("worker_concurrency", &self.worker_concurrency)
            .field("otel_exporter_endpoint", &self.otel_exporter_endpoint)
            .field("exchange_poll_secs", &self.exchange_poll_secs)
            .field("reserve_account_id", &self.reserve_account_id)
            .field("reserve_usdc_issuer", &self.reserve_usdc_issuer)
            .field("reserve_usdc_code", &self.reserve_usdc_code)
            .field("reserve_usdt0_issuer", &self.reserve_usdt0_issuer)
            .field("reserve_usdt0_code", &self.reserve_usdt0_code)
            .field("reserve_usdt0_tickers", &self.reserve_usdt0_tickers)
            .field("reserve_deposit_ttl_secs", &self.reserve_deposit_ttl_secs)
            .field("reserve_watch_secs", &self.reserve_watch_secs)
            .field(
                "reconciliation_snapshot_utc_hour",
                &self.reconciliation_snapshot_utc_hour,
            )
            .field(
                "reconciliation_max_accounts",
                &self.reconciliation_max_accounts,
            )
            .field(
                "reconciliation_deadline_secs",
                &self.reconciliation_deadline_secs,
            )
            .field("reserve_quote_ttl_secs", &self.reserve_quote_ttl_secs)
            .field("sep10", &self.sep10)
            // Presence only — never the value.
            .field("twilio_sid", &secret_state(&self.twilio_sid))
            .field("twilio_token", &secret_state(&self.twilio_token))
            .field(
                "ldap_bind_password",
                &secret_state(&self.ldap_bind_password),
            )
            .field(
                "github_client_secret",
                &secret_state(&self.github_client_secret),
            )
            .field(
                "fcm_service_account_key",
                &secret_state(&self.fcm_service_account_key),
            )
            .finish_non_exhaustive()
    }
}

/// Hard policy gate: wildcard CORS is forbidden on pubnet. `Ok(())` otherwise.
pub fn validate_cors_policy(
    network: &StellarNetwork,
    cors_allowed_origins: &str,
) -> Result<(), String> {
    if *network == StellarNetwork::Pubnet && cors_allowed_origins.trim() == "*" {
        return Err(
            "CORS_ALLOWED_ORIGINS='*' is not allowed when STELLAR_NETWORK=pubnet; set explicit origins"
                .to_string(),
        );
    }
    Ok(())
}

/// Return the first environment variable that is set among `keys`, in order.
///
/// Used to accept OpenBao-native `BAO_*` names while falling back to the
/// historical `VAULT_*` names (OpenBao is an API-compatible Vault fork).
pub fn env_any(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| env::var(k).ok())
}

/// Load configuration from a JSON config file (if present) and environment variables.
/// Environment variables take precedence over config file values.
///
/// Config file path is read from `CONFIG_FILE` env var (default: `config.json`).
pub fn load_config() -> Config {
    let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.json".to_string());
    let file_values: serde_json::Value = fs::read_to_string(&config_path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or(serde_json::Value::Null);

    let from_file = |key: &str| -> Option<String> {
        file_values
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    let public_endpoint = env::var("PUBLIC_ENDPOINT")
        .ok()
        .or_else(|| from_file("public_endpoint"))
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let service_address = env::var("SERVICE_ADDRESS")
        .ok()
        .or_else(|| from_file("service_address"))
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let log_file = env::var("LOG_FILE")
        .ok()
        .or_else(|| from_file("log_file"))
        .unwrap_or_else(|| "impala-bridge.log".to_string());

    let debug_mode = env::var("DEBUG_MODE")
        .ok()
        .or_else(|| from_file("debug_mode").map(|v| v.to_string()))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let twilio_sid = env::var("TWILIO_SID")
        .ok()
        .or_else(|| from_file("twilio_sid"));

    let twilio_token = env::var("TWILIO_TOKEN")
        .ok()
        .or_else(|| from_file("twilio_token"));

    let twilio_number = env::var("TWILIO_NUMBER")
        .ok()
        .or_else(|| from_file("twilio_number"));

    let ldap_url = env::var("LDAP_URL").ok().or_else(|| from_file("ldap_url"));

    let ldap_bind_dn = env::var("LDAP_BIND_DN")
        .ok()
        .or_else(|| from_file("ldap_bind_dn"));

    let ldap_bind_password = env::var("LDAP_BIND_PASSWORD")
        .ok()
        .or_else(|| from_file("ldap_bind_password"));

    let ldap_base_dn = env::var("LDAP_BASE_DN")
        .ok()
        .or_else(|| from_file("ldap_base_dn"));

    let ldap_search_filter = env::var("LDAP_SEARCH_FILTER")
        .ok()
        .or_else(|| from_file("ldap_search_filter"));

    let db_max_connections = env::var("DB_MAX_CONNECTIONS")
        .ok()
        .or_else(|| from_file("db_max_connections"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DB_MAX_CONNECTIONS);

    let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
        .ok()
        .or_else(|| from_file("cors_allowed_origins"))
        .unwrap_or_else(|| "*".to_string());

    let http_client_timeout_secs = env::var("HTTP_CLIENT_TIMEOUT_SECS")
        .ok()
        .or_else(|| from_file("http_client_timeout_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS);

    // OIDC SSO providers (multi-provider registry). Declare the set via
    // `SSO_PROVIDERS=okta,auth0,duo` (or an `sso_providers` comma-list string
    // in the config file); each provider is then configured with prefixed
    // vars. For backward compatibility, if `SSO_PROVIDERS` is unset but
    // `OKTA_ISSUER_URL` is set we synthesize a single `okta` provider.
    let provider_var = |name: &str, key: &str| -> Option<String> {
        let env_key = format!("{}_{}", name.to_uppercase(), key);
        let file_key = format!("{}_{}", name.to_lowercase(), key.to_lowercase());
        env::var(&env_key).ok().or_else(|| from_file(&file_key))
    };

    let provider_names: Vec<String> = match env::var("SSO_PROVIDERS")
        .ok()
        .or_else(|| from_file("sso_providers"))
    {
        Some(list) if !list.trim().is_empty() => list
            .split(',')
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => {
            if env::var("OKTA_ISSUER_URL")
                .ok()
                .or_else(|| from_file("okta_issuer_url"))
                .is_some()
            {
                vec!["okta".to_string()]
            } else {
                Vec::new()
            }
        }
    };

    let sso_providers = parse_sso_providers(&provider_names, provider_var);

    // Legacy single-provider Okta config, still consumed by the `/auth/okta`
    // cookie-capable flow (okta::init_okta_provider). The same variables also
    // feed the SSO registry's back-compat synthesis above.
    let okta_issuer_url = env::var("OKTA_ISSUER_URL")
        .ok()
        .or_else(|| from_file("okta_issuer_url"));

    let okta_client_id = env::var("OKTA_CLIENT_ID")
        .ok()
        .or_else(|| from_file("okta_client_id"));

    let okta_jwks_refresh_secs = env::var("OKTA_JWKS_REFRESH_SECS")
        .ok()
        .or_else(|| from_file("okta_jwks_refresh_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_JWKS_REFRESH_SECS);

    let google_client_id = env::var("GOOGLE_CLIENT_ID")
        .ok()
        .or_else(|| from_file("google_client_id"));

    let google_jwks_refresh_secs = env::var("GOOGLE_JWKS_REFRESH_SECS")
        .ok()
        .or_else(|| from_file("google_jwks_refresh_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_JWKS_REFRESH_SECS);

    let github_auth_enabled = env::var("GITHUB_AUTH_ENABLED")
        .ok()
        .or_else(|| from_file("github_auth_enabled"))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let github_client_id = env::var("GITHUB_CLIENT_ID")
        .ok()
        .or_else(|| from_file("github_client_id"));

    let github_client_secret = env::var("GITHUB_CLIENT_SECRET")
        .ok()
        .or_else(|| from_file("github_client_secret"));

    let github_oauth_token_url = env::var("GITHUB_OAUTH_TOKEN_URL")
        .ok()
        .or_else(|| from_file("github_oauth_token_url"))
        .unwrap_or_else(|| crate::constants::DEFAULT_GITHUB_OAUTH_TOKEN_URL.to_string());

    let github_api_url = env::var("GITHUB_API_URL")
        .ok()
        .or_else(|| from_file("github_api_url"))
        .filter(|v| !v.is_empty()) // compose passes "" when unset
        .unwrap_or_else(|| crate::constants::DEFAULT_GITHUB_API_URL.to_string());

    let sqs_queue_url = env::var("SQS_QUEUE_URL")
        .ok()
        .or_else(|| from_file("sqs_queue_url"));

    let sns_topic_arn = env::var("SNS_TOPIC_ARN")
        .ok()
        .or_else(|| from_file("sns_topic_arn"));

    let worker_concurrency = env::var("WORKER_CONCURRENCY")
        .ok()
        .or_else(|| from_file("worker_concurrency"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_WORKER_CONCURRENCY);

    let sqs_wait_time_seconds = env::var("SQS_WAIT_TIME_SECONDS")
        .ok()
        .or_else(|| from_file("sqs_wait_time_seconds"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_SQS_WAIT_TIME_SECONDS);

    let sqs_visibility_timeout = env::var("SQS_VISIBILITY_TIMEOUT")
        .ok()
        .or_else(|| from_file("sqs_visibility_timeout"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_SQS_VISIBILITY_TIMEOUT);

    let ses_from_address = env::var("SES_FROM_ADDRESS")
        .ok()
        .or_else(|| from_file("ses_from_address"));

    let fcm_project_id = env::var("FCM_PROJECT_ID")
        .ok()
        .or_else(|| from_file("fcm_project_id"));

    let fcm_service_account_key = env::var("FCM_SERVICE_ACCOUNT_KEY")
        .ok()
        .or_else(|| from_file("fcm_service_account_key"));

    let otel_exporter_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .or_else(|| from_file("otel_exporter_endpoint"));

    let otel_service_name = env::var("OTEL_SERVICE_NAME")
        .ok()
        .or_else(|| from_file("otel_service_name"));

    let otel_environment = env::var("OTEL_ENVIRONMENT")
        .ok()
        .or_else(|| from_file("otel_environment"));

    let stellar_network_str = env::var("STELLAR_NETWORK")
        .ok()
        .or_else(|| from_file("stellar_network"))
        .unwrap_or_else(|| "testnet".to_string());
    let stellar_network = StellarNetwork::from_str(&stellar_network_str);

    let (default_horizon, default_rpc, default_passphrase) = match stellar_network {
        StellarNetwork::Testnet => (
            STELLAR_TESTNET_HORIZON_URL,
            STELLAR_TESTNET_RPC_URL,
            STELLAR_TESTNET_PASSPHRASE,
        ),
        StellarNetwork::Pubnet => (
            STELLAR_PUBNET_HORIZON_URL,
            STELLAR_PUBNET_RPC_URL,
            STELLAR_PUBNET_PASSPHRASE,
        ),
    };

    let stellar_max_fee_stroops = env::var("STELLAR_MAX_FEE_STROOPS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("stellar_max_fee_stroops"))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(crate::constants::DEFAULT_STELLAR_MAX_FEE_STROOPS)
        .clamp(
            crate::constants::STELLAR_MAX_FEE_STROOPS_MIN,
            crate::constants::STELLAR_MAX_FEE_STROOPS_MAX,
        );

    let stellar_horizon_url = env::var("STELLAR_HORIZON_URL")
        .ok()
        .or_else(|| from_file("stellar_horizon_url"))
        .unwrap_or_else(|| default_horizon.to_string());

    let stellar_rpc_url = env::var("STELLAR_RPC_URL")
        .ok()
        .or_else(|| from_file("stellar_rpc_url"))
        .unwrap_or_else(|| default_rpc.to_string());

    let stellar_network_passphrase = env::var("STELLAR_NETWORK_PASSPHRASE")
        .ok()
        .or_else(|| from_file("stellar_network_passphrase"))
        .unwrap_or_else(|| default_passphrase.to_string());

    let soroban_contract_id = env::var("SOROBAN_CONTRACT_ID")
        .ok()
        .or_else(|| from_file("soroban_contract_id"));

    let admin_account_ids = env::var("ADMIN_ACCOUNT_IDS")
        .ok()
        .or_else(|| from_file("admin_account_ids"))
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<HashSet<String>>()
        })
        .unwrap_or_default();

    let mfa_required_roles = env::var("MFA_REQUIRED_ROLES")
        .ok()
        .or_else(|| from_file("mfa_required_roles"))
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<HashSet<String>>()
        })
        .unwrap_or_default();

    let mfa_max_age_secs = env::var("MFA_MAX_AGE_SECS")
        .ok()
        .or_else(|| from_file("mfa_max_age_secs"))
        .and_then(|v| v.parse().ok())
        .filter(|&v: &i64| v > 0)
        .unwrap_or(crate::constants::MFA_MAX_AGE_SECS_DEFAULT);

    let mfa_card_pin_trust = env::var("MFA_CARD_PIN_TRUST")
        .ok()
        .or_else(|| from_file("mfa_card_pin_trust"))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| {
            s == crate::constants::MFA_CARD_PIN_TRUST_CERTIFIED
                || s == crate::constants::MFA_CARD_PIN_TRUST_ANY
        })
        .unwrap_or_else(|| crate::constants::MFA_CARD_PIN_TRUST_CERTIFIED.to_string());

    let mfa_device_biometric = env::var("MFA_DEVICE_BIOMETRIC")
        .ok()
        .or_else(|| from_file("mfa_device_biometric"))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| {
            s == crate::constants::MFA_DEVICE_BIOMETRIC_OFF
                || s == crate::constants::MFA_DEVICE_BIOMETRIC_CLAIMED
        })
        .unwrap_or_else(|| crate::constants::MFA_DEVICE_BIOMETRIC_OFF.to_string());

    let admin_webhook_max_attempts = env::var("ADMIN_WEBHOOK_MAX_ATTEMPTS")
        .ok()
        .or_else(|| from_file("admin_webhook_max_attempts"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_WEBHOOK_MAX_ATTEMPTS);

    let admin_webhook_disable_threshold = env::var("ADMIN_WEBHOOK_DISABLE_THRESHOLD")
        .ok()
        .or_else(|| from_file("admin_webhook_disable_threshold"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_WEBHOOK_DISABLE_THRESHOLD);

    let admin_webhook_poll_secs = env::var("ADMIN_WEBHOOK_POLL_SECS")
        .ok()
        .or_else(|| from_file("admin_webhook_poll_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_WEBHOOK_POLL_SECS);

    let session_cookie_secure = env::var("SESSION_COOKIE_SECURE")
        .ok()
        .or_else(|| from_file("session_cookie_secure"))
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    // Defaults to false: first-touch registration on an existing account is a
    // way to claim one, so it has to be turned on deliberately.
    let allow_open_registration = env::var("ALLOW_OPEN_REGISTRATION")
        .ok()
        .or_else(|| from_file("allow_open_registration"))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Which X-Forwarded-For entry (from the right) is the client. Defaults to
    // the ALB's one hop; a direct-exposed bridge must set 0 or every caller
    // can pick its own per-source bucket by writing the header itself.
    let trusted_proxy_hops = env::var("TRUSTED_PROXY_HOPS")
        .ok()
        .or_else(|| from_file("trusted_proxy_hops"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(crate::constants::DEFAULT_TRUSTED_PROXY_HOPS);

    let redis_pool_size = env::var("REDIS_POOL_SIZE")
        .ok()
        .or_else(|| from_file("redis_pool_size"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_REDIS_POOL_SIZE);

    let request_timeout_secs = env::var("REQUEST_TIMEOUT_SECS")
        .ok()
        .or_else(|| from_file("request_timeout_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::REQUEST_TIMEOUT_SECS);

    let db_acquire_timeout_secs = env::var("DB_ACQUIRE_TIMEOUT_SECS")
        .ok()
        .or_else(|| from_file("db_acquire_timeout_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DB_ACQUIRE_TIMEOUT_SECS);

    let seed_protection_backend = env::var("SEED_PROTECTION_BACKEND")
        .ok()
        .or_else(|| from_file("seed_protection_backend"))
        .unwrap_or_else(|| "none".to_string());

    let kms_seed_key_id = env::var("KMS_SEED_KEY_ID")
        .ok()
        .or_else(|| from_file("kms_seed_key_id"));

    // Off unless explicitly turned on. See the field doc: this gates both the
    // admin endpoints and whether stored credentials are read at startup.
    let key_import_enabled = env::var("KEY_IMPORT_ENABLED")
        .ok()
        .or_else(|| from_file("key_import_enabled"))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // Vault/OpenBao: accept the OpenBao-native name first, then the Vault name,
    // then the config file. The internal field names stay `vault_*`.
    let vault_addr = env_any(&["BAO_ADDR", "VAULT_ADDR"]).or_else(|| from_file("vault_addr"));

    let vault_transit_key = env_any(&["BAO_TRANSIT_KEY", "VAULT_TRANSIT_KEY"])
        .or_else(|| from_file("vault_transit_key"));

    // Exchange providers. Secrets (OWLPAY_API_KEY, OWLPAY_WEBHOOK_SECRET,
    // CHANGELLY_API_KEY, CHANGELLY_PRIVATE_KEY, CHANGELLY_FIAT_API_KEY, …) are
    // deliberately NOT loaded here — the provider init fns read them straight
    // from the environment (see the seed-protection rule above).
    // The empty-string filter runs BEFORE the file fallback: compose always
    // injects `VAR: ${VAR:-}`, and a set-but-empty env var must fall through
    // to CONFIG_FILE rather than shadow it (docker-compose.yml warns about
    // exactly this shadowing for the SSO bootstrap config).
    let owlpay_api_url = env::var("OWLPAY_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("owlpay_api_url"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_OWLPAY_API_URL.to_string());

    let changelly_api_url = env::var("CHANGELLY_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("changelly_api_url"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CHANGELLY_API_URL.to_string());

    let changelly_fiat_api_url = env::var("CHANGELLY_FIAT_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("changelly_fiat_api_url"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CHANGELLY_FIAT_API_URL.to_string());

    // Clamped to >= 1s: a zero tick would spin the reconcile loop against the
    // database with no delay (poll_backoff_secs applies the same 1s floor).
    let exchange_poll_secs = env::var("EXCHANGE_POLL_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("exchange_poll_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_EXCHANGE_POLL_SECS)
        .max(1);

    let reserve_account_id = env::var("RESERVE_ACCOUNT_ID")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_account_id"))
        .filter(|v| !v.is_empty());

    let reserve_usdc_issuer = env::var("RESERVE_USDC_ISSUER")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdc_issuer"))
        .filter(|v| !v.is_empty());

    let reserve_usdc_code = env::var("RESERVE_USDC_CODE")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdc_code"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "USDC".to_string());

    let reserve_usdt0_issuer = env::var("RESERVE_USDT0_ISSUER")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdt0_issuer"))
        .filter(|v| !v.is_empty());

    let reserve_usdt0_code = env::var("RESERVE_USDT0_CODE")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdt0_code"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| crate::constants::RESERVE_DEFAULT_USDT0_CODE.to_string());

    // Comma-separated, whitespace-tolerant, compared case-insensitively
    // downstream — normalized to lowercase once here.
    let reserve_usdt0_tickers: Vec<String> = env::var("RESERVE_USDT0_TICKERS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdt0_tickers"))
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Clamped: too short races real deposits, too long hands out a free
    // price option on the pool (the quote is honored for the whole window).
    let reserve_deposit_ttl_secs = env::var("RESERVE_DEPOSIT_TTL_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_deposit_ttl_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RESERVE_DEPOSIT_TTL_SECS)
        .clamp(RESERVE_DEPOSIT_TTL_MIN_SECS, RESERVE_DEPOSIT_TTL_MAX_SECS);

    let reserve_watch_secs = env::var("RESERVE_WATCH_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_watch_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RESERVE_WATCH_SECS)
        .max(5);

    let reserve_quote_ttl_secs = env::var("RESERVE_QUOTE_TTL_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_quote_ttl_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RESERVE_QUOTE_TTL_SECS)
        .clamp(RESERVE_QUOTE_TTL_MIN_SECS, RESERVE_QUOTE_TTL_MAX_SECS);

    let reconciliation_snapshot_utc_hour = env::var("RECONCILIATION_SNAPSHOT_UTC_HOUR")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reconciliation_snapshot_utc_hour"))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(crate::constants::DEFAULT_RECONCILIATION_SNAPSHOT_UTC_HOUR)
        .min(23);
    let reconciliation_max_accounts = env::var("RECONCILIATION_MAX_ACCOUNTS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reconciliation_max_accounts"))
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(crate::constants::DEFAULT_RECONCILIATION_MAX_ACCOUNTS)
        .max(1);
    let reconciliation_deadline_secs = env::var("RECONCILIATION_DEADLINE_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reconciliation_deadline_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(crate::constants::DEFAULT_RECONCILIATION_DEADLINE_SECS)
        .max(10);

    // SEP-10: raw values only; validate_sep10_policy decides, and only when
    // enabled. Empty env values fall through to the config file.
    let sep10_var = |env_key: &str, file_key: &str| -> Option<String> {
        env::var(env_key)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| from_file(file_key))
            .filter(|v| !v.is_empty())
    };
    let sep10 = Sep10Settings {
        enabled: sep10_var("SEP10_ENABLED", "sep10_enabled")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        web_auth_endpoint: sep10_var("SEP10_WEB_AUTH_ENDPOINT", "sep10_web_auth_endpoint"),
        challenge_ttl_secs: sep10_var("SEP10_CHALLENGE_TTL_SECS", "sep10_challenge_ttl_secs"),
        challenge_global_max: sep10_var("SEP10_CHALLENGE_GLOBAL_MAX", "sep10_challenge_global_max"),
        key_activation_delay_secs: sep10_var(
            "SEP10_KEY_ACTIVATION_DELAY_SECS",
            "sep10_key_activation_delay_secs",
        ),
        stellar_network_raw: sep10_var("STELLAR_NETWORK", "stellar_network"),
        public_endpoint_raw: sep10_var("PUBLIC_ENDPOINT", "public_endpoint"),
    };

    Config {
        public_endpoint,
        service_address,
        log_file,
        debug_mode,
        twilio_sid,
        twilio_token,
        twilio_number,
        ldap_url,
        ldap_bind_dn,
        ldap_bind_password,
        ldap_base_dn,
        ldap_search_filter,
        db_max_connections,
        cors_allowed_origins,
        http_client_timeout_secs,
        okta_issuer_url,
        okta_client_id,
        okta_jwks_refresh_secs,
        google_client_id,
        google_jwks_refresh_secs,
        github_auth_enabled,
        github_api_url,
        github_client_id,
        github_client_secret,
        github_oauth_token_url,
        sso_providers,
        sqs_queue_url,
        sns_topic_arn,
        worker_concurrency,
        sqs_wait_time_seconds,
        sqs_visibility_timeout,
        ses_from_address,
        fcm_project_id,
        fcm_service_account_key,
        otel_exporter_endpoint,
        otel_service_name,
        otel_environment,
        stellar_network,
        stellar_horizon_url,
        stellar_max_fee_stroops,
        stellar_rpc_url,
        stellar_network_passphrase,
        soroban_contract_id,
        admin_account_ids,
        mfa_required_roles,
        mfa_max_age_secs,
        mfa_card_pin_trust,
        mfa_device_biometric,
        admin_webhook_max_attempts,
        admin_webhook_disable_threshold,
        admin_webhook_poll_secs,
        session_cookie_secure,
        allow_open_registration,
        trusted_proxy_hops,
        redis_pool_size,
        request_timeout_secs,
        db_acquire_timeout_secs,
        seed_protection_backend,
        key_import_enabled,
        kms_seed_key_id,
        vault_addr,
        vault_transit_key,
        owlpay_api_url,
        changelly_api_url,
        changelly_fiat_api_url,
        exchange_poll_secs,
        reserve_account_id,
        reserve_usdc_issuer,
        reserve_usdc_code,
        reserve_usdt0_issuer,
        reserve_usdt0_code,
        reserve_usdt0_tickers,
        reserve_deposit_ttl_secs,
        reserve_watch_secs,
        reserve_quote_ttl_secs,
        reconciliation_snapshot_utc_hour,
        reconciliation_max_accounts,
        reconciliation_deadline_secs,
        sep10,
    }
}

/// Minimal `Config` for unit tests (all integrations off, testnet defaults).
/// Tests mutate only the fields they exercise.
#[cfg(test)]
pub(crate) fn test_config() -> Config {
    Config {
        public_endpoint: String::new(),
        service_address: String::new(),
        log_file: String::new(),
        debug_mode: false,
        twilio_sid: None,
        twilio_token: None,
        twilio_number: None,
        ldap_url: None,
        ldap_bind_dn: None,
        ldap_bind_password: None,
        ldap_base_dn: None,
        ldap_search_filter: None,
        db_max_connections: 5,
        cors_allowed_origins: String::new(),
        http_client_timeout_secs: 30,
        okta_issuer_url: None,
        okta_client_id: None,
        okta_jwks_refresh_secs: DEFAULT_JWKS_REFRESH_SECS,
        google_client_id: None,
        google_jwks_refresh_secs: DEFAULT_JWKS_REFRESH_SECS,
        github_auth_enabled: false,
        github_api_url: DEFAULT_GITHUB_API_URL.to_string(),
        github_client_id: None,
        github_client_secret: None,
        github_oauth_token_url: DEFAULT_GITHUB_OAUTH_TOKEN_URL.to_string(),
        sso_providers: Vec::new(),
        sqs_queue_url: None,
        sns_topic_arn: None,
        worker_concurrency: 10,
        sqs_wait_time_seconds: 20,
        sqs_visibility_timeout: 300,
        ses_from_address: None,
        fcm_project_id: None,
        fcm_service_account_key: None,
        otel_exporter_endpoint: None,
        otel_service_name: None,
        otel_environment: None,
        stellar_network: StellarNetwork::Testnet,
        stellar_horizon_url: "https://horizon-testnet.stellar.org".to_string(),
        stellar_max_fee_stroops: crate::constants::DEFAULT_STELLAR_MAX_FEE_STROOPS,
        stellar_rpc_url: "https://soroban-testnet.stellar.org".to_string(),
        stellar_network_passphrase: "Test SDF Network ; September 2015".to_string(),
        soroban_contract_id: None,
        admin_account_ids: HashSet::new(),
        mfa_required_roles: HashSet::new(),
        mfa_max_age_secs: crate::constants::MFA_MAX_AGE_SECS_DEFAULT,
        mfa_card_pin_trust: crate::constants::MFA_CARD_PIN_TRUST_CERTIFIED.to_string(),
        mfa_device_biometric: crate::constants::MFA_DEVICE_BIOMETRIC_OFF.to_string(),
        admin_webhook_max_attempts: DEFAULT_ADMIN_WEBHOOK_MAX_ATTEMPTS,
        admin_webhook_disable_threshold: DEFAULT_ADMIN_WEBHOOK_DISABLE_THRESHOLD,
        admin_webhook_poll_secs: DEFAULT_ADMIN_WEBHOOK_POLL_SECS,
        session_cookie_secure: false,
        allow_open_registration: false,
        trusted_proxy_hops: crate::constants::DEFAULT_TRUSTED_PROXY_HOPS,
        redis_pool_size: DEFAULT_REDIS_POOL_SIZE,
        request_timeout_secs: REQUEST_TIMEOUT_SECS,
        db_acquire_timeout_secs: DB_ACQUIRE_TIMEOUT_SECS,
        seed_protection_backend: "none".to_string(),
        key_import_enabled: false,
        kms_seed_key_id: None,
        vault_addr: None,
        vault_transit_key: None,
        owlpay_api_url: DEFAULT_OWLPAY_API_URL.to_string(),
        changelly_api_url: DEFAULT_CHANGELLY_API_URL.to_string(),
        changelly_fiat_api_url: DEFAULT_CHANGELLY_FIAT_API_URL.to_string(),
        exchange_poll_secs: DEFAULT_EXCHANGE_POLL_SECS,
        reserve_account_id: None,
        reserve_usdc_issuer: None,
        reserve_usdc_code: "USDC".to_string(),
        reserve_usdt0_issuer: None,
        reserve_usdt0_code: crate::constants::RESERVE_DEFAULT_USDT0_CODE.to_string(),
        reserve_usdt0_tickers: Vec::new(),
        reserve_deposit_ttl_secs: DEFAULT_RESERVE_DEPOSIT_TTL_SECS,
        reserve_watch_secs: DEFAULT_RESERVE_WATCH_SECS,
        reserve_quote_ttl_secs: DEFAULT_RESERVE_QUOTE_TTL_SECS,
        reconciliation_snapshot_utc_hour:
            crate::constants::DEFAULT_RECONCILIATION_SNAPSHOT_UTC_HOUR,
        reconciliation_max_accounts: crate::constants::DEFAULT_RECONCILIATION_MAX_ACCOUNTS,
        reconciliation_deadline_secs: crate::constants::DEFAULT_RECONCILIATION_DEADLINE_SECS,
        sep10: Sep10Settings::default(),
    }
}

impl Config {
    pub fn stellar_config(&self) -> StellarConfig {
        StellarConfig {
            network: self.stellar_network.clone(),
            horizon_url: self.stellar_horizon_url.clone(),
            rpc_url: self.stellar_rpc_url.clone(),
            network_passphrase: self.stellar_network_passphrase.clone(),
            contract_id: self.soroban_contract_id.clone(),
            max_fee_stroops: self.stellar_max_fee_stroops,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `main.rs` logs `Config: {:?}` at startup under DEBUG_MODE, so the
    /// `Debug` impl is a log sink for anything it prints. Pin that no secret
    /// value can reach it — a derived `Debug` used to print all of these.
    #[test]
    fn debug_never_prints_secret_values() {
        let mut config = test_config();
        config.twilio_sid = Some("AC-sid-must-not-appear".to_string());
        config.twilio_token = Some("twilio-token-must-not-appear".to_string());
        config.ldap_bind_password = Some("ldap-password-must-not-appear".to_string());
        config.github_client_secret = Some("gh-secret-must-not-appear".to_string());
        config.fcm_service_account_key = Some("{\"private_key\":\"must-not-appear\"}".to_string());

        let rendered = format!("{:?}", config);

        for secret in [
            "AC-sid-must-not-appear",
            "twilio-token-must-not-appear",
            "ldap-password-must-not-appear",
            "gh-secret-must-not-appear",
            "must-not-appear",
        ] {
            assert!(
                !rendered.contains(secret),
                "Config Debug leaked a secret value: {rendered}"
            );
        }

        // Presence is still reported, so the log stays operationally useful.
        assert!(rendered.contains("<set:redacted>"));
        assert!(rendered.contains("service_address"));
    }

    #[test]
    fn debug_reports_absent_secrets_as_unset() {
        let mut config = test_config();
        config.twilio_token = None;
        config.ldap_bind_password = None;
        let rendered = format!("{:?}", config);
        assert!(rendered.contains("<unset>"), "{rendered}");
    }

    #[test]
    fn cors_wildcard_rejected_on_pubnet() {
        assert!(validate_cors_policy(&StellarNetwork::Pubnet, "*").is_err());
        assert!(validate_cors_policy(&StellarNetwork::Pubnet, "  *  ").is_err());
    }

    #[test]
    fn cors_wildcard_allowed_on_testnet() {
        assert!(validate_cors_policy(&StellarNetwork::Testnet, "*").is_ok());
    }

    #[test]
    fn cors_explicit_origins_allowed_on_pubnet() {
        assert!(
            validate_cors_policy(&StellarNetwork::Pubnet, "https://admin.impala.example.com")
                .is_ok()
        );
    }

    #[test]
    fn test_stellar_network_from_str_testnet() {
        assert_eq!(StellarNetwork::from_str("testnet"), StellarNetwork::Testnet);
    }

    #[test]
    fn test_stellar_network_from_str_pubnet() {
        assert_eq!(StellarNetwork::from_str("pubnet"), StellarNetwork::Pubnet);
    }

    #[test]
    fn test_stellar_network_from_str_mainnet() {
        assert_eq!(StellarNetwork::from_str("mainnet"), StellarNetwork::Pubnet);
    }

    #[test]
    fn test_stellar_network_from_str_public() {
        assert_eq!(StellarNetwork::from_str("public"), StellarNetwork::Pubnet);
    }

    #[test]
    fn test_stellar_network_from_str_unknown_defaults_testnet() {
        assert_eq!(
            StellarNetwork::from_str("anything"),
            StellarNetwork::Testnet
        );
    }

    #[test]
    fn test_stellar_network_from_str_case_insensitive() {
        assert_eq!(StellarNetwork::from_str("PUBNET"), StellarNetwork::Pubnet);
        assert_eq!(StellarNetwork::from_str("Testnet"), StellarNetwork::Testnet);
    }

    #[test]
    fn test_stellar_network_as_str_testnet() {
        assert_eq!(StellarNetwork::Testnet.as_str(), "testnet");
    }

    #[test]
    fn test_stellar_network_as_str_pubnet() {
        assert_eq!(StellarNetwork::Pubnet.as_str(), "pubnet");
    }

    #[test]
    fn test_token_kind_from_str() {
        assert_eq!(TokenKind::from_str_opt("id"), TokenKind::Id);
        assert_eq!(TokenKind::from_str_opt("id_token"), TokenKind::Id);
        assert_eq!(TokenKind::from_str_opt("ID"), TokenKind::Id);
        assert_eq!(TokenKind::from_str_opt("access"), TokenKind::Access);
        assert_eq!(TokenKind::from_str_opt(""), TokenKind::Access);
        assert_eq!(TokenKind::from_str_opt("anything"), TokenKind::Access);
    }

    #[test]
    fn test_stellar_config_from_config() {
        // Verify stellar_config() correctly copies fields
        // Note: we can't easily test load_config() since it reads env vars,
        // but we can test the Config -> StellarConfig conversion
        let mut config = test_config();
        config.soroban_contract_id = Some("CONTRACT123".to_string());
        let sc = config.stellar_config();
        assert_eq!(sc.network, StellarNetwork::Testnet);
        assert_eq!(sc.horizon_url, "https://horizon-testnet.stellar.org");
        assert_eq!(sc.rpc_url, "https://soroban-testnet.stellar.org");
        assert_eq!(sc.contract_id, Some("CONTRACT123".to_string()));
    }

    /// Build a `provider_var`-shaped lookup from `("NAME", "KEY", "value")`
    /// triples, mirroring the env-var naming used by `load_config`.
    fn lookup<'a>(
        entries: &'a [(&'a str, &'a str, &'a str)],
    ) -> impl Fn(&str, &str) -> Option<String> + 'a {
        move |name: &str, key: &str| {
            entries
                .iter()
                .find(|(n, k, _)| n.eq_ignore_ascii_case(name) && *k == key)
                .map(|(_, _, v)| v.to_string())
        }
    }

    #[test]
    fn sso_provider_parses_internal_issuer_and_allow_http() {
        let names = vec!["openbao".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[
                (
                    "openbao",
                    "ISSUER_URL",
                    "http://localhost:8200/v1/identity/oidc/provider/openbao",
                ),
                ("openbao", "CLIENT_ID", "generated-id"),
                (
                    "openbao",
                    "INTERNAL_ISSUER_URL",
                    "http://openbao:8200/v1/identity/oidc/provider/openbao",
                ),
                ("openbao", "ALLOW_HTTP", "true"),
                ("openbao", "TOKEN_KIND", "id"),
            ]),
        );
        assert_eq!(providers.len(), 1);
        let p = &providers[0];
        assert_eq!(
            p.internal_issuer_url.as_deref(),
            Some("http://openbao:8200/v1/identity/oidc/provider/openbao")
        );
        assert!(p.allow_http);
        assert_eq!(p.token_kind, TokenKind::Id);
        assert_eq!(p.audience, "generated-id");
    }

    #[test]
    fn sso_provider_new_keys_default_backward_compatible() {
        let names = vec!["okta".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[
                (
                    "okta",
                    "ISSUER_URL",
                    "https://example.okta.com/oauth2/default",
                ),
                ("okta", "CLIENT_ID", "abc123"),
            ]),
        );
        assert_eq!(providers.len(), 1);
        let p = &providers[0];
        assert_eq!(p.internal_issuer_url, None);
        assert!(!p.allow_http);
        assert_eq!(p.audience, "abc123");
        assert_eq!(p.token_kind, TokenKind::Access);
        assert_eq!(
            p.jwks_refresh_secs,
            crate::constants::DEFAULT_JWKS_REFRESH_SECS
        );
    }

    #[test]
    fn sso_provider_allow_http_accepts_true_and_1_only() {
        for (value, expected) in [
            ("true", true),
            ("1", true),
            ("false", false),
            ("yes", false),
            ("TRUE", false),
            ("", false),
        ] {
            let names = vec!["dev".to_string()];
            let providers = parse_sso_providers(
                &names,
                lookup(&[
                    ("dev", "ISSUER_URL", "https://idp.example.com"),
                    ("dev", "ALLOW_HTTP", value),
                ]),
            );
            assert_eq!(providers[0].allow_http, expected, "value {value:?}");
        }
    }

    #[test]
    fn sso_provider_blank_internal_issuer_treated_as_unset() {
        let names = vec!["dev".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[
                ("dev", "ISSUER_URL", "https://idp.example.com"),
                ("dev", "INTERNAL_ISSUER_URL", "   "),
            ]),
        );
        assert_eq!(providers[0].internal_issuer_url, None);
    }

    #[test]
    fn sso_provider_missing_issuer_drops_provider() {
        let names = vec!["ghost".to_string(), "real".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[("real", "ISSUER_URL", "https://idp.example.com")]),
        );
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "real");
    }

    // ── SEP-10 boot gate ───────────────────────────────────────────────

    fn sep10_config(endpoint: &str) -> Config {
        let mut c = test_config();
        c.seed_protection_backend = "openbao".to_string();
        c.sep10 = Sep10Settings {
            enabled: true,
            web_auth_endpoint: Some(endpoint.to_string()),
            stellar_network_raw: Some("testnet".to_string()),
            ..Sep10Settings::default()
        };
        c
    }

    #[test]
    fn sep10_disabled_checks_nothing() {
        let mut c = test_config();
        c.sep10.web_auth_endpoint = Some("ftp://nonsense".to_string());
        c.sep10.challenge_ttl_secs = Some("7".to_string());
        assert!(validate_sep10_policy(&c).unwrap().is_none());
        let admin = Sep10AdminSettings::from_config(&c, None);
        assert!(!admin.enabled);
        assert_eq!(
            admin.activation_delay_secs,
            DEFAULT_SEP10_KEY_ACTIVATION_DELAY_SECS
        );
        assert_eq!(admin.challenge_ttl_secs, DEFAULT_SEP10_CHALLENGE_TTL_SECS);
        assert_eq!(
            admin.home_domain, None,
            "an invalid endpoint reads as unconfigured"
        );
        assert_eq!(admin.web_auth_endpoint, None);
        // Disabled but configured: the admin status still reports the endpoint.
        c.sep10.web_auth_endpoint = Some("http://10.0.2.2:8080/auth/sep10".to_string());
        let admin = Sep10AdminSettings::from_config(&c, None);
        assert_eq!(admin.home_domain.as_deref(), Some("10.0.2.2:8080"));
        assert_eq!(
            admin.web_auth_endpoint.as_deref(),
            Some("http://10.0.2.2:8080/auth/sep10")
        );
        assert_eq!(admin.network_passphrase, STELLAR_TESTNET_PASSPHRASE);
    }

    #[test]
    fn sep10_enabled_with_a_good_endpoint_yields_the_policy() {
        let p = validate_sep10_policy(&sep10_config("https://api-testnet.example.com/auth/sep10"))
            .unwrap()
            .unwrap();
        assert_eq!(p.home_domain, "api-testnet.example.com");
        assert_eq!(
            p.web_auth_endpoint,
            "https://api-testnet.example.com/auth/sep10"
        );
        assert_eq!(p.challenge_ttl_secs, 300);
        assert_eq!(p.challenge_global_max, 600);
        assert_eq!(p.activation_delay_secs, 120);
        assert_eq!(p.network_passphrase, STELLAR_TESTNET_PASSPHRASE);
        for local in [
            "http://localhost:8080/auth/sep10",
            "http://127.0.0.1:8080/auth/sep10",
            "http://10.0.2.2:8080/auth/sep10",
        ] {
            let p = validate_sep10_policy(&sep10_config(local))
                .unwrap()
                .unwrap();
            assert!(local.contains(&p.home_domain), "{local}");
        }
    }

    #[test]
    fn sep10_endpoint_shape_is_enforced() {
        for bad in [
            "",
            "http://api-testnet.example.com/auth/sep10", // http off loopback
            "https://api-testnet.example.com/auth/sep10/", // trailing slash
            "https://api-testnet.example.com/auth",      // wrong path
            "https://api-testnet.example.com/api/testnet/auth/sep10", // shared-proxy topology
            "https://API-testnet.example.com/auth/sep10", // not canonical
            "https://api-testnet.example.com:443/auth/sep10", // default port written
            "https://api-testnet.example.com/auth/sep10?x=1",
            "https://user:pw@api-testnet.example.com/auth/sep10",
            "https://[::1]/auth/sep10",
            "not a url",
        ] {
            let mut c = sep10_config(bad);
            if bad.is_empty() {
                c.sep10.web_auth_endpoint = None;
            }
            assert!(
                validate_sep10_policy(&c).is_err(),
                "{bad:?} must be refused"
            );
        }
        // 59-byte authority accepted, 60 refused.
        let host59 = format!("{}.example.com", "a".repeat(59 - ".example.com".len()));
        assert_eq!(host59.len(), 59);
        assert!(
            validate_sep10_policy(&sep10_config(&format!("https://{host59}/auth/sep10"))).is_ok()
        );
        let host60 = format!("a{host59}");
        assert!(
            validate_sep10_policy(&sep10_config(&format!("https://{host60}/auth/sep10"))).is_err()
        );
    }

    #[test]
    fn sep10_refused_unless_testnet_passphrase() {
        let ok = "https://api-testnet.example.com/auth/sep10";
        // STELLAR_NETWORK unset: the enum says testnet, the gate does not.
        let mut c = sep10_config(ok);
        c.sep10.stellar_network_raw = None;
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config(ok);
        c.sep10.stellar_network_raw = Some("pubnet".to_string());
        assert!(validate_sep10_policy(&c).is_err());
        // Explicit testnet but the pubnet passphrase (or anything else).
        let mut c = sep10_config(ok);
        c.stellar_network_passphrase = STELLAR_PUBNET_PASSPHRASE.to_string();
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config(ok);
        c.stellar_network_passphrase = format!("{STELLAR_TESTNET_PASSPHRASE} ");
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config(ok);
        c.sep10.stellar_network_raw = Some("TestNet".to_string());
        assert!(validate_sep10_policy(&c).is_ok());
    }

    #[test]
    fn sep10_requires_real_seed_protection_and_reserved_names() {
        let ok = "https://api-testnet.example.com/auth/sep10";
        let mut c = sep10_config(ok);
        c.seed_protection_backend = "none".to_string();
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config(ok);
        c.seed_protection_backend = String::new();
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config(ok);
        c.sso_providers = parse_sso_providers(&["sep10".to_string()], |_, k| {
            (k == "ISSUER_URL").then(|| "https://idp.example.com".to_string())
        });
        assert!(validate_sep10_policy(&c).is_err());
    }

    #[test]
    fn sep10_public_endpoint_must_share_the_authority_when_set() {
        let ok = "https://api-testnet.example.com/auth/sep10";
        let mut c = sep10_config(ok);
        c.sep10.public_endpoint_raw = Some("https://api-testnet.example.com".to_string());
        assert!(validate_sep10_policy(&c).is_ok());
        c.sep10.public_endpoint_raw = Some("https://bridge.example.com".to_string());
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config("http://10.0.2.2:8080/auth/sep10");
        c.sep10.public_endpoint_raw = Some("http://localhost:8080".to_string());
        assert!(validate_sep10_policy(&c).is_err());
    }

    #[test]
    fn sep10_knobs_are_range_checked_when_enabled() {
        let ok = "https://api-testnet.example.com/auth/sep10";
        for (ttl, good) in [
            ("59", false),
            ("60", true),
            ("900", true),
            ("901", false),
            ("x", false),
        ] {
            let mut c = sep10_config(ok);
            c.sep10.challenge_ttl_secs = Some(ttl.to_string());
            assert_eq!(validate_sep10_policy(&c).is_ok(), good, "ttl {ttl}");
        }
        for (delay, good) in [
            ("119", false),
            ("120", true),
            ("86400", true),
            ("86401", false),
        ] {
            let mut c = sep10_config(ok);
            c.sep10.key_activation_delay_secs = Some(delay.to_string());
            assert_eq!(validate_sep10_policy(&c).is_ok(), good, "delay {delay}");
        }
        let mut c = sep10_config(ok);
        c.sep10.challenge_global_max = Some("0".to_string());
        assert!(validate_sep10_policy(&c).is_err());
        let mut c = sep10_config(ok);
        c.sep10.key_activation_delay_secs = Some("600".to_string());
        let p = validate_sep10_policy(&c).unwrap().unwrap();
        assert_eq!(
            Sep10AdminSettings::from_config(&c, Some(&p)).activation_delay_secs,
            600
        );
    }
}

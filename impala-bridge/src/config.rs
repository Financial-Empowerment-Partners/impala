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
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // config surface; several fields are populated from env but not yet read
pub struct Config {
    pub public_endpoint: String,
    pub service_address: String,
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
    pub sqs_queue_url: Option<String>,
    pub sns_topic_arn: Option<String>,
    pub worker_concurrency: usize,
    pub sqs_wait_time_seconds: i32,
    pub sqs_visibility_timeout: i32,
    pub ses_from_address: Option<String>,
    pub fcm_project_id: Option<String>,
    pub fcm_service_account_key: Option<String>,
    pub otel_exporter_endpoint: Option<String>,
    pub otel_service_name: Option<String>,
    pub otel_environment: Option<String>,
    pub stellar_network: StellarNetwork,
    pub stellar_horizon_url: String,
    pub stellar_rpc_url: String,
    pub stellar_network_passphrase: String,
    pub soroban_contract_id: Option<String>,
    /// Account IDs (JWT `sub`) granted admin; source of the `is_admin` claim.
    pub admin_account_ids: HashSet<String>,
    /// Max delivery attempts before an admin-webhook delivery is marked failed.
    pub admin_webhook_max_attempts: u32,
    /// Consecutive-failure count after which a webhook is auto-disabled.
    pub admin_webhook_disable_threshold: i64,
    /// Poll interval (seconds) for the admin-webhook delivery worker.
    pub admin_webhook_poll_secs: u64,
    /// Mark session cookies `Secure` (+ `__Host-` name prefix). Default true;
    /// the plain-HTTP local compose stack sets SESSION_COOKIE_SECURE=false.
    pub session_cookie_secure: bool,
    /// deadpool-redis pool size (REDIS_POOL_SIZE).
    pub redis_pool_size: usize,
    /// Global HTTP request timeout in seconds (REQUEST_TIMEOUT_SECS).
    pub request_timeout_secs: u64,
    /// Postgres pool acquire timeout in seconds (DB_ACQUIRE_TIMEOUT_SECS).
    pub db_acquire_timeout_secs: u64,
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
        stellar_rpc_url,
        stellar_network_passphrase,
        soroban_contract_id,
        admin_account_ids,
        admin_webhook_max_attempts,
        admin_webhook_disable_threshold,
        admin_webhook_poll_secs,
        session_cookie_secure,
        redis_pool_size,
        request_timeout_secs,
        db_acquire_timeout_secs,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

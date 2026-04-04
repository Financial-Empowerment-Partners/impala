use crate::constants::*;
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
    fn test_stellar_config_from_config() {
        // Verify stellar_config() correctly copies fields
        // Note: we can't easily test load_config() since it reads env vars,
        // but we can test the Config -> StellarConfig conversion
        let config = Config {
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
            okta_jwks_refresh_secs: 3600,
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
            stellar_rpc_url: "https://soroban-testnet.stellar.org".to_string(),
            stellar_network_passphrase: "Test SDF Network ; September 2015".to_string(),
            soroban_contract_id: Some("CONTRACT123".to_string()),
        };
        let sc = config.stellar_config();
        assert_eq!(sc.network, StellarNetwork::Testnet);
        assert_eq!(sc.horizon_url, "https://horizon-testnet.stellar.org");
        assert_eq!(sc.rpc_url, "https://soroban-testnet.stellar.org");
        assert_eq!(sc.contract_id, Some("CONTRACT123".to_string()));
    }
}

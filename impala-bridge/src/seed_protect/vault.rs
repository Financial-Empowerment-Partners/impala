//! HashiCorp Vault Transit backend for [`SeedProtector`].
//!
//! Uses Vault's Transit engine ("encryption as a service"): the seed plaintext is
//! sent to Vault, encrypted under a transit key that never leaves Vault, and only
//! the `vault:vN:...` ciphertext token is returned and persisted. This mirrors the
//! KMS envelope model — the wrapping key stays in the HSM/Vault, ciphertext lives
//! in Postgres — so both backends are behaviorally interchangeable.
//!
//! Auth: a static `VAULT_TOKEN`, or AppRole (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`)
//! exchanged for a token at startup. TLS verification is always on (rustls).

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::error;
use serde::Deserialize;

use super::{ProtectedSeed, ProtectorBackend, SecretBytes, SeedProtector};
use crate::config::Config;
use crate::error::AppError;

fn protect_error(context: &str, cause: impl std::fmt::Display) -> AppError {
    error!("vault seed protection: {}: {}", context, cause);
    AppError::InternalError("seed protection unavailable".to_string())
}

#[derive(Deserialize)]
struct TransitEncryptResponse {
    data: TransitEncryptData,
}
#[derive(Deserialize)]
struct TransitEncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct TransitDecryptResponse {
    data: TransitDecryptData,
}
#[derive(Deserialize)]
struct TransitDecryptData {
    plaintext: String,
}

#[derive(Deserialize)]
struct AppRoleLoginResponse {
    auth: AppRoleAuth,
}
#[derive(Deserialize)]
struct AppRoleAuth {
    client_token: String,
}

pub struct VaultSeedProtector {
    http: reqwest::Client,
    addr: String,
    token: String,
    transit_key: String,
}

impl VaultSeedProtector {
    /// Build from config: resolve `VAULT_ADDR` + `VAULT_TRANSIT_KEY` and obtain a
    /// token (static or via AppRole login). Returns `Err` (caller fails closed)
    /// when required config is missing.
    pub async fn from_config(config: &Config) -> Result<Self, String> {
        let addr = config
            .vault_addr
            .clone()
            .ok_or_else(|| "SEED_PROTECTION_BACKEND=vault requires VAULT_ADDR".to_string())?
            .trim_end_matches('/')
            .to_string();
        let transit_key = config.vault_transit_key.clone().ok_or_else(|| {
            "SEED_PROTECTION_BACKEND=vault requires VAULT_TRANSIT_KEY".to_string()
        })?;

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(
                crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS,
            ))
            .build()
            .map_err(|e| format!("vault: failed to build HTTP client: {}", e))?;

        // Auth secrets are read straight from the environment so they never enter
        // `Config` (which is `Debug`-logged at startup) and are never persisted.
        let token = if let Ok(token) = std::env::var("VAULT_TOKEN") {
            token
        } else if let (Ok(role_id), Ok(secret_id)) = (
            std::env::var("VAULT_ROLE_ID"),
            std::env::var("VAULT_SECRET_ID"),
        ) {
            approle_login(&http, &addr, &role_id, &secret_id).await?
        } else {
            return Err(
                "vault backend requires VAULT_TOKEN or VAULT_ROLE_ID + VAULT_SECRET_ID".to_string(),
            );
        };

        Ok(VaultSeedProtector {
            http,
            addr,
            token,
            transit_key,
        })
    }
}

/// Exchange an AppRole role_id/secret_id for a Vault client token.
async fn approle_login(
    http: &reqwest::Client,
    addr: &str,
    role_id: &str,
    secret_id: &str,
) -> Result<String, String> {
    let url = format!("{}/v1/auth/approle/login", addr);
    let resp = http
        .post(&url)
        .json(&serde_json::json!({ "role_id": role_id, "secret_id": secret_id }))
        .send()
        .await
        .map_err(|e| format!("vault approle login request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "vault approle login failed: HTTP {}",
            resp.status()
        ));
    }
    let parsed: AppRoleLoginResponse = resp
        .json()
        .await
        .map_err(|e| format!("vault approle login: invalid response: {}", e))?;
    Ok(parsed.auth.client_token)
}

/// Parse the version from a `vault:vN:...` transit ciphertext token.
fn parse_key_version(ciphertext: &str) -> Option<String> {
    // Format: "vault:v<NUM>:<base64>"
    let rest = ciphertext.strip_prefix("vault:v")?;
    let (version, _) = rest.split_once(':')?;
    Some(version.to_string())
}

#[async_trait]
impl SeedProtector for VaultSeedProtector {
    async fn encrypt_seed(&self, plaintext: &[u8]) -> Result<ProtectedSeed, AppError> {
        let url = format!("{}/v1/transit/encrypt/{}", self.addr, self.transit_key);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&serde_json::json!({ "plaintext": STANDARD.encode(plaintext) }))
            .send()
            .await
            .map_err(|e| protect_error("transit encrypt request", e))?;
        if !resp.status().is_success() {
            return Err(protect_error(
                "transit encrypt",
                format!("HTTP {}", resp.status()),
            ));
        }
        let parsed: TransitEncryptResponse = resp
            .json()
            .await
            .map_err(|e| protect_error("transit encrypt response", e))?;
        let key_version = parse_key_version(&parsed.data.ciphertext);

        Ok(ProtectedSeed {
            backend: ProtectorBackend::Vault,
            ciphertext: parsed.data.ciphertext.into_bytes(),
            wrapped_data_key: None,
            nonce: None,
            key_id: self.transit_key.clone(),
            key_version,
        })
    }

    async fn decrypt_seed(&self, protected: &ProtectedSeed) -> Result<SecretBytes, AppError> {
        let ciphertext = std::str::from_utf8(&protected.ciphertext)
            .map_err(|e| protect_error("transit decrypt", e))?;
        let url = format!("{}/v1/transit/decrypt/{}", self.addr, self.transit_key);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&serde_json::json!({ "ciphertext": ciphertext }))
            .send()
            .await
            .map_err(|e| protect_error("transit decrypt request", e))?;
        if !resp.status().is_success() {
            return Err(protect_error(
                "transit decrypt",
                format!("HTTP {}", resp.status()),
            ));
        }
        let parsed: TransitDecryptResponse = resp
            .json()
            .await
            .map_err(|e| protect_error("transit decrypt response", e))?;
        let plaintext = STANDARD
            .decode(parsed.data.plaintext.as_bytes())
            .map_err(|e| protect_error("transit decrypt base64", e))?;

        Ok(SecretBytes::new(plaintext))
    }

    fn backend(&self) -> ProtectorBackend {
        ProtectorBackend::Vault
    }
}

#[cfg(test)]
mod tests {
    use super::parse_key_version;

    #[test]
    fn test_parse_key_version_v1() {
        assert_eq!(
            parse_key_version("vault:v1:abcdefg=="),
            Some("1".to_string())
        );
    }

    #[test]
    fn test_parse_key_version_v42() {
        assert_eq!(parse_key_version("vault:v42:zzz"), Some("42".to_string()));
    }

    #[test]
    fn test_parse_key_version_malformed() {
        assert_eq!(parse_key_version("not-a-vault-token"), None);
        assert_eq!(parse_key_version("vault:v1"), None);
    }
}

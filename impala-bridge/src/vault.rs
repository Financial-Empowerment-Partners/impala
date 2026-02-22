use serde::Deserialize;
use std::env;

#[derive(Deserialize, Debug)]
struct VaultUnwrapResponse {
    data: serde_json::Value,
}

#[derive(Debug)]
pub enum BoxUnwrapError {
    VaultUrlMissing,
    RequestFailed(String),
    InvalidResponse(String),
}

impl std::fmt::Display for BoxUnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoxUnwrapError::VaultUrlMissing => {
                write!(f, "VAULT_ADDR environment variable not set")
            }
            BoxUnwrapError::RequestFailed(msg) => write!(f, "Vault request failed: {}", msg),
            BoxUnwrapError::InvalidResponse(msg) => write!(f, "Invalid Vault response: {}", msg),
        }
    }
}

impl std::error::Error for BoxUnwrapError {}

/// Unwrap a HashiCorp Vault wrapped secret using a wrapping token.
pub async fn box_unwrap(wrapping_token: &str) -> Result<serde_json::Value, BoxUnwrapError> {
    let vault_addr = env::var("VAULT_ADDR").map_err(|_| BoxUnwrapError::VaultUrlMissing)?;

    let unwrap_url = format!(
        "{}/v1/sys/wrapping/unwrap",
        vault_addr.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| BoxUnwrapError::RequestFailed(e.to_string()))?;

    let response = client
        .post(&unwrap_url)
        .header("X-Vault-Token", wrapping_token)
        .send()
        .await
        .map_err(|e| BoxUnwrapError::RequestFailed(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(BoxUnwrapError::RequestFailed(format!(
            "HTTP {}: {}",
            status, error_text
        )));
    }

    let unwrap_response: VaultUnwrapResponse = response
        .json()
        .await
        .map_err(|e| BoxUnwrapError::InvalidResponse(e.to_string()))?;

    Ok(unwrap_response.data)
}

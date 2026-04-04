use axum::extract::Extension;
use axum::Json;
use std::sync::Arc;

use crate::config::StellarConfig;
use crate::models::NetworkInfoResponse;

/// Return the current Stellar network configuration (`GET /network`).
pub async fn network_info(
    Extension(stellar_config): Extension<Arc<StellarConfig>>,
) -> Json<NetworkInfoResponse> {
    Json(NetworkInfoResponse {
        stellar_network: stellar_config.network.as_str().to_string(),
        stellar_horizon_url: stellar_config.horizon_url.clone(),
        stellar_rpc_url: stellar_config.rpc_url.clone(),
        network_passphrase: stellar_config.network_passphrase.clone(),
        soroban_contract_id: stellar_config.contract_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StellarConfig, StellarNetwork};

    #[tokio::test]
    async fn test_network_info_returns_config() {
        let config = Arc::new(StellarConfig {
            network: StellarNetwork::Testnet,
            horizon_url: "https://horizon-testnet.stellar.org".to_string(),
            rpc_url: "https://soroban-testnet.stellar.org".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            contract_id: Some("CTEST123".to_string()),
        });
        let result = network_info(Extension(config)).await;
        assert_eq!(result.0.stellar_network, "testnet");
        assert_eq!(
            result.0.stellar_horizon_url,
            "https://horizon-testnet.stellar.org"
        );
        assert_eq!(
            result.0.stellar_rpc_url,
            "https://soroban-testnet.stellar.org"
        );
        assert_eq!(result.0.soroban_contract_id, Some("CTEST123".to_string()));
    }

    #[tokio::test]
    async fn test_network_info_no_contract_id() {
        let config = Arc::new(StellarConfig {
            network: StellarNetwork::Pubnet,
            horizon_url: "https://horizon.stellar.org".to_string(),
            rpc_url: "https://soroban.stellar.org".to_string(),
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            contract_id: None,
        });
        let result = network_info(Extension(config)).await;
        assert_eq!(result.0.stellar_network, "pubnet");
        assert_eq!(result.0.soroban_contract_id, None);
    }
}

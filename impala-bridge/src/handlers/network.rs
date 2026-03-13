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

use axum::extract::Extension;
use axum::Json;
use log::{error, info, warn};
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::error::AppError;
use crate::models::{SubscribeRequest, SubscribeResponse};
use crate::streams;

/// Subscribe to network event streams (`POST /subscribe`).
pub async fn subscribe(
    _user: AuthenticatedUser,
    Extension(horizon_url): Extension<Arc<String>>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Json(payload): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, AppError> {
    info!("POST /subscribe: network={}", payload.network);
    match payload.network.as_str() {
        "stellar" => {
            let url = format!(
                "{}/ledgers?cursor=now&order=asc",
                horizon_url.trim_end_matches('/')
            );
            let redis = redis_client.clone();

            info!("subscribe: starting Stellar Horizon SSE stream");
            tokio::spawn(async move {
                if let Err(e) = streams::stellar_stream(&url, &redis).await {
                    error!("subscribe: Stellar stream terminated with error: {}", e);
                }
            });

            Ok(Json(SubscribeResponse {
                success: true,
                message: "Subscribed to Stellar Horizon ledger events".to_string(),
            }))
        }
        "payala" => {
            let listen_endpoint = match payload.listen_endpoint {
                Some(ref ep) if !ep.is_empty() => ep.clone(),
                _ => {
                    warn!("subscribe: missing listen_endpoint for payala network");
                    return Ok(Json(SubscribeResponse {
                        success: false,
                        message: "listen_endpoint is required for the payala network".to_string(),
                    }));
                }
            };

            let redis = redis_client.clone();

            info!(
                "subscribe: starting Payala TCP listener on {}",
                listen_endpoint
            );
            let ep_clone = listen_endpoint.clone();
            tokio::spawn(async move {
                if let Err(e) = streams::payala_stream(&ep_clone, &redis).await {
                    error!("subscribe: Payala stream terminated with error: {}", e);
                }
            });

            Ok(Json(SubscribeResponse {
                success: true,
                message: format!(
                    "Subscribed to Payala network events on {}",
                    listen_endpoint
                ),
            }))
        }
        _ => {
            warn!("subscribe: unsupported network '{}'", payload.network);
            Ok(Json(SubscribeResponse {
                success: false,
                message: format!("Unsupported network: {}", payload.network),
            }))
        }
    }
}

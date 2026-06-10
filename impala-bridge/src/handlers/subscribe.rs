use axum::extract::Extension;
use axum::Json;
use log::{info, warn};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::auth::AdminUser;
use crate::error::AppError;
use crate::models::{SubscribeRequest, SubscribeResponse};
use crate::streams;

/// Subscribe to network event streams (`POST /subscribe`). Admin-only.
///
/// Streams run under a supervisor loop ([`streams::supervise_stream`]) that
/// reconnects with exponential backoff and exits on server shutdown (the
/// server's `CancellationToken` is provided via Extension).
pub async fn subscribe(
    _user: AdminUser,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(cancel): Extension<CancellationToken>,
    Json(payload): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, AppError> {
    info!("POST /subscribe: network={}", payload.network);
    match payload.network.as_str() {
        "stellar" => {
            let url = format!(
                "{}/ledgers?cursor=now&order=asc",
                stellar_config.horizon_url.trim_end_matches('/')
            );
            let redis = redis_pool.clone();

            // One client per subscription, reused across supervisor
            // reconnects. connect_timeout only — a total-response timeout
            // would kill the long-lived SSE stream by construction.
            let client = match reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(
                    crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS,
                ))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    warn!("subscribe: failed to build HTTP client: {}", e);
                    return Ok(Json(SubscribeResponse {
                        success: false,
                        message: "Failed to initialize stream client".to_string(),
                    }));
                }
            };

            info!("subscribe: starting supervised Stellar Horizon SSE stream");
            tokio::spawn(async move {
                streams::supervise_stream("stellar_stream", cancel, move || {
                    let url = url.clone();
                    let redis = redis.clone();
                    let client = client.clone();
                    async move { streams::stellar_stream(&client, &url, &redis).await }
                })
                .await;
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

            let redis = redis_pool.clone();

            info!(
                "subscribe: starting supervised Payala TCP listener on {}",
                listen_endpoint
            );
            let ep_clone = listen_endpoint.clone();
            tokio::spawn(async move {
                let stream_cancel = cancel.clone();
                streams::supervise_stream("payala_stream", cancel, move || {
                    let ep = ep_clone.clone();
                    let redis = redis.clone();
                    let cancel = stream_cancel.clone();
                    async move { streams::payala_stream(&ep, &redis, cancel).await }
                })
                .await;
            });

            Ok(Json(SubscribeResponse {
                success: true,
                message: format!("Subscribed to Payala network events on {}", listen_endpoint),
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

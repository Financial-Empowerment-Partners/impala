use axum::extract::Extension;
use axum::Json;
use log::{info, warn};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::auth::AdminUser;
use crate::error::AppError;
use crate::models::{SubscribeRequest, SubscribeResponse};
use crate::streams;

/// Stream subscriptions already running, keyed by stream identity
/// ("stellar", "payala:<endpoint>").
///
/// `POST /subscribe` spawns a permanent supervised task that lives until
/// shutdown, so without a registry every repeat call accumulated another task —
/// each holding its own Horizon SSE connection or bound TCP listener — until
/// the host ran out of sockets. Duplicate stellar streams also multiplied Redis
/// writes for identical ledger data. Subscribing is now idempotent: a request
/// for an already-running stream is a successful no-op.
#[derive(Default)]
pub struct ActiveStreams(pub std::sync::Mutex<std::collections::HashSet<String>>);

impl ActiveStreams {
    /// Claim a stream key, returning false when it is already running.
    fn claim(&self, key: &str) -> bool {
        let mut set = self.0.lock().unwrap_or_else(|e| e.into_inner());
        set.insert(key.to_string())
    }

    /// Release a key so a future subscribe can restart the stream if its
    /// supervisor ever exits.
    fn release(&self, key: &str) {
        let mut set = self.0.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(key);
    }
}

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
    Extension(active): Extension<Arc<ActiveStreams>>,
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

            if !active.claim("stellar") {
                info!("subscribe: Stellar stream already running — no-op");
                return Ok(Json(SubscribeResponse {
                    success: true,
                    message: "Already subscribed to Stellar Horizon ledger events".to_string(),
                }));
            }

            info!("subscribe: starting supervised Stellar Horizon SSE stream");
            let active_stellar = active.clone();
            tokio::spawn(async move {
                streams::supervise_stream("stellar_stream", cancel, move || {
                    let url = url.clone();
                    let redis = redis.clone();
                    let client = client.clone();
                    async move { streams::stellar_stream(&client, &url, &redis).await }
                })
                .await;
                // The supervisor only returns on shutdown or a terminal error;
                // release the slot so a later subscribe can restart it.
                active_stellar.release("stellar");
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

            crate::validate::validate_listen_endpoint(&listen_endpoint)?;

            let redis = redis_pool.clone();

            let key = format!("payala:{}", listen_endpoint);
            if !active.claim(&key) {
                info!(
                    "subscribe: Payala listener already running on {} — no-op",
                    listen_endpoint
                );
                return Ok(Json(SubscribeResponse {
                    success: true,
                    message: "Already subscribed to Payala network events".to_string(),
                }));
            }

            info!(
                "subscribe: starting supervised Payala TCP listener on {}",
                listen_endpoint
            );
            let ep_clone = listen_endpoint.clone();
            let active_payala = active.clone();
            tokio::spawn(async move {
                let stream_cancel = cancel.clone();
                streams::supervise_stream("payala_stream", cancel, move || {
                    let ep = ep_clone.clone();
                    let redis = redis.clone();
                    let cancel = stream_cancel.clone();
                    async move { streams::payala_stream(&ep, &redis, cancel).await }
                })
                .await;
                active_payala.release(&key);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Subscribing twice must not start a second stream: each spawns a
    /// permanent task holding an SSE connection or a bound listener, so
    /// repeats used to accumulate until the host ran out of sockets.
    #[test]
    fn claim_is_idempotent_per_stream() {
        let active = ActiveStreams::default();
        assert!(active.claim("stellar"), "first subscribe starts the stream");
        assert!(!active.claim("stellar"), "repeat must be a no-op");
        assert!(!active.claim("stellar"));
    }

    #[test]
    fn payala_streams_are_keyed_per_endpoint() {
        let active = ActiveStreams::default();
        assert!(active.claim("payala:127.0.0.1:9000"));
        // A different endpoint is a genuinely different listener.
        assert!(active.claim("payala:127.0.0.1:9001"));
        assert!(!active.claim("payala:127.0.0.1:9000"));
    }

    /// If a supervisor exits, the slot must free so a later subscribe can
    /// restart the stream rather than silently no-opping forever.
    #[test]
    fn release_allows_a_restart() {
        let active = ActiveStreams::default();
        assert!(active.claim("stellar"));
        active.release("stellar");
        assert!(active.claim("stellar"), "a released stream can restart");
    }
}

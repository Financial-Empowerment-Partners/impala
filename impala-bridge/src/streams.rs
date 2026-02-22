use crate::constants::{CRON_SYNC_INTERVAL_SECS, MAX_SSE_BUFFER_SIZE};
use crate::validate::validate_callback_url;
use futures::StreamExt;
use log::{debug, error, info, warn};
use sqlx::PgPool;

/// Background task that periodically fetches callback URIs from the
/// `cron_sync` table, invokes each one, and stores the JSON response back
/// into the `callback_result` column.
pub async fn cron_sync_task(pool: PgPool) {
    let client = reqwest::Client::new();
    loop {
        let rows =
            sqlx::query_as::<_, (i32, String)>("SELECT id, callback_uri FROM cron_sync")
                .fetch_all(&pool)
                .await;

        match rows {
            Ok(rows) => {
                debug!("cron_sync: processing {} callback(s)", rows.len());
                for (id, callback_uri) in rows {
                    // Validate callback URL to prevent SSRF
                    if let Err(e) = validate_callback_url(&callback_uri) {
                        warn!(
                            "cron_sync: skipping id {} due to invalid callback_uri: {}",
                            id, e
                        );
                        continue;
                    }

                    match client.get(&callback_uri).send().await {
                        Ok(response) => match response.json::<serde_json::Value>().await {
                            Ok(body) => {
                                if let Err(e) = sqlx::query(
                                    "UPDATE cron_sync SET callback_result = $1 WHERE id = $2",
                                )
                                .bind(&body)
                                .bind(id)
                                .execute(&pool)
                                .await
                                {
                                    error!(
                                        "cron_sync: failed to update result for id {}: {}",
                                        id, e
                                    );
                                } else {
                                    debug!("cron_sync: updated result for id {}", id);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "cron_sync: JSON parse error for id {} ({}): {}",
                                    id, callback_uri, e
                                );
                            }
                        },
                        Err(e) => {
                            error!(
                                "cron_sync: request failed for id {} ({}): {}",
                                id, callback_uri, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("cron_sync: query failed: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(CRON_SYNC_INTERVAL_SECS)).await;
    }
}

/// Long-running SSE consumer for Stellar Horizon ledger events.
pub async fn stellar_stream(
    url: &str,
    redis_client: &redis::Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header("Accept", "text/event-stream")
        .send()
        .await?;

    if !response.status().is_success() {
        error!(
            "stellar_stream: Horizon returned HTTP {}",
            response.status()
        );
        return Err(format!("Horizon returned HTTP {}", response.status()).into());
    }

    info!("stellar_stream: connected to Horizon SSE");
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut event_data = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        if buffer.len() > MAX_SSE_BUFFER_SIZE {
            warn!(
                "stellar_stream: SSE buffer exceeded {} bytes, resetting",
                MAX_SSE_BUFFER_SIZE
            );
            buffer.clear();
            event_data.clear();
            continue;
        }

        while let Some(newline_pos) = buffer.find('\n') {
            let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
            buffer = buffer[newline_pos + 1..].to_string();

            if let Some(stripped) = line.strip_prefix("data:") {
                let data = stripped.trim();
                if data == "\"hello\"" {
                    continue;
                }
                event_data.push_str(data);
            } else if line.is_empty() && !event_data.is_empty() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&event_data) {
                    let sequence = parsed["sequence"]
                        .as_u64()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    info!("stellar_stream: ledger event sequence={}", sequence);

                    if let Ok(mut conn) = redis_client.get_async_connection().await {
                        let _: Result<(), _> = redis::AsyncCommands::set(
                            &mut conn,
                            "stellar:latest_ledger",
                            &sequence,
                        )
                        .await;

                        let timestamp =
                            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
                        let event_key = format!("stellar:ledger:{}", sequence);
                        let _: Result<(), _> =
                            redis::AsyncCommands::set(&mut conn, &event_key, &timestamp).await;
                    }
                }
                event_data.clear();
            }
        }
    }

    Ok(())
}

/// Long-running TCP listener for Payala network events.
pub async fn payala_stream(
    listen_endpoint: &str,
    redis_client: &redis::Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = listen_endpoint.parse().map_err(|e| {
        error!(
            "payala_stream: invalid listen_endpoint '{}': {}",
            listen_endpoint, e
        );
        format!("Invalid listen_endpoint '{}': {}", listen_endpoint, e)
    })?;

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        error!("payala_stream: failed to bind to {}: {}", addr, e);
        format!("Failed to bind to {}: {}", addr, e)
    })?;

    info!("payala_stream: TCP listener started on {}", addr);

    if let Ok(mut conn) = redis_client.get_async_connection().await {
        let _: Result<(), _> =
            redis::AsyncCommands::set(&mut conn, "payala:listen_endpoint", listen_endpoint).await;
    }

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        let redis = redis_client.clone();

        tokio::spawn(async move {
            info!("payala_stream: connection accepted from {}", peer_addr);

            let mut buf = vec![0u8; 65536];
            loop {
                let n = match tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        error!("payala_stream: read error from {}: {}", peer_addr, e);
                        break;
                    }
                };

                let raw = String::from_utf8_lossy(&buf[..n]).to_string();

                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let event_type = parsed["type"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();

                    info!(
                        "payala_stream: event from {}: type={}",
                        peer_addr, event_type
                    );

                    if let Ok(mut conn) = redis.get_async_connection().await {
                        let timestamp =
                            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
                        let event_key = format!(
                            "payala:event:{}:{}",
                            timestamp,
                            uuid::Uuid::new_v4()
                        );
                        let _: Result<(), _> =
                            redis::AsyncCommands::set(&mut conn, &event_key, &raw).await;
                        let _: Result<(), _> =
                            redis::AsyncCommands::set(&mut conn, "payala:latest_event", &raw)
                                .await;
                    }
                } else {
                    warn!(
                        "payala_stream: non-JSON data from {}: {} bytes",
                        peer_addr, n
                    );
                }
            }
        });
    }
}

use crate::constants::{
    CRON_SYNC_BATCH_LIMIT, CRON_SYNC_CONCURRENCY, CRON_SYNC_INTERVAL_SECS,
    DEFAULT_HTTP_CLIENT_TIMEOUT_SECS, MAX_SSE_BUFFER_SIZE, PAYALA_READ_TIMEOUT_SECS,
    SSE_READ_TIMEOUT_SECS, STREAM_BACKOFF_INITIAL_SECS, STREAM_BACKOFF_MAX_SECS,
    STREAM_HEALTHY_RESET_SECS,
};
use crate::validate::validate_callback_url;
use futures::StreamExt;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Compute the supervisor reconnect delay after `consecutive_failures`
/// short-lived connection attempts (pure, for unit testing).
///
/// Exponential: 1s, 2s, 4s, … capped at [`STREAM_BACKOFF_MAX_SECS`].
pub fn next_backoff(consecutive_failures: u32) -> u64 {
    let exp = consecutive_failures.saturating_sub(1);
    std::cmp::min(
        STREAM_BACKOFF_INITIAL_SECS.saturating_mul(2u64.saturating_pow(exp)),
        STREAM_BACKOFF_MAX_SECS,
    )
}

/// Run a stream connection factory in a supervision loop: reconnect on exit
/// (clean or error) with exponential backoff (reset after a connection stays
/// healthy for [`STREAM_HEALTHY_RESET_SECS`]), and exit promptly when the
/// server's `CancellationToken` fires (mirrors `okta::jwks_refresh_task`).
pub async fn supervise_stream<F, Fut>(name: &str, cancel: CancellationToken, mut connect: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
{
    let mut consecutive_failures: u32 = 0;
    loop {
        let started = tokio::time::Instant::now();
        let outcome = tokio::select! {
            result = connect() => Some(result),
            _ = cancel.cancelled() => None,
        };

        match outcome {
            None => {
                info!("{}: shutdown requested, exiting supervisor", name);
                return;
            }
            Some(Ok(())) => warn!("{}: stream ended, reconnecting", name),
            Some(Err(e)) => error!("{}: stream failed: {}", name, e),
        }

        if started.elapsed() >= Duration::from_secs(STREAM_HEALTHY_RESET_SECS) {
            consecutive_failures = 0;
        }
        consecutive_failures = consecutive_failures.saturating_add(1);

        let wait_secs = next_backoff(consecutive_failures);
        warn!(
            "{}: reconnecting in {}s (consecutive failures: {})",
            name, wait_secs, consecutive_failures
        );
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
            _ = cancel.cancelled() => {
                info!("{}: shutdown requested during backoff, exiting supervisor", name);
                return;
            }
        }
    }
}

/// Background task that periodically fetches callback URIs from the
/// `cron_sync` table, invokes each one, and stores the JSON response back
/// into the `callback_result` column.  Respects cancellation for graceful shutdown.
pub async fn cron_sync_task(pool: PgPool, cancel: CancellationToken) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            DEFAULT_HTTP_CLIENT_TIMEOUT_SECS,
        ))
        .build()
        .expect("Failed to create HTTP client");
    loop {
        // Bounded fetch: a runaway cron_sync table must not turn one tick
        // into an unbounded in-memory row set.
        let rows = sqlx::query_as::<_, (i32, String)>(
            "SELECT id, callback_uri FROM cron_sync ORDER BY id LIMIT $1",
        )
        .bind(CRON_SYNC_BATCH_LIMIT)
        .fetch_all(&pool)
        .await;

        match rows {
            Ok(rows) => {
                debug!("cron_sync: processing {} callback(s)", rows.len());
                // Bounded concurrency: serial delivery made one tick take up
                // to 30s × N; now at most CRON_SYNC_CONCURRENCY are in flight.
                futures::stream::iter(rows)
                    .map(|(id, callback_uri)| {
                        let pool = pool.clone();
                        let client = client.clone();
                        async move {
                            process_cron_callback(&pool, &client, id, &callback_uri).await
                        }
                    })
                    .buffer_unordered(CRON_SYNC_CONCURRENCY)
                    .collect::<Vec<_>>()
                    .await;
            }
            Err(e) => {
                error!("cron_sync: query failed: {}", e);
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(CRON_SYNC_INTERVAL_SECS)) => {}
            _ = cancel.cancelled() => {
                info!("cron_sync_task: shutdown requested, exiting");
                return;
            }
        }
    }
}

/// One cron callback delivery: SSRF-validate, GET, store the JSON response.
async fn process_cron_callback(
    pool: &PgPool,
    client: &reqwest::Client,
    id: i32,
    callback_uri: &str,
) -> CronOutcome {
    // Validate callback URL to prevent SSRF — per delivery, before any IO.
    if let Err(e) = validate_callback_url(callback_uri) {
        warn!(
            "cron_sync: skipping id {} due to invalid callback_uri: {}",
            id, e
        );
        return CronOutcome::SkippedInvalidUrl;
    }

    match client.get(callback_uri).send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(body) => {
                if let Err(e) =
                    sqlx::query("UPDATE cron_sync SET callback_result = $1 WHERE id = $2")
                        .bind(&body)
                        .bind(id)
                        .execute(pool)
                        .await
                {
                    error!("cron_sync: failed to update result for id {}: {}", id, e);
                    CronOutcome::Failed
                } else {
                    debug!("cron_sync: updated result for id {}", id);
                    CronOutcome::Updated
                }
            }
            Err(e) => {
                warn!(
                    "cron_sync: JSON parse error for id {} ({}): {}",
                    id, callback_uri, e
                );
                CronOutcome::Failed
            }
        },
        Err(e) => {
            error!(
                "cron_sync: request failed for id {} ({}): {}",
                id, callback_uri, e
            );
            CronOutcome::Failed
        }
    }
}

/// Outcome of a single cron callback delivery.
#[derive(Debug, PartialEq)]
enum CronOutcome {
    SkippedInvalidUrl,
    Updated,
    Failed,
}

/// Long-running SSE consumer for Stellar Horizon ledger events.
///
/// The client is supplied by the caller (built once per subscription, reused
/// across supervisor reconnects). NOTE for builders: `.timeout()` would bound
/// the *total* response time, which kills a long-lived SSE stream by
/// construction — bound only connection setup (`.connect_timeout()`); stream
/// liveness is enforced per-read below via SSE_READ_TIMEOUT_SECS.
pub async fn stellar_stream(
    client: &reqwest::Client,
    url: &str,
    redis_pool: &deadpool_redis::Pool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    loop {
        let chunk =
            match tokio::time::timeout(Duration::from_secs(SSE_READ_TIMEOUT_SECS), stream.next())
                .await
            {
                Ok(Some(chunk)) => chunk?,
                Ok(None) => break, // server closed the stream
                Err(_) => {
                    warn!(
                        "stellar_stream: no data for {}s, dropping stale connection",
                        SSE_READ_TIMEOUT_SECS
                    );
                    return Err(format!(
                        "SSE read timeout after {}s of silence",
                        SSE_READ_TIMEOUT_SECS
                    )
                    .into());
                }
            };
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

                    if let Ok(mut conn) = redis_pool.get().await {
                        let _: Result<(), _> = redis::AsyncCommands::set(
                            &mut *conn,
                            "stellar:latest_ledger",
                            &sequence,
                        )
                        .await;

                        let timestamp = chrono::Utc::now()
                            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                            .to_string();
                        let event_key = format!("stellar:ledger:{}", sequence);
                        let _: Result<(), _> =
                            redis::AsyncCommands::set(&mut *conn, &event_key, &timestamp).await;
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
    redis_pool: &deadpool_redis::Pool,
    cancel: CancellationToken,
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

    if let Ok(mut conn) = redis_pool.get().await {
        let _: Result<(), _> =
            redis::AsyncCommands::set(&mut *conn, "payala:listen_endpoint", listen_endpoint).await;
    }

    loop {
        let (socket, peer_addr) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = cancel.cancelled() => {
                info!("payala_stream: shutdown requested, closing listener");
                return Ok(());
            }
        };
        let redis = redis_pool.clone();
        let conn_cancel = cancel.clone();

        tokio::spawn(handle_payala_connection(
            socket,
            peer_addr,
            redis,
            Duration::from_secs(PAYALA_READ_TIMEOUT_SECS),
            conn_cancel,
        ));
    }
}

/// Handle a single accepted Payala connection: read JSON events and store them
/// in Redis. Closes the socket after `read_timeout` of silence (idle-socket
/// leak guard) or when the server shuts down.
async fn handle_payala_connection(
    mut socket: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    redis: deadpool_redis::Pool,
    read_timeout: Duration,
    cancel: CancellationToken,
) {
    info!("payala_stream: connection accepted from {}", peer_addr);

    let mut buf = vec![0u8; 65536];
    loop {
        let read = tokio::time::timeout(
            read_timeout,
            tokio::io::AsyncReadExt::read(&mut socket, &mut buf),
        );
        let n = tokio::select! {
            result = read => match result {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    error!("payala_stream: read error from {}: {}", peer_addr, e);
                    break;
                }
                Err(_) => {
                    warn!(
                        "payala_stream: no data from {} within {:?}, closing idle connection",
                        peer_addr, read_timeout
                    );
                    break;
                }
            },
            _ = cancel.cancelled() => {
                info!("payala_stream: shutdown requested, closing connection from {}", peer_addr);
                break;
            }
        };

        let raw = String::from_utf8_lossy(&buf[..n]).to_string();

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
            let event_type = parsed["type"].as_str().unwrap_or("unknown").to_string();

            info!(
                "payala_stream: event from {}: type={}",
                peer_addr, event_type
            );

            if let Ok(mut conn) = redis.get().await {
                let timestamp = chrono::Utc::now()
                    .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                    .to_string();
                let event_key = format!("payala:event:{}:{}", timestamp, uuid::Uuid::new_v4());
                let _: Result<(), _> =
                    redis::AsyncCommands::set(&mut *conn, &event_key, &raw).await;
                let _: Result<(), _> =
                    redis::AsyncCommands::set(&mut *conn, "payala:latest_event", &raw).await;
            }
        } else {
            warn!(
                "payala_stream: non-JSON data from {}: {} bytes",
                peer_addr, n
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_backoff_grows_exponentially_and_caps() {
        assert_eq!(next_backoff(1), 1);
        assert_eq!(next_backoff(2), 2);
        assert_eq!(next_backoff(3), 4);
        assert_eq!(next_backoff(9), 256);
        assert_eq!(next_backoff(10), 300, "caps at STREAM_BACKOFF_MAX_SECS");
        assert_eq!(next_backoff(64), 300, "no overflow at large shift counts");
        assert_eq!(next_backoff(u32::MAX), 300);
    }

    #[test]
    fn next_backoff_zero_failures_is_initial() {
        assert_eq!(next_backoff(0), STREAM_BACKOFF_INITIAL_SECS);
    }

    /// buffer_unordered(0) panics; LIMIT 0 disables the tick. Pin both.
    /// Deliberate constant assertions — they exist to break the build if the
    /// constants are ever mis-edited.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn cron_sync_batch_constants_sane() {
        assert!(CRON_SYNC_BATCH_LIMIT > 0);
        assert!(CRON_SYNC_CONCURRENCY >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_reconnects_and_exits_on_cancel() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let attempts = Arc::new(AtomicU32::new(0));
        let cancel = CancellationToken::new();

        let connect_attempts = attempts.clone();
        let connect = move || {
            let attempts = connect_attempts.clone();
            async move {
                let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if n >= 3 {
                    // Third attempt: hang until cancelled.
                    futures::future::pending::<()>().await;
                }
                Err::<(), Box<dyn std::error::Error + Send + Sync>>("connect refused".into())
            }
        };

        let supervisor_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            supervise_stream("test_stream", supervisor_cancel, connect).await;
        });

        // Paused time auto-advances through the backoff sleeps; wait until the
        // third (hanging) attempt is reached, then cancel.
        while attempts.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
        handle.await.expect("supervisor task should exit cleanly");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_exits_on_cancel_during_backoff() {
        let cancel = CancellationToken::new();
        let cancel_inner = cancel.clone();
        // Connect fails instantly; cancel fires while the supervisor sleeps.
        let connect = move || {
            let cancel = cancel_inner.clone();
            async move {
                cancel.cancel();
                Err::<(), Box<dyn std::error::Error + Send + Sync>>("boom".into())
            }
        };
        // Must terminate (no infinite reconnect loop after cancellation).
        supervise_stream("test_stream", cancel, connect).await;
    }

    #[tokio::test]
    async fn payala_connection_read_timeout_closes_idle_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        // Lazy pool pointing nowhere — never touched (the client sends no JSON).
        let pool = deadpool_redis::Config::from_url("redis://127.0.0.1:1/")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy pool creation");
        let cancel = CancellationToken::new();

        let server = tokio::spawn(async move {
            let (socket, peer_addr) = listener.accept().await.expect("accept");
            handle_payala_connection(socket, peer_addr, pool, Duration::from_millis(100), cancel)
                .await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        // Send nothing: the handler must time out and close the socket (EOF).
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read(&mut client, &mut buf),
        )
        .await
        .expect("server should close the idle connection before 5s")
        .expect("clean EOF expected");
        assert_eq!(n, 0, "server closes the connection after the read timeout");
        server.await.expect("handler task should exit");
    }
}

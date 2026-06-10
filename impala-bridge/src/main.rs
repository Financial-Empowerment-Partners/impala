mod admin_webhook_delivery;
mod auth;
mod config;
mod constants;
mod error;
mod events;
mod google;
mod handlers;
mod jobs;
mod jwt;
mod ldap;
mod middleware;
mod models;
mod notifications;
mod okta;
mod password;
mod redis_helpers;
mod session;
mod sns;
mod streams;
mod telemetry;
mod validate;
mod vault;
mod worker;

use axum::extract::Extension;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::routing::{get, post, put};
use axum::Router;
use log::{debug, error, info, warn};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use config::load_config;
use handlers::{
    account, admin_webhook, authenticate, card, card_auth, device_token, github as github_handler,
    google as google_handler, health, logout, mfa, network, notification_subscription, notify,
    okta as okta_handler, session as session_handler, subscribe, sync, token, transaction,
};

#[tokio::main]
async fn main() {
    // Install the process-wide rustls CryptoProvider before anything can open
    // a TLS connection. Multiple provider backends can end up compiled in via
    // transitive features, in which case rustls refuses to auto-select one and
    // the first handshake built from the process default — e.g. a rediss://
    // Redis connection — panics at runtime. Err means a provider was already
    // installed, which is equally fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = load_config();

    // Initialize OpenTelemetry (replaces syslog when OTEL_EXPORTER_OTLP_ENDPOINT is set)
    let otel_initialized = telemetry::init_otel(&config);

    if !otel_initialized {
        // Fall back to syslog logger
        let formatter = syslog::Formatter3164 {
            facility: syslog::Facility::LOG_DAEMON,
            hostname: None,
            process: "impala-bridge".into(),
            pid: std::process::id(),
        };
        match syslog::unix(formatter) {
            Ok(logger) => {
                log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                    .map(|()| {
                        log::set_max_level(if config.debug_mode {
                            log::LevelFilter::Debug
                        } else {
                            log::LevelFilter::Info
                        })
                    })
                    .expect("Failed to set syslog logger");
            }
            Err(e) => {
                eprintln!("Failed to connect to syslog: {}, falling back to stderr", e);
            }
        }
    }

    // Create application metrics (no-op when OTEL is not configured)
    let metrics = telemetry::create_metrics();

    let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "server".to_string());
    info!("impala-bridge starting up (mode={})", run_mode);
    debug!("Config: {:?}", config);

    // Resolve database URL (Vault unwrap or direct env var)
    let database_url = if let Ok(wrapped_token) = env::var("DATABASE_URL_WRAPPED") {
        info!("Unwrapping DATABASE_URL from Vault");
        match vault::box_unwrap(&wrapped_token).await {
            Ok(secret_data) => {
                info!("Vault secret unwrapped successfully");
                secret_data["database_url"]
                    .as_str()
                    .expect("database_url field not found in unwrapped secret")
                    .to_string()
            }
            Err(e) => {
                error!("Failed to unwrap DATABASE_URL from Vault: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        env::var("DATABASE_URL").expect("Either DATABASE_URL or DATABASE_URL_WRAPPED must be set")
    };

    // Create database connection pool with timeouts
    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(constants::DB_IDLE_TIMEOUT_SECS))
        .max_lifetime(Duration::from_secs(constants::DB_MAX_LIFETIME_SECS))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    info!(
        "Database connection pool established (max_connections={})",
        config.db_max_connections
    );

    // Create Redis connection pool
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let mut redis_cfg = deadpool_redis::Config::from_url(&redis_url);
    redis_cfg.pool = Some(deadpool_redis::PoolConfig::new(config.redis_pool_size));
    let redis_pool = redis_cfg
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("Failed to create Redis connection pool");
    let redis_pool = Arc::new(redis_pool);
    info!(
        "Redis connection pool created (max_size={})",
        config.redis_pool_size
    );

    match run_mode.as_str() {
        "migrate" => {
            info!("Running database migrations");
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .expect("Failed to run migrations");
            info!("Migrations completed successfully");
        }

        "worker" => {
            info!("Starting in worker mode");
            worker::run(pool, redis_pool, config, metrics).await;
        }

        _ => {
            // Default: server mode
            run_server(pool, redis_pool, config, metrics).await;
        }
    }
}

async fn run_server(
    pool: sqlx::PgPool,
    redis_pool: Arc<deadpool_redis::Pool>,
    config: config::Config,
    metrics: Arc<telemetry::AppMetrics>,
) {
    // JWT signing keys: JWT_SECRET signs and verifies; the optional
    // JWT_SECRET_PREVIOUS is verify-only, covering a secret-rotation window
    // (see SECURITY.md for the rotation runbook).
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set");
    // Empty string == unset (compose passes the var through unconditionally).
    let jwt_secret_previous = env::var("JWT_SECRET_PREVIOUS")
        .ok()
        .filter(|s| !s.is_empty());
    let jwt_keys = match jwt::JwtKeys::new(jwt_secret, jwt_secret_previous) {
        Ok(keys) => Arc::new(keys),
        Err(msg) => {
            error!("{}", msg);
            std::process::exit(1);
        }
    };

    // Browser cookie-session policy. Warn on the likely misconfiguration:
    // Secure cookies on a plain-HTTP public endpoint are silently dropped.
    let session_config = Arc::new(session::SessionConfig {
        cookie_secure: config.session_cookie_secure,
    });
    if session_config.cookie_secure && config.public_endpoint.starts_with("http://") {
        warn!(
            "SESSION_COOKIE_SECURE is on but PUBLIC_ENDPOINT is plain HTTP — browsers will drop the session cookie; set SESSION_COOKIE_SECURE=false for local HTTP development"
        );
    }

    // Admin allowlist: source of the `is_admin` JWT claim, stamped at issuance.
    let admin_ids: Arc<std::collections::HashSet<String>> =
        Arc::new(config.admin_account_ids.clone());
    info!("Admin allowlist: {} account(s) configured", admin_ids.len());

    // Stellar network configuration
    let stellar_config = Arc::new(config.stellar_config());
    info!(
        "Stellar network: {} (horizon={}, rpc={})",
        stellar_config.network.as_str(),
        stellar_config.horizon_url,
        stellar_config.rpc_url
    );
    if let Some(ref cid) = stellar_config.contract_id {
        info!("Soroban contract ID: {}", cid);
    }

    // Initialize Okta provider (if configured)
    let okta_provider = okta::init_okta_provider(&config).await;

    // Initialize Google provider (if configured)
    let google_provider = google::init_google_provider(&config).await;

    // Initialize GitHub provider (if enabled)
    let github_provider = if config.github_auth_enabled {
        info!(
            "github: token exchange enabled (api_url={})",
            config.github_api_url
        );
        Some(Arc::new(github_handler::GitHubProvider::new(&config)))
    } else {
        None
    };

    // Initialize SNS client for job dispatch (if configured)
    let sns_client = if config.sns_topic_arn.is_some() {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Some(Arc::new(aws_sdk_sns::Client::new(&aws_config)))
    } else {
        None
    };
    let sns_topic_arn = config
        .sns_topic_arn
        .clone()
        .map(|arn| sns::SnsTopicArn(Arc::new(arn)));

    // CORS policy — wildcard is a hard startup error on pubnet, allowed
    // (with an info log) on testnet.
    if let Err(msg) =
        config::validate_cors_policy(&config.stellar_network, &config.cors_allowed_origins)
    {
        error!("{}", msg);
        std::process::exit(1);
    }
    if config.cors_allowed_origins == "*" {
        info!("CORS_ALLOWED_ORIGINS is set to wildcard '*' (testnet mode)");
    }
    let cors = if config.cors_allowed_origins == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-request-nonce"),
                HeaderName::from_static("x-csrf-token"),
            ])
    } else {
        let origins: Vec<HeaderValue> = config
            .cors_allowed_origins
            .split(',')
            .filter_map(|o| o.trim().parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-request-nonce"),
                HeaderName::from_static("x-csrf-token"),
            ])
    };

    // Cancellation token for graceful background task shutdown.
    // Also handed to handlers via Extension so streams spawned from
    // POST /subscribe participate in graceful shutdown.
    let cancel = CancellationToken::new();

    // Build router with routes
    let app = Router::new()
        .route("/", get(health::default_route))
        .route("/health", get(health::health_check))
        .route("/version", get(health::get_version))
        .route(
            "/account",
            post(account::create_account)
                .get(account::get_account)
                .put(account::update_account),
        )
        .route("/authenticate", post(authenticate::authenticate))
        .route("/sync", post(sync::sync_account))
        .route("/token", post(token::token))
        .route("/subscribe", post(subscribe::subscribe))
        .route("/transaction", post(transaction::create_transaction))
        .route("/card", post(card::create_card).delete(card::delete_card))
        .route("/mfa", post(mfa::enroll_mfa).get(mfa::get_mfa))
        .route("/mfa/verify", post(mfa::verify_mfa))
        .route(
            "/notify",
            get(notify::list_notify)
                .post(notify::create_notify)
                .put(notify::update_notify),
        )
        .route(
            "/notification/subscriptions",
            get(notification_subscription::list_subscriptions)
                .post(notification_subscription::create_subscription),
        )
        .route(
            "/notification/subscriptions/{id}",
            put(notification_subscription::update_subscription)
                .delete(notification_subscription::delete_subscription),
        )
        .route(
            "/device-token",
            post(device_token::register_device_token).delete(device_token::delete_device_token),
        )
        .route("/logout", post(logout::logout))
        .route("/logout/all", post(logout::logout_all))
        .route("/session/login", post(session_handler::session_login))
        .route("/session/me", get(session_handler::session_me))
        .route("/session/logout", post(session_handler::session_logout))
        .route("/auth/okta", post(okta_handler::okta_token_exchange))
        .route("/auth/okta/config", get(okta_handler::okta_config))
        .route("/auth/google", post(google_handler::google_token_exchange))
        .route("/auth/google/config", get(google_handler::google_config))
        .route("/auth/github", post(github_handler::github_token_exchange))
        .route("/auth/card/challenge", post(card_auth::card_challenge))
        .route("/auth/card", post(card_auth::card_token_exchange))
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/network", get(network::network_info))
        // Admin-only webhook event feed (all gated by the AdminUser extractor).
        .route(
            "/admin/webhooks",
            post(admin_webhook::register_webhook).get(admin_webhook::list_webhooks),
        )
        .route(
            "/admin/webhooks/{id}",
            axum::routing::delete(admin_webhook::delete_webhook),
        )
        .route(
            "/admin/webhooks/{id}/test",
            post(admin_webhook::test_webhook),
        )
        .route("/admin/events", get(admin_webhook::list_events))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(1_048_576)) // 1 MB body limit
        // Global request deadline (408 on expiry). Safe for this app: the
        // bridge serves only request/response JSON — the SSE/TCP streams are
        // outbound consumers, not server-streamed responses.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.request_timeout_secs),
        ))
        .layer(CompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(middleware::MetricsLayer::new(metrics.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        .layer(Extension(pool.clone()))
        .layer(Extension(redis_pool.clone()))
        .layer(Extension(jwt_keys))
        .layer(Extension(session_config))
        .layer(Extension(stellar_config.clone()))
        .layer(Extension(admin_ids.clone()))
        .layer(Extension(metrics))
        .layer(Extension(cancel.clone()));

    // Add optional SNS client extension
    let app = if let (Some(client), Some(arn)) = (sns_client, sns_topic_arn) {
        app.layer(Extension(client)).layer(Extension(arn))
    } else {
        app
    };

    // Add Okta provider extension and spawn JWKS refresh task (if configured)
    let app = if let Some(ref provider) = okta_provider {
        let refresh_provider = provider.clone();
        let refresh_secs = config.okta_jwks_refresh_secs;
        let jwks_cancel = cancel.clone();
        tokio::spawn(async move {
            okta::jwks_refresh_task(refresh_provider, refresh_secs, jwks_cancel).await;
        });
        app.layer(Extension(provider.clone()))
    } else {
        app
    };

    // Add Google provider extension and spawn JWKS refresh task (if configured)
    let app = if let Some(ref provider) = google_provider {
        let refresh_provider = provider.clone();
        let refresh_secs = config.google_jwks_refresh_secs;
        let jwks_cancel = cancel.clone();
        tokio::spawn(async move {
            google::jwks_refresh_task(refresh_provider, refresh_secs, jwks_cancel).await;
        });
        app.layer(Extension(provider.clone()))
    } else {
        app
    };

    // Add GitHub provider extension (if enabled)
    let app = if let Some(ref provider) = github_provider {
        app.layer(Extension(provider.clone()))
    } else {
        app
    };

    // LDAP directory sync
    ldap::directory_sync(&pool, &config).await;

    // Spawn background cron_sync task with cancellation support
    let cron_pool = pool.clone();
    let cron_cancel = cancel.clone();
    tokio::spawn(async move {
        streams::cron_sync_task(cron_pool, cron_cancel).await;
    });

    // Spawn the admin-webhook delivery worker (outbox fan-out + signed delivery,
    // retry/backoff, auto-disable). In-process; no SNS/SQS dependency.
    let wh_pool = pool.clone();
    let wh_cancel = cancel.clone();
    let wh_cfg = admin_webhook_delivery::DeliveryConfig {
        poll_secs: config.admin_webhook_poll_secs,
        max_attempts: config.admin_webhook_max_attempts,
        disable_threshold: config.admin_webhook_disable_threshold,
    };
    tokio::spawn(async move {
        admin_webhook_delivery::run(wh_pool, wh_cfg, wh_cancel).await;
    });

    // Run server with graceful shutdown
    info!("Server listening on {}", config.service_address);
    let listener = tokio::net::TcpListener::bind(&config.service_address)
        .await
        .expect("Failed to bind SERVICE_ADDRESS");
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(cancel))
        .await
    {
        error!("Server error: {}", e);
    }

    telemetry::shutdown_otel();
}

async fn shutdown_signal(cancel: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { info!("Received Ctrl+C, shutting down"); }
            _ = sigterm.recv() => { info!("Received SIGTERM, shutting down"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C, shutting down");
    }

    // Signal background tasks to stop
    cancel.cancel();
}

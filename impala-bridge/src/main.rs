mod auth;
mod config;
mod constants;
mod error;
mod handlers;
mod jobs;
mod jwt;
mod ldap;
mod middleware;
mod models;
mod notifications;
mod okta;
mod redis_helpers;
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
use tower_http::trace::TraceLayer;

use config::load_config;
use handlers::{
    account, authenticate, card, device_token, health, logout, mfa, network,
    notification_subscription, notify, okta as okta_handler, subscribe, sync, token, transaction,
};

#[tokio::main]
async fn main() {
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
        .acquire_timeout(Duration::from_secs(constants::DB_ACQUIRE_TIMEOUT_SECS))
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
    let redis_cfg = deadpool_redis::Config::from_url(&redis_url);
    let redis_pool = redis_cfg
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("Failed to create Redis connection pool");
    let redis_pool = Arc::new(redis_pool);
    info!("Redis connection pool created");

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
    // JWT signing secret
    let jwt_secret =
        Arc::new(env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set"));
    if jwt_secret.len() < crate::constants::JWT_SECRET_MIN_LENGTH {
        error!(
            "JWT_SECRET must be at least {} characters for security",
            crate::constants::JWT_SECRET_MIN_LENGTH
        );
        std::process::exit(1);
    }

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

    // Initialize SNS client for job dispatch (if configured)
    let sns_client = if config.sns_topic_arn.is_some() {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Some(Arc::new(aws_sdk_sns::Client::new(&aws_config)))
    } else {
        None
    };
    let sns_topic_arn = config.sns_topic_arn.clone().map(Arc::new);

    // CORS layer — restrict to configured origins when not wildcard
    if config.cors_allowed_origins == "*" {
        if config.stellar_network == config::StellarNetwork::Testnet {
            info!("CORS_ALLOWED_ORIGINS is set to wildcard '*' (testnet mode)");
        } else {
            warn!("CORS_ALLOWED_ORIGINS is set to wildcard '*' — consider restricting to specific origins in production");
        }
    }
    let cors = if config.cors_allowed_origins == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-request-nonce"),
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
            ])
    };

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
            "/notification/subscriptions/:id",
            put(notification_subscription::update_subscription)
                .delete(notification_subscription::delete_subscription),
        )
        .route(
            "/device-token",
            post(device_token::register_device_token).delete(device_token::delete_device_token),
        )
        .route("/logout", post(logout::logout))
        .route("/auth/okta", post(okta_handler::okta_token_exchange))
        .route("/auth/okta/config", get(okta_handler::okta_config))
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/network", get(network::network_info))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(1_048_576)) // 1 MB body limit
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
        .layer(Extension(jwt_secret))
        .layer(Extension(stellar_config.clone()))
        .layer(Extension(metrics));

    // Add optional SNS client extension
    let app = if let (Some(client), Some(arn)) = (sns_client, sns_topic_arn) {
        app.layer(Extension(client)).layer(Extension(arn))
    } else {
        app
    };

    // Cancellation token for graceful background task shutdown
    let cancel = CancellationToken::new();

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

    // LDAP directory sync
    ldap::directory_sync(&pool, &config).await;

    // Spawn background cron_sync task with cancellation support
    let cron_pool = pool.clone();
    let cron_cancel = cancel.clone();
    tokio::spawn(async move {
        streams::cron_sync_task(cron_pool, cron_cancel).await;
    });

    // Run server with graceful shutdown
    info!("Server listening on {}", config.service_address);
    let server = axum::Server::bind(
        &config
            .service_address
            .parse()
            .expect("Invalid SERVICE_ADDRESS format"),
    )
    .serve(app.into_make_service())
    .with_graceful_shutdown(shutdown_signal(cancel));

    if let Err(e) = server.await {
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

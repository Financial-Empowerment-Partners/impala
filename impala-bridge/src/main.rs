mod auth;
mod config;
mod constants;
mod error;
mod handlers;
mod ldap;
mod models;
mod streams;
mod validate;
mod vault;

use axum::routing::{get, post};
use axum::Router;
use axum::extract::Extension;
use log::{debug, error, info};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use config::load_config;
use handlers::{account, authenticate, card, health, mfa, notify, subscribe, sync, token, transaction};

#[tokio::main]
async fn main() {
    let config = load_config();

    // Initialize syslog logger
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

    info!("impala-bridge starting up");
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
                panic!("Cannot proceed without database credentials");
            }
        }
    } else {
        env::var("DATABASE_URL")
            .expect("Either DATABASE_URL or DATABASE_URL_WRAPPED must be set")
    };

    // Create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    info!("Database connection pool established");

    // Connect to Redis
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    let redis_client = Arc::new(redis_client);
    info!("Redis client created");

    // JWT signing secret
    let jwt_secret = Arc::new(
        env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set"),
    );

    // Stellar URLs
    let horizon_url = Arc::new(
        env::var("STELLAR_HORIZON_URL")
            .unwrap_or_else(|_| "https://horizon.stellar.org".to_string()),
    );
    let stellar_rpc_url = Arc::new(
        env::var("STELLAR_RPC_URL")
            .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string()),
    );

    // CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router with routes
    let app = Router::new()
        .route("/", get(health::default_route))
        .route("/health", get(health::health_check))
        .route("/version", get(health::get_version))
        .route("/account", post(account::create_account).get(account::get_account).put(account::update_account))
        .route("/authenticate", post(authenticate::authenticate))
        .route("/sync", post(sync::sync_account))
        .route("/token", post(token::token))
        .route("/subscribe", post(subscribe::subscribe))
        .route("/transaction", post(transaction::create_transaction))
        .route("/card", post(card::create_card).delete(card::delete_card))
        .route("/mfa", post(mfa::enroll_mfa).get(mfa::get_mfa))
        .route("/mfa/verify", post(mfa::verify_mfa))
        .route("/notify", post(notify::create_notify).put(notify::update_notify))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(Extension(pool.clone()))
        .layer(Extension(redis_client.clone()))
        .layer(Extension(jwt_secret))
        .layer(Extension(horizon_url))
        .layer(Extension(stellar_rpc_url));

    // LDAP directory sync
    ldap::directory_sync(&pool, &config).await;

    // Spawn background cron_sync task
    let cron_pool = pool.clone();
    tokio::spawn(async move {
        streams::cron_sync_task(cron_pool).await;
    });

    // Run server with graceful shutdown
    info!("Server listening on {}", config.service_address);
    let server = axum::Server::bind(&config.service_address.parse().unwrap())
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal());

    if let Err(e) = server.await {
        error!("Server error: {}", e);
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
}

mod admin_webhook_delivery;
mod auth;
mod config;
mod constants;
mod error;
mod events;
mod exchange;
mod google;
mod handlers;
mod jobs;
mod jwt;
mod keys;
mod ldap;
mod middleware;
mod models;
mod notifications;
mod oidc;
mod okta;
mod password;
mod redis_helpers;
mod seed_protect;
mod session;
mod sns;
mod ssrf;
mod stellar;
mod streams;
mod telemetry;
mod validate;
mod vault;
mod worker;

use axum::extract::Extension;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::routing::{delete, get, post, put};
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
    account, admin, admin_keys, admin_replenish, admin_reserve, admin_webhook, authenticate, card,
    card_auth, device_token, exchange as exchange_handler, exchange_webhook,
    github as github_handler, google as google_handler, health, logout, managed_seed, mfa, network,
    notification_subscription, notify, okta as okta_handler, session as session_handler,
    sso as sso_handler, subscribe, sync, token, transaction,
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

    // Resolve database URL (Vault/OpenBao unwrap or direct env var)
    let database_url = if let Ok(wrapped_token) = env::var("DATABASE_URL_WRAPPED") {
        info!("Unwrapping DATABASE_URL from Vault/OpenBao");
        match vault::box_unwrap(&wrapped_token).await {
            Ok(secret_data) => {
                info!("Secret unwrapped successfully");
                secret_data["database_url"]
                    .as_str()
                    .expect("database_url field not found in unwrapped secret")
                    .to_string()
            }
            Err(e) => {
                error!("Failed to unwrap DATABASE_URL from Vault/OpenBao: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        env::var("DATABASE_URL").expect("Either DATABASE_URL or DATABASE_URL_WRAPPED must be set")
    };

    // Create database connection pool with timeouts.
    //
    // `after_connect` sets a per-session `statement_timeout` so no single
    // query can wedge a connection indefinitely. The value is deliberately
    // larger than the global HTTP request timeout so fast endpoints time out
    // at the HTTP layer first; the DB limit is the last-resort catch.
    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(config.db_acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(constants::DB_IDLE_TIMEOUT_SECS))
        .max_lifetime(Duration::from_secs(constants::DB_MAX_LIFETIME_SECS))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                // 60_000 ms = 60s. Must exceed REQUEST_TIMEOUT_SECS.
                sqlx::query("SET statement_timeout = 60000")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
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

    // Authentication policy. Open registration is off unless explicitly
    // enabled: with it on, POST /authenticate lets anyone who knows an account
    // id set the password on any account that has no credentials yet.
    let auth_policy = Arc::new(auth::AuthPolicy {
        allow_open_registration: config.allow_open_registration,
    });
    if auth_policy.allow_open_registration {
        warn!(
            "ALLOW_OPEN_REGISTRATION is on — POST /authenticate will set a password on any \
             existing account that has no credentials yet, including custodial and SSO-only \
             accounts. Leave this off unless registration is intentionally public."
        );
    }

    // Admin allowlist: overrides the DB role to `admin` in the JWT `role`
    // claim, stamped at issuance.
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

    // Initialize the OIDC SSO provider registry (Okta / Auth0 / Duo / …)
    let sso_registry = Arc::new(oidc::init_registry(&config).await);

    // Initialize the legacy single-provider Okta flow (cookie-capable
    // /auth/okta used by the web UI; bearer SSO rides the registry above).
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

    // Custodial Stellar seed protector + signer. Built once and injected like
    // other shared state. Fail closed at boot if the backend is misconfigured.
    let seed_protector = seed_protect::build_protector(&config)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to initialize seed protector: {}", e);
            std::process::exit(1);
        });
    info!(
        "Custodial seed protection backend: {}",
        config.seed_protection_backend
    );
    let stellar_signer = stellar::build_signer(&stellar_config);

    // Resolve exchange provider credentials, then build the clients from what
    // resolved. Ordering matters: the protector must exist first, because a
    // stored credential can only be opened through it.
    //
    // ACTIVATION MODEL: resolution happens exactly once, here. An admin import
    // is stored, not pushed into running processes — the fleet is autoscaled
    // and multi-instance, so a push would update one task and leave the others
    // on the previous key. Every task picks up an imported credential at the
    // same moment: its next restart. See src/keys/store.rs.
    if config.key_import_enabled {
        // Bound how long a superseded credential stays recoverable from a
        // database snapshot. Done here (and after every mutation) so no
        // background task is needed to enforce the retention window.
        keys::store::scrub_expired(&pool).await;
    }
    let resolutions = keys::store::resolve_all(&config, &pool, &seed_protector).await;

    let mut owlpay_provider = None;
    let mut changelly_crypto = None;
    let mut changelly_fiat = None;
    let mut effective_keys = Vec::with_capacity(resolutions.len());

    for resolution in &resolutions {
        // A credential the admin imported that cannot be built disables just
        // that provider; one supplied by the deployment is a hard startup
        // error, because that is a config mistake a human is watching for.
        let built = match resolution.parts.as_ref() {
            None => Ok(false),
            Some(parts) => match resolution.kind {
                constants::EXCHANGE_PROVIDER_OWLPAY => exchange::owlpay::build_owlpay_provider(
                    &config,
                    parts,
                    resolution.previous_parts.as_ref(),
                )
                .map(|p| {
                    owlpay_provider = Some(p);
                    true
                }),
                constants::EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => {
                    exchange::changelly::build_changelly_crypto(&config, parts).map(|p| {
                        changelly_crypto = Some(p);
                        true
                    })
                }
                constants::EXCHANGE_PROVIDER_CHANGELLY_FIAT => {
                    exchange::changelly::build_changelly_fiat(&config, parts).map(|p| {
                        changelly_fiat = Some(p);
                        true
                    })
                }
                other => Err(format!("no builder for credential kind '{}'", other)),
            },
        };

        let mut resolution_error = resolution.error.clone();
        let active = match built {
            Ok(active) => active,
            Err(msg) => {
                if resolution.source == constants::CREDENTIAL_SOURCE_ENV {
                    error!(
                        "Failed to initialize the '{}' provider from the environment: {}",
                        resolution.kind, msg
                    );
                    std::process::exit(1);
                }
                error!(
                    "Failed to build the '{}' provider from its stored credential: {}. \
                     The provider is DISABLED for this process.",
                    resolution.kind, msg
                );
                resolution_error = Some("stored credential could not build a client".to_string());
                false
            }
        };
        let mut effective = keys::store::EffectiveKey::from_resolution(resolution, active);
        effective.error = resolution_error;
        effective_keys.push(effective);
    }

    let key_runtime = Arc::new(keys::store::KeyRuntime {
        enabled: config.key_import_enabled,
        protection_backend: config.seed_protection_backend.clone(),
        effective: effective_keys,
    });
    for e in &key_runtime.effective {
        info!(
            "Exchange credential '{}': source={} active={} fingerprint={}",
            e.kind,
            e.source,
            e.active,
            e.fingerprint.as_deref().unwrap_or("-")
        );
    }

    // Conversion reserve (bridge service reserve for small exchange orders).
    // Fail closed: a designated reserve account whose seed the bridge cannot
    // sign for is a misconfigured money path.
    let conversion_reserve = exchange::reserve::init_conversion_reserve(&config, &pool)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to initialize conversion reserve: {}", e);
            std::process::exit(1);
        });
    if let Some(ref r) = conversion_reserve {
        info!(
            "Conversion reserve enabled: account={} address={} usdc={}:{}",
            r.reserve_account_id, r.stellar_address, r.usdc_code, r.usdc_issuer
        );
    }

    // Shared HTTP client for read-only on-chain Horizon lookups
    // (`GET /account/onchain`).
    let http_client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(config.http_client_timeout_secs))
            .build()
            .expect("failed to build shared HTTP client"),
    );

    // Narrow LDAP config carried as shared state for the per-account force-sync
    // endpoint (keeps `ldap_bind_password` out of a broadly-shared `Config`).
    let ldap_config = Arc::new(ldap::LdapConfig::from_config(&config));

    // CORS layer — restrict to configured origins when not wildcard
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

    // Keep a handle for the exchange reconcile loop; `metrics` itself is
    // moved into the router's Extension layer below.
    let exchange_metrics = metrics.clone();

    // Everything the conversion-reserve watcher needs, captured before the
    // Extension layers below take ownership of the shared handles.
    let reserve_watch_deps =
        conversion_reserve
            .as_ref()
            .map(|r| exchange::reserve_watch::ReserveWatchDeps {
                pool: pool.clone(),
                http: http_client.clone(),
                horizon_url: config.stellar_horizon_url.clone(),
                reserve: r.clone(),
                signer: stellar_signer.clone(),
                protector: seed_protector.clone(),
                metrics: metrics.clone(),
                changelly_crypto: changelly_crypto.clone(),
            });

    // Shared by the reconcile loop and the `?refresh=true` handler path so
    // both schedule the next poll on the same configured cadence.
    let reconcile_config = Arc::new(exchange::reconcile::ReconcileConfig {
        poll_secs: config.exchange_poll_secs,
    });

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
        .route("/account/onchain", get(account::get_account_onchain))
        .route("/accounts", get(admin::list_accounts))
        .route(
            "/admin/accounts/{account_id}",
            delete(admin::delete_account),
        )
        .route(
            "/admin/accounts/{account_id}/role",
            put(admin::set_account_role),
        )
        .route(
            "/admin/accounts/{account_id}/sync-profile",
            post(admin::sync_profile),
        )
        .route(
            "/admin/accounts/{account_id}/sync-mode",
            put(admin::set_sync_mode),
        )
        .route("/authenticate", post(authenticate::authenticate))
        .route("/sync", post(sync::sync_account))
        .route("/sync/payala", post(sync::sync_payala))
        .route("/reserves/{account_id}", get(sync::get_reserves))
        .route("/token", post(token::token))
        .route("/subscribe", post(subscribe::subscribe))
        .route("/transactions", get(transaction::list_transactions))
        .route("/transaction", post(transaction::create_transaction))
        .route("/transaction/{btxid}", get(transaction::get_transaction))
        .route(
            "/transaction/{btxid}/review",
            put(transaction::review_transaction),
        )
        .route(
            "/managed-account/generate",
            post(managed_seed::generate_managed_account),
        )
        .route(
            "/managed-account/import",
            post(managed_seed::import_managed_account),
        )
        .route("/managed-account/sign", post(managed_seed::sign_and_submit))
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
            "/notify/verify/send",
            post(notify::send_notify_verification),
        )
        .route("/notify/verify", post(notify::verify_notify))
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
        .route(
            "/auth/sso/{provider}",
            post(sso_handler::sso_token_exchange),
        )
        .route("/auth/sso/{provider}/config", get(sso_handler::sso_config))
        .route("/auth/providers", get(sso_handler::sso_providers))
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
        // Bridge key management (all AdminUser-gated). These install the
        // credentials that move money — see the DANGER block in
        // handlers/admin_keys.rs and docs/runbooks/import-keys.md. Imports ADD
        // by default; replacing anything already in effect requires an
        // explicit compare-and-swap plus a typed confirmation phrase.
        .route("/admin/keys", get(admin_keys::list_keys))
        .route("/admin/keys/{kind}", post(admin_keys::import_key))
        .route("/admin/keys/{kind}/merge", post(admin_keys::merge_key))
        .route("/admin/keys/{kind}/revoke", post(admin_keys::revoke_key))
        // Custodial Stellar seeds. `generate` is the only way to provision the
        // conversion-reserve account: an admin-supplied reserve seed would put
        // the pool's signing key in a human's hands permanently.
        .route(
            "/admin/stellar-seeds/generate",
            post(admin_keys::generate_seed),
        )
        .route("/admin/stellar-seeds/import", post(admin_keys::import_seed))
        // Conversion-reserve management (all AdminUser-gated): pool status,
        // per-provider routing policies ($20-$200 thresholds), the manual
        // ledger, stray-inflow queue, utilization forecast, and resolution of
        // orders waiting on an admin (fiat disbursement / frozen payouts).
        .route("/admin/exchange-reserve", get(admin_reserve::get_status))
        .route(
            "/admin/exchange-reserve/policies/{provider}",
            axum::routing::put(admin_reserve::update_policy),
        )
        .route(
            "/admin/exchange-reserve/buckets/{currency}",
            axum::routing::put(admin_reserve::update_bucket),
        )
        .route(
            "/admin/exchange-reserve/entries",
            post(admin_reserve::create_entry).get(admin_reserve::list_entries),
        )
        .route(
            "/admin/exchange-reserve/unmatched",
            get(admin_reserve::list_unmatched),
        )
        // Automated refunds: the queue, the master switch, a manual
        // obligation for inflows the driver deliberately refuses, and
        // resolution of anything frozen mid-flight.
        .route(
            "/admin/exchange-reserve/refunds",
            get(admin_reserve::list_refunds).post(admin_reserve::create_refund),
        )
        .route(
            "/admin/exchange-reserve/refunds/{refund_id}/resolve",
            post(admin_reserve::resolve_refund),
        )
        .route(
            "/admin/exchange-reserve/settings",
            axum::routing::put(admin_reserve::update_settings),
        )
        // Automated replenishment: policies (caps default to 0 = refuse to
        // run), a manual trigger that shares the watcher's advisory lock,
        // and the fiat-receipt confirmation the bridge cannot observe.
        .route(
            "/admin/exchange-reserve/replenishment",
            get(admin_replenish::get_status),
        )
        .route(
            "/admin/exchange-reserve/replenishment/policies/{kind}",
            axum::routing::put(admin_replenish::update_policy),
        )
        .route(
            "/admin/exchange-reserve/replenishment/run",
            post(admin_replenish::run_now),
        )
        .route(
            "/admin/exchange-reserve/replenishment/{cycle_id}/confirm-fiat",
            post(admin_replenish::confirm_fiat),
        )
        .route(
            "/admin/exchange-reserve/replenishment/{cycle_id}/write-off",
            post(admin_replenish::write_off),
        )
        .route(
            "/admin/exchange-reserve/forecast",
            get(admin_reserve::get_forecast),
        )
        .route(
            "/admin/exchange-reserve/orders/{order_id}/disburse",
            post(admin_reserve::disburse_order),
        )
        .route(
            "/admin/exchange-reserve/orders/{order_id}/resolve",
            post(admin_reserve::resolve_order),
        )
        // Exchange: fiat<->USDC on/off-ramp (OwlPay Harbor, Changelly Fiat)
        // and crypto->USDC swaps (Changelly). The /webhooks/* callbacks are
        // deliberately unauthenticated — each verifies its provider's own
        // signature over the raw request body before parsing.
        .route("/exchange/providers", get(exchange_handler::list_providers))
        .route("/exchange/reference", get(exchange_handler::get_reference))
        .route(
            "/exchange/owlpay/quotes/{quote_id}/requirements",
            get(exchange_handler::get_owlpay_quote_requirements),
        )
        .route("/exchange/quote", post(exchange_handler::create_quote))
        .route(
            "/exchange/orders",
            post(exchange_handler::create_order).get(exchange_handler::list_orders),
        )
        .route(
            "/exchange/orders/{order_id}",
            get(exchange_handler::get_order),
        )
        .route("/webhooks/owlpay", post(exchange_webhook::owlpay_webhook))
        .route(
            "/webhooks/changelly",
            post(exchange_webhook::changelly_webhook),
        )
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
        .layer(Extension(auth_policy))
        // Registry of running stream tasks, so repeated POST /subscribe calls
        // are idempotent instead of accumulating tasks and sockets.
        .layer(Extension(Arc::new(subscribe::ActiveStreams::default())))
        .layer(Extension(stellar_config.clone()))
        .layer(Extension(admin_ids.clone()))
        .layer(Extension(seed_protector.clone()))
        .layer(Extension(stellar_signer))
        // Always present, unlike the ConversionReserve handle: the quarantine
        // on /managed-account/* must stay armed even when the reserve failed
        // to initialize, which is exactly when its account is unclaimed.
        .layer(Extension(Arc::new(
            exchange::reserve::ReserveAccountGuard::from_config(&config),
        )))
        .layer(Extension(key_runtime.clone()))
        // Non-secret provider URLs + timeouts, so the import endpoint can
        // build a throwaway client and prove a submitted credential against
        // the provider before storing it.
        .layer(Extension(Arc::new(handlers::admin_keys::ProbeConfig(
            config.clone(),
        ))))
        .layer(Extension(http_client))
        .layer(Extension(ldap_config))
        .layer(Extension(metrics))
        .layer(Extension(reconcile_config.clone()))
        .layer(Extension(cancel.clone()));

    // Add optional SNS client extension
    let app = if let (Some(client), Some(arn)) = (sns_client, sns_topic_arn) {
        app.layer(Extension(client)).layer(Extension(arn))
    } else {
        app
    };

    // Add the legacy Okta provider extension and spawn its JWKS refresh task
    // (if configured).
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

    // Register the SSO provider registry and spawn one JWKS refresh task per
    // configured provider. The registry is always present (possibly empty).
    for provider in sso_registry.iter() {
        let refresh_provider = provider.clone();
        let refresh_secs = provider.jwks_refresh_secs;
        let jwks_cancel = cancel.clone();
        tokio::spawn(async move {
            oidc::jwks_refresh_task(refresh_provider, refresh_secs, jwks_cancel).await;
        });
    }
    let app = app.layer(Extension(sso_registry.clone()));

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

    // Add exchange provider extensions (if configured). Routes stay mounted
    // either way; handlers answer 400 "not configured" when the layer is absent.
    let app = if let Some(ref provider) = owlpay_provider {
        app.layer(Extension(provider.clone()))
    } else {
        app
    };
    let app = if let Some(ref provider) = changelly_crypto {
        app.layer(Extension(provider.clone()))
    } else {
        app
    };
    let app = if let Some(ref provider) = changelly_fiat {
        app.layer(Extension(provider.clone()))
    } else {
        app
    };
    // Conversion reserve handle (same optional pattern; the handle also
    // quarantines the reserve account inside managed-seed endpoints).
    let app = if let Some(ref reserve) = conversion_reserve {
        app.layer(Extension(reserve.clone()))
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

    // Spawn the exchange-order reconcile loop when any exchange provider is
    // configured. Changelly's swap API has no webhooks, so non-terminal
    // orders must be polled; for OwlPay/Changelly-Fiat the poll is a
    // belt-and-braces backstop behind their webhooks.
    if owlpay_provider.is_some() || changelly_crypto.is_some() || changelly_fiat.is_some() {
        let ex_pool = pool.clone();
        let ex_cancel = cancel.clone();
        let ex_owlpay = owlpay_provider.clone();
        let ex_crypto = changelly_crypto.clone();
        let ex_fiat = changelly_fiat.clone();
        let ex_cfg = (*reconcile_config).clone();
        tokio::spawn(async move {
            exchange::reconcile::run(
                ex_pool,
                ex_owlpay,
                ex_crypto,
                ex_fiat,
                exchange_metrics,
                ex_cfg,
                ex_cancel,
            )
            .await;
        });
    }

    // Spawn the conversion-reserve watcher: deposit matching on the reserve
    // Stellar account, automatic USDC payouts, stale-payout freezing, and
    // pay-in-window expiry. Cross-instance duplication is suppressed by an
    // advisory lock inside each tick.
    if let Some(deps) = reserve_watch_deps {
        let rw_cancel = cancel.clone();
        tokio::spawn(async move {
            exchange::reserve_watch::run(deps, rw_cancel).await;
        });
    }

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

    // Graceful-shutdown drain deadline. Axum waits for in-flight requests
    // to complete after shutdown_signal() returns; if that stalls (e.g. a
    // downstream hang), this watchdog bounds the wait so the orchestrator
    // doesn't have to SIGKILL us. The deadline is tuned to fit inside
    // typical ECS/Kubernetes stop timeouts (30s default).
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(constants::SHUTDOWN_DRAIN_DEADLINE_SECS)).await;
        warn!(
            "Graceful shutdown exceeded {}s drain deadline — forcing exit",
            constants::SHUTDOWN_DRAIN_DEADLINE_SECS
        );
        std::process::exit(0);
    });
}

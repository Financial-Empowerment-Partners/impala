use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json,
    Router,
};

use password_auth::{generate_hash, verify_password};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use futures::StreamExt;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use redis::AsyncCommands;
use log::{debug, error, info, warn};
use std::env;
use std::fs;
use std::sync::Arc;

/// HashiCorp Vault unwrap
#[derive(Deserialize, Debug)]
struct VaultUnwrapResponse {
    data: serde_json::Value,
}

#[derive(Debug)]
enum BoxUnwrapError {
    VaultUrlMissing,
    RequestFailed(String),
    InvalidResponse(String),
}

impl std::fmt::Display for BoxUnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoxUnwrapError::VaultUrlMissing => write!(f, "VAULT_ADDR environment variable not set"),
            BoxUnwrapError::RequestFailed(msg) => write!(f, "Vault request failed: {}", msg),
            BoxUnwrapError::InvalidResponse(msg) => write!(f, "Invalid Vault response: {}", msg),
        }
    }
}

impl std::error::Error for BoxUnwrapError {}

/// Unwrap a HashiCorp Vault wrapped secret using a wrapping token
///
/// # Arguments
/// * `wrapping_token` - The one-time wrapping token from Vault
///
/// # Returns
/// * `Ok(serde_json::Value)` - The unwrapped secret data
/// * `Err(BoxUnwrapError)` - If unwrapping fails
///
/// # Environment Variables
/// * `VAULT_ADDR` - The Vault endpoint (e.g., "https://vault.example.com:8200")
///
/// # Example
/// ```no_run
/// let secret = box_unwrap("s.1234567890abcdef").await?;
/// let password = secret["password"].as_str().unwrap();
/// ```
async fn box_unwrap(wrapping_token: &str) -> Result<serde_json::Value, BoxUnwrapError> {
    // Get Vault address from environment
    let vault_addr = env::var("VAULT_ADDR")
        .map_err(|_| BoxUnwrapError::VaultUrlMissing)?;

    // Build the unwrap endpoint URL
    let unwrap_url = format!("{}/v1/sys/wrapping/unwrap", vault_addr.trim_end_matches('/'));

    // Create HTTP client
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false) // Set to true only in development
        .build()
        .map_err(|e| BoxUnwrapError::RequestFailed(e.to_string()))?;

    // Make the unwrap request
    let response = client
        .post(&unwrap_url)
        .header("X-Vault-Token", wrapping_token)
        .send()
        .await
        .map_err(|e| BoxUnwrapError::RequestFailed(e.to_string()))?;

    // Check if request was successful
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(BoxUnwrapError::RequestFailed(
            format!("HTTP {}: {}", status, error_text)
        ));
    }

    // Parse the response
    let unwrap_response: VaultUnwrapResponse = response
        .json()
        .await
        .map_err(|e| BoxUnwrapError::InvalidResponse(e.to_string()))?;

    Ok(unwrap_response.data)
}

#[derive(Debug, Clone)]
struct Config {
    public_endpoint: String,
    service_address: String,
    log_file: String,
    debug_mode: bool,
    twilio_sid: Option<String>,
    twilio_token: Option<String>,
    twilio_number: Option<String>,
}

/// Load configuration from a JSON config file (if present) and environment variables.
/// Environment variables take precedence over config file values.
///
/// Config file path is read from `CONFIG_FILE` env var (default: `config.json`).
///
/// | Field            | Env Var            | Default              |
/// |------------------|--------------------|----------------------|
/// | public_endpoint  | PUBLIC_ENDPOINT    | http://localhost:8080 |
/// | service_address  | SERVICE_ADDRESS    | 0.0.0.0:8080         |
/// | log_file         | LOG_FILE           | impala-bridge.log    |
/// | debug_mode       | DEBUG_MODE         | false                |
/// | twilio_sid       | TWILIO_SID         | None                 |
/// | twilio_token     | TWILIO_TOKEN       | None                 |
/// | twilio_number    | TWILIO_NUMBER      | None                 |
fn load_config() -> Config {
    // Try to load base values from a config file
    let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.json".to_string());
    let file_values: serde_json::Value = fs::read_to_string(&config_path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or(serde_json::Value::Null);

    let from_file = |key: &str| -> Option<String> {
        file_values.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    };

    let public_endpoint = env::var("PUBLIC_ENDPOINT")
        .ok()
        .or_else(|| from_file("public_endpoint"))
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let service_address = env::var("SERVICE_ADDRESS")
        .ok()
        .or_else(|| from_file("service_address"))
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let log_file = env::var("LOG_FILE")
        .ok()
        .or_else(|| from_file("log_file"))
        .unwrap_or_else(|| "impala-bridge.log".to_string());

    let debug_mode = env::var("DEBUG_MODE")
        .ok()
        .or_else(|| from_file("debug_mode").map(|v| v.to_string()))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let twilio_sid = env::var("TWILIO_SID")
        .ok()
        .or_else(|| from_file("twilio_sid"));

    let twilio_token = env::var("TWILIO_TOKEN")
        .ok()
        .or_else(|| from_file("twilio_token"));

    let twilio_number = env::var("TWILIO_NUMBER")
        .ok()
        .or_else(|| from_file("twilio_number"));

    Config {
        public_endpoint,
        service_address,
        log_file,
        debug_mode,
        twilio_sid,
        twilio_token,
        twilio_number,
    }
}

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
            // Continue without syslog — log macros become no-ops
        }
    }

    info!("impala-bridge starting up");
    debug!("Config: {:?}", config);

    // Handle wrapped secrets during initialization
    // If DATABASE_URL_WRAPPED is set, unwrap it; otherwise use DATABASE_URL directly
    let database_url = if let Ok(wrapped_token) = env::var("DATABASE_URL_WRAPPED") {
        info!("Unwrapping DATABASE_URL from Vault");
        match box_unwrap(&wrapped_token).await {
            Ok(secret_data) => {
                info!("Vault secret unwrapped successfully");
                // Extract the database URL from the unwrapped secret
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
        // Fall back to regular DATABASE_URL environment variable
        env::var("DATABASE_URL")
            .expect("Either DATABASE_URL or DATABASE_URL_WRAPPED must be set")
    };

    // create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    info!("Database connection pool established");

    // connect to Redis
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    let redis_client = Arc::new(redis_client);
    info!("Redis client created");

    // JWT signing secret
    let jwt_secret = Arc::new(
        env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set"),
    );

    // Stellar Horizon URL
    let horizon_url = Arc::new(
        env::var("STELLAR_HORIZON_URL")
            .unwrap_or_else(|_| "https://horizon.stellar.org".to_string()),
    );

    // Stellar Soroban RPC URL
    let stellar_rpc_url = Arc::new(
        env::var("STELLAR_RPC_URL")
            .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string()),
    );

    // build our application with routes
    let app = Router::new()
        // `GET /` goes to `default_route`
        .route("/", get(default_route))
        // `GET /version` goes to `get_version`
        .route("/version", get(get_version))
        // `POST /account` goes to `create_account`, `GET /account` goes to `get_account`, `PUT /account` goes to `update_account`
        .route("/account", post(create_account).get(get_account).put(update_account))
        // `POST /authenticate` goes to `authenticate`
        .route("/authenticate", post(authenticate))
        .route("/sync", post(sync_account))
        .route("/token", post(token))
        .route("/subscribe", post(subscribe))
        .route("/transaction", post(create_transaction))
        .route("/card", post(create_card).delete(delete_card))
        .route("/mfa", post(enroll_mfa).get(get_mfa))
        .route("/mfa/verify", post(verify_mfa))
        .route("/notify", post(create_notify).put(update_notify))
        .layer(Extension(pool))
        .layer(Extension(redis_client))
        .layer(Extension(jwt_secret))
        .layer(Extension(horizon_url))
        .layer(Extension(stellar_rpc_url));

    // spawn background cron_sync task
    let cron_pool = pool.clone();
    tokio::spawn(async move {
        cron_sync_task(cron_pool).await;
    });

    // run our app
    info!("Server listening on {}", config.service_address);
    axum::Server::bind(&config.service_address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/// Background task that periodically fetches callback URIs from the
/// `cron_sync` table, invokes each one, and stores the JSON response back
/// into the `callback_result` column. Runs every 60 seconds.
async fn cron_sync_task(pool: PgPool) {
    let client = reqwest::Client::new();
    loop {
        let rows = sqlx::query_as::<_, (i32, String)>(
            "SELECT id, callback_uri FROM cron_sync"
        )
        .fetch_all(&pool)
        .await;

        match rows {
            Ok(rows) => {
                debug!("cron_sync: processing {} callback(s)", rows.len());
                for (id, callback_uri) in rows {
                    match client.get(&callback_uri).send().await {
                        Ok(response) => {
                            match response.json::<serde_json::Value>().await {
                                Ok(body) => {
                                    if let Err(e) = sqlx::query(
                                        "UPDATE cron_sync SET callback_result = $1 WHERE id = $2"
                                    )
                                    .bind(&body)
                                    .bind(id)
                                    .execute(&pool)
                                    .await
                                    {
                                        error!("cron_sync: failed to update result for id {}: {}", id, e);
                                    } else {
                                        debug!("cron_sync: updated result for id {}", id);
                                    }
                                }
                                Err(e) => {
                                    warn!("cron_sync: JSON parse error for id {} ({}): {}", id, callback_uri, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("cron_sync: request failed for id {} ({}): {}", id, callback_uri, e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("cron_sync: query failed: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// Health check endpoint (`GET /`). Returns a static greeting.
async fn default_route() -> &'static str {
    "Hello, World!"
}

#[derive(Serialize)]
struct VersionResponse {
    name: &'static str,
    version: &'static str,
    build_date: &'static str,
    rustc_version: &'static str,
    schema_version: Option<String>,
}

/// Return build info and database schema version (`GET /version`).
///
/// Build date and rustc version are injected at compile time by `build.rs`.
/// Schema version is read from the `impala_schema` table.
async fn get_version(
    Extension(pool): Extension<PgPool>,
) -> Json<VersionResponse> {
    // Query the database schema version
    let schema_version = sqlx::query_scalar::<_, String>(
        "SELECT current_version FROM impala_schema LIMIT 1"
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    Json(VersionResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        build_date: env!("BUILD_DATE"),
        rustc_version: env!("RUSTC_VERSION"),
        schema_version,
    })
}

#[derive(Deserialize)]
struct CreateAccountRequest {
    stellar_account_id: String,
    payala_account_id: String,
    first_name: String,
    middle_name: Option<String>,
    last_name: String,
    nickname: Option<String>,
    affiliation: Option<String>,
    gender: Option<String>,
}

#[derive(Serialize)]
struct CreateAccountResponse {
    success: bool,
    message: String,
}

#[derive(Deserialize)]
struct AuthenticateRequest {
    account_id: String,
    password: String,
}

#[derive(Serialize)]
struct AuthenticateResponse {
    success: bool,
    message: String,
    action: String, // "registered" or "authenticated"
}

/// Create a new linked Stellar/Payala account (`POST /account`).
///
/// Validates that stellar_account_id is a valid Stellar public key format
/// (56 chars, starts with 'G') and that required name fields are non-empty.
async fn create_account(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, StatusCode> {
    info!("POST /account: creating account for stellar_id={}", payload.stellar_account_id);

    // Validate stellar_account_id format (Stellar public keys are 56 chars starting with 'G')
    if payload.stellar_account_id.len() != 56 || !payload.stellar_account_id.starts_with('G') {
        warn!("create_account: invalid stellar_account_id format");
        return Ok(Json(CreateAccountResponse {
            success: false,
            message: "stellar_account_id must be 56 characters starting with 'G'".to_string(),
        }));
    }

    // Validate required name fields are non-empty and within bounds
    if payload.first_name.trim().is_empty() || payload.last_name.trim().is_empty() {
        warn!("create_account: empty name fields");
        return Ok(Json(CreateAccountResponse {
            success: false,
            message: "first_name and last_name must not be empty".to_string(),
        }));
    }

    if payload.first_name.len() > 64 || payload.last_name.len() > 64 {
        warn!("create_account: name fields exceed 64 characters");
        return Ok(Json(CreateAccountResponse {
            success: false,
            message: "Name fields must not exceed 64 characters".to_string(),
        }));
    }

    let result = sqlx::query(
        r#"
        INSERT INTO impala_account
            (stellar_account_id, payala_account_id, first_name, middle_name,
             last_name, nickname, affiliation, gender)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&payload.stellar_account_id)
    .bind(&payload.payala_account_id)
    .bind(&payload.first_name)
    .bind(&payload.middle_name)
    .bind(&payload.last_name)
    .bind(&payload.nickname)
    .bind(&payload.affiliation)
    .bind(&payload.gender)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!("create_account: account created for stellar_id={}", payload.stellar_account_id);
            Ok(Json(CreateAccountResponse {
                success: true,
                message: "Account created successfully".to_string(),
            }))
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("duplicate key") || err_str.contains("unique constraint") {
                warn!("create_account: duplicate account for stellar_id={}", payload.stellar_account_id);
                return Ok(Json(CreateAccountResponse {
                    success: false,
                    message: "An account with this identifier already exists".to_string(),
                }));
            }
            error!("create_account: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct GetAccountQuery {
    stellar_account_id: String,
}

#[derive(Serialize)]
struct GetAccountResponse {
    payala_account_id: String,
    first_name: String,
    middle_name: Option<String>,
    last_name: String,
    nickname: Option<String>,
    affiliation: Option<String>,
    gender: Option<String>,
}

/// Look up an account by Stellar account ID (`GET /account?stellar_account_id=...`).
async fn get_account(
    Extension(pool): Extension<PgPool>,
    Query(params): Query<GetAccountQuery>,
) -> Result<Json<GetAccountResponse>, StatusCode> {
    debug!("GET /account: lookup stellar_id={}", params.stellar_account_id);
    let result = sqlx::query_as::<_, (String, String, Option<String>, String, Option<String>, Option<String>, Option<String>)>(
        r#"
        SELECT payala_account_id, first_name, middle_name, last_name,
               nickname, affiliation, gender
        FROM impala_account
        WHERE stellar_account_id = $1
        "#,
    )
    .bind(&params.stellar_account_id)
    .fetch_optional(&pool)
    .await;

    match result {
        Ok(Some((payala_account_id, first_name, middle_name, last_name, nickname, affiliation, gender))) => {
            Ok(Json(GetAccountResponse {
                payala_account_id,
                first_name,
                middle_name,
                last_name,
                nickname,
                affiliation,
                gender,
            }))
        }
        Ok(None) => {
            debug!("get_account: not found for stellar_id={}", params.stellar_account_id);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("get_account: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct UpdateAccountRequest {
    stellar_account_id: Option<String>,
    payala_account_id: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    nickname: Option<String>,
    affiliation: Option<String>,
    gender: Option<String>,
}

#[derive(Serialize)]
struct UpdateAccountResponse {
    success: bool,
    message: String,
    rows_affected: u64,
}

/// Update account fields (`PUT /account`).
///
/// Accepts partial updates — only provided fields are modified.
/// Identifies the account by either `stellar_account_id` or `payala_account_id`.
/// Builds a dynamic SQL UPDATE with positional parameters.
async fn update_account(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateAccountRequest>,
) -> Result<Json<UpdateAccountResponse>, StatusCode> {
    info!("PUT /account: updating account");
    // Determine which identifier to use for the WHERE clause
    let (where_clause, where_value) = if let Some(ref stellar_id) = payload.stellar_account_id {
        ("stellar_account_id = $1", stellar_id.clone())
    } else if let Some(ref payala_id) = payload.payala_account_id {
        ("payala_account_id = $1", payala_id.clone())
    } else {
        warn!("update_account: no identifier provided");
        return Ok(Json(UpdateAccountResponse {
            success: false,
            message: "Either stellar_account_id or payala_account_id must be provided".to_string(),
            rows_affected: 0,
        }));
    };

    // Build dynamic SET clause based on provided fields
    let mut set_parts = Vec::new();
    let mut param_index = 2; // Start at 2 because $1 is used for WHERE clause

    if payload.stellar_account_id.is_some() && where_clause.contains("payala_account_id") {
        set_parts.push(format!("stellar_account_id = ${}", param_index));
        param_index += 1;
    }
    if payload.payala_account_id.is_some() && where_clause.contains("stellar_account_id") {
        set_parts.push(format!("payala_account_id = ${}", param_index));
        param_index += 1;
    }
    if payload.first_name.is_some() {
        set_parts.push(format!("first_name = ${}", param_index));
        param_index += 1;
    }
    if payload.middle_name.is_some() {
        set_parts.push(format!("middle_name = ${}", param_index));
        param_index += 1;
    }
    if payload.last_name.is_some() {
        set_parts.push(format!("last_name = ${}", param_index));
        param_index += 1;
    }
    if payload.nickname.is_some() {
        set_parts.push(format!("nickname = ${}", param_index));
        param_index += 1;
    }
    if payload.affiliation.is_some() {
        set_parts.push(format!("affiliation = ${}", param_index));
        param_index += 1;
    }
    if payload.gender.is_some() {
        set_parts.push(format!("gender = ${}", param_index));
        param_index += 1;
    }

    if set_parts.is_empty() {
        warn!("update_account: no fields provided to update");
        return Ok(Json(UpdateAccountResponse {
            success: false,
            message: "No fields provided to update".to_string(),
            rows_affected: 0,
        }));
    }

    // Build the complete SQL query
    let sql = format!(
        "UPDATE impala_account SET {} WHERE {}",
        set_parts.join(", "),
        where_clause
    );

    // Execute the query with bindings
    let mut query = sqlx::query(&sql);
    query = query.bind(&where_value);

    if payload.stellar_account_id.is_some() && where_clause.contains("payala_account_id") {
        query = query.bind(&payload.stellar_account_id);
    }
    if payload.payala_account_id.is_some() && where_clause.contains("stellar_account_id") {
        query = query.bind(&payload.payala_account_id);
    }
    if let Some(ref val) = payload.first_name {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.middle_name {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.last_name {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.nickname {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.affiliation {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.gender {
        query = query.bind(val);
    }

    let result = query.execute(&pool).await;

    match result {
        Ok(res) => {
            let rows_affected = res.rows_affected();
            if rows_affected == 0 {
                debug!("update_account: no matching account found");
                Ok(Json(UpdateAccountResponse {
                    success: false,
                    message: "No account found with the provided identifier".to_string(),
                    rows_affected: 0,
                }))
            } else {
                info!("update_account: updated {} row(s)", rows_affected);
                Ok(Json(UpdateAccountResponse {
                    success: true,
                    message: "Account updated successfully".to_string(),
                    rows_affected,
                }))
            }
        }
        Err(e) => {
            error!("update_account: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Register or authenticate a user (`POST /authenticate`).
///
/// If no credentials exist for the account, registers a new user by hashing
/// the password with Argon2 and storing it in `impala_auth`. If credentials
/// exist, verifies the password against the stored hash.
///
/// Requires the account to already exist in `impala_account`.
/// Enforces a minimum password length of 8 characters.
async fn authenticate(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, StatusCode> {
    info!("POST /authenticate: account_id={}", payload.account_id);

    // Validate password strength (minimum 8 characters)
    if payload.password.len() < 8 {
        warn!("authenticate: password too short for account_id={}", payload.account_id);
        return Ok(Json(AuthenticateResponse {
            success: false,
            message: "Password must be at least 8 characters".to_string(),
            action: "".to_string(),
        }));
    }

    // Verify account exists in impala_account table
    let account_exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM impala_account WHERE payala_account_id = $1"
    )
    .bind(&payload.account_id)
    .fetch_one(&pool)
    .await;

    match account_exists {
        Ok(count) if count == 0 => {
            warn!("authenticate: account not found for account_id={}", payload.account_id);
            return Ok(Json(AuthenticateResponse {
                success: false,
                message: "Account not found".to_string(),
                action: "".to_string(),
            }));
        }
        Err(e) => {
            error!("authenticate: database error looking up account: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        _ => {}
    }

    // Check if auth credentials exist in impala_auth table
    let existing_auth = sqlx::query_as::<_, (String,)>(
        "SELECT password_hash FROM impala_auth WHERE account_id = $1"
    )
    .bind(&payload.account_id)
    .fetch_optional(&pool)
    .await;

    match existing_auth {
        Ok(None) => {
            // No credentials exist - register new user
            let password_hash = generate_hash(&payload.password);

            let insert_result = sqlx::query(
                "INSERT INTO impala_auth (account_id, password_hash) VALUES ($1, $2)"
            )
            .bind(&payload.account_id)
            .bind(&password_hash)
            .execute(&pool)
            .await;

            match insert_result {
                Ok(_) => {
                    info!("authenticate: registered new user account_id={}", payload.account_id);
                    Ok(Json(AuthenticateResponse {
                        success: true,
                        message: "Registration successful".to_string(),
                        action: "registered".to_string(),
                    }))
                }
                Err(e) => {
                    error!("authenticate: failed to insert auth record: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Ok(Some((stored_hash,))) => {
            // Credentials exist - verify password
            match verify_password(&payload.password, &stored_hash) {
                Ok(_) => {
                    info!("authenticate: successful login for account_id={}", payload.account_id);
                    Ok(Json(AuthenticateResponse {
                        success: true,
                        message: "Authentication successful".to_string(),
                        action: "authenticated".to_string(),
                    }))
                }
                Err(_) => {
                    warn!("authenticate: invalid password for account_id={}", payload.account_id);
                    Ok(Json(AuthenticateResponse {
                        success: false,
                        message: "Invalid password".to_string(),
                        action: "authenticated".to_string(),
                    }))
                }
            }
        }
        Err(e) => {
            error!("authenticate: database error fetching auth record: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct SyncRequest {
    account_id: String,
}

#[derive(Serialize)]
struct SyncResponse {
    success: bool,
    message: String,
    timestamp: String,
}

/// Record a sync timestamp in Redis and reconcile with Stellar RPC (`POST /sync`).
///
/// Stores the current UTC timestamp in Redis keyed by `account_id`, then
/// queries the Soroban RPC `getTransactions` endpoint to check for
/// transactions that match records in the local database.
async fn sync_account(
    Extension(pool): Extension<PgPool>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Extension(stellar_rpc_url): Extension<Arc<String>>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, StatusCode> {
    info!("POST /sync: account_id={}", payload.account_id);

    let mut conn = redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            error!("sync_account: Redis connection error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

    conn.set::<_, _, ()>(&payload.account_id, &timestamp)
        .await
        .map_err(|e| {
            error!("sync_account: Redis set error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Call Stellar Soroban RPC getTransactions and check against local DB
    let client = reqwest::Client::new();
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransactions",
        "params": {}
    });

    match client
        .post(stellar_rpc_url.as_str())
        .json(&rpc_request)
        .send()
        .await
    {
        Ok(response) => {
            if let Ok(body) = response.json::<serde_json::Value>().await {
                if let Some(transactions) = body["result"]["transactions"].as_array() {
                    for tx in transactions {
                        if let Some(tx_id) = tx["id"].as_str() {
                            let exists = sqlx::query_scalar::<_, i64>(
                                "SELECT COUNT(*) FROM transaction WHERE stellar_tx_id = $1",
                            )
                            .bind(tx_id)
                            .fetch_one(&pool)
                            .await;

                            if let Ok(count) = exists {
                                if count > 0 {
                                    debug!("sync_account: matched local tx {}", tx_id);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("sync_account: Stellar RPC getTransactions error: {}", e);
        }
    }

    Ok(Json(SyncResponse {
        success: true,
        message: "Sync timestamp recorded".to_string(),
        timestamp,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    token_type: String,
    exp: usize,
    iat: usize,
}

#[derive(Deserialize)]
struct TokenRequest {
    username: Option<String>,
    password: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temporal_token: Option<String>,
}

/// Issue JWT tokens (`POST /token`).
///
/// Two flows:
/// - **Refresh token → temporal token**: provide `refresh_token` to get a
///   1-hour temporal token for API access.
/// - **Username + password → refresh token**: authenticate and receive a
///   30-day refresh token.
async fn token(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_secret): Extension<Arc<String>>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    debug!("POST /token: request received");
    let key = jwt_secret.as_bytes();

    // Flow 1: refresh_token provided -> return a short-lived temporal_token
    if let Some(ref refresh_token) = payload.refresh_token {
        let token_data = decode::<Claims>(
            refresh_token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
        .map_err(|e| {
            warn!("token: invalid refresh token presented: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

        if token_data.claims.token_type != "refresh" {
            warn!("token: wrong token type '{}' presented for refresh flow", token_data.claims.token_type);
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid token type".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }

        let now = chrono::Utc::now().timestamp() as usize;
        let temporal_claims = Claims {
            sub: token_data.claims.sub,
            token_type: "temporal".to_string(),
            iat: now,
            exp: now + 3600, // 1 hour
        };

        let temporal_token = encode(
            &Header::default(),
            &temporal_claims,
            &EncodingKey::from_secret(key),
        )
        .map_err(|e| {
            error!("token: failed to encode temporal token: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        info!("token: temporal token issued for sub={}", temporal_claims.sub);
        return Ok(Json(TokenResponse {
            success: true,
            message: "Temporal token issued".to_string(),
            refresh_token: None,
            temporal_token: Some(temporal_token),
        }));
    }

    // Flow 2: username + password provided -> authenticate and return a long-lived refresh_token
    let username = payload.username.as_deref().unwrap_or("");
    let password = payload.password.as_deref().unwrap_or("");

    if username.is_empty() || password.is_empty() {
        warn!("token: missing username or password");
        return Ok(Json(TokenResponse {
            success: false,
            message: "Either username/password or refresh_token must be provided".to_string(),
            refresh_token: None,
            temporal_token: None,
        }));
    }

    // Look up stored password hash
    let stored_hash = sqlx::query_as::<_, (String,)>(
        "SELECT password_hash FROM impala_auth WHERE account_id = $1",
    )
    .bind(username)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("token: database error looking up credentials: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let stored_hash = match stored_hash {
        Some((hash,)) => hash,
        None => {
            warn!("token: no credentials found for username={}", username);
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }
    };

    if verify_password(password, &stored_hash).is_err() {
        warn!("token: invalid password for username={}", username);
        return Ok(Json(TokenResponse {
            success: false,
            message: "Invalid credentials".to_string(),
            refresh_token: None,
            temporal_token: None,
        }));
    }

    let now = chrono::Utc::now().timestamp() as usize;
    let refresh_claims = Claims {
        sub: username.to_string(),
        token_type: "refresh".to_string(),
        iat: now,
        exp: now + 30 * 24 * 3600, // 30 days
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(key),
    )
    .map_err(|e| {
        error!("token: failed to encode refresh token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("token: refresh token issued for username={}", username);
    Ok(Json(TokenResponse {
        success: true,
        message: "Refresh token issued".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: None,
    }))
}

#[derive(Deserialize)]
struct SubscribeRequest {
    network: String,
    listen_endpoint: Option<String>,
}

#[derive(Serialize)]
struct SubscribeResponse {
    success: bool,
    message: String,
}

/// Subscribe to network event streams (`POST /subscribe`).
///
/// Spawns a background task for the requested network:
/// - `"stellar"`: connects to Horizon SSE `/ledgers` endpoint,
///   stores ledger sequences and timestamps in Redis.
/// - `"payala"`: binds a TCP listener on `listen_endpoint`,
///   stores incoming JSON events in Redis.
async fn subscribe(
    Extension(horizon_url): Extension<Arc<String>>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Json(payload): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, StatusCode> {
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
                if let Err(e) = stellar_stream(&url, &redis).await {
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

            info!("subscribe: starting Payala TCP listener on {}", listen_endpoint);
            tokio::spawn(async move {
                if let Err(e) = payala_stream(&listen_endpoint, &redis).await {
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

/// Long-running SSE consumer for Stellar Horizon ledger events.
/// Parses the Server-Sent Events stream, extracts ledger sequence numbers,
/// and stores each event's timestamp in Redis.
async fn stellar_stream(
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
        error!("stellar_stream: Horizon returned HTTP {}", response.status());
        return Err(format!("Horizon returned HTTP {}", response.status()).into());
    }

    info!("stellar_stream: connected to Horizon SSE");
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut event_data = String::new();
    const MAX_BUFFER_SIZE: usize = 1_048_576; // 1 MB

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // Prevent unbounded memory growth from malformed streams
        if buffer.len() > MAX_BUFFER_SIZE {
            warn!("stellar_stream: SSE buffer exceeded {} bytes, resetting", MAX_BUFFER_SIZE);
            buffer.clear();
            event_data.clear();
            continue;
        }

        while let Some(newline_pos) = buffer.find('\n') {
            let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
            buffer = buffer[newline_pos + 1..].to_string();

            if line.starts_with("data:") {
                let data = line[5..].trim();
                if data == "\"hello\"" {
                    continue;
                }
                event_data.push_str(data);
            } else if line.is_empty() && !event_data.is_empty() {
                // End of SSE event — process accumulated data
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&event_data) {
                    let sequence = parsed["sequence"]
                        .as_u64()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    info!("stellar_stream: ledger event sequence={}", sequence);

                    // Store latest ledger sequence in Redis
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
/// Accepts connections, parses incoming JSON messages, and stores each
/// event in Redis keyed by timestamp.
async fn payala_stream(
    listen_endpoint: &str,
    redis_client: &redis::Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = listen_endpoint.parse().map_err(|e| {
        error!("payala_stream: invalid listen_endpoint '{}': {}", listen_endpoint, e);
        format!("Invalid listen_endpoint '{}': {}", listen_endpoint, e)
    })?;

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        error!("payala_stream: failed to bind to {}: {}", addr, e);
        format!("Failed to bind to {}: {}", addr, e)
    })?;

    info!("payala_stream: TCP listener started on {}", addr);

    // Store the active listener endpoint in Redis
    if let Ok(mut conn) = redis_client.get_async_connection().await {
        let _: Result<(), _> = redis::AsyncCommands::set(
            &mut conn,
            "payala:listen_endpoint",
            listen_endpoint,
        )
        .await;
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

                    info!("payala_stream: event from {}: type={}", peer_addr, event_type);

                    if let Ok(mut conn) = redis.get_async_connection().await {
                        let timestamp =
                            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
                        let event_key = format!("payala:event:{}:{}", timestamp, uuid::Uuid::new_v4());
                        let _: Result<(), _> = redis::AsyncCommands::set(
                            &mut conn,
                            &event_key,
                            &raw,
                        )
                        .await;
                        let _: Result<(), _> = redis::AsyncCommands::set(
                            &mut conn,
                            "payala:latest_event",
                            &raw,
                        )
                        .await;
                    }
                } else {
                    warn!("payala_stream: non-JSON data from {}: {} bytes", peer_addr, n);
                }
            }
        });
    }
}

// ── Transaction ────────────────────────────────────────────────────────
// Records dual-chain transactions (Stellar and/or Payala) with a
// database CHECK constraint requiring at least one tx ID.

#[derive(Deserialize)]
struct CreateTransactionRequest {
    stellar_tx_id: Option<String>,
    payala_tx_id: Option<String>,
    stellar_hash: Option<String>,
    source_account: Option<String>,
    stellar_fee: Option<i64>,
    stellar_max_fee: Option<i64>,
    memo: Option<String>,
    signatures: Option<String>,
    preconditions: Option<String>,
    payala_currency: Option<String>,
    payala_digest: Option<String>,
}

#[derive(Serialize)]
struct CreateTransactionResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    btxid: Option<Uuid>,
}

/// Create a dual-chain transaction record (`POST /transaction`).
///
/// At least one of `stellar_tx_id` or `payala_tx_id` must be provided
/// (enforced both in application code and by a database CHECK constraint).
/// Returns the generated bridge transaction ID (`btxid`).
async fn create_transaction(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateTransactionRequest>,
) -> Result<Json<CreateTransactionResponse>, StatusCode> {
    info!("POST /transaction: stellar_tx_id={:?} payala_tx_id={:?}",
        payload.stellar_tx_id, payload.payala_tx_id);

    if payload.stellar_tx_id.is_none() && payload.payala_tx_id.is_none() {
        warn!("create_transaction: neither stellar_tx_id nor payala_tx_id provided");
        return Ok(Json(CreateTransactionResponse {
            success: false,
            message: "At least one of stellar_tx_id or payala_tx_id must be provided".to_string(),
            btxid: None,
        }));
    }

    let result = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO transaction
            (stellar_tx_id, payala_tx_id, stellar_hash, source_account,
             stellar_fee, stellar_max_fee, memo, signatures, preconditions,
             payala_currency, payala_digest)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING btxid
        "#,
    )
    .bind(&payload.stellar_tx_id)
    .bind(&payload.payala_tx_id)
    .bind(&payload.stellar_hash)
    .bind(&payload.source_account)
    .bind(&payload.stellar_fee)
    .bind(&payload.stellar_max_fee)
    .bind(&payload.memo)
    .bind(&payload.signatures)
    .bind(&payload.preconditions)
    .bind(&payload.payala_currency)
    .bind(&payload.payala_digest)
    .fetch_one(&pool)
    .await;

    match result {
        Ok(btxid) => {
            info!("create_transaction: created btxid={}", btxid);
            Ok(Json(CreateTransactionResponse {
                success: true,
                message: "Transaction created successfully".to_string(),
                btxid: Some(btxid),
            }))
        }
        Err(e) => {
            error!("create_transaction: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ── Card ───────────────────────────────────────────────────────────────
// Hardware smartcard registration and soft-deletion.

#[derive(Deserialize)]
struct CreateCardRequest {
    account_id: String,
    card_id: String,
    ec_pubkey: String,
    rsa_pubkey: String,
}

#[derive(Serialize)]
struct CardResponse {
    success: bool,
    message: String,
}

#[derive(Deserialize)]
struct DeleteCardRequest {
    card_id: String,
}

/// Register a hardware smartcard (`POST /card`).
/// Stores the card's EC and RSA public keys linked to an account.
async fn create_card(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateCardRequest>,
) -> Result<Json<CardResponse>, StatusCode> {
    info!("POST /card: registering card_id={} for account_id={}", payload.card_id, payload.account_id);
    let result = sqlx::query(
        r#"
        INSERT INTO card (account_id, card_id, ec_pubkey, rsa_pubkey)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&payload.account_id)
    .bind(&payload.card_id)
    .bind(&payload.ec_pubkey)
    .bind(&payload.rsa_pubkey)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!("create_card: card_id={} registered", payload.card_id);
            Ok(Json(CardResponse {
                success: true,
                message: "Card created successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("create_card: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Soft-delete a card (`DELETE /card`).
/// Sets `is_delete = TRUE` rather than removing the row.
async fn delete_card(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<DeleteCardRequest>,
) -> Result<Json<CardResponse>, StatusCode> {
    info!("DELETE /card: card_id={}", payload.card_id);
    let result = sqlx::query(
        "UPDATE card SET is_delete = TRUE, updated_at = CURRENT_TIMESTAMP WHERE card_id = $1 AND is_delete = FALSE"
    )
    .bind(&payload.card_id)
    .execute(&pool)
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                warn!("delete_card: card_id={} not found or already deleted", payload.card_id);
                Ok(Json(CardResponse {
                    success: false,
                    message: "Card not found or already deleted".to_string(),
                }))
            } else {
                info!("delete_card: card_id={} soft-deleted", payload.card_id);
                Ok(Json(CardResponse {
                    success: true,
                    message: "Card deleted successfully".to_string(),
                }))
            }
        }
        Err(e) => {
            error!("delete_card: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ── MFA ────────────────────────────────────────────────────────────────
// Multi-factor authentication enrollment and verification.
// Supports TOTP (shared secret) and SMS (phone number) methods.
// Uses composite PK (account_id, mfa_type) with UPSERT for re-enrollment.

#[derive(Deserialize)]
struct EnrollMfaRequest {
    account_id: String,
    mfa_type: String,          // "totp" or "sms"
    secret: Option<String>,    // shared secret for TOTP
    phone_number: Option<String>, // phone for SMS
}

#[derive(Serialize)]
struct MfaResponse {
    success: bool,
    message: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct MfaEnrollment {
    account_id: String,
    mfa_type: String,
    secret: Option<String>,
    phone_number: Option<String>,
    enabled: bool,
}

#[derive(Deserialize)]
struct MfaQuery {
    account_id: String,
}

#[derive(Deserialize)]
struct VerifyMfaRequest {
    account_id: String,
    mfa_type: String,
    code: String,
}

/// Enroll or re-enroll an MFA method (`POST /mfa`).
///
/// Supports `"totp"` (requires `secret`) and `"sms"` (requires `phone_number`).
/// Uses UPSERT on `(account_id, mfa_type)` so re-enrollment updates the existing row.
async fn enroll_mfa(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<EnrollMfaRequest>,
) -> Result<Json<MfaResponse>, StatusCode> {
    info!("POST /mfa: enrolling mfa_type={} for account_id={}", payload.mfa_type, payload.account_id);

    if payload.mfa_type != "totp" && payload.mfa_type != "sms" {
        warn!("enroll_mfa: invalid mfa_type '{}'", payload.mfa_type);
        return Ok(Json(MfaResponse {
            success: false,
            message: "mfa_type must be 'totp' or 'sms'".to_string(),
        }));
    }

    if payload.mfa_type == "totp" && payload.secret.is_none() {
        warn!("enroll_mfa: missing secret for TOTP enrollment");
        return Ok(Json(MfaResponse {
            success: false,
            message: "secret is required for TOTP enrollment".to_string(),
        }));
    }

    if payload.mfa_type == "sms" && payload.phone_number.is_none() {
        warn!("enroll_mfa: missing phone_number for SMS enrollment");
        return Ok(Json(MfaResponse {
            success: false,
            message: "phone_number is required for SMS enrollment".to_string(),
        }));
    }

    let result = sqlx::query(
        "INSERT INTO impala_mfa (account_id, mfa_type, secret, phone_number, enabled)
         VALUES ($1, $2, $3, $4, TRUE)
         ON CONFLICT (account_id, mfa_type)
         DO UPDATE SET secret = EXCLUDED.secret,
                       phone_number = EXCLUDED.phone_number,
                       enabled = TRUE"
    )
    .bind(&payload.account_id)
    .bind(&payload.mfa_type)
    .bind(&payload.secret)
    .bind(&payload.phone_number)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!("enroll_mfa: {} enrolled for account_id={}", payload.mfa_type, payload.account_id);
            Ok(Json(MfaResponse {
                success: true,
                message: "MFA enrolled successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("enroll_mfa: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List all MFA enrollments for an account (`GET /mfa?account_id=…`).
///
/// Returns an array of [MfaEnrollment] rows, each containing the type,
/// shared secret (TOTP), phone number (SMS), and enabled status.
async fn get_mfa(
    Extension(pool): Extension<PgPool>,
    Query(params): Query<MfaQuery>,
) -> Result<Json<Vec<MfaEnrollment>>, StatusCode> {
    debug!("GET /mfa: account_id={}", params.account_id);
    let rows = sqlx::query_as::<_, MfaEnrollment>(
        "SELECT account_id, mfa_type, secret, phone_number, enabled
         FROM impala_mfa WHERE account_id = $1"
    )
    .bind(&params.account_id)
    .fetch_all(&pool)
    .await;

    match rows {
        Ok(enrollments) => {
            debug!("get_mfa: found {} enrollment(s) for account_id={}", enrollments.len(), params.account_id);
            Ok(Json(enrollments))
        }
        Err(e) => {
            error!("get_mfa: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ── Notify ─────────────────────────────────────────────────────────────
// Notification preference records supporting webhook, SMS, mobile push,
// and in-app delivery channels with contact details per medium.

#[derive(Deserialize)]
struct CreateNotifyRequest {
    account_id: String,
    medium: String,              // "webhook", "sms", "mobile_push", "to_app"
    mobile: Option<String>,      // mobile phone number
    wa: Option<String>,          // WhatsApp number/ID
    signal: Option<String>,      // Signal number/ID
    tel: Option<String>,         // landline / alternative telephone
    email: Option<String>,       // email address
    url: Option<String>,         // webhook callback URL
    app: Option<String>,         // application identifier for push
}

#[derive(Serialize)]
struct NotifyResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i32>,
}

/// Create a notification preference record (`POST /notify`).
///
/// Validates the delivery medium (`webhook`, `sms`, `mobile_push`, `to_app`),
/// basic email format, and webhook URL scheme before inserting. Returns the
/// generated row ID on success.
async fn create_notify(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateNotifyRequest>,
) -> Result<Json<NotifyResponse>, StatusCode> {
    info!("POST /notify: medium={} for account_id={}", payload.medium, payload.account_id);

    let valid_mediums = ["webhook", "sms", "mobile_push", "to_app"];
    if !valid_mediums.contains(&payload.medium.as_str()) {
        warn!("create_notify: invalid medium '{}'", payload.medium);
        return Ok(Json(NotifyResponse {
            success: false,
            message: format!(
                "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app",
                payload.medium
            ),
            id: None,
        }));
    }

    // Validate email format if provided
    if let Some(ref email) = payload.email {
        if !email.contains('@') || email.len() > 254 {
            warn!("create_notify: invalid email address for account_id={}", payload.account_id);
            return Ok(Json(NotifyResponse {
                success: false,
                message: "Invalid email address".to_string(),
                id: None,
            }));
        }
    }

    // Validate webhook URL if provided
    if let Some(ref url) = payload.url {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            warn!("create_notify: invalid webhook URL scheme for account_id={}", payload.account_id);
            return Ok(Json(NotifyResponse {
                success: false,
                message: "URL must start with http:// or https://".to_string(),
                id: None,
            }));
        }
    }

    let result = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO notify (account_id, medium, mobile, wa, signal, tel, email, url, app)
        VALUES ($1, $2::notify_medium, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(&payload.account_id)
    .bind(&payload.medium)
    .bind(&payload.mobile)
    .bind(&payload.wa)
    .bind(&payload.signal)
    .bind(&payload.tel)
    .bind(&payload.email)
    .bind(&payload.url)
    .bind(&payload.app)
    .fetch_one(&pool)
    .await;

    match result {
        Ok(id) => {
            info!("create_notify: created notify id={} for account_id={}", id, payload.account_id);
            Ok(Json(NotifyResponse {
                success: true,
                message: "Notification record created successfully".to_string(),
                id: Some(id),
            }))
        }
        Err(e) => {
            error!("create_notify: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct UpdateNotifyRequest {
    id: i32,
    medium: Option<String>,
    mobile: Option<String>,
    wa: Option<String>,
    signal: Option<String>,
    tel: Option<String>,
    email: Option<String>,
    url: Option<String>,
    app: Option<String>,
}

/// Update an existing notification record by ID (`PUT /notify`).
///
/// Accepts partial updates — only provided fields are modified. Builds a
/// dynamic SQL UPDATE with positional parameters.
async fn update_notify(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateNotifyRequest>,
) -> Result<Json<NotifyResponse>, StatusCode> {
    info!("PUT /notify: updating id={}", payload.id);

    if let Some(ref medium) = payload.medium {
        let valid_mediums = ["webhook", "sms", "mobile_push", "to_app"];
        if !valid_mediums.contains(&medium.as_str()) {
            warn!("update_notify: invalid medium '{}'", medium);
            return Ok(Json(NotifyResponse {
                success: false,
                message: format!(
                    "Invalid medium '{}'. Must be one of: webhook, sms, mobile_push, to_app",
                    medium
                ),
                id: None,
            }));
        }
    }

    // Build dynamic SET clause
    let mut set_parts = Vec::new();
    let mut param_index = 2u32; // $1 is the id in the WHERE clause

    if payload.medium.is_some() {
        set_parts.push(format!("medium = ${}::notify_medium", param_index));
        param_index += 1;
    }
    if payload.mobile.is_some() {
        set_parts.push(format!("mobile = ${}", param_index));
        param_index += 1;
    }
    if payload.wa.is_some() {
        set_parts.push(format!("wa = ${}", param_index));
        param_index += 1;
    }
    if payload.signal.is_some() {
        set_parts.push(format!("signal = ${}", param_index));
        param_index += 1;
    }
    if payload.tel.is_some() {
        set_parts.push(format!("tel = ${}", param_index));
        param_index += 1;
    }
    if payload.email.is_some() {
        set_parts.push(format!("email = ${}", param_index));
        param_index += 1;
    }
    if payload.url.is_some() {
        set_parts.push(format!("url = ${}", param_index));
        param_index += 1;
    }
    if payload.app.is_some() {
        set_parts.push(format!("app = ${}", param_index));
        param_index += 1;
    }

    if set_parts.is_empty() {
        warn!("update_notify: no fields provided to update for id={}", payload.id);
        return Ok(Json(NotifyResponse {
            success: false,
            message: "No fields provided to update".to_string(),
            id: None,
        }));
    }

    let sql = format!(
        "UPDATE notify SET {} WHERE id = $1",
        set_parts.join(", ")
    );

    let mut query = sqlx::query(&sql);
    query = query.bind(payload.id);

    if let Some(ref val) = payload.medium {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.mobile {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.wa {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.signal {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.tel {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.email {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.url {
        query = query.bind(val);
    }
    if let Some(ref val) = payload.app {
        query = query.bind(val);
    }

    let result = query.execute(&pool).await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                debug!("update_notify: no record found for id={}", payload.id);
                Ok(Json(NotifyResponse {
                    success: false,
                    message: "No notification record found with the provided id".to_string(),
                    id: None,
                }))
            } else {
                info!("update_notify: updated id={}", payload.id);
                Ok(Json(NotifyResponse {
                    success: true,
                    message: "Notification record updated successfully".to_string(),
                    id: Some(payload.id),
                }))
            }
        }
        Err(e) => {
            error!("update_notify: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Verify an MFA code (`POST /mfa/verify`).
///
/// Looks up the enrollment for the given `(account_id, mfa_type)`, checks
/// that it is enabled, and validates the code. Currently a placeholder —
/// real TOTP validation (RFC 6238) and SMS code lookup are not yet implemented.
async fn verify_mfa(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<VerifyMfaRequest>,
) -> Result<Json<MfaResponse>, StatusCode> {
    info!("POST /mfa/verify: mfa_type={} for account_id={}", payload.mfa_type, payload.account_id);

    let enrollment = sqlx::query_as::<_, MfaEnrollment>(
        "SELECT account_id, mfa_type, secret, phone_number, enabled
         FROM impala_mfa WHERE account_id = $1 AND mfa_type = $2"
    )
    .bind(&payload.account_id)
    .bind(&payload.mfa_type)
    .fetch_optional(&pool)
    .await;

    match enrollment {
        Ok(None) => {
            warn!("verify_mfa: no enrollment found for account_id={} mfa_type={}", payload.account_id, payload.mfa_type);
            Ok(Json(MfaResponse {
                success: false,
                message: "MFA not enrolled for this account/type".to_string(),
            }))
        }
        Ok(Some(record)) => {
            if !record.enabled {
                warn!("verify_mfa: MFA disabled for account_id={} mfa_type={}", payload.account_id, payload.mfa_type);
                return Ok(Json(MfaResponse {
                    success: false,
                    message: "MFA is disabled for this enrollment".to_string(),
                }));
            }

            // Verification logic depends on mfa_type.
            // For TOTP: compare the provided code against the shared secret (requires a TOTP library).
            // For SMS: compare against a code previously sent and stored in Redis/DB.
            // This is a placeholder that validates the code is non-empty.
            if payload.code.is_empty() {
                warn!("verify_mfa: empty code submitted for account_id={}", payload.account_id);
                return Ok(Json(MfaResponse {
                    success: false,
                    message: "Code must not be empty".to_string(),
                }));
            }

            // TODO: implement actual TOTP validation / SMS code lookup
            info!("verify_mfa: MFA verified for account_id={} mfa_type={}", payload.account_id, payload.mfa_type);
            Ok(Json(MfaResponse {
                success: true,
                message: "MFA verification successful".to_string(),
            }))
        }
        Err(e) => {
            error!("verify_mfa: database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

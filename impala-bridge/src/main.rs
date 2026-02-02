use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    routing::{get, post, put},
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
    if config.debug_mode {
        println!("Config: {:?}", config);
    }
    // Handle wrapped secrets during initialization
    // If DATABASE_URL_WRAPPED is set, unwrap it; otherwise use DATABASE_URL directly
    let database_url = if let Ok(wrapped_token) = env::var("DATABASE_URL_WRAPPED") {
        println!("Unwrapping DATABASE_URL from Vault...");
        match box_unwrap(&wrapped_token).await {
            Ok(secret_data) => {
                // Extract the database URL from the unwrapped secret
                secret_data["database_url"]
                    .as_str()
                    .expect("database_url field not found in unwrapped secret")
                    .to_string()
            }
            Err(e) => {
                eprintln!("Failed to unwrap DATABASE_URL: {}", e);
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

    // connect to Redis
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    let redis_client = Arc::new(redis_client);

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
        .route("/mfa", post(enroll_mfa).get(get_mfa))
        .route("/mfa/verify", post(verify_mfa))
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
    axum::Server::bind(&config.service_address.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

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
                                        eprintln!("cron_sync update error for id {}: {}", id, e);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("cron_sync JSON parse error for id {} ({}): {}", id, callback_uri, e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("cron_sync request error for id {} ({}): {}", id, callback_uri, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("cron_sync query error: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

// simple handler that responds with a hello message
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

async fn create_account(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, StatusCode> {
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
        Ok(_) => Ok(Json(CreateAccountResponse {
            success: true,
            message: "Account created successfully".to_string(),
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
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

async fn get_account(
    Extension(pool): Extension<PgPool>,
    Query(params): Query<GetAccountQuery>,
) -> Result<Json<GetAccountResponse>, StatusCode> {
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
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            eprintln!("Database error: {}", e);
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

async fn update_account(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateAccountRequest>,
) -> Result<Json<UpdateAccountResponse>, StatusCode> {
    // Determine which identifier to use for the WHERE clause
    let (where_clause, where_value) = if let Some(ref stellar_id) = payload.stellar_account_id {
        ("stellar_account_id = $1", stellar_id.clone())
    } else if let Some(ref payala_id) = payload.payala_account_id {
        ("payala_account_id = $1", payala_id.clone())
    } else {
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
                Ok(Json(UpdateAccountResponse {
                    success: false,
                    message: "No account found with the provided identifier".to_string(),
                    rows_affected: 0,
                }))
            } else {
                Ok(Json(UpdateAccountResponse {
                    success: true,
                    message: "Account updated successfully".to_string(),
                    rows_affected,
                }))
            }
        }
        Err(e) => {
            eprintln!("Database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn authenticate(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, StatusCode> {
    // Validate password strength (minimum 8 characters)
    if payload.password.len() < 8 {
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
            return Ok(Json(AuthenticateResponse {
                success: false,
                message: "Account not found".to_string(),
                action: "".to_string(),
            }));
        }
        Err(e) => {
            eprintln!("Database error: {}", e);
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
                Ok(_) => Ok(Json(AuthenticateResponse {
                    success: true,
                    message: "Registration successful".to_string(),
                    action: "registered".to_string(),
                })),
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Ok(Some((stored_hash,))) => {
            // Credentials exist - verify password
            match verify_password(&payload.password, &stored_hash) {
                Ok(_) => Ok(Json(AuthenticateResponse {
                    success: true,
                    message: "Authentication successful".to_string(),
                    action: "authenticated".to_string(),
                })),
                Err(_) => Ok(Json(AuthenticateResponse {
                    success: false,
                    message: "Invalid password".to_string(),
                    action: "authenticated".to_string(),
                })),
            }
        }
        Err(e) => {
            eprintln!("Database error: {}", e);
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

async fn sync_account(
    Extension(pool): Extension<PgPool>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Extension(stellar_rpc_url): Extension<Arc<String>>,
    Json(payload): Json<SyncRequest>,
) -> Result<Json<SyncResponse>, StatusCode> {
    let mut conn = redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            eprintln!("Redis connection error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();

    conn.set::<_, _, ()>(&payload.account_id, &timestamp)
        .await
        .map_err(|e| {
            eprintln!("Redis set error: {}", e);
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
                                    println!("Updating tx {}", tx_id);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Stellar RPC getTransactions error: {}", e);
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

async fn token(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_secret): Extension<Arc<String>>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let key = jwt_secret.as_bytes();

    // Flow 1: refresh_token provided -> return a short-lived temporal_token
    if let Some(ref refresh_token) = payload.refresh_token {
        let token_data = decode::<Claims>(
            refresh_token,
            &DecodingKey::from_secret(key),
            &Validation::default(),
        )
        .map_err(|e| {
            eprintln!("Invalid refresh token: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

        if token_data.claims.token_type != "refresh" {
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
            eprintln!("Failed to encode temporal token: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

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
        eprintln!("Database error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let stored_hash = match stored_hash {
        Some((hash,)) => hash,
        None => {
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }
    };

    if verify_password(password, &stored_hash).is_err() {
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
        eprintln!("Failed to encode refresh token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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

async fn subscribe(
    Extension(horizon_url): Extension<Arc<String>>,
    Extension(redis_client): Extension<Arc<redis::Client>>,
    Json(payload): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, StatusCode> {
    match payload.network.as_str() {
        "stellar" => {
            let url = format!(
                "{}/ledgers?cursor=now&order=asc",
                horizon_url.trim_end_matches('/')
            );
            let redis = redis_client.clone();

            tokio::spawn(async move {
                if let Err(e) = stellar_stream(&url, &redis).await {
                    eprintln!("Stellar stream error: {}", e);
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
                    return Ok(Json(SubscribeResponse {
                        success: false,
                        message: "listen_endpoint is required for the payala network".to_string(),
                    }));
                }
            };

            let redis = redis_client.clone();

            tokio::spawn(async move {
                if let Err(e) = payala_stream(&listen_endpoint, &redis).await {
                    eprintln!("Payala stream error: {}", e);
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
        _ => Ok(Json(SubscribeResponse {
            success: false,
            message: format!("Unsupported network: {}", payload.network),
        })),
    }
}

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
        return Err(format!("Horizon returned HTTP {}", response.status()).into());
    }

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut event_data = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

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

                    println!("Stellar ledger event: sequence={}", sequence);

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

async fn payala_stream(
    listen_endpoint: &str,
    redis_client: &redis::Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = listen_endpoint.parse().map_err(|e| {
        format!("Invalid listen_endpoint '{}': {}", listen_endpoint, e)
    })?;

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        format!("Failed to bind to {}: {}", addr, e)
    })?;

    println!("Payala listener started on {}", addr);

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
            println!("Payala connection from {}", peer_addr);

            let mut buf = vec![0u8; 65536];
            loop {
                let n = match tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Payala read error from {}: {}", peer_addr, e);
                        break;
                    }
                };

                let raw = String::from_utf8_lossy(&buf[..n]).to_string();

                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let event_type = parsed["type"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();

                    println!("Payala event from {}: type={}", peer_addr, event_type);

                    if let Ok(mut conn) = redis.get_async_connection().await {
                        let timestamp =
                            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
                        let event_key = format!("payala:event:{}", timestamp);
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
                    eprintln!("Payala non-JSON data from {}: {} bytes", peer_addr, n);
                }
            }
        });
    }
}

// ── Transaction ────────────────────────────────────────────────────────

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

async fn create_transaction(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateTransactionRequest>,
) -> Result<Json<CreateTransactionResponse>, StatusCode> {
    if payload.stellar_tx_id.is_none() && payload.payala_tx_id.is_none() {
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
        Ok(btxid) => Ok(Json(CreateTransactionResponse {
            success: true,
            message: "Transaction created successfully".to_string(),
            btxid: Some(btxid),
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ── MFA ────────────────────────────────────────────────────────────────

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

/// POST /mfa – enroll or update an MFA method for an account
async fn enroll_mfa(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<EnrollMfaRequest>,
) -> Result<Json<MfaResponse>, StatusCode> {
    if payload.mfa_type != "totp" && payload.mfa_type != "sms" {
        return Ok(Json(MfaResponse {
            success: false,
            message: "mfa_type must be 'totp' or 'sms'".to_string(),
        }));
    }

    if payload.mfa_type == "totp" && payload.secret.is_none() {
        return Ok(Json(MfaResponse {
            success: false,
            message: "secret is required for TOTP enrollment".to_string(),
        }));
    }

    if payload.mfa_type == "sms" && payload.phone_number.is_none() {
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
        Ok(_) => Ok(Json(MfaResponse {
            success: true,
            message: "MFA enrolled successfully".to_string(),
        })),
        Err(e) => {
            eprintln!("MFA enrollment error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /mfa?account_id=… – list MFA enrollments for an account
async fn get_mfa(
    Extension(pool): Extension<PgPool>,
    Query(params): Query<MfaQuery>,
) -> Result<Json<Vec<MfaEnrollment>>, StatusCode> {
    let rows = sqlx::query_as::<_, MfaEnrollment>(
        "SELECT account_id, mfa_type, secret, phone_number, enabled
         FROM impala_mfa WHERE account_id = $1"
    )
    .bind(&params.account_id)
    .fetch_all(&pool)
    .await;

    match rows {
        Ok(enrollments) => Ok(Json(enrollments)),
        Err(e) => {
            eprintln!("MFA lookup error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /mfa/verify – verify an MFA code (TOTP or SMS)
async fn verify_mfa(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<VerifyMfaRequest>,
) -> Result<Json<MfaResponse>, StatusCode> {
    let enrollment = sqlx::query_as::<_, MfaEnrollment>(
        "SELECT account_id, mfa_type, secret, phone_number, enabled
         FROM impala_mfa WHERE account_id = $1 AND mfa_type = $2"
    )
    .bind(&payload.account_id)
    .bind(&payload.mfa_type)
    .fetch_optional(&pool)
    .await;

    match enrollment {
        Ok(None) => Ok(Json(MfaResponse {
            success: false,
            message: "MFA not enrolled for this account/type".to_string(),
        })),
        Ok(Some(record)) => {
            if !record.enabled {
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
                return Ok(Json(MfaResponse {
                    success: false,
                    message: "Code must not be empty".to_string(),
                }));
            }

            // TODO: implement actual TOTP validation / SMS code lookup
            Ok(Json(MfaResponse {
                success: true,
                message: "MFA verification successful".to_string(),
            }))
        }
        Err(e) => {
            eprintln!("MFA verify error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

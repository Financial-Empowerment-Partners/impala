//! SEP-10 web authentication with card-held Stellar keys: the public
//! sub-router (`docs/sep10-card-keys.md` §6, `docs/sep10-authentication.md`
//! §4.1-4.4, §7, §9).
//!
//! - `GET /.well-known/stellar.toml` — `NETWORK_PASSPHRASE`, `SIGNING_KEY`
//!   (the ring's active key, so it can never drift), `WEB_AUTH_ENDPOINT`.
//! - `GET /auth/sep10?account=G…` — a server-signed challenge. Stateless:
//!   no per-request Redis write, no per-G budget, no DB read.
//! - `POST /auth/sep10` — a challenge signed by a registered card's Stellar
//!   key yields exactly the session `POST /auth/card` mints for that card's
//!   account.
//!
//! The router is mounted only with `SEP10_ENABLED=true` and merged in
//! `main.rs` after the global timeout, so its own body limit, timeout and
//! wildcard CORS (never with credentials) wrap every response it produces,
//! errors included. Its handlers take no auth extractor and read no cookie or
//! `Authorization` header: a browser gains nothing curl does not have.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, FromRequest, Query, Request};
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use log::{info, warn};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::client_source::ClientSource;
use crate::config::Sep10Policy;
use crate::constants::{
    PREAUTH_SOURCE_MAX_REQUESTS, PREAUTH_SOURCE_WINDOW_SECS, RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECS, SEP10_BODY_LIMIT_BYTES, SEP10_CHALLENGE_GLOBAL_SCOPE,
    SEP10_CHALLENGE_GLOBAL_WINDOW_SECS, SEP10_CLAIM_MARGIN_SECS, SEP10_RATE_LIMIT_SCOPE,
    SEP10_TIMEOUT_SECS, SEP10_TOML_MAX_AGE_SECS, SEP10_TRANSACTION_MAX_CHARS,
};
use crate::error::AppError;
use crate::jwt::JwtKeys;
use crate::models::{Sep10ChallengeResponse, Sep10TokenRequest, Sep10TokenResponse, TokenResponse};
use crate::sep10::backend::Sep10Backend;
use crate::sep10::challenge::{build_login_challenge, ChallengeParams};
use crate::sep10::key::{unix_now, RingSnapshot, Sep10Ring};
use crate::sep10::source_bucket;
use crate::sep10::verify::{self, Expectation, Reject, RingAt};
use crate::telemetry::{token_exchange_outcome, AppMetrics};

/// The three public routes, with their own limits and wildcard CORS.
pub fn public_router() -> Router {
    Router::new()
        .route("/.well-known/stellar.toml", get(stellar_toml))
        .route("/auth/sep10", get(sep10_challenge).post(sep10_token))
        .layer(RequestBodyLimitLayer::new(SEP10_BODY_LIMIT_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(SEP10_TIMEOUT_SECS),
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
        )
}

fn unavailable() -> AppError {
    AppError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "sep10_unavailable",
        "SEP-10 sign-in is temporarily unavailable",
    )
}

/// The stellar.toml body: strict `KEY = "value"` lines (contract §5).
pub(crate) fn render_toml(policy: &Sep10Policy, signing_key: &str) -> String {
    format!(
        "NETWORK_PASSPHRASE = \"{}\"\nSIGNING_KEY = \"{}\"\nWEB_AUTH_ENDPOINT = \"{}\"\n",
        policy.network_passphrase, signing_key, policy.web_auth_endpoint
    )
}

/// `GET /.well-known/stellar.toml`. 503 while no key is serving.
pub async fn stellar_toml(
    Extension(ring): Extension<Arc<Sep10Ring>>,
    Extension(policy): Extension<Arc<Sep10Policy>>,
) -> Result<Response, AppError> {
    let (_, key) = ring.snapshot().signer(unix_now()).ok_or_else(unavailable)?;
    let signing_key = crate::validate::encode_stellar_account_id(&key.public());
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                format!("max-age={SEP10_TOML_MAX_AGE_SECS}"),
            ),
        ],
        render_toml(&policy, &signing_key),
    )
        .into_response())
}

#[derive(Deserialize)]
struct ChallengeQuery {
    account: Option<String>,
    home_domain: Option<String>,
    memo: Option<String>,
    // Accepted and ignored, as the SEP-10 parameter table allows.
    #[serde(rename = "client_domain")]
    _client_domain: Option<String>,
}

/// Validate the GET parameters; the client's raw key on success.
fn challenge_client(
    uri: &Uri,
    policy: &Sep10Policy,
    snapshot: &RingSnapshot,
) -> Result<[u8; 32], AppError> {
    let q = Query::<ChallengeQuery>::try_from_uri(uri)
        .map_err(|_| AppError::BadRequest("invalid query string".to_string()))?
        .0;
    let unsupported =
        || AppError::BadRequest("muxed accounts and memos are not supported".to_string());
    if q.memo.is_some() {
        return Err(unsupported());
    }
    let account = q
        .account
        .filter(|a| !a.is_empty())
        .ok_or_else(|| AppError::BadRequest("account is required".to_string()))?;
    if account.starts_with('M') {
        return Err(unsupported());
    }
    let client = crate::validate::decode_stellar_account_id(&account)?;
    if let Some(home) = q.home_domain.filter(|h| !h.is_empty()) {
        if home != policy.home_domain {
            return Err(AppError::BadRequest(format!(
                "home_domain must be {}",
                policy.home_domain
            )));
        }
    }
    if snapshot.is_ring_key(&client) {
        return Err(AppError::BadRequest(
            "account must not be the server signing key".to_string(),
        ));
    }
    Ok(client)
}

/// `GET /auth/sep10` — issue a login challenge. Order: per-source budget,
/// the one shared global ceiling (503 when exhausted), parameters, build.
pub async fn sep10_challenge(
    Extension(backend): Extension<Arc<dyn Sep10Backend>>,
    Extension(ring): Extension<Arc<Sep10Ring>>,
    Extension(policy): Extension<Arc<Sep10Policy>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    ClientSource(source): ClientSource,
    uri: Uri,
) -> Result<Response, AppError> {
    let now = unix_now();
    let snapshot = ring.snapshot();
    let (version, key) = snapshot.signer(now).ok_or_else(unavailable)?;

    backend
        .rate_limit(
            "preauth_src",
            &source_bucket(&source),
            PREAUTH_SOURCE_MAX_REQUESTS,
            PREAUTH_SOURCE_WINDOW_SECS,
        )
        .await?;
    match backend
        .rate_limit(
            SEP10_CHALLENGE_GLOBAL_SCOPE,
            "all",
            policy.challenge_global_max,
            SEP10_CHALLENGE_GLOBAL_WINDOW_SECS,
        )
        .await
    {
        Ok(()) => {}
        Err(AppError::RateLimited { .. }) => {
            warn!("sep10: global challenge ceiling reached; answering 503");
            return Err(unavailable());
        }
        Err(e) => return Err(e),
    }

    let client = challenge_client(&uri, &policy, &snapshot)?;
    let transaction = build_login_challenge(
        &key,
        version,
        &ChallengeParams {
            client,
            home_domain: &policy.home_domain,
            web_auth_domain: &policy.home_domain,
            network_id: policy.network_id,
            min_time: now.max(0) as u64,
            ttl_secs: policy.challenge_ttl_secs,
        },
    )?;
    metrics.record_sep10_challenge("login");
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(Sep10ChallengeResponse {
            transaction,
            network_passphrase: policy.network_passphrase.clone(),
        }),
    )
        .into_response())
}

/// The `POST /auth/sep10` body: `application/json` or
/// `application/x-www-form-urlencoded` with one `transaction` field. In form
/// bodies a decoded space is mapped back to `+` (unescaped base64).
pub struct Sep10PostBody {
    pub transaction: String,
    /// MFA extras, JSON bodies only (a form body leaves them `None`): a card
    /// PIN proof and/or a phone device-key assertion over the challenge hash
    /// (`docs/mfa-card-pin-biometrics.md` §5.1).
    pub pin_proof: Option<String>,
    pub device_key_id: Option<String>,
    pub device_signature: Option<String>,
}

fn body_error(message: &str) -> Response {
    AppError::BadRequest(message.to_string()).into_response()
}

/// The single `transaction` field of a form body.
pub(crate) fn form_transaction(body: &[u8]) -> Option<String> {
    let mut found = None;
    for (k, v) in url::form_urlencoded::parse(body) {
        if k == "transaction" {
            if found.is_some() {
                return None;
            }
            found = Some(v.replace(' ', "+"));
        }
    }
    found
}

impl<S> FromRequest<S> for Sep10PostBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let form =
            match content_type.as_str() {
                "application/json" => false,
                "application/x-www-form-urlencoded" => true,
                _ => return Err(body_error(
                    "Content-Type must be application/json or application/x-www-form-urlencoded",
                )),
            };
        // A body over the sub-router's limit surfaces here as 413.
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let (transaction, pin_proof, device_key_id, device_signature) = if form {
            // Extras are JSON-only: a form sign-in is a bare card tap.
            let tx = form_transaction(&bytes)
                .ok_or_else(|| body_error("the form body needs exactly one transaction field"))?;
            (tx, None, None, None)
        } else {
            let req = serde_json::from_slice::<Sep10TokenRequest>(&bytes)
                .map_err(|_| body_error("the JSON body needs a transaction string"))?;
            (
                req.transaction,
                req.pin_proof,
                req.device_key_id,
                req.device_signature,
            )
        };
        if transaction.is_empty() || transaction.len() > SEP10_TRANSACTION_MAX_CHARS {
            return Err(body_error("transaction must be 1-8192 base64 characters"));
        }
        Ok(Sep10PostBody {
            transaction,
            pin_proof,
            device_key_id,
            device_signature,
        })
    }
}

/// `POST /auth/sep10` — exchange a signed challenge for bridge tokens.
pub async fn sep10_token(
    Extension(backend): Extension<Arc<dyn Sep10Backend>>,
    Extension(ring): Extension<Arc<Sep10Ring>>,
    Extension(policy): Extension<Arc<Sep10Policy>>,
    Extension(jwt_keys): Extension<Arc<JwtKeys>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    ClientSource(source): ClientSource,
    body: Sep10PostBody,
) -> Result<Json<Sep10TokenResponse>, AppError> {
    let result = sep10_token_inner(
        backend.as_ref(),
        &ring,
        &policy,
        &jwt_keys,
        &metrics,
        &source,
        &body,
        unix_now(),
    )
    .await;
    metrics.record_token_exchange("sep10", token_exchange_outcome(&result));
    result
}

fn reject(metrics: &AppMetrics, reason: Reject) -> AppError {
    metrics.record_sep10_rejection(reason.label());
    AppError::Unauthorized
}

/// The order is the card order (F1) with the per-identity scope moved behind
/// the master signature, because a G-address, unlike a card id, is public:
///
/// 1. `preauth_src` per source bucket
/// 2. decode — the only 400
/// 3. issued-challenge check — 401, not counted
/// 4. `check_lockout("sep10:{G}")`
/// 5. master signature — the ONLY counted failure
/// 6. `sep10` per-G budget
/// 7. the active card with this Stellar address — unknown: 401, not counted
/// 8. the role the session would carry — privileged: 401, not counted, and
///    the challenge is not claimed (the card signs in at `POST /auth/card`)
/// 9. single-use claim on the tx hash — a lost claim is a replay: 401
/// 10. `clear_lockout`, then the session `POST /auth/card` mints
///
/// Before all of it, a ring that is not live answers 503. Redis and DB errors
/// propagate as 500 (fail closed), never as 401.
#[allow(clippy::too_many_arguments)]
async fn sep10_token_inner(
    backend: &dyn Sep10Backend,
    ring: &Sep10Ring,
    policy: &Sep10Policy,
    jwt_keys: &JwtKeys,
    metrics: &AppMetrics,
    source: &str,
    body: &Sep10PostBody,
    now: i64,
) -> Result<Json<Sep10TokenResponse>, AppError> {
    let transaction = body.transaction.as_str();
    let snapshot = ring.snapshot();
    if !snapshot.is_live(now) {
        return Err(unavailable());
    }
    let bucket = source_bucket(source);

    backend
        .rate_limit(
            "preauth_src",
            &bucket,
            PREAUTH_SOURCE_MAX_REQUESTS,
            PREAUTH_SOURCE_WINDOW_SECS,
        )
        .await?;

    let decoded = verify::decode(transaction, &policy.network_id).map_err(|r| {
        metrics.record_sep10_rejection(r.label());
        AppError::BadRequest("transaction is not a strict v1 transaction envelope".to_string())
    })?;

    let issued = verify::check_issued(
        &decoded,
        &RingAt {
            snapshot: &snapshot,
            now,
        },
        &Expectation {
            home_domain: &policy.home_domain,
            web_auth_domain: &policy.home_domain,
            network_id: policy.network_id,
            ttl_secs: policy.challenge_ttl_secs,
            now,
        },
    )
    .map_err(|r| {
        info!(
            "sep10: refused, not a live issued challenge ({})",
            r.label()
        );
        reject(metrics, r)
    })?;

    let address = crate::validate::encode_stellar_account_id(&issued.client);
    let lockout_id = format!("sep10:{address}");
    backend.check_lockout(&lockout_id, &bucket).await?;

    match verify::verify_master(&decoded, &issued) {
        Ok(()) => {}
        Err(Reject::BadMasterSignature) => {
            // A real guess over a live issued challenge: the only counted
            // failure, decided before any lookup, so registered and
            // unregistered addresses answer identically.
            warn!("sep10: master signature failed for {}", address);
            backend.increment_lockout(&lockout_id, &bucket).await;
            return Err(reject(metrics, Reject::BadMasterSignature));
        }
        Err(other) => {
            warn!("sep10: refused for {} ({})", address, other.label());
            return Err(reject(metrics, other));
        }
    }

    backend
        .rate_limit(
            SEP10_RATE_LIMIT_SCOPE,
            &address,
            RATE_LIMIT_MAX_REQUESTS,
            RATE_LIMIT_WINDOW_SECS,
        )
        .await?;

    let Some(account_id) = backend.card_account(&address).await? else {
        // Unknown or deleted card: the key holder signed, but nothing is
        // registered to it. Generic 401, not counted.
        warn!("sep10: no active card is registered for {}", address);
        metrics.record_sep10_rejection("ineligible");
        return Err(AppError::Unauthorized);
    };

    // The role this session would carry: the one POST /auth/card stamps (DB
    // role, ADMIN_ACCOUNT_IDS override). A privileged account is never
    // served here: this route is public, wildcard-CORS and single-factor (a
    // tap, no PIN), so it must not hand out reserve, key or oversight
    // authority (sep10-authentication.md D2 refused the same accounts). The
    // card keeps signing in with the legacy challenge, which is the client's
    // documented fallback for this 401. Generic, decided only after the key
    // holder proved possession, not counted, and the challenge is not burned.
    let role = backend.issuance_role(&account_id).await;
    if crate::auth::role_is_privileged(&role) {
        warn!(
            "sep10: account_id={} holds a privileged role; SEP-10 sign-in refused",
            account_id
        );
        metrics.record_sep10_rejection("privileged");
        return Err(AppError::Unauthorized);
    }

    let claim_ttl = (issued.max_time as i64 - now + SEP10_CLAIM_MARGIN_SECS).max(1) as u64;
    if !backend
        .claim_challenge(&hex::encode(issued.hash), claim_ttl)
        .await?
    {
        warn!("sep10: challenge for {} was already used (replay)", address);
        metrics.record_sep10_rejection("replay");
        return Err(AppError::Unauthorized);
    }

    backend.clear_lockout(&lockout_id, &bucket).await;

    // Card possession is proven; add any PIN proof / device-key assertion the
    // client sent over the challenge hash (a present-but-bad extra is a hard
    // 401, never ignored). SEP-10 verifies only non-privileged accounts, so a
    // PIN proof here yields `sc` + `pin`.
    let mut methods = vec![crate::constants::AMR_CARD.to_string()];
    methods.extend(
        backend
            .card_extras(
                &address,
                &account_id,
                &issued.hash,
                body.pin_proof.as_deref(),
                body.device_key_id.as_deref(),
                body.device_signature.as_deref(),
            )
            .await?,
    );
    let assurance =
        crate::jwt::SessionAssurance::now(methods, backend.account_mfa_required(&account_id).await);

    // Otherwise exactly the session POST /auth/card mints for this account.
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(jwt_keys, &account_id, &role, &assurance)?;
    info!(
        "sep10: card key {} signed in; tokens issued for account_id={} (key v{})",
        address, account_id, issued.version
    );
    Ok(Json(Sep10TokenResponse {
        token: temporal_token.clone(),
        house: TokenResponse {
            success: true,
            message: "SEP-10 authentication successful".to_string(),
            refresh_token: Some(refresh_token),
            temporal_token: Some(temporal_token),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sep10::signature_hint;
    use crate::sep10::verify::tests::{encode, envelope_parts};
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use axum::body::Body;
    use base64::Engine;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use stellar_base::xdr::{DecoratedSignature, Signature, SignatureHint, TransactionEnvelope};
    use tower::ServiceExt;

    const SRC: &str = include_str!("sep10_auth.rs");
    const MAIN: &str = include_str!("../main.rs");

    fn non_test(src: &str) -> &str {
        src.find("#[cfg(test)]").map_or(src, |i| &src[..i])
    }

    // ── Fake backend: records every stateful call in order ────────────

    #[derive(Default)]
    struct Fake {
        log: Mutex<Vec<String>>,
        lockouts: Mutex<HashMap<String, u64>>,
        claims: Mutex<std::collections::HashSet<String>>,
        cards: Mutex<HashMap<String, String>>,
        redis_down: Mutex<bool>,
        db_down: Mutex<bool>,
        global_exhausted: Mutex<bool>,
        /// The role `issuance_role` answers; view-only when unset.
        role: Mutex<Option<&'static str>>,
    }

    impl Fake {
        fn log(&self, s: impl Into<String>) {
            self.log.lock().unwrap().push(s.into());
        }
        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.log.lock().unwrap())
        }
        fn down(&self) -> Result<(), AppError> {
            if *self.redis_down.lock().unwrap() {
                Err(AppError::InternalError(
                    "Service temporarily unavailable".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait::async_trait]
    impl Sep10Backend for Fake {
        async fn rate_limit(
            &self,
            scope: &str,
            _id: &str,
            _m: u64,
            _w: usize,
        ) -> Result<(), AppError> {
            self.log(format!("rate:{scope}"));
            self.down()?;
            if scope == SEP10_CHALLENGE_GLOBAL_SCOPE && *self.global_exhausted.lock().unwrap() {
                return Err(AppError::RateLimited { retry_after: 60 });
            }
            Ok(())
        }
        async fn check_lockout(&self, id: &str, source: &str) -> Result<(), AppError> {
            self.log("lockout:check");
            self.down()?;
            let n = *self
                .lockouts
                .lock()
                .unwrap()
                .get(&format!("{id}|{source}"))
                .unwrap_or(&0);
            if n >= crate::constants::LOCKOUT_THRESHOLD {
                return Err(AppError::RateLimited { retry_after: 900 });
            }
            Ok(())
        }
        async fn increment_lockout(&self, id: &str, source: &str) {
            self.log("lockout:incr");
            *self
                .lockouts
                .lock()
                .unwrap()
                .entry(format!("{id}|{source}"))
                .or_default() += 1;
        }
        async fn clear_lockout(&self, id: &str, source: &str) {
            self.log("lockout:clear");
            self.lockouts
                .lock()
                .unwrap()
                .remove(&format!("{id}|{source}"));
        }
        async fn claim_challenge(&self, hash_hex: &str, ttl: u64) -> Result<bool, AppError> {
            self.log(format!("claim:{}", ttl > 0));
            self.down()?;
            Ok(self.claims.lock().unwrap().insert(hash_hex.to_string()))
        }
        async fn card_account(&self, address: &str) -> Result<Option<String>, AppError> {
            self.log("card");
            if *self.db_down.lock().unwrap() {
                return Err(AppError::InternalError("Database error".into()));
            }
            Ok(self.cards.lock().unwrap().get(address).cloned())
        }
        async fn issuance_role(&self, _account_id: &str) -> String {
            self.log("role");
            self.role
                .lock()
                .unwrap()
                .unwrap_or(crate::constants::ROLE_VIEW_ONLY)
                .to_string()
        }
        async fn account_mfa_required(&self, _account_id: &str) -> bool {
            false
        }
        async fn card_extras(
            &self,
            _stellar_address: &str,
            _account_id: &str,
            _hash: &[u8; 32],
            _pin_proof: Option<&str>,
            _device_key_id: Option<&str>,
            _device_signature: Option<&str>,
        ) -> Result<Vec<String>, AppError> {
            // The sign-in-order tests exercise a bare tap (no extras logged, so
            // the asserted call sequence is unchanged); the extras are verified
            // end-to-end in the mfa module's own tests.
            Ok(vec![])
        }
    }

    const HOME: &str = "127.0.0.1:8080";
    const ACCOUNT: &str = "00112233-4455-6677-8899-aabbccddeeff";

    fn policy() -> Sep10Policy {
        Sep10Policy {
            web_auth_endpoint: format!("http://{HOME}/auth/sep10"),
            home_domain: HOME.to_string(),
            network_passphrase: crate::constants::STELLAR_TESTNET_PASSPHRASE.to_string(),
            network_id: crate::sep10::network_id(crate::constants::STELLAR_TESTNET_PASSPHRASE),
            challenge_ttl_secs: 300,
            challenge_global_max: 600,
            activation_delay_secs: 120,
        }
    }

    struct Harness {
        app: Router,
        fake: Arc<Fake>,
        client: Ed25519KeyPair,
        address: String,
        server: [u8; 32],
        jwt: Arc<JwtKeys>,
    }

    async fn harness() -> Harness {
        let (ring, server) = crate::sep10::key::tests::ring_with_active_key(300).await;
        let fake = Arc::new(Fake::default());
        let client = Ed25519KeyPair::generate().unwrap();
        let address = crate::validate::encode_stellar_account_id(
            &client.public_key().as_ref().try_into().unwrap(),
        );
        fake.cards
            .lock()
            .unwrap()
            .insert(address.clone(), ACCOUNT.to_string());
        let jwt = Arc::new(JwtKeys::new("x".repeat(40), None).unwrap());
        let backend: Arc<dyn Sep10Backend> = fake.clone();
        let app = public_router()
            .layer(Extension(backend))
            .layer(Extension(ring))
            .layer(Extension(Arc::new(policy())))
            .layer(Extension(jwt.clone()))
            .layer(Extension(crate::telemetry::create_metrics()))
            .layer(Extension(Arc::new(crate::auth::AuthPolicy {
                allow_open_registration: false,
                trusted_proxy_hops: 0,
            })));
        Harness {
            app,
            fake,
            client,
            address,
            server,
            jwt,
        }
    }

    async fn send(
        app: &Router,
        req: Request,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value, String) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, headers, json, text)
    }

    fn get_req(uri: &str) -> Request {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    fn post_json(tx: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri("/auth/sep10")
            .header("content-type", "application/json")
            .header("origin", "https://wallet.example")
            .body(Body::from(
                serde_json::json!({ "transaction": tx }).to_string(),
            ))
            .unwrap()
    }

    impl Harness {
        async fn challenge(&self) -> String {
            let (status, headers, json, _) = send(
                &self.app,
                get_req(&format!("/auth/sep10?account={}", self.address)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
            assert_eq!(
                json["network_passphrase"],
                crate::constants::STELLAR_TESTNET_PASSPHRASE
            );
            json["transaction"].as_str().unwrap().to_string()
        }

        fn sign(&self, challenge: &str, key: &Ed25519KeyPair) -> String {
            let d = verify::decode(challenge, &policy().network_id).unwrap();
            let public: [u8; 32] = self.client.public_key().as_ref().try_into().unwrap();
            let mut v1 = envelope_parts(challenge);
            let mut sigs = v1.signatures.to_vec();
            sigs.push(DecoratedSignature {
                hint: SignatureHint(signature_hint(&public)),
                signature: Signature(key.sign(&d.hash).as_ref().to_vec().try_into().unwrap()),
            });
            v1.signatures = sigs.try_into().unwrap();
            encode(TransactionEnvelope::Tx(v1))
        }

        async fn signed(&self) -> String {
            let c = self.challenge().await;
            self.fake.calls();
            self.sign(&c, &self.client)
        }
    }

    // ── The happy path, end to end ────────────────────────────────────

    #[tokio::test]
    async fn a_card_key_signs_in_with_exactly_the_card_session() {
        let h = harness().await;
        let tx = h.signed().await;
        let (status, headers, json, _) = send(&h.app, post_json(&tx)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert!(headers.get("access-control-allow-credentials").is_none());
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "SEP-10 authentication successful");
        assert_eq!(json["token"], json["temporal_token"]);
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "message",
                "refresh_token",
                "success",
                "temporal_token",
                "token"
            ]
        );
        // The tokens are the house pair for the card's account.
        let claims = crate::jwt::decode_claims(
            &h.jwt,
            json["temporal_token"].as_str().unwrap(),
            crate::constants::TOKEN_TYPE_TEMPORAL,
        )
        .unwrap();
        assert_eq!(claims.sub, ACCOUNT);
        assert!(crate::jwt::decode_claims(
            &h.jwt,
            json["refresh_token"].as_str().unwrap(),
            crate::constants::TOKEN_TYPE_REFRESH,
        )
        .is_ok());
        // The documented order, all of it.
        assert_eq!(
            h.fake.calls(),
            [
                "rate:preauth_src",
                "lockout:check",
                "rate:sep10",
                "card",
                "role",
                "claim:true",
                "lockout:clear"
            ]
        );
        // Replay: the same signed challenge again is a 401 at the claim.
        let (status, _, json, _) = send(&h.app, post_json(&tx)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"]["code"], "unauthorized");
        assert_eq!(
            h.fake.calls(),
            [
                "rate:preauth_src",
                "lockout:check",
                "rate:sep10",
                "card",
                "role",
                "claim:true"
            ]
        );
    }

    /// A card tap never yields reserve, key or oversight authority through
    /// this route: every role with a capability is refused with the generic
    /// 401, after the signature check, without a token, a counted failure or
    /// a burned challenge. The ladder roles sign in.
    #[tokio::test]
    async fn a_privileged_account_is_refused_and_nothing_is_minted_or_burned() {
        use crate::constants::{
            ROLE_ADMIN, ROLE_AUDITOR, ROLE_DEVICE, ROLE_KEY_CUSTODIAN, ROLE_TOKEN, ROLE_TREASURER,
            ROLE_VIEW_ONLY,
        };
        for role in [ROLE_ADMIN, ROLE_TREASURER, ROLE_KEY_CUSTODIAN, ROLE_AUDITOR] {
            let h = harness().await;
            *h.fake.role.lock().unwrap() = Some(role);
            let tx = h.signed().await;
            let (status, _, json, text) = send(&h.app, post_json(&tx)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{role}");
            assert_eq!(json["error"]["code"], "unauthorized", "{role}");
            assert!(!text.contains("token"), "{role}: {text}");
            assert_eq!(
                h.fake.calls(),
                [
                    "rate:preauth_src",
                    "lockout:check",
                    "rate:sep10",
                    "card",
                    "role"
                ],
                "{role}"
            );
            assert!(h.fake.lockouts.lock().unwrap().is_empty(), "{role}");
            assert!(h.fake.claims.lock().unwrap().is_empty(), "{role}: burned");
        }
        for role in [ROLE_VIEW_ONLY, ROLE_DEVICE, ROLE_TOKEN] {
            let h = harness().await;
            *h.fake.role.lock().unwrap() = Some(role);
            let tx = h.signed().await;
            let (status, _, json, _) = send(&h.app, post_json(&tx)).await;
            assert_eq!(status, StatusCode::OK, "{role}: {json}");
        }
    }

    #[tokio::test]
    async fn form_bodies_are_accepted_and_spaces_map_back_to_plus() {
        let h = harness().await;
        let tx = h.signed().await;
        // An unescaped '+' in a form body decodes to ' '.
        let body = format!("transaction={}", tx.replace('/', "%2F").replace('=', "%3D"));
        let req = Request::builder()
            .method("POST")
            .uri("/auth/sep10")
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .body(Body::from(body))
            .unwrap();
        let (status, _, json, _) = send(&h.app, req).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            form_transaction(b"transaction=ab+cd%2B"),
            Some("ab+cd+".to_string())
        );
        assert_eq!(form_transaction(b"transaction=a&transaction=b"), None);
        assert_eq!(form_transaction(b"other=a"), None);
    }

    // ── Which failures count, and when each gate runs ─────────────────

    #[tokio::test]
    async fn only_a_bad_master_signature_counts_and_it_precedes_the_per_g_budget() {
        let h = harness().await;
        let c = h.challenge().await;
        h.fake.calls();
        let stranger = Ed25519KeyPair::generate().unwrap();
        let forged = h.sign(&c, &stranger);
        let (status, _, _, _) = send(&h.app, post_json(&forged)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            h.fake.calls(),
            ["rate:preauth_src", "lockout:check", "lockout:incr"],
            "no per-G budget and no lookup before a verified signature"
        );
        // Five counted failures lock this (G, source) out: 429 before the signature check.
        for _ in 0..4 {
            send(&h.app, post_json(&forged)).await;
        }
        h.fake.calls();
        let (status, headers, _, _) = send(&h.app, post_json(&h.sign(&c, &h.client))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(headers.get(header::RETRY_AFTER).is_some());
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(h.fake.calls(), ["rate:preauth_src", "lockout:check"]);
    }

    #[tokio::test]
    async fn malformed_and_not_issued_never_count() {
        let h = harness().await;
        // Malformed: 400, before the issued check, no lockout touched.
        let (status, headers, json, _) = send(&h.app, post_json("AAAA")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "bad_request");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(h.fake.calls(), ["rate:preauth_src"]);
        // Not issued (the unsigned challenge alone): 401, not counted.
        let c = h.challenge().await;
        h.fake.calls();
        let (status, headers, _, _) = send(&h.app, post_json(&c)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(h.fake.calls(), ["rate:preauth_src"]);
        assert!(h.fake.lockouts.lock().unwrap().is_empty());
        // A challenge for another server key (not ours): 401, not counted.
        let (other, _) = crate::sep10::key::tests::test_key();
        let p = policy();
        let foreign = build_login_challenge(
            &other,
            1,
            &ChallengeParams {
                client: h.client.public_key().as_ref().try_into().unwrap(),
                home_domain: HOME,
                web_auth_domain: HOME,
                network_id: p.network_id,
                min_time: unix_now() as u64,
                ttl_secs: 300,
            },
        )
        .unwrap();
        let (status, _, _, _) = send(&h.app, post_json(&h.sign(&foreign, &h.client))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(h.fake.calls(), ["rate:preauth_src"]);
    }

    #[tokio::test]
    async fn an_unknown_or_deleted_card_is_a_generic_401_not_counted() {
        let h = harness().await;
        h.fake.cards.lock().unwrap().clear();
        let tx = h.signed().await;
        let (status, _, json, _) = send(&h.app, post_json(&tx)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"]["code"], "unauthorized");
        assert_eq!(
            h.fake.calls(),
            ["rate:preauth_src", "lockout:check", "rate:sep10", "card"]
        );
        assert!(h.fake.lockouts.lock().unwrap().is_empty());
        assert!(h.fake.claims.lock().unwrap().is_empty(), "nothing burned");
    }

    #[tokio::test]
    async fn redis_and_db_failures_are_500_never_401() {
        let h = harness().await;
        let tx = h.signed().await;
        *h.fake.redis_down.lock().unwrap() = true;
        let (status, headers, _, _) = send(&h.app, post_json(&tx)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        *h.fake.redis_down.lock().unwrap() = false;
        *h.fake.db_down.lock().unwrap() = true;
        let (status, _, _, _) = send(&h.app, post_json(&tx)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        *h.fake.db_down.lock().unwrap() = false;
        // The challenge was never burned by the failed attempts.
        let (status, _, _, _) = send(&h.app, post_json(&tx)).await;
        assert_eq!(status, StatusCode::OK);
    }

    // ── GET ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_validates_parameters_after_the_budgets_and_writes_nothing_per_address() {
        let h = harness().await;
        h.challenge().await;
        assert_eq!(
            h.fake.calls(),
            ["rate:preauth_src", "rate:sep10_challenge_global"],
            "no per-G scope, no lookup, no claim on GET"
        );
        let muxed = "MAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSAAAAAAAAAAE2LP26";
        for (uri, what) in [
            ("/auth/sep10".to_string(), "missing account"),
            (format!("/auth/sep10?account={muxed}"), "muxed"),
            (format!("/auth/sep10?account={}&memo=1", h.address), "memo"),
            (
                format!("/auth/sep10?account={}&home_domain=evil.example", h.address),
                "home_domain",
            ),
            (
                format!(
                    "/auth/sep10?account={}{}",
                    &h.address[..55],
                    if h.address.ends_with('A') { 'B' } else { 'A' }
                ),
                "checksum",
            ),
            (
                format!(
                    "/auth/sep10?account={}",
                    crate::validate::encode_stellar_account_id(&h.server)
                ),
                "server key",
            ),
        ] {
            let (status, headers, json, _) = send(&h.app, get_req(&uri)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {json}");
            assert_eq!(
                headers.get("access-control-allow-origin").unwrap(),
                "*",
                "{what}"
            );
        }
        // home_domain equal to ours and client_domain are accepted.
        let (status, _, _, _) = send(
            &h.app,
            get_req(&format!(
                "/auth/sep10?account={}&home_domain={HOME}&client_domain=x.example",
                h.address
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // The global ceiling answers 503, with ACAO.
        *h.fake.global_exhausted.lock().unwrap() = true;
        let (status, headers, json, _) = send(
            &h.app,
            get_req(&format!("/auth/sep10?account={}", h.address)),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["error"]["code"], "sep10_unavailable");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    }

    #[tokio::test]
    async fn the_issued_challenge_has_the_contract_shape() {
        let h = harness().await;
        let c = h.challenge().await;
        let v1 = envelope_parts(&c);
        assert_eq!(v1.signatures.len(), 1);
        assert_eq!(v1.tx.fee, 200);
        assert_eq!(v1.tx.seq_num.0, 0);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&c)
            .unwrap();
        assert_eq!(&bytes[..4], &[0, 0, 0, 2]);
        // It verifies (server side) for this client.
        let d = verify::decode(&c, &policy().network_id).unwrap();
        let ring_snapshot_ok = verify::check_issued(
            &d,
            &crate::sep10::verify::tests::Fixed {
                key: Arc::new(crate::sep10::key::tests::test_key().0),
                version: 1,
                others: vec![],
            },
            &verify::tests::exp(unix_now()),
        );
        assert!(
            ring_snapshot_ok.is_err(),
            "a different key never accepts it"
        );
    }

    #[tokio::test]
    async fn stellar_toml_follows_the_active_key() {
        let h = harness().await;
        let (status, headers, _, text) = send(&h.app, get_req("/.well-known/stellar.toml")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "max-age=60");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(
            text,
            format!(
                "NETWORK_PASSPHRASE = \"Test SDF Network ; September 2015\"\nSIGNING_KEY = \"{}\"\nWEB_AUTH_ENDPOINT = \"http://127.0.0.1:8080/auth/sep10\"\n",
                crate::validate::encode_stellar_account_id(&h.server)
            )
        );
    }

    #[tokio::test]
    async fn no_serving_key_is_503_with_acao_and_never_touches_redis() {
        let fake = Arc::new(Fake::default());
        let backend: Arc<dyn Sep10Backend> = fake.clone();
        let app = public_router()
            .layer(Extension(backend))
            .layer(Extension(Arc::new(Sep10Ring::new(300))))
            .layer(Extension(Arc::new(policy())))
            .layer(Extension(Arc::new(
                JwtKeys::new("x".repeat(40), None).unwrap(),
            )))
            .layer(Extension(crate::telemetry::create_metrics()))
            .layer(Extension(Arc::new(crate::auth::AuthPolicy {
                allow_open_registration: false,
                trusted_proxy_hops: 0,
            })));
        for req in [
            get_req("/.well-known/stellar.toml"),
            get_req("/auth/sep10?account=GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"),
            post_json("AAAA"),
        ] {
            let (status, headers, json, _) = send(&app, req).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(json["error"]["code"], "sep10_unavailable");
            assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        }
        assert!(fake.calls().is_empty());
    }

    // ── CORS, limits, routes ──────────────────────────────────────────

    #[tokio::test]
    async fn preflight_wrong_content_type_and_oversize_bodies_carry_acao() {
        let h = harness().await;
        let preflight = Request::builder()
            .method("OPTIONS")
            .uri("/auth/sep10")
            .header("origin", "https://wallet.example")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap();
        let (status, headers, _, _) = send(&h.app, preflight).await;
        assert!(status.is_success(), "{status}");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert!(headers.get("access-control-allow-credentials").is_none());
        let methods = headers
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.contains("GET") && methods.contains("POST") && methods.contains("OPTIONS"));

        let wrong_type = Request::builder()
            .method("POST")
            .uri("/auth/sep10")
            .header("content-type", "text/plain")
            .body(Body::from("transaction=x"))
            .unwrap();
        let (status, headers, json, _) = send(&h.app, wrong_type).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "bad_request");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");

        let huge = format!(
            "{{\"transaction\":\"{}\"}}",
            "A".repeat(SEP10_BODY_LIMIT_BYTES)
        );
        let oversize = Request::builder()
            .method("POST")
            .uri("/auth/sep10")
            .header("content-type", "application/json")
            .body(Body::from(huge))
            .unwrap();
        let (status, headers, _, _) = send(&h.app, oversize).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");

        // A transaction field over 8192 characters (inside the body limit).
        let (status, _, _, _) = send(&h.app, post_json(&"A".repeat(8200))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The exact path and method set (design §4.3).
    #[test]
    fn the_public_router_holds_exactly_three_routes() {
        let src = non_test(SRC);
        let routes: Vec<&str> = src
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with(".route("))
            .collect();
        assert_eq!(
            routes,
            [
                ".route(\"/.well-known/stellar.toml\", get(stellar_toml))",
                ".route(\"/auth/sep10\", get(sep10_challenge).post(sep10_token))"
            ]
        );
        assert_eq!(src.matches("pub async fn ").count(), 3);
    }

    /// No auth extractor, no cookie, no Authorization read (design §4.3).
    #[test]
    fn the_public_handlers_take_no_credentials() {
        let src = non_test(SRC);
        for handler in ["stellar_toml", "sep10_challenge", "sep10_token"] {
            let start = src.find(&format!("pub async fn {handler}(")).unwrap();
            let sig = &src[start..start + src[start..].find("->").unwrap()];
            for forbidden in [
                "AuthenticatedUser",
                "AnyAuthUser",
                "Privileged",
                "AdminUser",
                "AuthContext",
                "SessionUser",
                "CookieJar",
                "HeaderMap",
            ] {
                assert!(!sig.contains(forbidden), "{handler} takes {forbidden}");
            }
        }
        for forbidden in ["CookieJar", "header::COOKIE", "\"cookie\"", "session::"] {
            assert!(!src.contains(forbidden), "{forbidden}");
        }
        assert_eq!(
            src.matches("AUTHORIZATION").count(),
            1,
            "only in allow_headers"
        );
    }

    /// Order pins from design §14: `increment_lockout` appears once, in the
    /// master-signature arm; the per-G budget comes after `verify_master`;
    /// the lockout check precedes it; the claim precedes the mint.
    #[test]
    fn post_order_is_pinned() {
        let src = non_test(SRC);
        let body = &src[src.find("async fn sep10_token_inner(").unwrap()..];
        assert_eq!(src.matches("increment_lockout(").count(), 1);
        let pos = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("{needle} missing from sep10_token_inner"))
        };
        let master_arm = pos("Err(Reject::BadMasterSignature) => {");
        let incr = pos("increment_lockout(");
        assert!(incr > master_arm && incr < pos("Err(other) =>"));
        assert!(pos("\"preauth_src\"") < pos("verify::decode("));
        assert!(pos("verify::decode(") < pos("verify::check_issued("));
        assert!(pos("verify::check_issued(") < pos("check_lockout("));
        assert!(pos("check_lockout(") < pos("verify::verify_master("));
        assert!(pos("verify::verify_master(") < pos("SEP10_RATE_LIMIT_SCOPE"));
        assert!(pos("SEP10_RATE_LIMIT_SCOPE") < pos("card_account("));
        assert!(pos("card_account(") < pos("backend.issuance_role(&account_id)"));
        // The privileged refusal sits between the role and the claim: it
        // burns no challenge and can never follow a mint.
        assert!(pos("backend.issuance_role(&account_id)") < pos("role_is_privileged(&role)"));
        assert!(pos("role_is_privileged(&role)") < pos("claim_challenge("));
        assert!(pos("claim_challenge(") < pos("clear_lockout("));
        assert!(pos("clear_lockout(") < pos("encode_token_pair("));
        // The session is minted exactly the card way, with the role checked
        // above and the factors (card, plus any PIN proof / device key) carried
        // in the assurance.
        assert!(body
            .contains("crate::jwt::encode_token_pair(jwt_keys, &account_id, &role, &assurance)"));
        assert_eq!(body.matches("issuance_role(").count(), 1);
    }

    /// CORS and merge pins (design §4.3), over the whole source tree.
    #[test]
    fn wildcard_cors_is_scoped_by_construction() {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push((
                        p.display().to_string(),
                        std::fs::read_to_string(&p).unwrap(),
                    ));
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        let mut any = Vec::new();
        for (path, text) in &files {
            let code = non_test(text);
            assert!(
                !code.contains("allow_credentials"),
                "{path} enables credentialed CORS"
            );
            for _ in code.matches("allow_origin(Any)") {
                any.push(path.rsplit('/').next().unwrap().to_string());
            }
        }
        any.sort();
        assert_eq!(any, ["main.rs", "sep10_auth.rs"]);
        // main.rs: only in the testnet wildcard branch.
        let m = non_test(MAIN);
        let at = m.find("allow_origin(Any)").unwrap();
        assert!(m[..at]
            .rfind("if config.cors_allowed_origins == \"*\" {")
            .is_some());
        // The merge follows the global TimeoutLayer and precedes Compression,
        // so the global CORS / 1 MB limit / timeout never wrap the sub-router.
        let merge = m
            .find("app.merge(handlers::sep10_auth::public_router())")
            .unwrap();
        let timeout = m.find("TimeoutLayer::with_status_code(").unwrap();
        let compression = m.find(".layer(CompressionLayer::new())").unwrap();
        assert!(timeout < merge && merge < compression);
        assert_eq!(m.matches("sep10_auth::public_router()").count(), 1);
        // Mounted only when enabled.
        let guard = m[..merge].rfind("if sep10_policy.is_some() {").unwrap();
        assert!(merge - guard < 120);
    }
}

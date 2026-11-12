//! SEP-10 server signing key custody (`/admin/sep10/signing-keys*`,
//! `docs/sep10-authentication.md` §8).
//!
//! The key is **generate-only**, like the card issuer key: created inside the
//! bridge, sealed by the configured seed protector together with its
//! challenge MAC key, never imported, never exported. It moves no funds (the
//! server account is never funded and never a signer anywhere), but it is
//! the trust anchor every SEP-10 client pins through stellar.toml, so its
//! lifecycle is explicit and confirmed:
//!
//! - `generate` creates a `pending` version (refused while one is pending);
//! - `activate` schedules it at `now + SEP10_KEY_ACTIVATION_DELAY_SECS` (DB
//!   clock) under a compare-and-swap on the active key's fingerprint plus a
//!   typed phrase naming the network; every replica's ring switches at that
//!   instant and the previous key is `superseded`;
//! - `revoke` refuses a version at once on this replica, at the next poll on
//!   the others, and scrubs its sealed material.
//!
//! These routes are always mounted (the key must exist before SEP-10 is
//! enabled); using the key is not `KEY_IMPORT_ENABLED`-gated. See
//! docs/runbooks/sep10.md.

use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;

use crate::auth::{ManageKeys, Privileged, ReadAccounts, ReadKeys};
use crate::config::Sep10AdminSettings;
use crate::constants::{
    KEY_IMPORT_RATE_LIMIT_SCOPE, SEP10_KEY_POLL_SECS, SIGN_RATE_LIMIT_MAX_REQUESTS,
    SIGN_RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::events::{emit_event, AccountEvent};
use crate::keys::store::KeyRuntime;
use crate::models::{
    ActivateSep10KeyRequest, ActivateSep10KeyResponse, AdminCardListResponse, AdminCardView,
    GenerateSep10KeyResponse, RevokeSep10KeyRequest, RevokeSep10KeyResponse, Sep10KeyView,
    Sep10StatusResponse,
};
use crate::seed_protect::SeedProtector;
use crate::sep10::key::{self, Sep10Ring};

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("admin_sep10: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// The phrase that confirms an activation.
pub(crate) fn activation_phrase(network: &str) -> String {
    format!("activate sep10-signing {network}")
}

/// The phrase that confirms a revocation.
pub(crate) fn revocation_phrase(network: &str, version: i32) -> String {
    format!("revoke sep10-signing {network} v{version}")
}

/// Checks an activation request: `confirm_supersede` must be the active
/// key's fingerprint (or `none` when no key is active) and `confirm_phrase`
/// the network phrase. Compared in constant time.
pub(crate) fn check_activation(
    active_fingerprint: Option<&str>,
    request: &ActivateSep10KeyRequest,
    network: &str,
) -> Result<(), AppError> {
    let expected_supersede = active_fingerprint.unwrap_or("none");
    let phrase = activation_phrase(network);
    let fp_ok = request
        .confirm_supersede
        .as_deref()
        .is_some_and(|g| crate::keys::tokens_match(g, expected_supersede));
    let phrase_ok = request
        .confirm_phrase
        .as_deref()
        .is_some_and(|g| crate::keys::tokens_match(g, &phrase));
    if fp_ok && phrase_ok {
        return Ok(());
    }
    Err(AppError::Conflict(format!(
        "Activating a SEP-10 signing key changes the SIGNING_KEY every client pins. To proceed \
         send confirm_supersede=\"{expected_supersede}\" (the active key's fingerprint, or none) \
         and confirm_phrase=\"{phrase}\"."
    )))
}

/// Refuses an activation this replica could not serve. After the swap the
/// previous key is `superseded`, which is terminal: a new key that the
/// replicas cannot unseal (a protector permission that covers the old key
/// but not this one, say) would leave every sign-in at 503 until another key
/// is generated and activated. So when this replica runs a key ring, the
/// ring must already hold the version opened. A replica without a ring
/// (`SEP10_ENABLED=false`) cannot tell and does not refuse.
pub(crate) fn check_ring_can_serve(ring: Option<&Sep10Ring>, version: i32) -> Result<(), AppError> {
    match ring {
        Some(ring) if !ring.snapshot().has_opened(version) => Err(AppError::coded(
            StatusCode::CONFLICT,
            "sep10_key_not_opened",
            format!(
                "This replica has not opened signing key version {version} yet. Its key ring \
                 polls every {SEP10_KEY_POLL_SECS} seconds: retry shortly. If this persists the \
                 replicas cannot unseal the key (check the seed protector's permissions and the \
                 bridge log); activating it would stop SEP-10 sign-in."
            ),
        )),
        _ => Ok(()),
    }
}

fn require_phrase(given: Option<&str>, expected: &str) -> Result<(), AppError> {
    if given.is_some_and(|g| crate::keys::tokens_match(g, expected)) {
        Ok(())
    } else {
        Err(AppError::Conflict(format!(
            "Revoking a SEP-10 signing key refuses its challenges at once. To proceed send \
             confirm_phrase=\"{expected}\"."
        )))
    }
}

async fn rate_limit(redis_pool: &deadpool_redis::Pool, account_id: &str) -> Result<(), AppError> {
    crate::redis_helpers::check_rate_limit(
        redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await
}

/// 409 `pending_key_exists`: one pending version at a time.
fn pending_key_exists(version: Option<i32>) -> AppError {
    let which = version.map_or_else(|| "A version".to_string(), |v| format!("Version {v}"));
    AppError::coded(
        StatusCode::CONFLICT,
        "pending_key_exists",
        format!("{which} is already pending; activate or revoke it before generating another"),
    )
}

fn rfc3339(t: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    t.map(|t| t.to_rfc3339())
}

type AdminRow = (
    i32,
    String,
    String,
    String,
    String,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// Active cards registered with a Stellar address (the status object's
/// `registered_card_keys`).
pub(crate) const REGISTERED_CARD_KEYS_SQL: &str =
    "SELECT COUNT(*) FROM card WHERE is_delete = FALSE AND stellar_address IS NOT NULL";

/// An account's cards for the dashboard, newest first, at most 100. Exactly
/// these five public columns: never the EC key or the cross-signatures
/// (pinned by `admin_card_list_sql_is_pinned`).
pub(crate) const ADMIN_ACCOUNT_CARDS_SQL: &str = "SELECT card_id, is_delete, created_at, \
     deleted_at, stellar_address FROM card WHERE account_id = $1 \
     ORDER BY created_at DESC NULLS LAST, id DESC LIMIT 100";

/// `GET /admin/sep10/signing-keys` — the status object
/// (docs/sep10-card-keys.md §6.1): configuration, the count of registered
/// card keys, and every key version, newest first. Public data only.
pub async fn list_signing_keys(
    _user: Privileged<ReadKeys>,
    Extension(pool): Extension<PgPool>,
    Extension(settings): Extension<Arc<Sep10AdminSettings>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    ring: Option<Extension<Arc<Sep10Ring>>>,
) -> Result<Json<Sep10StatusResponse>, AppError> {
    // This instance's own view of the keys: what it could serve right now.
    let snapshot = ring.as_ref().map(|Extension(r)| r.snapshot());
    let rows: Vec<AdminRow> = sqlx::query_as(key::SSK_ADMIN_LIST_SQL)
        .fetch_all(&pool)
        .await
        .map_err(db_err("list"))?;
    let registered_card_keys: i64 = sqlx::query_scalar(REGISTERED_CARD_KEYS_SQL)
        .fetch_one(&pool)
        .await
        .map_err(db_err("card keys"))?;
    Ok(Json(Sep10StatusResponse {
        enabled: settings.enabled,
        home_domain: settings.home_domain.clone(),
        web_auth_endpoint: settings.web_auth_endpoint.clone(),
        network: stellar_config.network.as_str().to_string(),
        network_passphrase: settings.network_passphrase.clone(),
        challenge_ttl_secs: settings.challenge_ttl_secs,
        registered_card_keys,
        key_ring_live: snapshot.as_ref().map(|s| s.is_live(key::unix_now())),
        keys: rows
            .into_iter()
            .map(
                |(version, state, address, fingerprint, by, at, activate, superseded, revoked)| {
                    Sep10KeyView {
                        version,
                        opened: opened_here(snapshot.as_deref(), version, state.trim()),
                        state: state.trim().to_string(),
                        public_address: address.trim().to_string(),
                        fingerprint,
                        generated_by: by,
                        generated_at: at.to_rfc3339(),
                        activate_at: rfc3339(activate),
                        superseded_at: rfc3339(superseded),
                        revoked_at: rfc3339(revoked),
                    }
                },
            )
            .collect(),
    }))
}

/// The `opened` field of a key row: what this instance's ring holds. Nothing
/// is claimed without a ring, and a revoked version is never open.
pub(crate) fn opened_here(
    snapshot: Option<&key::RingSnapshot>,
    version: i32,
    state: &str,
) -> Option<bool> {
    if state == "revoked" {
        return None;
    }
    snapshot.map(|s| s.has_opened(version))
}

type CardRow = (
    String,
    bool,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
);

/// `GET /admin/accounts/{account_id}/cards` — an account's cards (active and
/// deleted), newest first, at most 100, with the Stellar address when the
/// card has one. Read-only.
pub async fn list_account_cards(
    _user: Privileged<ReadAccounts>,
    Extension(pool): Extension<PgPool>,
    Path(account_id): Path<String>,
) -> Result<Json<AdminCardListResponse>, AppError> {
    if account_id.is_empty() || account_id.len() > 64 {
        return Err(AppError::BadRequest(
            "account_id must be 1-64 characters".to_string(),
        ));
    }
    let rows: Vec<CardRow> = sqlx::query_as(ADMIN_ACCOUNT_CARDS_SQL)
        .bind(&account_id)
        .fetch_all(&pool)
        .await
        .map_err(db_err("account cards"))?;
    Ok(Json(AdminCardListResponse {
        cards: rows
            .into_iter()
            .map(
                |(card_id, is_delete, created_at, deleted_at, stellar_address)| AdminCardView {
                    card_id,
                    active: !is_delete,
                    created_at: rfc3339(created_at),
                    deleted_at: rfc3339(deleted_at),
                    stellar_address: stellar_address.map(|a| a.trim().to_string()),
                },
            )
            .collect(),
    }))
}

/// `POST /admin/sep10/signing-keys/generate` — a new `pending` version (201).
/// Any request body (`{}` by convention) is ignored.
#[allow(clippy::too_many_arguments)]
pub async fn generate_signing_key(
    user: Privileged<ManageKeys>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
) -> Result<(StatusCode, Json<GenerateSep10KeyResponse>), AppError> {
    crate::handlers::admin_keys::require_enabled(&runtime)?;
    rate_limit(&redis_pool, &user.account_id).await?;

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let pending: Option<i32> = sqlx::query_scalar(key::SSK_PENDING_FOR_UPDATE_SQL)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("pending"))?;
    if let Some(v) = pending {
        return Err(pending_key_exists(Some(v)));
    }
    let version: i32 = sqlx::query_scalar(key::SSK_NEXT_VERSION_SQL)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("next version"))?;

    let (seed, public) = key::generate_material()?;
    let protected = protector.encrypt_seed(&key::seal(version, &seed)).await?;
    drop(seed);
    let address = crate::validate::encode_stellar_account_id(&public);
    let fingerprint = key::fingerprint(&public);

    let inserted = sqlx::query(key::SSK_INSERT_SQL)
        .bind(version)
        .bind(protected.backend.as_str())
        .bind(&protected.ciphertext)
        .bind(&protected.wrapped_data_key)
        .bind(&protected.nonce)
        .bind(&protected.key_id)
        .bind(&protected.key_version)
        .bind(&address)
        .bind(&fingerprint)
        .bind(&user.account_id)
        .execute(&mut *tx)
        .await;
    if let Err(e) = inserted {
        let msg = e.to_string();
        if msg.contains("uq_sep10_signing_key_pending") {
            return Err(pending_key_exists(None));
        }
        if msg.contains("duplicate key") || msg.contains("unique constraint") {
            return Err(AppError::Conflict(
                "Another SEP-10 key generation won the race; list the keys and retry".to_string(),
            ));
        }
        error!("admin_sep10: insert failed: {}", e);
        return Err(AppError::InternalError("Database error".to_string()));
    }
    emit_event(
        &mut tx,
        &AccountEvent::Sep10KeyGenerated {
            account_id: user.account_id.clone(),
            version,
            fingerprint: fingerprint.clone(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;
    info!(
        "admin_sep10: SEP-10 signing key version {} ({}) generated (pending) by {}",
        version, fingerprint, user.account_id
    );

    Ok((
        StatusCode::CREATED,
        Json(GenerateSep10KeyResponse {
            version,
            state: "pending".to_string(),
            public_address: address,
            fingerprint,
        }),
    ))
}

/// `POST /admin/sep10/signing-keys/{version}/activate` — schedule a pending
/// version to take over after the activation delay.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an extractor
pub async fn activate_signing_key(
    user: Privileged<ManageKeys>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(settings): Extension<Arc<Sep10AdminSettings>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    ring: Option<Extension<Arc<Sep10Ring>>>,
    Path(version): Path<i32>,
    Json(payload): Json<ActivateSep10KeyRequest>,
) -> Result<Json<ActivateSep10KeyResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    let network = stellar_config.network.as_str();

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let active: Option<(i32, String)> = sqlx::query_as(key::SSK_ACTIVE_FOR_UPDATE_SQL)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("active key"))?;
    let target: Option<(String, String, Option<i64>)> =
        sqlx::query_as(key::SSK_VERSION_FOR_UPDATE_SQL)
            .bind(version)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err("target key"))?;
    let (state, fingerprint, scheduled) = target
        .ok_or_else(|| AppError::NotFound(format!("No SEP-10 signing key version {version}")))?;
    if state.trim() != "pending" {
        return Err(AppError::Conflict(format!(
            "Version {version} is {}; only a pending key can be activated",
            state.trim()
        )));
    }
    if let Some(at) = scheduled {
        return Err(AppError::Conflict(format!(
            "Version {version} is already scheduled to activate at unix {at}"
        )));
    }
    check_activation(
        active.as_ref().map(|(_, fp)| fp.as_str()),
        &payload,
        network,
    )?;
    check_ring_can_serve(ring.as_ref().map(|Extension(r)| r.as_ref()), version)?;

    let activate_at: Option<i64> = sqlx::query_scalar(key::SSK_SCHEDULE_ACTIVATION_SQL)
        .bind(version)
        .bind(settings.activation_delay_secs as i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("schedule"))?
        .flatten();
    let Some(activate_at) = activate_at else {
        return Err(AppError::Conflict(
            "The key changed while activating; list the keys and retry".to_string(),
        ));
    };
    let supersedes_version = active.as_ref().map(|(v, _)| *v);
    emit_event(
        &mut tx,
        &AccountEvent::Sep10KeyActivated {
            account_id: user.account_id.clone(),
            version,
            fingerprint: fingerprint.clone(),
            supersedes_version,
            activate_at,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;
    warn!(
        "admin_sep10: SEP-10 signing key version {} ({}) scheduled to activate at unix {} by {} \
         (supersedes {:?})",
        version, fingerprint, activate_at, user.account_id, supersedes_version
    );

    Ok(Json(ActivateSep10KeyResponse {
        version,
        // Still pending: the swap happens at activate_at, on every replica.
        state: "pending".to_string(),
        activate_at: chrono::DateTime::from_timestamp(activate_at, 0)
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| activate_at.to_string()),
    }))
}

/// `POST /admin/sep10/signing-keys/{version}/revoke` — refuse and scrub.
pub async fn revoke_signing_key(
    user: Privileged<ManageKeys>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    ring: Option<Extension<Arc<Sep10Ring>>>,
    Path(version): Path<i32>,
    Json(payload): Json<RevokeSep10KeyRequest>,
) -> Result<Json<RevokeSep10KeyResponse>, AppError> {
    rate_limit(&redis_pool, &user.account_id).await?;
    require_phrase(
        payload.confirm_phrase.as_deref(),
        &revocation_phrase(stellar_config.network.as_str(), version),
    )?;

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let target: Option<(String, String, Option<i64>)> =
        sqlx::query_as(key::SSK_VERSION_FOR_UPDATE_SQL)
            .bind(version)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err("target key"))?;
    let (state, fingerprint, _) = target
        .ok_or_else(|| AppError::NotFound(format!("No SEP-10 signing key version {version}")))?;
    let previous_state = state.trim().to_string();
    if previous_state == "revoked" {
        return Err(AppError::Conflict(format!(
            "Version {version} is already revoked"
        )));
    }
    let revoked = sqlx::query(key::SSK_REVOKE_SQL)
        .bind(version)
        .execute(&mut *tx)
        .await
        .map_err(db_err("revoke"))?;
    if revoked.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "The key changed while revoking; list the keys and retry".to_string(),
        ));
    }
    emit_event(
        &mut tx,
        &AccountEvent::Sep10KeyRevoked {
            account_id: user.account_id.clone(),
            version,
            fingerprint: fingerprint.clone(),
            previous_state: previous_state.clone(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;
    if let Some(Extension(ring)) = ring {
        ring.mark_revoked(version);
    }
    warn!(
        "admin_sep10: SEP-10 signing key version {} ({}, was {}) REVOKED by {}",
        version, fingerprint, previous_state, user.account_id
    );

    if previous_state == "active" {
        warn!(
            "admin_sep10: the ACTIVE SEP-10 key was revoked; SEP-10 answers 503 until another \
             key is generated and activated"
        );
    }
    Ok(Json(RevokeSep10KeyResponse {
        version,
        state: "revoked".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = include_str!("admin_sep10.rs");

    fn req(fp: Option<&str>, phrase: Option<&str>) -> ActivateSep10KeyRequest {
        ActivateSep10KeyRequest {
            confirm_supersede: fp.map(str::to_string),
            confirm_phrase: phrase.map(str::to_string),
        }
    }

    /// Activation is refused while this replica's ring has not opened the
    /// version (the swap would otherwise be an outage with no way back), and
    /// is not second-guessed on a replica that runs no ring.
    #[tokio::test]
    async fn activation_needs_the_ring_to_hold_the_version_opened() {
        let (ring, _public) = crate::sep10::key::tests::ring_with_active_key(300).await;
        assert!(check_ring_can_serve(Some(&ring), 1).is_ok());
        match check_ring_can_serve(Some(&ring), 2) {
            Err(AppError::Coded {
                status,
                code,
                message,
                ..
            }) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(code, "sep10_key_not_opened");
                assert!(message.contains("version 2"));
            }
            other => panic!("expected a coded 409, got {:?}", other.err()),
        }
        assert!(check_ring_can_serve(None, 2).is_ok());
        // The check runs before anything is scheduled.
        let handler = &SRC[SRC.find("pub async fn activate_signing_key(").unwrap()..];
        let handler = &handler[..handler.find("\npub async fn revoke_signing_key(").unwrap()];
        assert!(
            handler.find("check_ring_can_serve(").unwrap()
                < handler.find("SSK_SCHEDULE_ACTIVATION_SQL").unwrap()
        );
    }

    #[test]
    fn first_activation_confirms_none_and_the_phrase() {
        let p = Some("activate sep10-signing testnet");
        assert!(check_activation(None, &req(Some("none"), p), "testnet").is_ok());
        assert!(check_activation(None, &req(None, p), "testnet").is_err());
        assert!(check_activation(None, &req(Some("none"), None), "testnet").is_err());
        assert!(check_activation(
            None,
            &req(Some("none"), Some("activate sep10-signing pubnet")),
            "testnet"
        )
        .is_err());
    }

    #[test]
    fn rotation_requires_the_active_fingerprint() {
        let fp = "0123456789abcdef0123";
        let p = Some("activate sep10-signing testnet");
        assert!(check_activation(Some(fp), &req(Some(fp), p), "testnet").is_ok());
        assert!(check_activation(Some(fp), &req(Some("none"), p), "testnet").is_err());
        assert!(check_activation(Some(fp), &req(Some("ffff"), p), "testnet").is_err());
        let e = check_activation(Some(fp), &req(None, None), "testnet").unwrap_err();
        assert!(e.to_string().contains(fp), "the refusal names what to send");
    }

    #[test]
    fn revocation_phrase_names_network_and_version() {
        assert_eq!(
            revocation_phrase("testnet", 3),
            "revoke sep10-signing testnet v3"
        );
        assert!(require_phrase(
            Some("revoke sep10-signing testnet v3"),
            &revocation_phrase("testnet", 3)
        )
        .is_ok());
        assert!(require_phrase(
            Some("revoke sep10-signing testnet v4"),
            &revocation_phrase("testnet", 3)
        )
        .is_err());
        assert!(require_phrase(None, &revocation_phrase("testnet", 3)).is_err());
    }

    /// The account-cards listing reads exactly five public columns, newest
    /// first, capped at 100; the count reads only active Stellar cards.
    #[test]
    fn admin_card_list_sql_is_pinned() {
        let cols: Vec<&str> = ADMIN_ACCOUNT_CARDS_SQL
            .trim_start_matches("SELECT ")
            .split(" FROM ")
            .next()
            .unwrap()
            .split(',')
            .map(str::trim)
            .collect();
        assert_eq!(
            cols,
            [
                "card_id",
                "is_delete",
                "created_at",
                "deleted_at",
                "stellar_address"
            ]
        );
        assert!(ADMIN_ACCOUNT_CARDS_SQL.contains("WHERE account_id = $1 "));
        assert!(ADMIN_ACCOUNT_CARDS_SQL
            .contains("ORDER BY created_at DESC NULLS LAST, id DESC LIMIT 100"));
        assert!(!ADMIN_ACCOUNT_CARDS_SQL.contains("ec_pubkey"));
        assert!(!ADMIN_ACCOUNT_CARDS_SQL.contains("_sig"));
        assert_eq!(
            REGISTERED_CARD_KEYS_SQL,
            "SELECT COUNT(*) FROM card WHERE is_delete = FALSE AND stellar_address IS NOT NULL"
        );
        let main = include_str!("../main.rs");
        let at = main.find("\"/admin/accounts/{account_id}/cards\"").unwrap();
        assert!(main[at..at + 120].contains("get(admin_sep10::list_account_cards)"));
    }

    fn field_names(models: &str, name: &str) -> Vec<String> {
        let start = models
            .find(&format!("pub struct {name} {{"))
            .unwrap_or_else(|| panic!("{name} missing"));
        let body = &models[start..start + models[start..].find("\n}").unwrap()];
        body.lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| l.starts_with("pub "))
            .map(|l| l["pub ".len()..l.find(':').unwrap()].to_string())
            .collect()
    }

    /// No admin response carries key material beyond the public address and
    /// the fingerprint (contract §6.1): every field of every response shape
    /// is pinned, by name, to the documented list.
    #[test]
    fn admin_responses_carry_public_data_only() {
        let models = include_str!("../models.rs");
        for (name, want) in [
            (
                "Sep10StatusResponse",
                &[
                    "enabled",
                    "home_domain",
                    "web_auth_endpoint",
                    "network",
                    "network_passphrase",
                    "challenge_ttl_secs",
                    "registered_card_keys",
                    "key_ring_live",
                    "keys",
                ][..],
            ),
            (
                "Sep10KeyView",
                &[
                    "version",
                    "state",
                    "public_address",
                    "fingerprint",
                    "generated_by",
                    "generated_at",
                    "activate_at",
                    "superseded_at",
                    "revoked_at",
                    "opened",
                ][..],
            ),
            (
                "GenerateSep10KeyResponse",
                &["version", "state", "public_address", "fingerprint"][..],
            ),
            (
                "ActivateSep10KeyResponse",
                &["version", "state", "activate_at"][..],
            ),
            ("RevokeSep10KeyResponse", &["version", "state"][..]),
            ("AdminCardListResponse", &["cards"][..]),
            (
                "AdminCardView",
                &[
                    "card_id",
                    "active",
                    "created_at",
                    "deleted_at",
                    "stellar_address",
                ][..],
            ),
        ] {
            assert_eq!(field_names(models, name), want, "{name}");
        }
        // The handlers build only these shapes.
        let non_test = &SRC[..SRC.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "ec_pubkey",
            "binding_sig",
            "proof_sig",
            "decrypt",
            "open_sealed",
        ] {
            assert!(!non_test.contains(forbidden), "{forbidden}");
        }
    }

    /// `opened` is this instance's own answer: true only for a version its
    /// ring holds open, null without a ring and for a revoked version. It is
    /// the same question `activate` asks (`check_ring_can_serve`).
    #[tokio::test]
    async fn opened_reports_what_this_instance_can_serve() {
        let (ring, _public) = crate::sep10::key::tests::ring_with_active_key(300).await;
        let snapshot = ring.snapshot();
        assert_eq!(opened_here(Some(&snapshot), 1, "active"), Some(true));
        assert_eq!(opened_here(Some(&snapshot), 2, "pending"), Some(false));
        assert_eq!(opened_here(Some(&snapshot), 1, "revoked"), None);
        assert_eq!(opened_here(None, 1, "active"), None);
        assert!(snapshot.is_live(key::unix_now()));
        // Agreement with the activation gate, for every version.
        for version in [1, 2] {
            assert_eq!(
                opened_here(Some(&snapshot), version, "pending") == Some(true),
                check_ring_can_serve(Some(&ring), version).is_ok()
            );
        }
    }

    #[test]
    fn pending_key_exists_is_a_coded_409() {
        match pending_key_exists(Some(2)) {
            AppError::Coded { status, code, .. } => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(code, "pending_key_exists");
            }
            other => panic!("{other:?}"),
        }
    }

    /// The four routes are mounted unconditionally with these exact handlers.
    #[test]
    fn admin_routes_are_pinned() {
        let main = include_str!("../main.rs");
        for (path, handler) in [
            (
                "\"/admin/sep10/signing-keys\"",
                "get(admin_sep10::list_signing_keys)",
            ),
            (
                "\"/admin/sep10/signing-keys/generate\"",
                "post(admin_sep10::generate_signing_key)",
            ),
            (
                "\"/admin/sep10/signing-keys/{version}/activate\"",
                "post(admin_sep10::activate_signing_key)",
            ),
            (
                "\"/admin/sep10/signing-keys/{version}/revoke\"",
                "post(admin_sep10::revoke_signing_key)",
            ),
        ] {
            let at = main
                .find(path)
                .unwrap_or_else(|| panic!("{path} not routed"));
            assert!(main[at..at + 200].contains(handler), "{path} → {handler}");
        }
        assert_eq!(main.matches("\"/admin/sep10/").count(), 4);
    }
}

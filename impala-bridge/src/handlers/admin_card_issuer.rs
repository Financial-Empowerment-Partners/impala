//! Card program issuer key (`/admin/card-issuer*`) and bridge-issued card
//! certificates (`/admin/cards/{card_id}/certificate`).
//!
//! The issuer key is **generate-only** (like the conversion-reserve seed): it
//! is created inside the bridge, sealed by the configured seed protector, and
//! never imported or exported. Whoever holds it can certify any card key and
//! sign any credit, so an import path would put that mint authority in a
//! person's hands. Rotation supersedes the active key under an explicit
//! fingerprint compare-and-swap plus a typed phrase naming the network; old
//! versions stay as public keys so the certificates they signed keep
//! verifying. Certificates are bridge-issued only (contract addendum §A.8):
//! `POST /card` never accepts a client-supplied certificate.
//!
//! See docs/runbooks/card-issuer.md.

use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{ManageKeys, Privileged, ReadKeys};
use crate::constants::{
    KEY_IMPORT_RATE_LIMIT_SCOPE, SIGN_RATE_LIMIT_MAX_REQUESTS, SIGN_RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::events::{emit_event, AccountEvent};
use crate::keys::store::KeyRuntime;
use crate::models::{
    CertifyCardRequest, CertifyCardResponse, GenerateIssuerKeyRequest, GenerateIssuerKeyResponse,
    IssuerKeyListResponse, IssuerKeyView,
};
use crate::offline::issuer::{self, POLICY_IDENTITY_SQL};
use crate::offline::signable;
use crate::seed_protect::SeedProtector;

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("admin_card_issuer: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// The phrase that confirms an issuer-key rotation.
pub(crate) fn rotation_phrase(network: &str) -> String {
    format!("replace card-issuer {network}")
}

/// Checks a rotation request against the active key: `None` when no key is
/// active (first generation needs no confirmation).
pub(crate) fn check_rotation(
    active_fingerprint: Option<&str>,
    request: &GenerateIssuerKeyRequest,
    network: &str,
) -> Result<bool, AppError> {
    let Some(active) = active_fingerprint else {
        return Ok(false);
    };
    let phrase = rotation_phrase(network);
    let fp_ok = request
        .confirm_supersede
        .as_deref()
        .is_some_and(|g| crate::keys::tokens_match(g, active));
    let phrase_ok = request
        .confirm_phrase
        .as_deref()
        .is_some_and(|g| crate::keys::tokens_match(g, &phrase));
    if fp_ok && phrase_ok {
        Ok(true)
    } else {
        Err(AppError::Conflict(format!(
            "A card issuer key is active (fingerprint {active}). Rotating it invalidates the \
             program key installed on every card until they are re-personalized and \
             re-certified. To proceed send confirm_supersede=\"{active}\" and \
             confirm_phrase=\"{phrase}\"."
        )))
    }
}

/// Validates a certify request; returns the card tag for the currency.
pub(crate) fn check_certify_request(
    req: &CertifyCardRequest,
    reserve: Option<&crate::exchange::reserve::ConversionReserve>,
) -> Result<[u8; 4], AppError> {
    if !(0..=7).contains(&req.card_minor_scale) {
        return Err(AppError::BadRequest(
            "card_minor_scale must be 0..7".to_string(),
        ));
    }
    let tag = signable::currency_tag(&req.currency)
        .ok_or_else(|| AppError::BadRequest("currency must be XLM, USDC or USDT0".to_string()))?;
    let configured = req.currency == crate::constants::RESERVE_CURRENCY_XLM
        || reserve.is_some_and(|r| r.asset_for_bucket(&req.currency).is_some());
    if !configured {
        return Err(AppError::BadRequest(format!(
            "currency {} is not a configured reserve asset",
            req.currency
        )));
    }
    Ok(tag)
}

/// `POST /admin/card-issuer/generate` — create (or rotate) the program issuer key.
#[allow(clippy::too_many_arguments)]
pub async fn generate_issuer_key(
    user: Privileged<ManageKeys>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Json(payload): Json<GenerateIssuerKeyRequest>,
) -> Result<Json<GenerateIssuerKeyResponse>, AppError> {
    crate::handlers::admin_keys::require_enabled(&runtime)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    let network = stellar_config.network.as_str();

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let active: Option<(i32, String)> = sqlx::query_as(issuer::ISSUER_ACTIVE_FOR_UPDATE_SQL)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("active key"))?;
    let replaced = check_rotation(
        active.as_ref().map(|(_, fp)| fp.as_str()),
        &payload,
        network,
    )?;

    let version: i32 = sqlx::query_scalar(issuer::ISSUER_NEXT_VERSION_SQL)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err("next version"))?;
    let (pkcs8, public) = issuer::generate()?;
    let protected = protector
        .encrypt_seed(&issuer::seal(version, &pkcs8))
        .await?;
    drop(pkcs8);
    let public_hex = hex::encode(&public);
    let fingerprint = issuer::fingerprint(&public);

    if replaced {
        sqlx::query(issuer::ISSUER_SUPERSEDE_SQL)
            .execute(&mut *tx)
            .await
            .map_err(db_err("supersede"))?;
    }
    let inserted = sqlx::query(issuer::ISSUER_INSERT_SQL)
        .bind(version)
        .bind(protected.backend.as_str())
        .bind(&protected.ciphertext)
        .bind(&protected.wrapped_data_key)
        .bind(&protected.nonce)
        .bind(&protected.key_id)
        .bind(&protected.key_version)
        .bind(&public_hex)
        .bind(&fingerprint)
        .bind(&user.account_id)
        .execute(&mut *tx)
        .await;
    if let Err(e) = inserted {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique constraint") {
            return Err(AppError::Conflict(
                "Another issuer key generation won the race; list the keys and retry with \
                 the new active fingerprint"
                    .to_string(),
            ));
        }
        error!("admin_card_issuer: issuer insert failed: {}", e);
        return Err(AppError::InternalError("Database error".to_string()));
    }

    // Program identity: minted with the first key, unchanged by rotation.
    let program_candidate = Uuid::new_v4();
    let (program_id, redemption_uuid): (Option<Vec<u8>>, Option<Uuid>) =
        sqlx::query_as(issuer::POLICY_MINT_IDENTITY_SQL)
            .bind(program_candidate.as_bytes().as_slice())
            .bind(&user.account_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err("program identity"))?;
    let program_id =
        program_id.ok_or_else(|| AppError::InternalError("program id missing".into()))?;
    let redemption_uuid =
        redemption_uuid.ok_or_else(|| AppError::InternalError("redemption uuid missing".into()))?;

    emit_event(
        &mut tx,
        &AccountEvent::CardIssuerKeyGenerated {
            account_id: user.account_id.clone(),
            version,
            fingerprint: fingerprint.clone(),
            replaced,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;

    if replaced {
        warn!(
            "admin_card_issuer: card issuer key ROTATED to version {} ({}) by {}",
            version, fingerprint, user.account_id
        );
    } else {
        info!(
            "admin_card_issuer: card issuer key version {} ({}) generated by {}",
            version, fingerprint, user.account_id
        );
    }

    Ok(Json(GenerateIssuerKeyResponse {
        version,
        public_key_hex: public_hex,
        fingerprint,
        redemption_uuid: redemption_uuid.to_string(),
        program_id_hex: hex::encode(program_id),
        replaced,
        note: "The key was generated inside the bridge and sealed with the configured \
               protection backend; it cannot be exported. Rotation requires re-installing the \
               program key on cards and re-certifying them."
            .to_string(),
    }))
}

type IssuerListRow = (
    i32,
    String,
    String,
    String,
    String,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// `GET /admin/card-issuer` — every key version (public data) and the program identity.
pub async fn list_issuer_keys(
    _user: Privileged<ReadKeys>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<IssuerKeyListResponse>, AppError> {
    let rows: Vec<IssuerListRow> = sqlx::query_as(
        "SELECT version, state, public_key_hex, fingerprint, generated_by, generated_at, \
         superseded_at FROM card_issuer_key ORDER BY version DESC",
    )
    .fetch_all(&pool)
    .await
    .map_err(db_err("list"))?;
    let (program_id, redemption_uuid): (Option<Vec<u8>>, Option<Uuid>) =
        sqlx::query_as(POLICY_IDENTITY_SQL)
            .fetch_one(&pool)
            .await
            .map_err(db_err("program identity"))?;
    Ok(Json(IssuerKeyListResponse {
        keys: rows
            .into_iter()
            .map(
                |(version, state, public_key_hex, fingerprint, generated_by, at, sup)| {
                    IssuerKeyView {
                        version,
                        state,
                        public_key_hex: public_key_hex.trim().to_string(),
                        fingerprint,
                        generated_by,
                        generated_at: at.to_rfc3339(),
                        superseded_at: sup.map(|t| t.to_rfc3339()),
                    }
                },
            )
            .collect(),
        redemption_uuid: redemption_uuid.map(|u| u.to_string()),
        program_id_hex: program_id.map(hex::encode),
    }))
}

/// `POST /admin/cards/{card_id}/certificate` — sign the card's CERT message
/// with the active issuer key and record it on the active card row.
#[allow(clippy::too_many_arguments)]
pub async fn certify_card(
    user: Privileged<ManageKeys>,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    reserve: Option<Extension<Arc<crate::exchange::reserve::ConversionReserve>>>,
    Path(card_id): Path<String>,
    Json(payload): Json<CertifyCardRequest>,
) -> Result<Json<CertifyCardResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    crate::validate::validate_card_id(&card_id)?;
    let tag = check_certify_request(&payload, reserve.as_ref().map(|Extension(r)| r.as_ref()))?;

    let card: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT account_id, ec_pubkey, issuer_cert_hex FROM card \
         WHERE card_id = $1 AND is_delete = FALSE",
    )
    .bind(&card_id)
    .fetch_optional(&pool)
    .await
    .map_err(db_err("card lookup"))?;
    let (account_id, ec_pubkey_hex, existing) =
        card.ok_or_else(|| AppError::NotFound("No active card with this card_id".to_string()))?;
    // The certificate binds the account UUID the card signs with (card_auth.rs).
    let account = Uuid::parse_str(account_id.trim()).map_err(|_| {
        AppError::Conflict("Card certificates require a UUID account id".to_string())
    })?;
    let point: [u8; signable::POINT_LEN] = hex::decode(ec_pubkey_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .filter(|p: &[u8; signable::POINT_LEN]| p[0] == 0x04)
        .ok_or_else(|| {
            AppError::Conflict(
                "The registered ec_pubkey must be a 65-byte uncompressed point to be certified"
                    .to_string(),
            )
        })?;
    if existing.is_some() && !payload.recertify {
        return Err(AppError::Conflict(
            "Card is already certified; send recertify=true to replace its certificate".to_string(),
        ));
    }

    let (program_id, _): (Option<Vec<u8>>, Option<Uuid>) = sqlx::query_as(POLICY_IDENTITY_SQL)
        .fetch_one(&pool)
        .await
        .map_err(db_err("program identity"))?;
    let program_id: [u8; 16] = program_id
        .and_then(|p| p.try_into().ok())
        .ok_or_else(|| AppError::Conflict("No card issuer key; generate one first".to_string()))?;

    let (key, version) = issuer::load_issuer_key(&pool, protector.as_ref(), None).await?;
    let message = signable::card_cert_message(&program_id, &account, tag, &point);
    let cert = key.sign(&message)?;
    let issuer_public = key.public_key();
    if !signable::verify_p256(&issuer_public, &message, &cert) {
        error!("admin_card_issuer: freshly signed certificate does not verify");
        return Err(AppError::InternalError(
            "certificate self-check failed".to_string(),
        ));
    }
    let cert_hex = hex::encode(&cert);

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let updated = sqlx::query(issuer::CERTIFY_SQL)
        .bind(&card_id)
        .bind(&cert_hex)
        .bind(version)
        .bind(&payload.currency)
        .bind(payload.card_minor_scale)
        .bind(payload.recertify)
        .execute(&mut *tx)
        .await
        .map_err(db_err("certify"))?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "Card changed while certifying (deleted or certified concurrently); retry".to_string(),
        ));
    }
    let replaced = existing.is_some();
    emit_event(
        &mut tx,
        &AccountEvent::CardCertified {
            account_id: user.account_id.clone(),
            card_id: card_id.clone(),
            issuer_version: version,
            replaced,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;
    info!(
        "admin_card_issuer: card {} certified under issuer version {} by {}",
        card_id, version, user.account_id
    );

    Ok(Json(CertifyCardResponse {
        card_id,
        issuer_version: version,
        issuer_cert_hex: cert_hex,
        cert_message_hex: hex::encode(message),
        cert_id: signable::cert_id_hex(&message),
        issuer_public_key_hex: hex::encode(&issuer_public),
        program_id_hex: hex::encode(program_id),
        currency: payload.currency,
        card_minor_scale: payload.card_minor_scale,
        replaced,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = include_str!("admin_card_issuer.rs");

    fn req(fp: Option<&str>, phrase: Option<&str>) -> GenerateIssuerKeyRequest {
        GenerateIssuerKeyRequest {
            confirm_supersede: fp.map(str::to_string),
            confirm_phrase: phrase.map(str::to_string),
        }
    }

    #[test]
    fn first_generation_needs_no_confirmation() {
        assert!(!check_rotation(None, &req(None, None), "testnet").unwrap());
    }

    #[test]
    fn rotation_requires_the_active_fingerprint_and_the_network_phrase() {
        let fp = "0123456789abcdef0123";
        assert!(check_rotation(Some(fp), &req(None, None), "testnet").is_err());
        assert!(check_rotation(Some(fp), &req(Some(fp), None), "testnet").is_err());
        assert!(check_rotation(
            Some(fp),
            &req(Some("ffff"), Some("replace card-issuer testnet")),
            "testnet"
        )
        .is_err());
        assert!(check_rotation(
            Some(fp),
            &req(Some(fp), Some("replace card-issuer pubnet")),
            "testnet"
        )
        .is_err());
        assert!(check_rotation(
            Some(fp),
            &req(Some(fp), Some("replace card-issuer testnet")),
            "testnet"
        )
        .unwrap());
    }

    #[test]
    fn certify_request_validation() {
        let ok = CertifyCardRequest {
            currency: "XLM".into(),
            card_minor_scale: 7,
            recertify: false,
        };
        assert_eq!(check_certify_request(&ok, None).unwrap(), *b"XLM\0");
        let usdc = CertifyCardRequest {
            currency: "USDC".into(),
            card_minor_scale: 7,
            recertify: false,
        };
        assert!(
            check_certify_request(&usdc, None).is_err(),
            "USDC needs a configured reserve"
        );
        let usd = CertifyCardRequest {
            currency: "USD".into(),
            card_minor_scale: 2,
            recertify: false,
        };
        assert!(check_certify_request(&usd, None).is_err());
        let scale = CertifyCardRequest {
            currency: "XLM".into(),
            card_minor_scale: 8,
            recertify: false,
        };
        assert!(check_certify_request(&scale, None).is_err());
    }

    /// Generate-only: no import route or handler for the issuer key exists.
    #[test]
    fn issuer_key_is_generate_only() {
        let non_test = &SRC[..SRC.find("#[cfg(test)]").unwrap()];
        assert!(!non_test.contains("pub async fn import"));
        assert!(
            !non_test.contains("from_pkcs8("),
            "keys enter only via offline::issuer"
        );
        let main = include_str!("../main.rs");
        for line in main.lines().filter(|l| l.contains("/admin/card-issuer")) {
            assert!(!line.contains("import"), "no import route: {line}");
        }
        assert_eq!(non_test.matches("pub async fn ").count(), 3);
    }

    /// Nothing secret leaves: responses carry public keys, fingerprints and
    /// the DER certificate only; the PKCS#8 is dropped after sealing.
    #[test]
    fn responses_never_carry_private_material() {
        let non_test = &SRC[..SRC.find("#[cfg(test)]").unwrap()];
        assert!(non_test.contains("drop(pkcs8);"));
        for forbidden in ["pkcs8:", "private", "ciphertext:"] {
            assert!(!non_test.contains(forbidden), "{forbidden}");
        }
    }
}

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::constants::{RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS};
use crate::error::AppError;
use crate::models::{CardResponse, CreateCardRequest, DeleteCardRequest, SetCardStellarKeyRequest};

/// Four columns, four binds; `rsa_pubkey` is the normalized `Option`
/// (pinned by `insert_binds_pinned`, executed by the DB lane). Every card
/// registered without Stellar fields takes exactly this statement, as
/// before migration 040.
pub(crate) const CARD_INSERT_SQL: &str =
    "INSERT INTO card (account_id, card_id, ec_pubkey, rsa_pubkey) VALUES ($1, $2, $3, $4)";

/// A card with a verified Stellar key (040): the four columns above plus the
/// address and both cross-signatures — seven columns, seven binds, pinned by
/// `stellar_insert_binds_pinned`. A separate statement rather than a widened
/// shared one, so the legacy path cannot lose a bind.
pub(crate) const CARD_INSERT_STELLAR_SQL: &str = "INSERT INTO card (account_id, card_id, \
     ec_pubkey, rsa_pubkey, stellar_address, stellar_binding_sig, stellar_proof_sig) \
     VALUES ($1, $2, $3, $4, $5, $6, $7)";

/// The partial unique index a second active card with the same address hits.
const STELLAR_ADDRESS_INDEX: &str = "uq_card_active_stellar_address";

/// The caller's own active card, for `PUT /card/stellar-key`: two binds. The
/// EC key the cross-signatures are checked against comes from this row,
/// never from the request.
pub(crate) const CARD_STELLAR_LOOKUP_SQL: &str = "SELECT ec_pubkey, stellar_address FROM card \
     WHERE card_id = $1 AND account_id = $2 AND is_delete = FALSE";

/// Attach a verified Stellar key to the caller's own active card that has
/// none: three columns, five binds, one guarded statement. A card that
/// already has an address is never overwritten (`stellar_address IS NULL`).
pub(crate) const CARD_SET_STELLAR_SQL: &str = "UPDATE card SET stellar_address = $1, \
     stellar_binding_sig = $2, stellar_proof_sig = $3, updated_at = CURRENT_TIMESTAMP \
     WHERE card_id = $4 AND account_id = $5 AND is_delete = FALSE AND stellar_address IS NULL";

/// Register a hardware smartcard (`POST /card`).
pub async fn create_card(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<CreateCardRequest>,
) -> Result<Json<CardResponse>, AppError> {
    crate::auth::require_owner(&user, &payload.account_id)?;

    // Per-account rate limiting. Blocks scripted bulk-registration attempts.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "card",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    crate::validate::validate_card_id(&payload.card_id)?;
    crate::validate::validate_ec_pubkey(&payload.ec_pubkey)?;
    let rsa_pubkey = optional_rsa_pubkey(payload.rsa_pubkey.as_deref())?;
    // The optional Stellar key (040): all three fields or none; both
    // cross-signatures verified against messages rebuilt from THIS request.
    let stellar = crate::sep10::binding::check_stellar_fields(
        &payload.account_id,
        &payload.card_id,
        &payload.ec_pubkey,
        payload.stellar_address.as_deref(),
        payload.stellar_binding_sig.as_deref(),
        payload.stellar_proof_sig.as_deref(),
    )?;
    info!(
        "POST /card: registering card_id={} for account_id={} (stellar key: {})",
        payload.card_id,
        payload.account_id,
        stellar.is_some()
    );
    let mut tx = pool.begin().await.map_err(|e| {
        error!("create_card: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let result = match &stellar {
        None => {
            sqlx::query(CARD_INSERT_SQL)
                .bind(&payload.account_id)
                .bind(&payload.card_id)
                .bind(&payload.ec_pubkey)
                .bind(rsa_pubkey)
                .execute(&mut *tx)
                .await
        }
        Some(binding) => {
            sqlx::query(CARD_INSERT_STELLAR_SQL)
                .bind(&payload.account_id)
                .bind(&payload.card_id)
                .bind(&payload.ec_pubkey)
                .bind(rsa_pubkey)
                .bind(&binding.stellar_address)
                .bind(&binding.binding_sig_hex)
                .bind(&binding.proof_sig_hex)
                .execute(&mut *tx)
                .await
        }
    };

    match result {
        Ok(_) => {
            crate::events::emit_event(
                &mut tx,
                &crate::events::AccountEvent::CardRegistered {
                    account_id: payload.account_id.clone(),
                    card_id: payload.card_id.clone(),
                },
            )
            .await?;
            if stellar.is_some() {
                // A second way to sign in as this account now exists: that
                // is its own line in the audit trail.
                crate::events::emit_event(
                    &mut tx,
                    &crate::events::AccountEvent::CardStellarKeyRegistered {
                        account_id: payload.account_id.clone(),
                        card_id: payload.card_id.clone(),
                    },
                )
                .await?;
            }
            tx.commit().await.map_err(|e| {
                error!("create_card: commit error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;
            info!("create_card: card_id={} registered", payload.card_id);
            Ok(Json(CardResponse {
                success: true,
                message: "Card created successfully".to_string(),
            }))
        }
        Err(e) => {
            if stellar.is_some() && is_stellar_address_conflict(&e) {
                warn!(
                    "create_card: card_id={} refused: its Stellar address is active on another card",
                    payload.card_id
                );
                return Err(AppError::coded(
                    StatusCode::CONFLICT,
                    "stellar_address_in_use",
                    "This Stellar address is already registered on another active card",
                ));
            }
            error!("create_card: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// A unique violation on the active-address index (and only that one).
fn is_stellar_address_conflict(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db) => {
            db.code().as_deref() == Some("23505") && db.constraint() == Some(STELLAR_ADDRESS_INDEX)
        }
        _ => false,
    }
}

/// Attach a Stellar key to an already registered card (`PUT /card/stellar-key`).
///
/// A card the issuer certifies is registered BEFORE it is personalized (the
/// certificate needs the card row), and the card makes its two
/// cross-signatures only at personalization, so that `POST /card` cannot
/// carry them. This route adds them afterwards, once, under the same proof:
/// both signatures must verify over messages rebuilt from the caller's
/// account, the card id and the EC key STORED on the row (nothing but the
/// address and the signatures is taken from the request).
///
/// - the card must be the caller's own active card: otherwise 404;
/// - a card that already has this address: success, nothing changes;
/// - a card that already has another address: 409 `stellar_key_already_set`
///   (the key is generated on the card and never changes);
/// - an address active on another card: 409 `stellar_address_in_use`;
/// - signatures that do not verify: 400 `invalid_stellar_binding`.
pub async fn set_card_stellar_key(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Json(payload): Json<SetCardStellarKeyRequest>,
) -> Result<Json<CardResponse>, AppError> {
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "card",
        &user.account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    crate::validate::validate_card_id(&payload.card_id)?;

    let row: Option<(String, Option<String>)> = sqlx::query_as(CARD_STELLAR_LOOKUP_SQL)
        .bind(&payload.card_id)
        .bind(&user.account_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("set_card_stellar_key: lookup error: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
    let Some((ec_pubkey, existing)) = row else {
        return Err(AppError::NotFound("Card not found".to_string()));
    };

    let binding = crate::sep10::binding::check_stellar_fields(
        &user.account_id,
        &payload.card_id,
        ec_pubkey.trim(),
        Some(&payload.stellar_address),
        Some(&payload.stellar_binding_sig),
        Some(&payload.stellar_proof_sig),
    )?
    .ok_or_else(|| {
        AppError::coded(
            StatusCode::BAD_REQUEST,
            crate::sep10::binding::INVALID_STELLAR_BINDING,
            "stellar_address, stellar_binding_sig and stellar_proof_sig are required",
        )
    })?;

    if let Some(current) = existing {
        return stellar_key_already_set(current.trim() == binding.stellar_address);
    }

    let mut tx = pool.begin().await.map_err(|e| {
        error!("set_card_stellar_key: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    let result = sqlx::query(CARD_SET_STELLAR_SQL)
        .bind(&binding.stellar_address)
        .bind(&binding.binding_sig_hex)
        .bind(&binding.proof_sig_hex)
        .bind(&payload.card_id)
        .bind(&user.account_id)
        .execute(&mut *tx)
        .await;
    match result {
        Ok(res) if res.rows_affected() == 1 => {
            // In the same transaction as the write: a login credential is
            // never attached without its line in the audit trail.
            crate::events::emit_event(
                &mut tx,
                &crate::events::AccountEvent::CardStellarKeyRegistered {
                    account_id: user.account_id.clone(),
                    card_id: payload.card_id.clone(),
                },
            )
            .await?;
            tx.commit().await.map_err(|e| {
                error!("set_card_stellar_key: commit error: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;
            info!(
                "set_card_stellar_key: card_id={} now has a Stellar key",
                payload.card_id
            );
            Ok(Json(CardResponse {
                success: true,
                message: "Stellar key registered".to_string(),
            }))
        }
        // Nothing matched: the card was deleted, or another request attached
        // a key, between the lookup and here. Refuse; nothing was written.
        Ok(_) => stellar_key_already_set(false),
        Err(e) if is_stellar_address_conflict(&e) => {
            warn!(
                "set_card_stellar_key: card_id={} refused: its Stellar address is active on another card",
                payload.card_id
            );
            Err(AppError::coded(
                StatusCode::CONFLICT,
                "stellar_address_in_use",
                "This Stellar address is already registered on another active card",
            ))
        }
        Err(e) => {
            error!("set_card_stellar_key: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

/// The answer for a card that already has a Stellar key: the same key is a
/// repeat of a finished request, any other is refused.
fn stellar_key_already_set(same: bool) -> Result<Json<CardResponse>, AppError> {
    if same {
        Ok(Json(CardResponse {
            success: true,
            message: "Stellar key already registered".to_string(),
        }))
    } else {
        Err(AppError::coded(
            StatusCode::CONFLICT,
            "stellar_key_already_set",
            "This card already has a Stellar key; a card's key never changes",
        ))
    }
}

/// Normalize the legacy `rsa_pubkey`: absent or empty is NULL (applet 0.2 has
/// no RSA key, and the Android demo sends `""` when the read fails); anything
/// else must still pass `validate_rsa_pubkey`.
fn optional_rsa_pubkey(key: Option<&str>) -> Result<Option<&str>, AppError> {
    match key {
        None | Some("") => Ok(None),
        Some(k) => {
            crate::validate::validate_rsa_pubkey(k)?;
            Ok(Some(k))
        }
    }
}

/// Soft-delete a card (`DELETE /card`).
pub async fn delete_card(
    user: AuthenticatedUser,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<DeleteCardRequest>,
) -> Result<Json<CardResponse>, AppError> {
    info!("DELETE /card: card_id={}", payload.card_id);
    let mut tx = pool.begin().await.map_err(|e| {
        error!("delete_card: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;
    let result = sqlx::query(
        "UPDATE card SET is_delete = TRUE, deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE card_id = $1 AND account_id = $2 AND is_delete = FALSE",
    )
    .bind(&payload.card_id)
    .bind(&user.account_id)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() == 0 {
                warn!(
                    "delete_card: card_id={} not found or already deleted",
                    payload.card_id
                );
                Ok(Json(CardResponse {
                    success: false,
                    message: "Card not found or already deleted".to_string(),
                }))
            } else {
                crate::events::emit_event(
                    &mut tx,
                    &crate::events::AccountEvent::CardDeleted {
                        account_id: user.account_id.clone(),
                        card_id: payload.card_id.clone(),
                    },
                )
                .await?;
                tx.commit().await.map_err(|e| {
                    error!("delete_card: commit error: {}", e);
                    AppError::InternalError("Database error".to_string())
                })?;
                info!("delete_card: card_id={} soft-deleted", payload.card_id);
                Ok(Json(CardResponse {
                    success: true,
                    message: "Card deleted successfully".to_string(),
                }))
            }
        }
        Err(e) => {
            error!("delete_card: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLER_SRC: &str = include_str!("card.rs");
    const MIGRATION_038: &str = include_str!("../../migrations/038_card_rsa_pubkey_optional.sql");

    #[test]
    fn rsa_pubkey_absent_or_empty_is_null() {
        assert_eq!(optional_rsa_pubkey(None).unwrap(), None);
        assert_eq!(optional_rsa_pubkey(Some("")).unwrap(), None);
    }

    #[test]
    fn rsa_pubkey_present_is_still_validated() {
        let good = "A".repeat(200);
        assert_eq!(
            optional_rsa_pubkey(Some(&good)).unwrap(),
            Some(good.as_str())
        );
        assert!(optional_rsa_pubkey(Some("short")).is_err());
        assert!(optional_rsa_pubkey(Some(&"!".repeat(200))).is_err());
    }

    #[test]
    fn create_card_request_accepts_missing_and_null_rsa_pubkey() {
        let base = r#""account_id":"a","card_id":"00112233","ec_pubkey":"04""#;
        let missing: CreateCardRequest = serde_json::from_str(&format!("{{{base}}}")).unwrap();
        assert!(missing.rsa_pubkey.is_none());
        let null: CreateCardRequest =
            serde_json::from_str(&format!("{{{base},\"rsa_pubkey\":null}}")).unwrap();
        assert!(null.rsa_pubkey.is_none());
    }

    /// The INSERT has four columns and four binds, the fourth being the
    /// normalized `Option`, never the raw payload field (an empty string
    /// would collide on the partial unique index for the second card).
    #[test]
    fn insert_binds_pinned() {
        assert_eq!(
            CARD_INSERT_SQL,
            "INSERT INTO card (account_id, card_id, ec_pubkey, rsa_pubkey) VALUES ($1, $2, $3, $4)"
        );
        let start = HANDLER_SRC.find("sqlx::query(CARD_INSERT_SQL)").unwrap();
        let end = HANDLER_SRC[start..].find(".execute(").unwrap() + start;
        let binds = HANDLER_SRC[start..end].matches(".bind(").count();
        assert_eq!(binds, 4);
        assert!(HANDLER_SRC[start..end].contains(".bind(rsa_pubkey)"));
    }

    /// The Stellar INSERT has seven columns and exactly seven binds, in
    /// column order; the legacy statement is untouched.
    #[test]
    fn stellar_insert_binds_pinned() {
        let cols = CARD_INSERT_STELLAR_SQL
            .split('(')
            .nth(1)
            .unwrap()
            .split(')')
            .next()
            .unwrap()
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(
            cols,
            [
                "account_id",
                "card_id",
                "ec_pubkey",
                "rsa_pubkey",
                "stellar_address",
                "stellar_binding_sig",
                "stellar_proof_sig"
            ]
        );
        for n in 1..=7 {
            assert!(CARD_INSERT_STELLAR_SQL.contains(&format!("${n}")));
        }
        assert!(!CARD_INSERT_STELLAR_SQL.contains("$8"));
        let start = HANDLER_SRC
            .find("sqlx::query(CARD_INSERT_STELLAR_SQL)")
            .unwrap();
        let end = HANDLER_SRC[start..].find(".execute(").unwrap() + start;
        let binds: Vec<&str> = HANDLER_SRC[start..end]
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with(".bind("))
            .collect();
        assert_eq!(
            binds,
            [
                ".bind(&payload.account_id)",
                ".bind(&payload.card_id)",
                ".bind(&payload.ec_pubkey)",
                ".bind(rsa_pubkey)",
                ".bind(&binding.stellar_address)",
                ".bind(&binding.binding_sig_hex)",
                ".bind(&binding.proof_sig_hex)"
            ]
        );
        // Exactly two INSERT call sites: the legacy one and this one.
        let non_test = &HANDLER_SRC[..HANDLER_SRC.find("#[cfg(test)]").unwrap()];
        assert_eq!(non_test.matches("sqlx::query(CARD_INSERT").count(), 2);
        assert_eq!(non_test.matches("INSERT INTO card").count(), 2);
    }

    /// Only the active-address index maps to 409; the constraint name the
    /// handler matches is the one migration 040 creates.
    #[test]
    fn stellar_conflict_matches_the_migration_index() {
        let ddl = include_str!("../../migrations/040_sep10_card_keys.sql");
        assert!(ddl.contains(&format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS {STELLAR_ADDRESS_INDEX}"
        )));
        assert!(!is_stellar_address_conflict(&sqlx::Error::RowNotFound));
    }

    /// The attach statement: three columns, five binds in order, guarded on
    /// the owner, the live row and an empty address; the lookup: two binds.
    #[test]
    fn stellar_attach_sql_pinned() {
        assert_eq!(
            CARD_SET_STELLAR_SQL,
            "UPDATE card SET stellar_address = $1, stellar_binding_sig = $2, \
             stellar_proof_sig = $3, updated_at = CURRENT_TIMESTAMP WHERE card_id = $4 \
             AND account_id = $5 AND is_delete = FALSE AND stellar_address IS NULL"
        );
        assert_eq!(
            CARD_STELLAR_LOOKUP_SQL,
            "SELECT ec_pubkey, stellar_address FROM card WHERE card_id = $1 \
             AND account_id = $2 AND is_delete = FALSE"
        );
        let binds = |anchor: &str, terminator: &str| -> Vec<&str> {
            let start = HANDLER_SRC.find(anchor).unwrap();
            let end = HANDLER_SRC[start..].find(terminator).unwrap() + start;
            HANDLER_SRC[start..end]
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with(".bind("))
                .collect()
        };
        assert_eq!(
            binds("sqlx::query(CARD_SET_STELLAR_SQL)", ".execute("),
            [
                ".bind(&binding.stellar_address)",
                ".bind(&binding.binding_sig_hex)",
                ".bind(&binding.proof_sig_hex)",
                ".bind(&payload.card_id)",
                ".bind(&user.account_id)"
            ]
        );
        assert_eq!(
            binds(
                "sqlx::query_as(CARD_STELLAR_LOOKUP_SQL)",
                ".fetch_optional("
            ),
            [".bind(&payload.card_id)", ".bind(&user.account_id)"]
        );
        // The columns exist with the names migration 040 gives them, and the
        // card row has the updated_at the statement touches.
        let ddl = include_str!("../../migrations/040_sep10_card_keys.sql");
        for column in [
            "stellar_address",
            "stellar_binding_sig",
            "stellar_proof_sig",
        ] {
            assert!(ddl.contains(&format!("ADD COLUMN IF NOT EXISTS {column} ")));
        }
        // The cross-signatures are checked against the caller's account and
        // the row's EC key: the handler never reads an account or key from
        // the request (the request type has neither).
        let start = HANDLER_SRC
            .find("pub async fn set_card_stellar_key(")
            .unwrap();
        let end = HANDLER_SRC[start..]
            .find("\nfn stellar_key_already_set")
            .unwrap()
            + start;
        let handler = &HANDLER_SRC[start..end];
        assert!(handler
            .contains("&user.account_id,\n        &payload.card_id,\n        ec_pubkey.trim(),"));
        assert!(!handler.contains("payload.account_id"));
        assert!(!handler.contains("payload.ec_pubkey"));
        assert!(
            handler.find("check_stellar_fields(").unwrap()
                < handler.find("CARD_SET_STELLAR_SQL").unwrap()
        );
    }

    #[test]
    fn a_card_keeps_the_stellar_key_it_has() {
        assert!(stellar_key_already_set(true).unwrap().0.success);
        let err = stellar_key_already_set(false).err().unwrap();
        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn set_stellar_key_request_requires_every_field() {
        let full = r#"{"card_id":"00","stellar_address":"G","stellar_binding_sig":"30","stellar_proof_sig":"00"}"#;
        assert!(serde_json::from_str::<SetCardStellarKeyRequest>(full).is_ok());
        for missing in [
            "card_id",
            "stellar_address",
            "stellar_binding_sig",
            "stellar_proof_sig",
        ] {
            let mut v: serde_json::Value = serde_json::from_str(full).unwrap();
            v.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<SetCardStellarKeyRequest>(v).is_err(),
                "{missing} must be required"
            );
        }
    }

    #[test]
    fn create_card_request_accepts_missing_stellar_fields() {
        let body = r#"{"account_id":"a","card_id":"00112233","ec_pubkey":"04"}"#;
        let req: CreateCardRequest = serde_json::from_str(body).unwrap();
        assert!(req.stellar_address.is_none());
        assert!(req.stellar_binding_sig.is_none());
        assert!(req.stellar_proof_sig.is_none());
    }

    #[test]
    fn migration_038_makes_rsa_pubkey_nullable_with_partial_unique_index() {
        assert!(MIGRATION_038.contains("ALTER TABLE card ALTER COLUMN rsa_pubkey DROP NOT NULL;"));
        assert!(MIGRATION_038.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_card_rsa_pubkey\n    ON card(rsa_pubkey) WHERE rsa_pubkey IS NOT NULL;"
        ));
        assert!(MIGRATION_038
            .contains("ALTER TABLE card DROP CONSTRAINT IF EXISTS card_rsa_pubkey_key;"));
    }
}

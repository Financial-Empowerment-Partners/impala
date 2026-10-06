use axum::extract::Extension;
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::auth::AuthenticatedUser;
use crate::constants::{RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS};
use crate::error::AppError;
use crate::models::{CardResponse, CreateCardRequest, DeleteCardRequest};

/// Four columns, four binds; `rsa_pubkey` is the normalized `Option`
/// (pinned by `insert_binds_pinned`, executed by the DB lane).
pub(crate) const CARD_INSERT_SQL: &str =
    "INSERT INTO card (account_id, card_id, ec_pubkey, rsa_pubkey) VALUES ($1, $2, $3, $4)";

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
    info!(
        "POST /card: registering card_id={} for account_id={}",
        payload.card_id, payload.account_id
    );
    let mut tx = pool.begin().await.map_err(|e| {
        error!("create_card: begin tx error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let result = sqlx::query(CARD_INSERT_SQL)
        .bind(&payload.account_id)
        .bind(&payload.card_id)
        .bind(&payload.ec_pubkey)
        .bind(rsa_pubkey)
        .execute(&mut *tx)
        .await;

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
            error!("create_card: database error: {}", e);
            Err(AppError::InternalError("Database error".to_string()))
        }
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

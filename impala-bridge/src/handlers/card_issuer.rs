//! Public `GET /card-issuer`: the program key and identities a terminal pins
//! offline (PERSONALIZE parts A and B, the redemption recipient). Public data
//! only; unauthenticated like `/network`.

use axum::extract::Extension;
use axum::Json;
use log::error;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;

/// Active key + program identity, or `None` when no key is active.
pub(crate) const CARD_ISSUER_PUBLIC_SQL: &str = "SELECT k.version, k.public_key_hex, \
     k.fingerprint, p.redemption_uuid, p.program_id FROM card_issuer_key k \
     CROSS JOIN offline_policy p WHERE k.state = 'active' AND p.id";

pub async fn get_card_issuer(Extension(pool): Extension<PgPool>) -> Result<Json<Value>, AppError> {
    type Row = (i32, String, String, Option<Uuid>, Option<Vec<u8>>);
    let row: Option<Row> = sqlx::query_as(CARD_ISSUER_PUBLIC_SQL)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            error!("card_issuer: lookup failed: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
    Ok(Json(match row {
        Some((version, public_key_hex, fingerprint, Some(redemption_uuid), Some(program_id))) => {
            json!({
                "configured": true,
                "version": version,
                "public_key_hex": public_key_hex.trim(),
                "fingerprint": fingerprint,
                "redemption_uuid": redemption_uuid.to_string(),
                "program_id_hex": hex::encode(program_id),
            })
        }
        _ => json!({ "configured": false }),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_sql_reads_only_public_columns() {
        for secret in ["ciphertext", "wrapped_data_key", "nonce", "key_id"] {
            assert!(!CARD_ISSUER_PUBLIC_SQL.contains(secret), "{secret}");
        }
        assert!(CARD_ISSUER_PUBLIC_SQL.contains("k.state = 'active'"));
    }
}

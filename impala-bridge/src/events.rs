//! Account & transaction state-change events for the admin webhook feed.
//!
//! Events are appended to the durable `event_outbox` table (the canonical feed),
//! and a background worker (`admin_webhook_delivery`) fans them out to registered
//! admin webhooks as **HMAC-SHA256-signed** POSTs. Payloads deliberately exclude
//! secrets/PII (no MFA secret, no raw device token).

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{Postgres, Transaction};

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

/// A backend state change worth surfacing to admins.
#[derive(Debug, Clone)]
pub enum AccountEvent {
    AccountCreated {
        account_id: String,
        stellar_account_id: String,
    },
    AccountUpdated {
        account_id: String,
        fields: Vec<String>,
    },
    TransactionCreated {
        account_id: String,
        btxid: String,
        stellar_tx_id: Option<String>,
        payala_tx_id: Option<String>,
    },
    CardRegistered {
        account_id: String,
        card_id: String,
    },
    CardDeleted {
        account_id: String,
        card_id: String,
    },
    MfaEnrolled {
        account_id: String,
        mfa_type: String,
    },
    DeviceTokenRegistered {
        account_id: String,
        platform: String,
    },
    DeviceTokenDeleted {
        account_id: String,
    },
}

impl AccountEvent {
    /// Stable dotted event-type string (also used for webhook event filtering).
    pub fn event_type(&self) -> &'static str {
        match self {
            AccountEvent::AccountCreated { .. } => "account.created",
            AccountEvent::AccountUpdated { .. } => "account.updated",
            AccountEvent::TransactionCreated { .. } => "transaction.created",
            AccountEvent::CardRegistered { .. } => "card.registered",
            AccountEvent::CardDeleted { .. } => "card.deleted",
            AccountEvent::MfaEnrolled { .. } => "mfa.enrolled",
            AccountEvent::DeviceTokenRegistered { .. } => "device_token.registered",
            AccountEvent::DeviceTokenDeleted { .. } => "device_token.deleted",
        }
    }

    pub fn account_id(&self) -> &str {
        match self {
            AccountEvent::AccountCreated { account_id, .. }
            | AccountEvent::AccountUpdated { account_id, .. }
            | AccountEvent::TransactionCreated { account_id, .. }
            | AccountEvent::CardRegistered { account_id, .. }
            | AccountEvent::CardDeleted { account_id, .. }
            | AccountEvent::MfaEnrolled { account_id, .. }
            | AccountEvent::DeviceTokenRegistered { account_id, .. }
            | AccountEvent::DeviceTokenDeleted { account_id } => account_id,
        }
    }

    /// Event-specific data. **Never** includes secrets/PII: no MFA secret, no raw
    /// device token (only its platform), no card private material (pubkeys are public).
    pub fn data(&self) -> Value {
        match self {
            AccountEvent::AccountCreated {
                stellar_account_id, ..
            } => json!({ "stellar_account_id": stellar_account_id }),
            AccountEvent::AccountUpdated { fields, .. } => json!({ "fields": fields }),
            AccountEvent::TransactionCreated {
                btxid,
                stellar_tx_id,
                payala_tx_id,
                ..
            } => json!({
                "btxid": btxid,
                "stellar_tx_id": stellar_tx_id,
                "payala_tx_id": payala_tx_id,
            }),
            AccountEvent::CardRegistered { card_id, .. } => json!({ "card_id": card_id }),
            AccountEvent::CardDeleted { card_id, .. } => json!({ "card_id": card_id }),
            AccountEvent::MfaEnrolled { mfa_type, .. } => json!({ "mfa_type": mfa_type }),
            AccountEvent::DeviceTokenRegistered { platform, .. } => {
                json!({ "platform": platform })
            }
            AccountEvent::DeviceTokenDeleted { .. } => json!({}),
        }
    }
}

/// Append an event to the durable outbox within an existing transaction, so the
/// event is committed atomically with the state change (no lost/phantom events).
pub async fn emit_event(
    tx: &mut Transaction<'_, Postgres>,
    event: &AccountEvent,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO event_outbox (event_type, account_id, payload) VALUES ($1, $2, $3)")
        .bind(event.event_type())
        .bind(event.account_id())
        .bind(event.data())
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            log::error!("emit_event: failed to insert outbox row: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
    Ok(())
}

/// Compute the webhook signature: `hex(HMAC_SHA256(secret, "{timestamp}.{body}"))`.
///
/// Receivers recompute this over the raw request body + `X-Impala-Timestamp`
/// header and compare in constant time, rejecting timestamps outside a ~5 minute
/// replay window.
pub fn sign(secret: &[u8], timestamp: i64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_and_account_id_map_correctly() {
        let e = AccountEvent::AccountUpdated {
            account_id: "acct-1".into(),
            fields: vec!["nickname".into()],
        };
        assert_eq!(e.event_type(), "account.updated");
        assert_eq!(e.account_id(), "acct-1");
        assert_eq!(e.data(), json!({ "fields": ["nickname"] }));
    }

    #[test]
    fn mfa_payload_never_leaks_secret() {
        let e = AccountEvent::MfaEnrolled {
            account_id: "acct-1".into(),
            mfa_type: "totp".into(),
        };
        let data = e.data();
        assert_eq!(data, json!({ "mfa_type": "totp" }));
        assert!(data.get("secret").is_none());
    }

    #[test]
    fn device_token_payload_never_leaks_token() {
        let e = AccountEvent::DeviceTokenRegistered {
            account_id: "acct-1".into(),
            platform: "android".into(),
        };
        let data = e.data();
        assert_eq!(data, json!({ "platform": "android" }));
        assert!(data.get("token").is_none());
    }

    #[test]
    fn sign_is_deterministic_and_changes_with_inputs() {
        let secret = b"shhh-very-secret";
        let a = sign(secret, 1_700_000_000, "{\"x\":1}");
        let b = sign(secret, 1_700_000_000, "{\"x\":1}");
        assert_eq!(a, b, "same inputs => same signature");
        assert_eq!(a.len(), 64, "hex sha256 is 64 chars");
        assert_ne!(
            a,
            sign(secret, 1_700_000_001, "{\"x\":1}"),
            "timestamp matters"
        );
        assert_ne!(a, sign(secret, 1_700_000_000, "{\"x\":2}"), "body matters");
        assert_ne!(
            a,
            sign(b"other", 1_700_000_000, "{\"x\":1}"),
            "secret matters"
        );
    }

    #[test]
    fn sign_matches_known_vector() {
        // Fixed external vectors (computed independently with Python's hmac +
        // hashlib). These pin the wire format byte-identically across sha2/hmac
        // crate upgrades — webhook receivers verify against this exact value.
        assert_eq!(
            sign(b"key", 1, "body"),
            "91b5374b153842ad05b2c4eab9349b8321b14703165bd3fb8b034dfb8be98ae5"
        );
        assert_eq!(
            sign(b"shhh-very-secret", 1_700_000_000, "{\"x\":1}"),
            "77e18a0dd1a0698c1d963420492966388e474f2cdb2241340e70f1f948fe1de0"
        );
        // and the streaming construction matches the concatenated form
        let mut mac = HmacSha256::new_from_slice(b"key").unwrap();
        mac.update(b"1.body");
        assert_eq!(
            sign(b"key", 1, "body"),
            hex::encode(mac.finalize().into_bytes())
        );
    }
}

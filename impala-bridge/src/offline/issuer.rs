//! The card program issuer key: generate-only, sealed by the seed protector.
//!
//! Like the conversion-reserve seed, the issuer key is generated INSIDE the
//! bridge and never leaves it: there is no import path (an imported issuer key
//! would put mint authority for every card in a person's hands), no export, and
//! no response, log line or event ever carries private bytes — payloads carry
//! the public key and its fingerprint only.
//!
//! The sealed plaintext is `ISSUER_KEY_HEADER_MAGIC \n version \n ‖ PKCS#8`,
//! so a ciphertext copied into another version's row fails to open; on load the
//! derived public point must equal the row's `public_key_hex` (the transplant
//! defence `load_protected_seed` applies to custodial seeds).

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use log::error;
use sqlx::PgPool;
use zeroize::Zeroizing;

use crate::constants::{CARD_ISSUER_FP_KIND, CARD_ISSUER_FP_PART, ISSUER_KEY_HEADER_MAGIC};
use crate::error::AppError;
use crate::seed_protect::{ProtectedSeed, ProtectorBackend, SeedProtector};

/// The active row, locked for the generate transaction.
pub(crate) const ISSUER_ACTIVE_FOR_UPDATE_SQL: &str =
    "SELECT version, fingerprint FROM card_issuer_key WHERE state = 'active' FOR UPDATE";

/// Next version, predicted; the primary key arbitrates a race.
pub(crate) const ISSUER_NEXT_VERSION_SQL: &str =
    "SELECT COALESCE(MAX(version), 0) + 1 FROM card_issuer_key";

/// Guarded: only the active row moves, and only to superseded.
pub(crate) const ISSUER_SUPERSEDE_SQL: &str = "UPDATE card_issuer_key SET state = 'superseded', \
     superseded_at = CURRENT_TIMESTAMP WHERE state = 'active'";

/// Ten binds and one literal (`'active'`); pinned by `issuer_insert_binds_ten_with_one_literal`.
pub(crate) const ISSUER_INSERT_SQL: &str = "INSERT INTO card_issuer_key (version, state, backend, \
     ciphertext, wrapped_data_key, nonce, key_id, key_version, public_key_hex, fingerprint, \
     generated_by) VALUES ($1, 'active', $2, $3, $4, $5, $6, $7, $8, $9, $10)";

/// Mints the program identity with the FIRST key and never changes it after
/// (`COALESCE`): rotation keeps program_id and redemption_uuid.
pub(crate) const POLICY_MINT_IDENTITY_SQL: &str = "UPDATE offline_policy SET \
     program_id = COALESCE(program_id, $1), \
     redemption_uuid = COALESCE(redemption_uuid, gen_random_uuid()), \
     updated_by = $2 WHERE id RETURNING program_id, redemption_uuid";

/// Program identity read (public data).
pub(crate) const POLICY_IDENTITY_SQL: &str =
    "SELECT program_id, redemption_uuid FROM offline_policy WHERE id";

/// Loads sealed material for one version (or the active one when `$1` is NULL).
pub(crate) const ISSUER_LOAD_SQL: &str = "SELECT version, state, backend, ciphertext, \
     wrapped_data_key, nonce, key_id, key_version, public_key_hex FROM card_issuer_key \
     WHERE ($1::INTEGER IS NULL AND state = 'active') OR version = $1";

/// Write-once certificate unless `$6` (recertify); guarded on the active row.
pub(crate) const CERTIFY_SQL: &str = "UPDATE card SET issuer_cert_hex = $2, \
     cert_issuer_version = $3, currency = $4, card_minor_scale = $5, \
     certified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
     WHERE card_id = $1 AND is_delete = FALSE AND (issuer_cert_hex IS NULL OR $6)";

/// A loaded issuer signing key. Never printed; dropped with the request.
pub(crate) struct IssuerKey {
    key: EcdsaKeyPair,
}

impl std::fmt::Debug for IssuerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerKey([REDACTED])")
    }
}

impl IssuerKey {
    /// The 65-byte uncompressed public point.
    pub(crate) fn public_key(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }

    /// DER ECDSA-P256/SHA-256 over `msg`.
    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, AppError> {
        self.key
            .sign(&SystemRandom::new(), msg)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| {
                error!("card issuer: signing failed");
                AppError::InternalError("issuer signing failed".to_string())
            })
    }
}

/// Generates a fresh P-256 key: `(pkcs8, public_point)`.
pub(crate) fn generate() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AppError> {
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
        .map_err(|_| AppError::InternalError("issuer key generation failed".to_string()))?;
    let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8)
        .map_err(|_| AppError::InternalError("issuer key generation failed".to_string()))?;
    let public = key.public_key().as_ref().to_vec();
    Ok((pkcs8, public))
}

/// The bound header sealed ahead of the PKCS#8 bytes.
pub(crate) fn issuer_header(version: i32) -> String {
    format!("{}\n{}\n", ISSUER_KEY_HEADER_MAGIC, version)
}

/// `header ‖ pkcs8`, ready for `SeedProtector::encrypt_seed`.
pub(crate) fn seal(version: i32, pkcs8: &[u8]) -> Zeroizing<Vec<u8>> {
    let header = issuer_header(version);
    let mut buf = Zeroizing::new(Vec::with_capacity(header.len() + pkcs8.len()));
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(pkcs8);
    buf
}

/// Opens a decrypted blob for `version`, checking the header and that the key
/// derives `expected_public_hex`. Error strings are fixed: on a transplanted
/// blob the leading bytes are another version's private key.
pub(crate) fn open_sealed(
    version: i32,
    plaintext: &[u8],
    expected_public_hex: &str,
) -> Result<IssuerKey, AppError> {
    let header = issuer_header(version);
    if !plaintext.starts_with(header.as_bytes()) {
        error!("card issuer: key blob for version {version} failed its binding check");
        return Err(AppError::InternalError(
            "issuer key failed the binding check".to_string(),
        ));
    }
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &plaintext[header.len()..])
        .map_err(|_| AppError::InternalError("issuer key is unreadable".to_string()))?;
    let derived = hex::encode(key.public_key().as_ref());
    if !derived.eq_ignore_ascii_case(expected_public_hex.trim()) {
        error!(
            "card issuer: key for version {version} derives a different public key than its row \
             claims — REFUSING to sign"
        );
        return Err(AppError::InternalError(
            "issuer key does not match its record".to_string(),
        ));
    }
    Ok(IssuerKey { key })
}

/// `keys::fingerprint("card_issuer", "public_key", point)`.
pub(crate) fn fingerprint(public_point: &[u8]) -> String {
    crate::keys::fingerprint(CARD_ISSUER_FP_KIND, CARD_ISSUER_FP_PART, public_point)
}

type IssuerRow = (
    i32,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    String,
);

/// Loads, decrypts and verifies the issuer key (`version = None` → active).
/// Returns the key and its version. Refuses revoked and scrubbed rows.
pub(crate) async fn load_issuer_key(
    pool: &PgPool,
    protector: &dyn SeedProtector,
    version: Option<i32>,
) -> Result<(IssuerKey, i32), AppError> {
    let row: Option<IssuerRow> = sqlx::query_as(ISSUER_LOAD_SQL)
        .bind(version)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("card issuer: key lookup failed: {e}");
            AppError::InternalError("Database error".to_string())
        })?;
    let (version, state, backend_tag, ciphertext, wrapped, nonce, key_id, key_version, public_hex) =
        row.ok_or_else(|| AppError::Conflict("No card issuer key; generate one first".to_string()))?;
    if state == "revoked" {
        return Err(AppError::Conflict(
            "The card issuer key is revoked".to_string(),
        ));
    }
    let ciphertext = ciphertext.ok_or_else(|| {
        AppError::Conflict("The card issuer key material was scrubbed".to_string())
    })?;
    let backend = ProtectorBackend::from_tag(&backend_tag)
        .ok_or_else(|| AppError::InternalError("Corrupt issuer key record".to_string()))?;
    if backend != protector.backend() {
        error!(
            "card issuer: key backend '{}' != configured backend '{}'",
            backend.as_str(),
            protector.backend().as_str()
        );
        return Err(AppError::InternalError(
            "issuer key protection backend mismatch".to_string(),
        ));
    }
    let raw = protector
        .decrypt_seed(&ProtectedSeed {
            backend,
            ciphertext,
            wrapped_data_key: wrapped,
            nonce,
            key_id: key_id.unwrap_or_default(),
            key_version,
        })
        .await?;
    let key = open_sealed(version, raw.as_slice(), &public_hex)?;
    Ok((key, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_round_trips_through_its_sealed_form_and_signs_verifiably() {
        let (pkcs8, public) = generate().unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);
        let sealed = seal(3, &pkcs8);
        assert!(sealed.starts_with(b"impala-issuer-v1\n3\n"));
        let key = open_sealed(3, &sealed, &hex::encode(&public)).unwrap();
        let sig = key.sign(b"message").unwrap();
        assert!(crate::offline::signable::verify_p256(
            &public, b"message", &sig
        ));
        assert_eq!(format!("{key:?}"), "IssuerKey([REDACTED])");
    }

    #[test]
    fn a_blob_moved_to_another_version_or_row_fails_to_open() {
        let (pkcs8, public) = generate().unwrap();
        let (_, other_public) = generate().unwrap();
        let sealed = seal(1, &pkcs8);
        let e = open_sealed(2, &sealed, &hex::encode(&public)).unwrap_err();
        assert!(e.to_string().contains("binding check"));
        let e = open_sealed(1, &sealed, &hex::encode(&other_public)).unwrap_err();
        assert!(e.to_string().contains("does not match its record"));
        // Error strings never echo key bytes.
        assert!(!e.to_string().contains(&hex::encode(&pkcs8[..8])));
    }

    #[test]
    fn issuer_insert_binds_ten_with_one_literal() {
        let cols = ISSUER_INSERT_SQL
            .split('(')
            .nth(1)
            .unwrap()
            .split(')')
            .next()
            .unwrap()
            .split(',')
            .count();
        assert_eq!(cols, 11);
        for n in 1..=10 {
            assert!(ISSUER_INSERT_SQL.contains(&format!("${n}")), "missing ${n}");
        }
        assert!(!ISSUER_INSERT_SQL.contains("$11"));
        assert!(ISSUER_INSERT_SQL.contains("($1, 'active', $2,"));
    }

    #[test]
    fn mutations_are_guarded() {
        assert!(ISSUER_SUPERSEDE_SQL.contains("WHERE state = 'active'"));
        assert!(CERTIFY_SQL.contains("is_delete = FALSE"));
        assert!(CERTIFY_SQL.contains("(issuer_cert_hex IS NULL OR $6)"));
        assert!(POLICY_MINT_IDENTITY_SQL.contains("program_id = COALESCE(program_id, $1)"));
        assert!(POLICY_MINT_IDENTITY_SQL.contains("COALESCE(redemption_uuid, gen_random_uuid())"));
    }

    /// Every column the SQL names exists in migration 039 (no DB-executing
    /// tests: schema-vs-query drift is otherwise a runtime failure).
    #[test]
    fn sql_columns_exist_in_migration_039() {
        let ddl = include_str!("../../migrations/039_card_issuer.sql");
        for col in [
            "version",
            "state",
            "backend",
            "ciphertext",
            "wrapped_data_key",
            "nonce",
            "key_id",
            "key_version",
            "public_key_hex",
            "fingerprint",
            "generated_by",
            "superseded_at",
            "program_id",
            "redemption_uuid",
            "updated_by",
            "issuer_cert_hex",
            "cert_issuer_version",
            "currency",
            "card_minor_scale",
            "certified_at",
        ] {
            assert!(
                ddl.contains(&format!("    {col} ")) || ddl.contains(&format!("{col} ")),
                "{col}"
            );
        }
    }
}

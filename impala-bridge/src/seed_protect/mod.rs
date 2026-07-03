//! Pluggable protection for custodial Stellar secret seeds.
//!
//! A [`SeedProtector`] turns a plaintext seed into a [`ProtectedSeed`] (ciphertext
//! and metadata safe to persist in Postgres) and back. Two interchangeable
//! backends are selected per-deployment via `SEED_PROTECTION_BACKEND`:
//!
//! - **kms**  — AWS KMS envelope encryption (`GenerateDataKey` + local AES-256-GCM).
//! - **vault** / **openbao** — HashiCorp Vault or OpenBao Transit engine
//!   (`transit/encrypt|decrypt`). OpenBao is an API-compatible Vault fork, so both
//!   values map to the same backend and persist the canonical `vault` tag (the
//!   ciphertexts are byte-identical and mutually decryptable).
//!
//! Security invariants (do not weaken):
//! - Plaintext seeds live only inside [`SecretBytes`], which zeroizes on drop.
//! - Every backend fails **closed**: any error maps to [`AppError::InternalError`]
//!   with a generic message; the cause is logged but the seed never is.
//! - The `none` backend hard-disables the feature (every call errors).

use std::sync::Arc;

use async_trait::async_trait;
use zeroize::ZeroizeOnDrop;

use crate::config::Config;
use crate::error::AppError;

pub mod kms;
pub mod vault;

/// Plaintext secret-seed bytes that are scrubbed from memory on drop.
///
/// The "seed bytes" carried here are the UTF-8 bytes of a Stellar `S...` strkey,
/// which round-trips through [`crate::stellar::StellarSigner`].
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

// Never render seed material in logs / debug output.
impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

/// Which backend produced (and can decrypt) a [`ProtectedSeed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectorBackend {
    Kms,
    Vault,
}

impl ProtectorBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectorBackend::Kms => "kms",
            ProtectorBackend::Vault => "vault",
        }
    }

    /// Parse the persisted `backend` tag from the `managed_seed` table.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "kms" => Some(ProtectorBackend::Kms),
            "vault" => Some(ProtectorBackend::Vault),
            _ => None,
        }
    }
}

/// Encrypted seed plus the metadata required to decrypt it later. Every field is
/// safe to persist in the `managed_seed` table; none of it is plaintext.
#[derive(Clone)]
pub struct ProtectedSeed {
    pub backend: ProtectorBackend,
    /// AES-GCM ciphertext (KMS) or the `vault:vN:...` token bytes (Vault).
    pub ciphertext: Vec<u8>,
    /// KMS-encrypted data key (KMS backend only).
    pub wrapped_data_key: Option<Vec<u8>>,
    /// AES-GCM nonce (KMS backend only).
    pub nonce: Option<Vec<u8>>,
    /// KMS key ARN/id or Vault transit key name.
    pub key_id: String,
    /// Vault transit key version (parsed from the ciphertext token), if any.
    pub key_version: Option<String>,
}

// Ciphertext is not plaintext, but redact anyway to keep key material out of logs.
impl std::fmt::Debug for ProtectedSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedSeed")
            .field("backend", &self.backend)
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// Backend that turns plaintext seeds into [`ProtectedSeed`]s and back.
#[async_trait]
pub trait SeedProtector: Send + Sync {
    async fn encrypt_seed(&self, plaintext: &[u8]) -> Result<ProtectedSeed, AppError>;
    async fn decrypt_seed(&self, protected: &ProtectedSeed) -> Result<SecretBytes, AppError>;
    fn backend(&self) -> ProtectorBackend;
}

/// Disabled backend: present when `SEED_PROTECTION_BACKEND=none` so the custodial
/// endpoints fail closed instead of panicking on a missing extension.
pub struct NoneProtector;

#[async_trait]
impl SeedProtector for NoneProtector {
    async fn encrypt_seed(&self, _plaintext: &[u8]) -> Result<ProtectedSeed, AppError> {
        Err(AppError::InternalError(
            "custodial seed protection is not configured".to_string(),
        ))
    }
    async fn decrypt_seed(&self, _protected: &ProtectedSeed) -> Result<SecretBytes, AppError> {
        Err(AppError::InternalError(
            "custodial seed protection is not configured".to_string(),
        ))
    }
    fn backend(&self) -> ProtectorBackend {
        // Arbitrary; NoneProtector never produces a persisted seed.
        ProtectorBackend::Kms
    }
}

/// Build the configured seed protector once at startup.
///
/// Returns `Err` (so the caller can fail-closed and exit) when a backend is
/// selected but its required configuration is missing.
pub async fn build_protector(config: &Config) -> Result<Arc<dyn SeedProtector>, String> {
    match config.seed_protection_backend.as_str() {
        "kms" => {
            let key_id = config.kms_seed_key_id.clone().ok_or_else(|| {
                "SEED_PROTECTION_BACKEND=kms requires KMS_SEED_KEY_ID".to_string()
            })?;
            Ok(Arc::new(kms::KmsSeedProtector::new(key_id).await))
        }
        // OpenBao is an API-compatible Vault fork: same Transit endpoints, header,
        // and `vault:vN:` ciphertext. Both map to the one Transit protector, whose
        // `backend()` reports `Vault` so the persisted tag (and the decrypt-time
        // backend-match check in handlers/managed_seed) stays stable across labels.
        "vault" | "openbao" => {
            let protector = vault::VaultSeedProtector::from_config(config).await?;
            Ok(Arc::new(protector))
        }
        "none" | "" => Ok(Arc::new(NoneProtector)),
        other => Err(format!(
            "unknown SEED_PROTECTION_BACKEND '{}' (expected kms|vault|openbao|none)",
            other
        )),
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Deterministic in-memory protector for unit tests (no AWS/Vault/network).
    ///
    /// "Encryption" is a reversible byte rotation — enough to prove the
    /// encrypt → store → decrypt round-trip and the ownership/zeroize plumbing
    /// without any external dependency. NOT for production use.
    pub struct MockProtector;

    #[async_trait]
    impl SeedProtector for MockProtector {
        async fn encrypt_seed(&self, plaintext: &[u8]) -> Result<ProtectedSeed, AppError> {
            let ciphertext: Vec<u8> = plaintext.iter().map(|b| b.wrapping_add(1)).collect();
            Ok(ProtectedSeed {
                backend: ProtectorBackend::Kms,
                ciphertext,
                wrapped_data_key: Some(vec![0xAB]),
                nonce: Some(vec![0u8; 12]),
                key_id: "mock-key".to_string(),
                key_version: None,
            })
        }
        async fn decrypt_seed(&self, protected: &ProtectedSeed) -> Result<SecretBytes, AppError> {
            let plaintext: Vec<u8> = protected
                .ciphertext
                .iter()
                .map(|b| b.wrapping_sub(1))
                .collect();
            Ok(SecretBytes::new(plaintext))
        }
        fn backend(&self) -> ProtectorBackend {
            ProtectorBackend::Kms
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::MockProtector;
    use super::*;

    #[tokio::test]
    async fn test_mock_protector_round_trip() {
        let protector = MockProtector;
        let seed = b"SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let protected = protector.encrypt_seed(seed).await.unwrap();
        assert_ne!(protected.ciphertext, seed.to_vec());
        let decrypted = protector.decrypt_seed(&protected).await.unwrap();
        assert_eq!(decrypted.as_slice(), seed);
    }

    #[tokio::test]
    async fn test_none_protector_fails_closed() {
        let protector = NoneProtector;
        assert!(protector.encrypt_seed(b"seed").await.is_err());
        let dummy = ProtectedSeed {
            backend: ProtectorBackend::Kms,
            ciphertext: vec![1, 2, 3],
            wrapped_data_key: None,
            nonce: None,
            key_id: "x".to_string(),
            key_version: None,
        };
        assert!(protector.decrypt_seed(&dummy).await.is_err());
    }

    #[tokio::test]
    async fn test_openbao_routes_to_vault_backend() {
        // "openbao" must reach the Transit (vault) arm, not the unknown-backend arm.
        // With vault_addr unset, from_config returns the addr-required error before
        // any network/token work, proving routing reached the vault arm.
        let mut config = crate::config::test_config();
        config.seed_protection_backend = "openbao".to_string();
        config.vault_addr = None;
        // Can't `unwrap_err()` — the Ok type `Arc<dyn SeedProtector>` isn't `Debug`.
        let err = match build_protector(&config).await {
            Ok(_) => panic!("openbao backend built without an address"),
            Err(e) => e,
        };
        assert!(
            err.contains("VAULT_ADDR") || err.contains("BAO_ADDR"),
            "expected addr-required error, got: {err}"
        );
        assert!(
            !err.contains("unknown SEED_PROTECTION_BACKEND"),
            "openbao fell through to unknown-backend arm: {err}"
        );
    }

    #[test]
    fn test_secret_bytes_debug_is_redacted() {
        let s = SecretBytes::new(b"super-secret-seed".to_vec());
        let rendered = format!("{:?}", s);
        assert!(!rendered.contains("super-secret-seed"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn test_protected_seed_debug_is_redacted() {
        let p = ProtectedSeed {
            backend: ProtectorBackend::Vault,
            ciphertext: b"vault:v1:abcdef".to_vec(),
            wrapped_data_key: None,
            nonce: None,
            key_id: "transit-seeds".to_string(),
            key_version: Some("1".to_string()),
        };
        let rendered = format!("{:?}", p);
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("abcdef"));
    }

    #[test]
    fn test_backend_as_str() {
        assert_eq!(ProtectorBackend::Kms.as_str(), "kms");
        assert_eq!(ProtectorBackend::Vault.as_str(), "vault");
    }
}

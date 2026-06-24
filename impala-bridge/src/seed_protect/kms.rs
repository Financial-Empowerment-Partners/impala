//! AWS KMS envelope-encryption backend for [`SeedProtector`].
//!
//! Encryption: ask KMS for a fresh data key (`GenerateDataKey`, AES-256), encrypt
//! the seed locally with AES-256-GCM under the plaintext data key, then persist
//! the KMS-wrapped data key + nonce + ciphertext. The plaintext data key is
//! zeroized immediately. Decryption reverses it via KMS `Decrypt`.
//!
//! The plaintext seed only ever exists inside the KMS HSM boundary (the data key)
//! and this process's memory for the duration of one operation.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use log::error;
use rand::RngCore;
use zeroize::Zeroizing;

use super::{ProtectedSeed, ProtectorBackend, SecretBytes, SeedProtector};
use crate::error::AppError;

const NONCE_LEN: usize = 12;

/// Generic, non-leaking failure surfaced to clients. The cause is logged; the
/// seed and key material never are.
fn protect_error(context: &str, cause: impl std::fmt::Display) -> AppError {
    error!("kms seed protection: {}: {}", context, cause);
    AppError::InternalError("seed protection unavailable".to_string())
}

pub struct KmsSeedProtector {
    client: aws_sdk_kms::Client,
    key_id: String,
}

impl KmsSeedProtector {
    /// Build a KMS-backed protector. Loads AWS config from the default provider
    /// chain (IAM task role on ECS), so requires `kms:GenerateDataKey`,
    /// `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` on `key_id`.
    pub async fn new(key_id: String) -> Self {
        let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        KmsSeedProtector {
            client: aws_sdk_kms::Client::new(&aws_config),
            key_id,
        }
    }
}

#[async_trait]
impl SeedProtector for KmsSeedProtector {
    async fn encrypt_seed(&self, plaintext: &[u8]) -> Result<ProtectedSeed, AppError> {
        // 1. Generate a fresh AES-256 data key wrapped by the CMK.
        let data_key = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| protect_error("generate_data_key", e))?;

        let plaintext_key = Zeroizing::new(
            data_key
                .plaintext
                .ok_or_else(|| protect_error("generate_data_key", "missing plaintext key"))?
                .into_inner(),
        );
        let wrapped_data_key = data_key
            .ciphertext_blob
            .ok_or_else(|| protect_error("generate_data_key", "missing wrapped key"))?
            .into_inner();

        // 2. AES-256-GCM encrypt the seed under the data key with a random nonce.
        let cipher =
            Aes256Gcm::new_from_slice(&plaintext_key).map_err(|e| protect_error("aes init", e))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| protect_error("aes encrypt", e))?;

        Ok(ProtectedSeed {
            backend: ProtectorBackend::Kms,
            ciphertext,
            wrapped_data_key: Some(wrapped_data_key),
            nonce: Some(nonce_bytes.to_vec()),
            key_id: self.key_id.clone(),
            key_version: None,
        })
    }

    async fn decrypt_seed(&self, protected: &ProtectedSeed) -> Result<SecretBytes, AppError> {
        let wrapped = protected
            .wrapped_data_key
            .as_ref()
            .ok_or_else(|| protect_error("decrypt", "missing wrapped data key"))?;
        let nonce = protected
            .nonce
            .as_ref()
            .ok_or_else(|| protect_error("decrypt", "missing nonce"))?;
        if nonce.len() != NONCE_LEN {
            return Err(protect_error("decrypt", "bad nonce length"));
        }

        // 1. Unwrap the data key via KMS.
        let decrypted = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(wrapped.clone()))
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| protect_error("kms decrypt", e))?;
        let plaintext_key = Zeroizing::new(
            decrypted
                .plaintext
                .ok_or_else(|| protect_error("kms decrypt", "missing plaintext key"))?
                .into_inner(),
        );

        // 2. AES-256-GCM decrypt the seed.
        let cipher =
            Aes256Gcm::new_from_slice(&plaintext_key).map_err(|e| protect_error("aes init", e))?;
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce);
        let nonce = Nonce::from(nonce_arr);
        let plaintext = cipher
            .decrypt(&nonce, protected.ciphertext.as_ref())
            .map_err(|e| protect_error("aes decrypt", e))?;

        Ok(SecretBytes::new(plaintext))
    }

    fn backend(&self) -> ProtectorBackend {
        ProtectorBackend::Kms
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Validates the local AES-256-GCM envelope step (the KMS data-key half needs
    // live AWS, so it is exercised only in the e2e flow). Deterministic key+nonce.
    #[test]
    fn test_aes_gcm_round_trip() {
        let key = [7u8; 32];
        let nonce = [0u8; 12];
        let seed = b"SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let n = Nonce::from(nonce);
        let ct = cipher.encrypt(&n, seed.as_ref()).unwrap();
        assert_ne!(ct, seed.to_vec());
        let pt = cipher.decrypt(&n, ct.as_ref()).unwrap();
        assert_eq!(pt, seed.to_vec());
    }

    #[test]
    fn test_aes_gcm_tamper_detected() {
        let key = [9u8; 32];
        let nonce = [1u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let n = Nonce::from(nonce);
        let mut ct = cipher.encrypt(&n, b"seed".as_ref()).unwrap();
        ct[0] ^= 0xFF; // flip a byte
        assert!(cipher.decrypt(&n, ct.as_ref()).is_err());
    }
}

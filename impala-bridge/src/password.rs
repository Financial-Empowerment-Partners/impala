//! Argon2 operations offloaded via `spawn_blocking`.
//!
//! `password_auth`'s argon2 hashing/verification is pure CPU work in the
//! tens-of-milliseconds range; running it inline on a tokio worker thread
//! stalls every other task scheduled there. These wrappers move the work to
//! the blocking pool while preserving the handlers' timing-equalization
//! behavior on the account-not-found path.

use log::error;
use password_auth::{generate_hash, verify_password};

use crate::error::AppError;

/// Hash a password (registration / federated-account provisioning).
pub async fn hash_password(password: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || generate_hash(password))
        .await
        .map_err(|e| {
            error!("hash_password: blocking task failed: {e}");
            AppError::InternalError("Internal error".to_string())
        })
}

/// Verify a password against a stored argon2 hash. `Ok(false)` is a wrong
/// password; `Err` is an infrastructure failure.
pub async fn verify_password_async(password: String, hash: String) -> Result<bool, AppError> {
    tokio::task::spawn_blocking(move || verify_password(password, &hash).is_ok())
        .await
        .map_err(|e| {
            error!("verify_password_async: blocking task failed: {e}");
            AppError::InternalError("Internal error".to_string())
        })
}

/// Account-not-found timing equalizer: performs the SAME work as the real
/// verification path (generate_hash + verify_password on dummy inputs), just
/// off-runtime. Do not "optimize" this to a precomputed hash — that would
/// change the timing profile this exists to preserve.
pub async fn dummy_verify() {
    let result = tokio::task::spawn_blocking(|| {
        let dummy_hash = generate_hash("dummy-password-for-timing");
        let _ = verify_password("not-the-real-password", &dummy_hash);
    })
    .await;
    if let Err(e) = result {
        // The response is already the generic "Invalid credentials".
        error!("dummy_verify: blocking task failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_then_verify_roundtrip() {
        let hash = hash_password("correct horse battery staple".to_string())
            .await
            .expect("hashing succeeds");
        assert!(
            verify_password_async("correct horse battery staple".to_string(), hash.clone())
                .await
                .expect("verification runs")
        );
        assert!(!verify_password_async("wrong password".to_string(), hash)
            .await
            .expect("verification runs"));
    }

    #[tokio::test]
    async fn dummy_verify_completes() {
        dummy_verify().await;
    }

    /// Smoke check that verification does not stall the multi-thread runtime:
    /// a concurrent timer task must keep making progress while argon2 runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_does_not_block_runtime() {
        let hash = hash_password("pw".to_string()).await.expect("hash");
        let verify = tokio::spawn(verify_password_async("pw".to_string(), hash));
        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        })
        .await
        .expect("runtime stayed responsive while argon2 ran");
        assert!(verify.await.expect("join").expect("verify"));
    }
}

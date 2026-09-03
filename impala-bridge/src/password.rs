//! Argon2 operations offloaded via `spawn_blocking`, under a global
//! concurrency bound.
//!
//! Two properties here are load-bearing:
//!
//! - **Bounded amplification.** Every argon2id run costs ~19 MiB and ~10 ms
//!   of CPU (argon2 0.5 defaults via `password-auth`). The pre-auth
//!   endpoints are throttled per *username*, so an unauthenticated caller who
//!   rotates usernames gets a fresh budget each time and can hold hundreds of
//!   blocking threads inside argon2 at once — enough to OOM a task. The
//!   semaphore caps concurrent runs; when the bridge is saturated the request
//!   is shed with 503 (`Retryable`) rather than the process falling over. The
//!   permit is MOVED INTO the blocking closure: a request timeout drops the
//!   async future but the blocking thread keeps running, so a permit held
//!   only by the future would be released before the memory was.
//! - **No existence oracle.** The account-not-found path performs exactly
//!   ONE verify against a precomputed dummy hash — the same work as a real
//!   verify against a stored hash — so response time does not reveal whether
//!   an account exists. (The previous generate+verify pair took twice as long
//!   as the real path: an oracle that inverted its own intent.) Both paths
//!   shed identically under saturation for the same reason.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use log::{error, warn};
use password_auth::{generate_hash, verify_password};
use tokio::sync::Semaphore;

use crate::constants::{ARGON2_MAX_CONCURRENT, ARGON2_QUEUE_WAIT_SECS};
use crate::error::AppError;

fn limiter() -> &'static Arc<Semaphore> {
    static LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(Semaphore::new(ARGON2_MAX_CONCURRENT)))
}

/// A PHC string minted once with the same `Argon2::default()` parameters
/// fresh hashes use, so verifying against it costs what a real verify costs.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| generate_hash("dummy-password-for-timing"))
}

/// Run one argon2 operation on the blocking pool under the global bound.
/// Waits briefly for a permit to absorb bursts, then sheds with 503.
async fn run_bounded<T, F>(f: F, context: &'static str) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_bounded_on(limiter().clone(), f, context).await
}

/// [`run_bounded`] against an explicit semaphore (the global one in
/// production; a private one in the saturation test so it cannot starve
/// tests running in parallel).
async fn run_bounded_on<T, F>(
    sem: Arc<Semaphore>,
    f: F,
    context: &'static str,
) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = match tokio::time::timeout(
        Duration::from_secs(ARGON2_QUEUE_WAIT_SECS),
        sem.acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            error!("{}: argon2 semaphore closed", context);
            return Err(AppError::InternalError("Internal error".to_string()));
        }
        Err(_) => {
            warn!(
                "{}: argon2 concurrency bound ({}) saturated for {}s; shedding request",
                context, ARGON2_MAX_CONCURRENT, ARGON2_QUEUE_WAIT_SECS
            );
            return Err(AppError::Retryable(
                "Service busy; retry shortly".to_string(),
            ));
        }
    };
    tokio::task::spawn_blocking(move || {
        // Held for the whole run, on the thread that does the work.
        let _permit = permit;
        f()
    })
    .await
    .map_err(|e| {
        error!("{}: blocking task failed: {e}", context);
        AppError::InternalError("Internal error".to_string())
    })
}

/// Hash a password (registration / federated-account provisioning).
pub async fn hash_password(password: String) -> Result<String, AppError> {
    run_bounded(move || generate_hash(password), "hash_password").await
}

/// Verify a password against a stored argon2 hash. `Ok(false)` is a wrong
/// password; `Err` is an infrastructure failure or load shedding.
pub async fn verify_password_async(password: String, hash: String) -> Result<bool, AppError> {
    run_bounded(
        move || verify_password(password, &hash).is_ok(),
        "verify_password",
    )
    .await
}

/// Account-not-found timing equalizer: exactly the work of one real verify
/// (a single `verify_password` against a precomputed hash of the same cost),
/// under the same bound, so a missing account is indistinguishable from a
/// wrong password — including under load shedding, which is why this
/// propagates the error instead of swallowing it.
pub async fn dummy_verify() -> Result<(), AppError> {
    run_bounded(
        || {
            let _ = verify_password("not-the-real-password", dummy_hash());
        },
        "dummy_verify",
    )
    .await
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
        dummy_verify().await.expect("dummy verify runs");
    }

    #[tokio::test]
    async fn dummy_hash_is_a_real_argon2_phc_of_current_params() {
        // The equalizer only equalizes if the dummy hash carries the same
        // cost parameters as a freshly minted hash.
        // "$argon2id$v=19$m=...,t=...,p=...$salt$hash": the first three
        // fields are the algorithm, version and cost parameters.
        let fresh = generate_hash("x");
        let params = |h: &str| h.split('$').take(4).collect::<Vec<_>>().join("$");
        assert_eq!(params(dummy_hash()), params(&fresh));
        assert!(dummy_hash().starts_with("$argon2"));
    }

    /// The bound is a real bound: with every permit held, a verify sheds
    /// (Retryable) instead of running — this is the property that stops an
    /// unauthenticated caller from OOMing the task.
    #[tokio::test]
    async fn saturated_bound_sheds_instead_of_running() {
        // A private one-permit semaphore: the global limiter is shared with
        // every other test in this process.
        let sem = Arc::new(Semaphore::new(1));
        let held = sem
            .clone()
            .acquire_owned()
            .await
            .expect("acquire the permit");
        let started = std::time::Instant::now();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let r = run_bounded_on(
            sem.clone(),
            move || flag.store(true, std::sync::atomic::Ordering::SeqCst),
            "test",
        )
        .await;
        assert!(matches!(r, Err(AppError::Retryable(_))), "{:?}", r);
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "work ran while saturated"
        );
        // Shed after the bounded wait, never before it (bursts get a chance).
        assert!(started.elapsed() >= Duration::from_secs(ARGON2_QUEUE_WAIT_SECS));
        drop(held);
        let flag = ran.clone();
        run_bounded_on(
            sem,
            move || flag.store(true, std::sync::atomic::Ordering::SeqCst),
            "test",
        )
        .await
        .expect("runs once a permit is free");
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Smoke check that verification does not stall the multi-thread runtime:
    /// a hash+verify round trip completes while an unrelated timer task keeps
    /// ticking (the whole reason this module exists).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn does_not_block_the_runtime() {
        let ticker = tokio::spawn(async {
            let mut n = 0u32;
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                n += 1;
            }
            n
        });
        let hash = hash_password("pw".to_string()).await.unwrap();
        assert!(verify_password_async("pw".to_string(), hash).await.unwrap());
        assert_eq!(ticker.await.unwrap(), 3);
    }
}

use deadpool_redis::Pool as RedisPool;
use log::{error, warn};
use redis::AsyncCommands;

use crate::constants::LOCKOUT_DURATION_SECS;
use crate::error::AppError;

/// Check whether the caller has exceeded the rate limit for the given scope and
/// identity.  When Redis is unavailable the request is **rejected** (fail-closed).
pub async fn check_rate_limit(
    pool: &RedisPool,
    scope: &str,
    id: &str,
    max_requests: u64,
    window_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("check_rate_limit: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:rate:{scope}:{id}");

    // A missing key (Nil) means zero prior requests; only a real Redis error is
    // fail-closed. Decoding Nil straight into u64 would error, so read Option.
    let count: u64 = conn
        .get::<_, Option<u64>>(&key)
        .await
        .map_err(|e| {
            warn!("check_rate_limit: Redis GET failed for {}: {}", key, e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?
        .unwrap_or(0);

    if count >= max_requests {
        return Err(AppError::RateLimited {
            retry_after: window_secs as u64,
        });
    }

    let _: i64 = conn.incr(&key, 1u64).await.map_err(|e| {
        warn!("check_rate_limit: Redis INCR failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let _: bool = conn.expire(&key, window_secs as i64).await.map_err(|e| {
        warn!("check_rate_limit: Redis EXPIRE failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    Ok(())
}

/// Check whether the given identity is currently locked out due to repeated
/// failures.  Fails closed when Redis is unavailable.
pub async fn check_lockout(pool: &RedisPool, id: &str, threshold: u64) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("check_lockout: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:lockout:{id}");

    let count: u64 = conn
        .get::<_, Option<u64>>(&key)
        .await
        .map_err(|e| {
            warn!("check_lockout: Redis GET failed for {}: {}", key, e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?
        .unwrap_or(0);

    if count >= threshold {
        return Err(AppError::RateLimited {
            retry_after: LOCKOUT_DURATION_SECS as u64,
        });
    }

    Ok(())
}

/// Increment the lockout counter for the given identity.  Fire-and-forget: errors
/// are logged but never returned.
pub async fn increment_lockout(pool: &RedisPool, id: &str, ttl_secs: usize) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("increment_lockout: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = format!("impala:lockout:{id}");

    if let Err(e) = conn.incr::<_, u64, u64>(&key, 1).await {
        warn!("increment_lockout: Redis INCR failed for {}: {}", key, e);
        return;
    }

    if let Err(e) = conn.expire::<_, ()>(&key, ttl_secs as i64).await {
        warn!("increment_lockout: Redis EXPIRE failed for {}: {}", key, e);
    }
}

/// Clear the lockout counter for the given identity.  Fire-and-forget.
pub async fn clear_lockout(pool: &RedisPool, id: &str) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("clear_lockout: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = format!("impala:lockout:{id}");

    if let Err(e) = conn.del::<_, ()>(&key).await {
        warn!("clear_lockout: Redis DEL failed for {}: {}", key, e);
    }
}

/// Check whether MFA verification attempts have been exhausted.  Fails closed.
pub async fn check_mfa_lockout(
    pool: &RedisPool,
    account_id: &str,
    mfa_type: &str,
    threshold: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("check_mfa_lockout: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:mfa_attempts:{account_id}:{mfa_type}");

    let count: u64 = conn
        .get::<_, Option<u64>>(&key)
        .await
        .map_err(|e| {
            warn!("check_mfa_lockout: Redis GET failed for {}: {}", key, e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?
        .unwrap_or(0);

    if count >= threshold {
        return Err(AppError::RateLimited {
            retry_after: LOCKOUT_DURATION_SECS as u64,
        });
    }

    Ok(())
}

/// Increment the MFA attempt counter.  Fire-and-forget.
pub async fn increment_mfa_attempts(
    pool: &RedisPool,
    account_id: &str,
    mfa_type: &str,
    ttl_secs: usize,
) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!(
                "increment_mfa_attempts: failed to get Redis connection: {}",
                e
            );
            return;
        }
    };

    let key = format!("impala:mfa_attempts:{account_id}:{mfa_type}");

    if let Err(e) = conn.incr::<_, u64, u64>(&key, 1).await {
        warn!(
            "increment_mfa_attempts: Redis INCR failed for {}: {}",
            key, e
        );
        return;
    }

    if let Err(e) = conn.expire::<_, ()>(&key, ttl_secs as i64).await {
        warn!(
            "increment_mfa_attempts: Redis EXPIRE failed for {}: {}",
            key, e
        );
    }
}

/// Clear the MFA attempt counter after a successful verification.  Fire-and-forget.
pub async fn clear_mfa_attempts(pool: &RedisPool, account_id: &str, mfa_type: &str) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("clear_mfa_attempts: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = format!("impala:mfa_attempts:{account_id}:{mfa_type}");

    if let Err(e) = conn.del::<_, ()>(&key).await {
        warn!("clear_mfa_attempts: Redis DEL failed for {}: {}", key, e);
    }
}

/// Store a freshly-issued card-auth challenge (hex-encoded) for the given
/// card.  Fails closed: when Redis is unavailable no challenge is issued
/// (an unstored challenge could never be verified anyway).
pub async fn store_card_challenge(
    pool: &RedisPool,
    card_id: &str,
    challenge_hex: &str,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "store_card_challenge: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:card_challenge:{card_id}");

    conn.set_ex::<_, &str, ()>(&key, challenge_hex, ttl_secs as u64)
        .await
        .map_err(|e| {
            warn!(
                "store_card_challenge: Redis SET_EX failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;

    Ok(())
}

/// Atomically consume the stored card-auth challenge via GETDEL, making every
/// challenge single-use (a replayed signature finds no challenge and fails).
/// Returns `Ok(None)` when no challenge is outstanding (expired, never issued,
/// or already consumed).  Fails closed: a Redis error rejects the attempt.
pub async fn consume_card_challenge(
    pool: &RedisPool,
    card_id: &str,
) -> Result<Option<String>, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "consume_card_challenge: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:card_challenge:{card_id}");

    let challenge: Option<String> = conn.get_del(&key).await.map_err(|e| {
        warn!(
            "consume_card_challenge: Redis GETDEL failed for {}: {}",
            key, e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    Ok(challenge)
}

/// Mark a JWT as revoked, strictly: unlike [`revoke_token`], a Redis failure
/// is returned to the caller. Used where an unrecorded revocation is itself a
/// security bug (logout must not silently fail).
pub async fn revoke_token_strict(
    pool: &RedisPool,
    jti: &str,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("revoke_token_strict: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:revoked:{jti}");

    conn.set_ex::<_, &str, ()>(&key, "1", ttl_secs as u64)
        .await
        .map_err(|e| {
            warn!(
                "revoke_token_strict: Redis SET_EX failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })
}

/// Record that a refresh token's JTI has been rotated out (single-use refresh
/// tokens). Fail-closed by design: the marker write must succeed **before** a
/// replacement pair is minted, so two live refresh tokens can never coexist.
pub async fn mark_refresh_rotated(
    pool: &RedisPool,
    jti: &str,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "mark_refresh_rotated: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:rotated:{jti}");

    conn.set_ex::<_, &str, ()>(&key, "1", ttl_secs as u64)
        .await
        .map_err(|e| {
            warn!(
                "mark_refresh_rotated: Redis SET_EX failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })
}

/// Check whether a refresh token's JTI was already rotated out (reuse).
/// Fails closed: a Redis error rejects the exchange.
pub async fn is_refresh_rotated(pool: &RedisPool, jti: &str) -> Result<bool, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("is_refresh_rotated: failed to get Redis connection: {}", e);
        AppError::Unauthorized
    })?;

    let key = format!("impala:rotated:{jti}");

    conn.exists(&key).await.map_err(|e| {
        warn!("is_refresh_rotated: Redis EXISTS failed for {}: {}", key, e);
        AppError::Unauthorized
    })
}

/// Revoke an entire refresh-token family (reuse detection): every token
/// carrying this `fid` — refresh and temporal alike — is rejected from now on.
pub async fn revoke_token_family(
    pool: &RedisPool,
    fid: &str,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("revoke_token_family: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:revoked_family:{fid}");

    conn.set_ex::<_, &str, ()>(&key, "1", ttl_secs as u64)
        .await
        .map_err(|e| {
            warn!(
                "revoke_token_family: Redis SET_EX failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })
}

/// Logout-everywhere: record the bump timestamp for an account. Every JWT with
/// `iat <= epoch` and every session with `created_at <= epoch` is rejected.
/// TTL is bounded by the refresh-token lifetime — anything issued before the
/// bump has expired naturally once the key lapses.
pub async fn bump_auth_epoch(
    pool: &RedisPool,
    account_id: &str,
    now_ts: u64,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("bump_auth_epoch: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:auth_epoch:{account_id}");

    conn.set_ex::<_, u64, ()>(&key, now_ts, ttl_secs as u64)
        .await
        .map_err(|e| {
            warn!("bump_auth_epoch: Redis SET_EX failed for {}: {}", key, e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })
}

/// Read the logout-everywhere epoch for an account (None = never bumped).
/// Fails closed for the auth path.
pub async fn get_auth_epoch(pool: &RedisPool, account_id: &str) -> Result<Option<u64>, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("get_auth_epoch: failed to get Redis connection: {}", e);
        AppError::Unauthorized
    })?;

    let key = format!("impala:auth_epoch:{account_id}");

    conn.get::<_, Option<u64>>(&key).await.map_err(|e| {
        warn!("get_auth_epoch: Redis GET failed for {}: {}", key, e);
        AppError::Unauthorized
    })
}

/// Pure decision: is a token issued at `iat` killed by a logout-everywhere
/// epoch? Boundary is inclusive — a token minted in the same second as the
/// bump is revoked (fail in the closed direction).
pub fn is_iat_revoked(iat: usize, epoch: Option<u64>) -> bool {
    matches!(epoch, Some(e) if iat as u64 <= e)
}

/// One pipelined round trip validating a bearer token against every Redis
/// revocation surface: revoked JTI (logout), revoked family (refresh-token
/// reuse), and the account's logout-everywhere epoch. Fails closed.
pub async fn check_bearer_token_validity(
    pool: &RedisPool,
    jti: &str,
    fid: &str,
    account_id: &str,
    iat: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "check_bearer_token_validity: failed to get Redis connection: {}",
            e
        );
        AppError::Unauthorized
    })?;

    let (jti_revoked, family_revoked, epoch): (bool, bool, Option<u64>) = redis::pipe()
        .cmd("EXISTS")
        .arg(format!("impala:revoked:{jti}"))
        .cmd("EXISTS")
        .arg(format!("impala:revoked_family:{fid}"))
        .cmd("GET")
        .arg(format!("impala:auth_epoch:{account_id}"))
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            warn!("check_bearer_token_validity: Redis pipeline failed: {}", e);
            AppError::Unauthorized
        })?;

    if jti_revoked || family_revoked || is_iat_revoked(iat, epoch) {
        return Err(AppError::Unauthorized);
    }

    Ok(())
}

// ── Browser cookie sessions ────────────────────────────────────────────

/// Server-side session record stored as a Redis hash under
/// `impala:session:{sha256_hex(sid)}` — keyed by the *hash* of the session id
/// so a Redis dump never yields usable cookies.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub account_id: String,
    pub csrf: String,
    pub created_at: u64,
    pub is_admin: bool,
}

fn session_key(sid_hash: &str) -> String {
    format!("impala:session:{sid_hash}")
}

/// Create a session record. Fail-closed: no cookie is issued on error.
pub async fn create_session(
    pool: &RedisPool,
    sid_hash: &str,
    record: &SessionRecord,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("create_session: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = session_key(sid_hash);

    redis::pipe()
        .cmd("HSET")
        .arg(&key)
        .arg("account_id")
        .arg(&record.account_id)
        .arg("csrf")
        .arg(&record.csrf)
        .arg("created_at")
        .arg(record.created_at)
        .arg("is_admin")
        .arg(record.is_admin as u8)
        .cmd("EXPIRE")
        .arg(&key)
        .arg(ttl_secs as i64)
        .query_async::<()>(&mut conn)
        .await
        .map_err(|e| {
            warn!(
                "create_session: Redis HSET/EXPIRE failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })
}

/// Fetch a session record (None = no such session). Fails closed: a Redis
/// error rejects the request rather than treating it as logged-out-vs-in.
pub async fn get_session(
    pool: &RedisPool,
    sid_hash: &str,
) -> Result<Option<SessionRecord>, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("get_session: failed to get Redis connection: {}", e);
        AppError::Unauthorized
    })?;

    let key = session_key(sid_hash);

    let map: std::collections::HashMap<String, String> = conn.hgetall(&key).await.map_err(|e| {
        warn!("get_session: Redis HGETALL failed for {}: {}", key, e);
        AppError::Unauthorized
    })?;

    if map.is_empty() {
        return Ok(None);
    }

    let record = SessionRecord {
        account_id: map.get("account_id").cloned().unwrap_or_default(),
        csrf: map.get("csrf").cloned().unwrap_or_default(),
        created_at: map
            .get("created_at")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        is_admin: map.get("is_admin").map(|v| v == "1").unwrap_or(false),
    };

    // A record missing its core fields is corrupt — treat as absent.
    if record.account_id.is_empty() || record.csrf.is_empty() || record.created_at == 0 {
        warn!("get_session: corrupt session record at {}", key);
        return Ok(None);
    }

    Ok(Some(record))
}

/// Slide the session's idle TTL. Fire-and-forget: a failure only shortens the
/// session, which fails in the closed direction.
pub async fn touch_session(pool: &RedisPool, sid_hash: &str, ttl_secs: usize) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("touch_session: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = session_key(sid_hash);

    if let Err(e) = conn.expire::<_, ()>(&key, ttl_secs as i64).await {
        warn!("touch_session: Redis EXPIRE failed for {}: {}", key, e);
    }
}

/// Destroy a session. Fail-closed: a logout that didn't actually delete the
/// record must surface an error, never report success.
pub async fn delete_session(pool: &RedisPool, sid_hash: &str) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("delete_session: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = session_key(sid_hash);

    conn.del::<_, ()>(&key).await.map_err(|e| {
        warn!("delete_session: Redis DEL failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::is_iat_revoked;

    /// Boundary semantics of the logout-everywhere epoch: `iat == epoch` is
    /// revoked (inclusive — fail in the closed direction).
    #[test]
    fn iat_epoch_boundaries() {
        assert!(!is_iat_revoked(100, None));
        assert!(is_iat_revoked(100, Some(100)), "iat == epoch must revoke");
        assert!(is_iat_revoked(99, Some(100)));
        assert!(!is_iat_revoked(101, Some(100)));
    }

    /// Guards the `tokio-rustls-comp` feature on the `redis` crate: without
    /// TLS support compiled in, `rediss://` URLs are rejected at pool-creation
    /// time. Terraform's ElastiCache in-transit encryption rollout depends on
    /// the bridge accepting `rediss://` REDIS_URLs.
    #[tokio::test]
    async fn rediss_url_pool_creation_succeeds() {
        let cfg = deadpool_redis::Config::from_url("rediss://:password@redis.example.com:6380/0");
        let pool = cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1));
        assert!(
            pool.is_ok(),
            "rediss:// pool creation failed (is the redis `tokio-rustls-comp` feature enabled?): {:?}",
            pool.err()
        );
    }

    /// Plain redis:// URLs must keep working alongside TLS support.
    #[tokio::test]
    async fn redis_url_pool_creation_succeeds() {
        let cfg = deadpool_redis::Config::from_url("redis://:password@localhost:6379");
        assert!(cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .is_ok());
    }
}

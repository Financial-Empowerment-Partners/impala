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

    let count: u64 = conn.get(&key).await.map_err(|e| {
        warn!("check_rate_limit: Redis GET failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    if count >= max_requests {
        return Err(AppError::RateLimited {
            retry_after: window_secs as u64,
        });
    }

    let _: () = conn.incr(&key, 1u64).await.map_err(|e| {
        warn!("check_rate_limit: Redis INCR failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let _: () = conn.expire(&key, window_secs).await.map_err(|e| {
        warn!("check_rate_limit: Redis EXPIRE failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    Ok(())
}

/// Check whether the given identity is currently locked out due to repeated
/// failures.  Fails closed when Redis is unavailable.
pub async fn check_lockout(
    pool: &RedisPool,
    id: &str,
    threshold: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("check_lockout: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:lockout:{id}");

    let count: u64 = conn.get(&key).await.map_err(|e| {
        warn!("check_lockout: Redis GET failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

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

    if let Err(e) = conn.expire::<_, ()>(&key, ttl_secs).await {
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

/// Check whether a JWT has been revoked.  Fails closed: if Redis is unavailable
/// the token is treated as revoked (`Err(AppError::Unauthorized)`).
pub async fn is_token_revoked(
    pool: &RedisPool,
    jti: &str,
) -> Result<bool, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("is_token_revoked: failed to get Redis connection: {}", e);
        AppError::Unauthorized
    })?;

    let key = format!("impala:revoked:{jti}");

    let exists: bool = conn.exists(&key).await.map_err(|e| {
        warn!("is_token_revoked: Redis EXISTS failed for {}: {}", key, e);
        AppError::Unauthorized
    })?;

    Ok(exists)
}

/// Mark a JWT as revoked for the given TTL.  Fire-and-forget.
pub async fn revoke_token(pool: &RedisPool, jti: &str, ttl_secs: usize) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("revoke_token: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = format!("impala:revoked:{jti}");

    if let Err(e) = conn.set_ex::<_, &str, ()>(&key, "1", ttl_secs).await {
        warn!("revoke_token: Redis SET_EX failed for {}: {}", key, e);
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

    let count: u64 = conn.get(&key).await.map_err(|e| {
        warn!("check_mfa_lockout: Redis GET failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

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

    if let Err(e) = conn.expire::<_, ()>(&key, ttl_secs).await {
        warn!(
            "increment_mfa_attempts: Redis EXPIRE failed for {}: {}",
            key, e
        );
    }
}

/// Clear the MFA attempt counter after a successful verification.  Fire-and-forget.
pub async fn clear_mfa_attempts(
    pool: &RedisPool,
    account_id: &str,
    mfa_type: &str,
) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!(
                "clear_mfa_attempts: failed to get Redis connection: {}",
                e
            );
            return;
        }
    };

    let key = format!("impala:mfa_attempts:{account_id}:{mfa_type}");

    if let Err(e) = conn.del::<_, ()>(&key).await {
        warn!(
            "clear_mfa_attempts: Redis DEL failed for {}: {}",
            key, e
        );
    }
}

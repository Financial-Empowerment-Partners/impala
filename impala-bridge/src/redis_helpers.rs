use deadpool_redis::Pool as RedisPool;
use log::{error, warn};
use redis::AsyncCommands;

use crate::client_source::source_fingerprint;
use crate::constants::LOCKOUT_DURATION_SECS;
use crate::error::AppError;

/// Fixed-window counter step, executed server-side so the increment and the
/// window's TTL land in a single atomic operation.
///
/// A GET-then-INCR pair would let every request of a concurrent burst observe
/// the same pre-increment value and slip past the cap together; incrementing
/// first makes each caller's own count authoritative. `EXPIRE` is applied only
/// when the counter is created (`== 1`) so the window is fixed rather than
/// sliding — and because it rides the same script, a counter can never be left
/// without a TTL (which would lock the identity out permanently).
const RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"#;

/// Check whether the caller has exceeded the rate limit for the given scope and
/// identity.  When Redis is unavailable the request is **rejected** (fail-closed).
///
/// The counter is incremented *before* the comparison, so `max_requests`
/// concurrent callers cannot each read a stale count and all be admitted.
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

    let count: u64 = redis::Script::new(RATE_LIMIT_SCRIPT)
        .key(&key)
        .arg(window_secs as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| {
            warn!("check_rate_limit: Redis script failed for {}: {}", key, e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;

    // `count` includes this request, so the Nth caller within the window sees
    // `count == N`; rejecting at `> max_requests` admits exactly `max_requests`.
    if count > max_requests {
        return Err(AppError::RateLimited {
            retry_after: window_secs as u64,
        });
    }

    Ok(())
}

/// Check whether the given identity is currently locked out for this client
/// source due to repeated failures.  Fails closed when Redis is unavailable.
///
/// Lockouts are keyed on `(identity, source)` (see `client_source.rs`): a
/// guesser locks the identity only for the source it guesses from, so it
/// cannot take an operator, card or MFA identity offline from anywhere at a
/// trickle the WAF never notices. The per-identity rate limits — not this —
/// bound a guesser spread across many sources.
pub async fn check_lockout(
    pool: &RedisPool,
    id: &str,
    source: &str,
    threshold: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("check_lockout: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = lockout_key(id, source);

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

/// Increment the lockout counter for the given `(identity, source)` pair.
/// Fire-and-forget: errors are logged but never returned.
///
/// Call this only for a real guess — a wrong password against a stored one,
/// a bad signature over a live challenge, a wrong MFA code. Unknown
/// identities, federated accounts and missing challenges must not count:
/// nothing was guessed against, and counting them let a caller pre-lock an
/// identity before it was ever provisioned.
pub async fn increment_lockout(pool: &RedisPool, id: &str, source: &str, ttl_secs: usize) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("increment_lockout: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = lockout_key(id, source);

    if let Err(e) = conn.incr::<_, u64, u64>(&key, 1).await {
        warn!("increment_lockout: Redis INCR failed for {}: {}", key, e);
        return;
    }

    if let Err(e) = conn.expire::<_, ()>(&key, ttl_secs as i64).await {
        warn!("increment_lockout: Redis EXPIRE failed for {}: {}", key, e);
    }
}

/// Clear the lockout counter for the given `(identity, source)` pair after a
/// successful authentication from that source.  Fire-and-forget.
pub async fn clear_lockout(pool: &RedisPool, id: &str, source: &str) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("clear_lockout: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = lockout_key(id, source);

    if let Err(e) = conn.del::<_, ()>(&key).await {
        warn!("clear_lockout: Redis DEL failed for {}: {}", key, e);
    }
}

/// Check whether MFA verification attempts from this client source have been
/// exhausted for the `(account, mfa_type)` pair.  Fails closed. Scoped by
/// source for the same reason as `check_lockout`.
pub async fn check_mfa_lockout(
    pool: &RedisPool,
    account_id: &str,
    mfa_type: &str,
    source: &str,
    threshold: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("check_mfa_lockout: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = mfa_attempts_key(account_id, mfa_type, source);

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

/// Increment the MFA attempt counter for `(account, mfa_type, source)`.
/// Fire-and-forget. Only a wrong code against an outstanding factor counts —
/// an absent enrollment or an SMS code that was never issued is not a guess.
pub async fn increment_mfa_attempts(
    pool: &RedisPool,
    account_id: &str,
    mfa_type: &str,
    source: &str,
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

    let key = mfa_attempts_key(account_id, mfa_type, source);

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

/// Clear the MFA attempt counter for `(account, mfa_type, source)` after a
/// successful verification.  Fire-and-forget.
pub async fn clear_mfa_attempts(pool: &RedisPool, account_id: &str, mfa_type: &str, source: &str) {
    let mut conn = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            error!("clear_mfa_attempts: failed to get Redis connection: {}", e);
            return;
        }
    };

    let key = mfa_attempts_key(account_id, mfa_type, source);

    if let Err(e) = conn.del::<_, ()>(&key).await {
        warn!("clear_mfa_attempts: Redis DEL failed for {}: {}", key, e);
    }
}

/// Append a card-auth challenge entry to the card's bounded outstanding set,
/// evicting the oldest beyond `max_outstanding`, in one server-side step.
///
/// The set is a Redis list under `impala:card_challenges:{card_id}` whose
/// entries carry their own expiry (`{expires_at}:{challenge_hex}`, built by
/// `card_auth`), so several challenges can be live at once — a card UID is
/// public, and a single overwritable slot let anyone who knew one clobber the
/// legitimate holder's challenge. The key's TTL is re-armed to the challenge
/// TTL on every push: by the time it lapses every entry has expired too.
///
/// RPUSH + LTRIM + EXPIRE ride one script so the cap and the TTL can never be
/// left unapplied by a failure between commands.
const CARD_CHALLENGE_PUSH_SCRIPT: &str = r#"
redis.call('RPUSH', KEYS[1], ARGV[1])
redis.call('LTRIM', KEYS[1], -tonumber(ARGV[2]), -1)
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
"#;

/// Store a freshly-issued card-auth challenge entry for the given card.
/// Fails closed: when Redis is unavailable no challenge is issued (an
/// unstored challenge could never be verified anyway).
pub async fn push_card_challenge(
    pool: &RedisPool,
    card_id: &str,
    entry: &str,
    max_outstanding: usize,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!("push_card_challenge: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = card_challenges_key(card_id);

    let _pushed: i64 = redis::Script::new(CARD_CHALLENGE_PUSH_SCRIPT)
        .key(&key)
        .arg(entry)
        .arg(max_outstanding as i64)
        .arg(ttl_secs as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| {
            warn!(
                "push_card_challenge: Redis script failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;

    Ok(())
}

/// Read (without consuming) every outstanding challenge entry for a card,
/// oldest first. Expiry is per entry and is the caller's to check. Fails
/// closed: a Redis error rejects the attempt.
pub async fn list_card_challenges(
    pool: &RedisPool,
    card_id: &str,
) -> Result<Vec<String>, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "list_card_challenges: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = card_challenges_key(card_id);

    conn.lrange::<_, Vec<String>>(&key, 0, -1)
        .await
        .map_err(|e| {
            warn!(
                "list_card_challenges: Redis LRANGE failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })
}

/// Atomically consume exactly one outstanding challenge entry (`LREM`),
/// making every challenge single-use. Returns `Ok(true)` when this caller
/// removed it and `Ok(false)` when it was already gone — a concurrent
/// presentation of the same signature lost the race, or the entry expired
/// out from under it — which the caller must treat as a replay. Fails closed.
pub async fn consume_card_challenge(
    pool: &RedisPool,
    card_id: &str,
    entry: &str,
) -> Result<bool, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "consume_card_challenge: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = card_challenges_key(card_id);

    let removed: i64 = conn.lrem(&key, 1, entry).await.map_err(|e| {
        warn!(
            "consume_card_challenge: Redis LREM failed for {}: {}",
            key, e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    Ok(removed == 1)
}

/// A pending SMS notification-enrollment verification.
///
/// The destination is stored alongside the code so a code issued for one
/// number can never confirm another: if the row's `mobile` changed between
/// send and submit, the numbers disagree and the attempt is rejected. The
/// database trigger clears `mobile_verified_at` on such a change; this closes
/// the same gap for a code that was already in flight.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PendingNotifyVerification {
    pub code: String,
    pub mobile: String,
}

fn notify_verify_key(notify_id: i32) -> String {
    format!("impala:notify_verify:{notify_id}")
}

fn notify_verify_attempts_key(notify_id: i32) -> String {
    format!("impala:notify_verify_attempts:{notify_id}")
}

/// Store a freshly-issued SMS enrollment code for `notify_id`.
///
/// Fails closed: if Redis is unavailable no code is stored, and the caller
/// must not send an SMS it could never verify. Storing replaces any code
/// already outstanding and resets the attempt counter, so a resend gives the
/// recipient a clean slate rather than inheriting a nearly-exhausted one.
pub async fn store_notify_verification(
    pool: &RedisPool,
    notify_id: i32,
    code: &str,
    mobile: &str,
    ttl_secs: usize,
) -> Result<(), AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "store_notify_verification: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let pending = PendingNotifyVerification {
        code: code.to_string(),
        mobile: mobile.to_string(),
    };
    let encoded = serde_json::to_string(&pending).map_err(|e| {
        error!("store_notify_verification: failed to serialize: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = notify_verify_key(notify_id);
    conn.set_ex::<_, &str, ()>(&key, &encoded, ttl_secs as u64)
        .await
        .map_err(|e| {
            warn!(
                "store_notify_verification: Redis SET_EX failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;

    // Best-effort: a stale attempt counter only costs the recipient retries,
    // and failing the send over it would be worse.
    let _: Result<(), _> = conn.del(notify_verify_attempts_key(notify_id)).await;

    Ok(())
}

/// Read the pending verification for `notify_id` without consuming it.
///
/// Left in place on a wrong code so the recipient can retype it; the attempt
/// counter, not deletion, is what bounds guessing. Fails closed.
pub async fn peek_notify_verification(
    pool: &RedisPool,
    notify_id: i32,
) -> Result<Option<PendingNotifyVerification>, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "peek_notify_verification: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = notify_verify_key(notify_id);
    let raw: Option<String> = conn.get(&key).await.map_err(|e| {
        warn!(
            "peek_notify_verification: Redis GET failed for {}: {}",
            key, e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    match raw {
        None => Ok(None),
        Some(s) => match serde_json::from_str::<PendingNotifyVerification>(&s) {
            Ok(p) => Ok(Some(p)),
            Err(e) => {
                // Unreadable record: treat as absent and clear it rather than
                // wedging the row until the TTL runs out.
                warn!(
                    "peek_notify_verification: unreadable record for {}: {}",
                    key, e
                );
                let _: Result<(), _> = conn.del(&key).await;
                Ok(None)
            }
        },
    }
}

/// Discard the pending verification for `notify_id` (consumed or burned).
pub async fn clear_notify_verification(pool: &RedisPool, notify_id: i32) {
    let Ok(mut conn) = pool.get().await else {
        warn!("clear_notify_verification: failed to get Redis connection");
        return;
    };
    let _: Result<(), _> = conn.del(notify_verify_key(notify_id)).await;
    let _: Result<(), _> = conn.del(notify_verify_attempts_key(notify_id)).await;
}

/// Count a wrong code against `notify_id` and report whether the budget is now
/// spent. The counter carries the code's own TTL, so it cannot outlive it.
///
/// Fails closed: an unreadable counter is treated as exhausted, because the
/// alternative is unbounded guessing while Redis is degraded.
pub async fn increment_notify_verification_attempts(
    pool: &RedisPool,
    notify_id: i32,
    max_attempts: u64,
    ttl_secs: usize,
) -> bool {
    let Ok(mut conn) = pool.get().await else {
        warn!("increment_notify_verification_attempts: failed to get Redis connection");
        return true;
    };

    let key = notify_verify_attempts_key(notify_id);
    let attempts: Result<u64, _> = conn.incr(&key, 1u64).await;
    match attempts {
        Ok(n) => {
            if n == 1 {
                let _: Result<(), _> = conn.expire(&key, ttl_secs as i64).await;
            }
            n >= max_attempts
        }
        Err(e) => {
            warn!(
                "increment_notify_verification_attempts: Redis INCR failed for {}: {}",
                key, e
            );
            true
        }
    }
}

/// Mark a JWT as revoked, strictly: a Redis failure is returned to the
/// caller. Used where an unrecorded revocation is itself a security bug
/// (logout must not silently fail).
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

/// Atomically claim a refresh token's JTI as rotated out (single-use refresh
/// tokens). Returns `true` when this caller won the claim and may mint a
/// replacement pair, `false` when the JTI had already been rotated — which is
/// the reuse signal.
///
/// The claim is a single `SET NX EX`, not a check followed by a write: an
/// unconditional write always "succeeds" and so cannot tell the caller whether
/// it was the one that burned the token. Under concurrency that let several
/// presentations of the same refresh token each mint a live pair while reuse
/// detection stayed silent. Exactly one caller can now win, and every other
/// presentation is reported as reuse.
///
/// Fail-closed by design: the claim must succeed **before** a replacement pair
/// is minted, so two live refresh tokens can never coexist.
pub async fn claim_refresh_rotation(
    pool: &RedisPool,
    jti: &str,
    ttl_secs: usize,
) -> Result<bool, AppError> {
    let mut conn = pool.get().await.map_err(|e| {
        error!(
            "claim_refresh_rotation: failed to get Redis connection: {}",
            e
        );
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:rotated:{jti}");

    // `SET key 1 NX EX ttl` replies OK to the winner and Nil to everyone else.
    let claimed: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs as u64)
        .query_async(&mut *conn)
        .await
        .map_err(|e| {
            warn!(
                "claim_refresh_rotation: Redis SET NX failed for {}: {}",
                key, e
            );
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;

    Ok(claimed.is_some())
}

/// Atomically claim a one-time MFA code as consumed. Returns `true` if this
/// call was the first to present `code` (accept it), `false` if it was
/// already consumed (a replay — reject). The marker keys on a hash of the
/// code (never the code itself) and lives for `ttl_secs`, which the caller
/// sizes to cover the code's whole acceptance window so a valid TOTP cannot
/// be replayed anywhere inside its ±skew validity. Fail-closed: a Redis error
/// surfaces as a service error rather than silently permitting a replay.
pub async fn claim_mfa_code(
    pool: &RedisPool,
    account_id: &str,
    mfa_type: &str,
    code: &str,
    ttl_secs: usize,
) -> Result<bool, AppError> {
    use sha2::{Digest, Sha256};
    let mut conn = pool.get().await.map_err(|e| {
        error!("claim_mfa_code: failed to get Redis connection: {}", e);
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;
    let digest = hex::encode(Sha256::digest(code.as_bytes()));
    let key = format!("impala:mfa_used:{account_id}:{mfa_type}:{digest}");
    let claimed: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_secs as u64)
        .query_async(&mut *conn)
        .await
        .map_err(|e| {
            warn!("claim_mfa_code: Redis SET NX failed for {}: {}", key, e);
            AppError::InternalError("Service temporarily unavailable".to_string())
        })?;
    Ok(claimed.is_some())
}

// NOTE: there is deliberately no `is_refresh_rotated` read helper. Checking
// the marker and then writing it is two round trips, and the window between
// them is exactly where concurrent reuse slipped through undetected.
// `claim_refresh_rotation` answers "was it already rotated?" and burns it in
// one atomic step; route every rotation through that.

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
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = format!("impala:auth_epoch:{account_id}");

    conn.get::<_, Option<u64>>(&key).await.map_err(|e| {
        warn!("get_auth_epoch: Redis GET failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
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
        // Infrastructure failure, NOT a revoked token. Still fail-closed (the
        // request is rejected), but it must not masquerade as 401: callers
        // treat 401 as "this credential is dead" and discard it, so reporting
        // a Redis outage that way makes clients throw away tokens that are
        // still perfectly valid once Redis returns.
        AppError::InternalError("Service temporarily unavailable".to_string())
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
            AppError::InternalError("Service temporarily unavailable".to_string())
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
        AppError::InternalError("Service temporarily unavailable".to_string())
    })?;

    let key = session_key(sid_hash);

    let map: std::collections::HashMap<String, String> = conn.hgetall(&key).await.map_err(|e| {
        warn!("get_session: Redis HGETALL failed for {}: {}", key, e);
        AppError::InternalError("Service temporarily unavailable".to_string())
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

// Canonical Redis key builders — the single source of truth for the key
// formats. The lockout, MFA-attempt and card-challenge helpers above build
// their keys here; the rate-limit and revocation call sites still format
// theirs inline and are pinned by the tests below.

/// Construct a rate-limit Redis key for the given scope and identity.
#[allow(dead_code)]
pub(crate) fn rate_limit_key(scope: &str, id: &str) -> String {
    format!("impala:rate:{scope}:{id}")
}

/// Construct a lockout Redis key for the given `(identity, source)` pair.
/// The source rides as a fixed-width digest so IPv6 colons never enter the
/// key structure and the identity segment stays unambiguous.
pub(crate) fn lockout_key(id: &str, source: &str) -> String {
    format!("impala:lockout:{id}:{}", source_fingerprint(source))
}

/// Construct a token revocation Redis key for the given JTI.
#[allow(dead_code)]
pub(crate) fn revoked_key(jti: &str) -> String {
    format!("impala:revoked:{jti}")
}

/// Construct an MFA attempts Redis key for `(account, mfa_type, source)`.
pub(crate) fn mfa_attempts_key(account_id: &str, mfa_type: &str, source: &str) -> String {
    format!(
        "impala:mfa_attempts:{account_id}:{mfa_type}:{}",
        source_fingerprint(source)
    )
}

/// Construct the outstanding-challenge list key for a card. Deliberately a
/// different name from the retired single-slot string key
/// (`impala:card_challenge:{id}`): a rolling deploy must never RPUSH onto a
/// string the previous binary SET (WRONGTYPE).
pub(crate) fn card_challenges_key(card_id: &str) -> String {
    format!("impala:card_challenges:{card_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_rate_limit_key_format() {
        let key = rate_limit_key("auth", "user@example.com");
        assert_eq!(key, "impala:rate:auth:user@example.com");
    }

    #[test]
    fn test_rate_limit_key_token_scope() {
        let key = rate_limit_key("token", "admin");
        assert_eq!(key, "impala:rate:token:admin");
    }

    /// Lockouts are `(identity, source)`-scoped: the same identity from two
    /// sources must land on two keys, and the source rides as a fixed-width
    /// digest (an IPv6 source would otherwise inject colons into the key).
    #[test]
    fn test_lockout_key_format() {
        let key = lockout_key("user123", "203.0.113.7");
        assert_eq!(
            key,
            format!(
                "impala:lockout:user123:{}",
                source_fingerprint("203.0.113.7")
            )
        );
        assert_ne!(key, lockout_key("user123", "203.0.113.8"));
        assert_ne!(key, lockout_key("user124", "203.0.113.7"));
        let v6 = lockout_key("user123", "2001:db8::1");
        assert_eq!(v6.matches(':').count(), 3, "source must not add colons");
    }

    #[test]
    fn test_revoked_key_format() {
        let key = revoked_key("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(key, "impala:revoked:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_mfa_attempts_key_format() {
        let key = mfa_attempts_key("user1", "totp", "203.0.113.7");
        assert_eq!(
            key,
            format!(
                "impala:mfa_attempts:user1:totp:{}",
                source_fingerprint("203.0.113.7")
            )
        );
        assert_ne!(key, mfa_attempts_key("user1", "totp", "203.0.113.8"));
    }

    #[test]
    fn test_mfa_attempts_key_sms() {
        let key = mfa_attempts_key("user2", "sms", "unknown");
        assert!(key.starts_with("impala:mfa_attempts:user2:sms:"));
        assert_ne!(key, mfa_attempts_key("user2", "totp", "unknown"));
    }

    /// The challenge set must not share a key with the retired single-slot
    /// string (`impala:card_challenge:{id}`), or a rolling deploy RPUSHes
    /// onto a string and every card login fails with WRONGTYPE.
    #[test]
    fn test_card_challenges_key_is_distinct_from_legacy_slot() {
        let key = card_challenges_key("0123456789abcdef");
        assert_eq!(key, "impala:card_challenges:0123456789abcdef");
        assert_ne!(key, "impala:card_challenge:0123456789abcdef");
    }

    /// The push script keeps the newest `max` entries and re-arms the TTL —
    /// pin the three commands so a refactor cannot drop the cap or leave a
    /// list without an expiry.
    #[test]
    fn test_card_challenge_push_script_shape() {
        assert!(CARD_CHALLENGE_PUSH_SCRIPT.contains("RPUSH"));
        assert!(CARD_CHALLENGE_PUSH_SCRIPT.contains("LTRIM', KEYS[1], -tonumber(ARGV[2]), -1"));
        assert!(CARD_CHALLENGE_PUSH_SCRIPT.contains("EXPIRE', KEYS[1], ARGV[3]"));
    }

    #[test]
    fn test_key_format_consistency_with_inline_keys() {
        // Verify the helper functions produce the same keys as the inline format! calls
        // used in the async functions above
        assert!(rate_limit_key("auth", "x").starts_with("impala:rate:"));
        assert!(lockout_key("x", "s").starts_with("impala:lockout:"));
        assert!(revoked_key("x").starts_with("impala:revoked:"));
        assert!(mfa_attempts_key("x", "y", "s").starts_with("impala:mfa_attempts:"));
        assert!(card_challenges_key("x").starts_with("impala:card_challenges:"));
    }

    /// The pending record must survive a round trip intact: the stored number
    /// is what binds a code to a destination, so losing it would let a code
    /// issued for one number confirm another.
    #[test]
    fn pending_notify_verification_round_trips() {
        let pending = PendingNotifyVerification {
            code: "000123".to_string(),
            mobile: "+15551234567".to_string(),
        };
        let encoded = serde_json::to_string(&pending).unwrap();
        let decoded: PendingNotifyVerification = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.code, "000123");
        assert_eq!(decoded.mobile, "+15551234567");
    }

    #[test]
    fn notify_verification_keys_are_namespaced_and_distinct() {
        // The code and its attempt counter must never collide: one key doing
        // both jobs would let a failed attempt overwrite the code.
        assert!(notify_verify_key(7).starts_with("impala:notify_verify:"));
        assert!(notify_verify_attempts_key(7).starts_with("impala:notify_verify_attempts:"));
        assert_ne!(notify_verify_key(7), notify_verify_attempts_key(7));
    }

    #[test]
    fn notify_verification_keys_are_per_row() {
        assert_ne!(notify_verify_key(7), notify_verify_key(8));
        assert_ne!(notify_verify_attempts_key(7), notify_verify_attempts_key(8));
    }
}

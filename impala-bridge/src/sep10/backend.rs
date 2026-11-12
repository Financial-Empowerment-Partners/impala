//! The stateful operations `POST /auth/sep10` and `GET /auth/sep10` perform,
//! behind one trait so the handler's order (which gate runs when, which
//! failure counts) is tested in-process. The production implementation only
//! delegates to the shared helpers every other login path uses
//! (`redis_helpers`, `auth::issuance_role`) — every call fails closed.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use log::error;
use sqlx::PgPool;

use crate::constants::{LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD};
use crate::error::AppError;

/// The account of the ACTIVE card whose Stellar key is `$1`.
///
/// The cast is load-bearing. The column is `CHAR(56)` and sqlx binds a Rust
/// string as `text`; Postgres resolves `bpchar = text` by casting the COLUMN
/// to text, which cannot use `uq_card_active_stellar_address`, so every
/// sign-in would scan the card table. `$1::bpchar` keeps the comparison on
/// the indexed type.
pub(crate) const CARD_BY_STELLAR_ADDRESS_SQL: &str =
    "SELECT account_id FROM card WHERE stellar_address = $1::bpchar AND is_delete = FALSE";

// async_trait marks the boxed futures #[must_use] (clippy::double_must_use).
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait Sep10Backend: Send + Sync {
    /// `check_rate_limit(scope, id, max, window)`; fails closed.
    async fn rate_limit(
        &self,
        scope: &str,
        id: &str,
        max_requests: u64,
        window_secs: usize,
    ) -> Result<(), AppError>;
    /// `check_lockout(id, source, LOCKOUT_THRESHOLD)`; fails closed.
    async fn check_lockout(&self, id: &str, source: &str) -> Result<(), AppError>;
    /// One counted failure (fire-and-forget, as on every other path).
    async fn increment_lockout(&self, id: &str, source: &str);
    /// Reset after a success (fire-and-forget).
    async fn clear_lockout(&self, id: &str, source: &str);
    /// `SET impala:sep10:claim:{hash} 1 NX EX ttl`: `true` for the one winner.
    async fn claim_challenge(&self, hash_hex: &str, ttl_secs: u64) -> Result<bool, AppError>;
    /// The account of the active card registered with this Stellar address.
    async fn card_account(&self, stellar_address: &str) -> Result<Option<String>, AppError>;
    /// `auth::issuance_role` — the same role every login path stamps.
    async fn issuance_role(&self, account_id: &str) -> String;
}

/// Redis + Postgres.
pub struct LiveBackend {
    pub pool: PgPool,
    pub redis: Arc<deadpool_redis::Pool>,
    pub admin_ids: Arc<HashSet<String>>,
}

#[async_trait]
impl Sep10Backend for LiveBackend {
    async fn rate_limit(
        &self,
        scope: &str,
        id: &str,
        max_requests: u64,
        window_secs: usize,
    ) -> Result<(), AppError> {
        crate::redis_helpers::check_rate_limit(&self.redis, scope, id, max_requests, window_secs)
            .await
    }

    async fn check_lockout(&self, id: &str, source: &str) -> Result<(), AppError> {
        crate::redis_helpers::check_lockout(&self.redis, id, source, LOCKOUT_THRESHOLD).await
    }

    async fn increment_lockout(&self, id: &str, source: &str) {
        crate::redis_helpers::increment_lockout(&self.redis, id, source, LOCKOUT_DURATION_SECS)
            .await
    }

    async fn clear_lockout(&self, id: &str, source: &str) {
        crate::redis_helpers::clear_lockout(&self.redis, id, source).await
    }

    async fn claim_challenge(&self, hash_hex: &str, ttl_secs: u64) -> Result<bool, AppError> {
        crate::redis_helpers::claim_sep10_challenge(&self.redis, hash_hex, ttl_secs).await
    }

    async fn card_account(&self, stellar_address: &str) -> Result<Option<String>, AppError> {
        sqlx::query_scalar::<_, String>(CARD_BY_STELLAR_ADDRESS_SQL)
            .bind(stellar_address)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                error!("sep10: database error looking up the card: {}", e);
                AppError::InternalError("Database error".to_string())
            })
    }

    async fn issuance_role(&self, account_id: &str) -> String {
        crate::auth::issuance_role(&self.pool, &self.admin_ids, account_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_card_lookup_reads_only_active_rows_by_stellar_address() {
        assert!(CARD_BY_STELLAR_ADDRESS_SQL
            .contains("WHERE stellar_address = $1::bpchar AND is_delete = FALSE"));
        assert!(!CARD_BY_STELLAR_ADDRESS_SQL.contains("$2"));
        // The predicate of the partial unique index this lookup rides on.
        let migration = include_str!("../../migrations/040_sep10_card_keys.sql");
        assert!(migration.contains(
            "ON card(stellar_address) WHERE is_delete = FALSE AND stellar_address IS NOT NULL"
        ));
        assert!(migration.contains("stellar_address CHAR(56)"));
    }
}

//! The SEP-10 server signing key: generate-only, sealed, versioned, and held
//! at runtime by a background ring (`docs/sep10-authentication.md` §8).
//!
//! **Material.** A random 32-byte Ed25519 seed and a random 32-byte MAC key
//! (`k_mac`, which binds every challenge nonce to this key version), sealed
//! together by the seed protector as
//! `"impala-sep10-v1\n{version}\n" ‖ seed32 ‖ k_mac32`. There is no import
//! route and no export; no response, log line or event carries either half —
//! payloads carry the public address (admin responses, stellar.toml) or its
//! fingerprint (events) only. Opening checks the backend, the bound header,
//! the exact length, and that the derived public key equals the row's
//! `public_address` (the transplant defence the issuer key uses).
//!
//! **States.** `pending` (generated, not yet serving) → `activate` sets
//! `activate_at = now + SEP10_KEY_ACTIVATION_DELAY_SECS` → at that instant
//! every replica's ring switches to it (by DB clock) and the previous key
//! becomes `superseded`, still verifying its own challenges for
//! TTL + 120 s → `revoked` at any time (material scrubbed, refused at once).
//!
//! **Ring.** A background task polls the table every 30 s and decrypts only
//! versions it has not opened yet (one task: single-flight per version),
//! with a negative cache (exponential backoff 5 s → 60 s) for versions that
//! fail. Request handlers only read the latest [`RingSnapshot`]; they never
//! reach the protector, so unauthenticated traffic cannot drive KMS/Vault
//! calls. A ring that has not refreshed for 5 minutes is stale and the public
//! routes answer 503.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use hmac::{Hmac, KeyInit, Mac};
use log::{error, info, warn};
use sha2::Sha256;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::constants::{
    SEP10_DECRYPT_BACKOFF_MAX_SECS, SEP10_DECRYPT_BACKOFF_MIN_SECS, SEP10_FP_KIND, SEP10_FP_PART,
    SEP10_KEY_HEADER_MAGIC, SEP10_KEY_POLL_SECS, SEP10_RING_STALE_SECS,
    SEP10_SUPERSEDED_GRACE_MARGIN_SECS, SEP10_SUPERSEDED_SCRUB_DELAY_SECS,
};
use crate::error::AppError;
use crate::seed_protect::{ProtectedSeed, ProtectorBackend, SeedProtector};

type HmacSha256 = Hmac<Sha256>;

// ── SQL (pinned by tests; executed by the DB lane) ─────────────────────

/// Fails boot when SEP-10 is enabled but migration 040 has not run.
pub(crate) const SSK_TABLE_PRESENT_SQL: &str = "SELECT 1 FROM sep10_signing_key LIMIT 0";

/// A pending version blocks a second generation (the partial unique index
/// arbitrates a race).
pub(crate) const SSK_PENDING_FOR_UPDATE_SQL: &str =
    "SELECT version FROM sep10_signing_key WHERE state = 'pending' FOR UPDATE";

/// Next version, predicted; the primary key arbitrates a race.
pub(crate) const SSK_NEXT_VERSION_SQL: &str =
    "SELECT COALESCE(MAX(version), 0) + 1 FROM sep10_signing_key";

/// Ten binds and one literal (`'pending'`); pinned by
/// `ssk_insert_binds_ten_with_one_literal`.
pub(crate) const SSK_INSERT_SQL: &str = "INSERT INTO sep10_signing_key (version, state, backend, \
     ciphertext, wrapped_data_key, nonce, key_id, key_version, public_address, fingerprint, \
     generated_by) VALUES ($1, 'pending', $2, $3, $4, $5, $6, $7, $8, $9, $10)";

/// The active row, locked for activation.
pub(crate) const SSK_ACTIVE_FOR_UPDATE_SQL: &str =
    "SELECT version, fingerprint FROM sep10_signing_key WHERE state = 'active' FOR UPDATE";

/// One version, locked for activation or revocation.
pub(crate) const SSK_VERSION_FOR_UPDATE_SQL: &str = "SELECT state, fingerprint, \
     FLOOR(EXTRACT(EPOCH FROM activate_at))::BIGINT FROM sep10_signing_key \
     WHERE version = $1 FOR UPDATE";

/// Guarded: only an unscheduled pending row gets an activation instant, by
/// DB clock (`$2` seconds from now).
pub(crate) const SSK_SCHEDULE_ACTIVATION_SQL: &str = "UPDATE sep10_signing_key SET \
     activate_at = CURRENT_TIMESTAMP + ($2::BIGINT * INTERVAL '1 second') \
     WHERE version = $1 AND state = 'pending' AND activate_at IS NULL \
     RETURNING FLOOR(EXTRACT(EPOCH FROM activate_at))::BIGINT";

/// Guarded and total: the version leaves every serving state and its sealed
/// material is scrubbed in the same statement (`chk_ssk_scrub`).
pub(crate) const SSK_REVOKE_SQL: &str = "UPDATE sep10_signing_key SET state = 'revoked', \
     revoked_at = CURRENT_TIMESTAMP, ciphertext = NULL, wrapped_data_key = NULL, nonce = NULL, \
     scrubbed_at = CURRENT_TIMESTAMP WHERE version = $1 AND state <> 'revoked'";

/// Promotion at `activate_at` (any replica; idempotent): lock the live rows,
/// supersede the active one as of the pending row's `activate_at`, then
/// promote the pending row.
pub(crate) const SSK_LOCK_LIVE_SQL: &str =
    "SELECT version FROM sep10_signing_key WHERE state IN ('active', 'pending') FOR UPDATE";
pub(crate) const SSK_PROMOTE_SUPERSEDE_SQL: &str = "UPDATE sep10_signing_key SET \
     state = 'superseded', superseded_at = p.activate_at FROM (SELECT activate_at \
     FROM sep10_signing_key WHERE state = 'pending' AND activate_at <= CURRENT_TIMESTAMP) p \
     WHERE sep10_signing_key.state = 'active'";
pub(crate) const SSK_PROMOTE_ACTIVATE_SQL: &str = "UPDATE sep10_signing_key SET state = 'active' \
     WHERE state = 'pending' AND activate_at <= CURRENT_TIMESTAMP";

/// Housekeeping (any replica; idempotent): a superseded version's sealed
/// material is useless once its grace has passed (the ring neither accepts
/// nor decrypts it, and superseded is terminal), so it is scrubbed `$1`
/// seconds after the supersession, by DB clock. Guarded: superseded rows
/// that still hold material, nothing else (`chk_ssk_scrub`).
pub(crate) const SSK_SCRUB_SUPERSEDED_SQL: &str = "UPDATE sep10_signing_key SET \
     ciphertext = NULL, wrapped_data_key = NULL, nonce = NULL, \
     scrubbed_at = CURRENT_TIMESTAMP WHERE state = 'superseded' AND scrubbed_at IS NULL \
     AND superseded_at < CURRENT_TIMESTAMP - ($1::BIGINT * INTERVAL '1 second')";

/// The ring's metadata view (public data only).
pub(crate) const SSK_RING_LIST_SQL: &str = "SELECT version, state, public_address, fingerprint, \
     FLOOR(EXTRACT(EPOCH FROM activate_at))::BIGINT, \
     FLOOR(EXTRACT(EPOCH FROM superseded_at))::BIGINT FROM sep10_signing_key \
     WHERE state <> 'revoked' ORDER BY version";

/// The DB clock the activation fence is defined in.
pub(crate) const SSK_DB_NOW_SQL: &str =
    "SELECT FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT";

/// Sealed material for one version (never for a revoked one).
pub(crate) const SSK_MATERIAL_SQL: &str = "SELECT backend, ciphertext, wrapped_data_key, nonce, \
     key_id, key_version, public_address FROM sep10_signing_key \
     WHERE version = $1 AND state <> 'revoked'";

/// The admin inventory (public data only).
pub(crate) const SSK_ADMIN_LIST_SQL: &str = "SELECT version, state, public_address, fingerprint, \
     generated_by, generated_at, activate_at, superseded_at, revoked_at FROM sep10_signing_key \
     ORDER BY version DESC";

/// Unix seconds, local clock.
pub fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ── Key material ───────────────────────────────────────────────────────

/// An opened SEP-10 signing key. Exposes signing of a challenge hash and the
/// nonce MAC; never its seed. Never printed.
pub struct Sep10Key {
    pair: Ed25519KeyPair,
    k_mac: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl std::fmt::Debug for Sep10Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sep10Key([REDACTED])")
    }
}

impl Sep10Key {
    /// From `seed32 ‖ k_mac32`.
    pub(crate) fn from_material(material: &[u8; 64]) -> Result<Self, AppError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&material[..32])
            .map_err(|_| AppError::InternalError("sep10 key is unreadable".to_string()))?;
        let public: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| AppError::InternalError("sep10 key is unreadable".to_string()))?;
        let mut k_mac = Zeroizing::new([0u8; 32]);
        k_mac.copy_from_slice(&material[32..]);
        Ok(Sep10Key {
            pair,
            k_mac,
            public,
        })
    }

    /// The raw Ed25519 public key (the `G…` address's 32 bytes).
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The server signature over a challenge's transaction hash.
    pub fn sign_challenge_hash(&self, hash: &[u8; 32]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.pair.sign(hash).as_ref());
        out
    }

    /// `HMAC-SHA256(k_mac, data)`: the challenge nonce MAC.
    pub fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(self.k_mac.as_slice()).expect("HMAC accepts a 32-byte key");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

/// Fresh material: `(seed32 ‖ k_mac32, public)`. Both halves come from the
/// CSPRNG; the material is zeroized on drop.
pub(crate) fn generate_material() -> Result<(Zeroizing<[u8; 64]>, [u8; 32]), AppError> {
    let mut material = Zeroizing::new([0u8; 64]);
    aws_lc_rs::rand::fill(material.as_mut_slice())
        .map_err(|_| AppError::InternalError("sep10 key generation failed".to_string()))?;
    let public = Sep10Key::from_material(&material)?.public();
    Ok((material, public))
}

/// The bound header sealed ahead of the material.
pub(crate) fn sep10_header(version: i32) -> String {
    format!("{}\n{}\n", SEP10_KEY_HEADER_MAGIC, version)
}

/// `header ‖ seed32 ‖ k_mac32`, ready for `SeedProtector::encrypt_seed`.
pub(crate) fn seal(version: i32, material: &[u8; 64]) -> Zeroizing<Vec<u8>> {
    let header = sep10_header(version);
    let mut buf = Zeroizing::new(Vec::with_capacity(header.len() + 64));
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(material);
    buf
}

/// Opens a decrypted blob for `version`. Error strings are fixed: on a
/// transplanted blob the leading bytes are another version's material.
pub(crate) fn open_sealed(
    version: i32,
    plaintext: &[u8],
    expected_public: &[u8; 32],
) -> Result<Sep10Key, AppError> {
    let header = sep10_header(version);
    if !plaintext.starts_with(header.as_bytes()) || plaintext.len() != header.len() + 64 {
        error!("sep10 key: blob for version {version} failed its binding check");
        return Err(AppError::InternalError(
            "sep10 key failed the binding check".to_string(),
        ));
    }
    let mut material = Zeroizing::new([0u8; 64]);
    material.copy_from_slice(&plaintext[header.len()..]);
    let key = Sep10Key::from_material(&material)?;
    if key.public() != *expected_public {
        error!(
            "sep10 key: version {version} derives a different public key than its row claims — \
             REFUSING to sign"
        );
        return Err(AppError::InternalError(
            "sep10 key does not match its record".to_string(),
        ));
    }
    Ok(key)
}

/// `keys::fingerprint("sep10_signing", "public_key", raw32)`.
pub(crate) fn fingerprint(public: &[u8; 32]) -> String {
    crate::keys::fingerprint(SEP10_FP_KIND, SEP10_FP_PART, public)
}

// ── Row source (the ring's only I/O) ───────────────────────────────────

/// Public metadata for one non-revoked version.
#[derive(Debug, Clone)]
pub struct KeyMeta {
    pub version: i32,
    pub state: String,
    pub public_address: String,
    pub fingerprint: String,
    pub activate_at: Option<i64>,
    pub superseded_at: Option<i64>,
}

/// Sealed material for one version, as stored.
pub struct SealedRow {
    pub backend: String,
    pub ciphertext: Option<Vec<u8>>,
    pub wrapped_data_key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub key_id: Option<String>,
    pub key_version: Option<String>,
    pub public_address: String,
}

// async_trait marks the boxed futures #[must_use] (clippy::double_must_use).
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait KeyRowSource: Send + Sync {
    /// Apply any activation whose instant has passed (idempotent).
    async fn promote_due(&self) -> Result<(), AppError>;
    /// Every non-revoked version, plus the DB clock (unix seconds).
    async fn list(&self) -> Result<(Vec<KeyMeta>, i64), AppError>;
    /// Sealed material for one version; `None` when it vanished or was revoked.
    async fn sealed(&self, version: i32) -> Result<Option<SealedRow>, AppError>;
    /// Scrub the sealed material of versions superseded more than
    /// `older_than_secs` ago (idempotent); returns how many rows changed.
    async fn scrub_superseded(&self, _older_than_secs: i64) -> Result<u64, AppError> {
        Ok(0)
    }
}

/// The Postgres row source.
pub struct PgKeyRows(pub PgPool);

fn ring_db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        warn!("sep10 ring: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

type MetaRow = (i32, String, String, String, Option<i64>, Option<i64>);
type MaterialRow = (
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    String,
);

#[async_trait]
impl KeyRowSource for PgKeyRows {
    async fn promote_due(&self) -> Result<(), AppError> {
        let mut tx = self.0.begin().await.map_err(ring_db_err("begin"))?;
        sqlx::query(SSK_LOCK_LIVE_SQL)
            .fetch_all(&mut *tx)
            .await
            .map_err(ring_db_err("lock"))?;
        let superseded = sqlx::query(SSK_PROMOTE_SUPERSEDE_SQL)
            .execute(&mut *tx)
            .await
            .map_err(ring_db_err("supersede"))?
            .rows_affected();
        let promoted = sqlx::query(SSK_PROMOTE_ACTIVATE_SQL)
            .execute(&mut *tx)
            .await
            .map_err(ring_db_err("promote"))?
            .rows_affected();
        tx.commit().await.map_err(ring_db_err("commit"))?;
        if promoted > 0 {
            info!(
                "sep10 ring: scheduled activation applied ({} superseded, {} promoted)",
                superseded, promoted
            );
        }
        Ok(())
    }

    async fn list(&self) -> Result<(Vec<KeyMeta>, i64), AppError> {
        let rows: Vec<MetaRow> = sqlx::query_as(SSK_RING_LIST_SQL)
            .fetch_all(&self.0)
            .await
            .map_err(ring_db_err("list"))?;
        let now: i64 = sqlx::query_scalar(SSK_DB_NOW_SQL)
            .fetch_one(&self.0)
            .await
            .map_err(ring_db_err("clock"))?;
        Ok((
            rows.into_iter()
                .map(
                    |(version, state, public_address, fingerprint, activate_at, superseded_at)| {
                        KeyMeta {
                            version,
                            state,
                            public_address,
                            fingerprint,
                            activate_at,
                            superseded_at,
                        }
                    },
                )
                .collect(),
            now,
        ))
    }

    async fn scrub_superseded(&self, older_than_secs: i64) -> Result<u64, AppError> {
        Ok(sqlx::query(SSK_SCRUB_SUPERSEDED_SQL)
            .bind(older_than_secs)
            .execute(&self.0)
            .await
            .map_err(ring_db_err("scrub"))?
            .rows_affected())
    }

    async fn sealed(&self, version: i32) -> Result<Option<SealedRow>, AppError> {
        let row: Option<MaterialRow> = sqlx::query_as(SSK_MATERIAL_SQL)
            .bind(version)
            .fetch_optional(&self.0)
            .await
            .map_err(ring_db_err("material"))?;
        Ok(row.map(
            |(
                backend,
                ciphertext,
                wrapped_data_key,
                nonce,
                key_id,
                key_version,
                public_address,
            )| {
                SealedRow {
                    backend,
                    ciphertext,
                    wrapped_data_key,
                    nonce,
                    key_id,
                    key_version,
                    public_address,
                }
            },
        ))
    }
}

/// Boot check: with SEP-10 enabled, migration 040 must be applied.
pub async fn assert_table_present(pool: &PgPool) -> Result<(), String> {
    sqlx::query(SSK_TABLE_PRESENT_SQL)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| {
            format!(
                "SEP10_ENABLED=true but sep10_signing_key is not readable ({e}); run migration \
                 040 (RUN_MODE=migrate) before rolling this binary"
            )
        })
}

// ── Ring ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Pending,
    Active,
    Superseded,
}

impl KeyState {
    fn from_db(s: &str) -> Option<Self> {
        match s.trim() {
            "pending" => Some(KeyState::Pending),
            "active" => Some(KeyState::Active),
            "superseded" => Some(KeyState::Superseded),
            _ => None,
        }
    }
}

/// One version as the ring sees it.
#[derive(Clone)]
pub struct RingEntry {
    pub version: i32,
    pub state: KeyState,
    pub public: [u8; 32],
    pub activate_at: Option<i64>,
    pub superseded_at: Option<i64>,
    key: Option<Arc<Sep10Key>>,
}

/// An immutable view of the ring. Every question is answered for a given
/// local `now`; key-state transitions are evaluated on the DB clock
/// (`now + clock_offset` as measured at the last poll), so every replica
/// switches keys at the same instant.
pub struct RingSnapshot {
    entries: Vec<RingEntry>,
    revoked: HashSet<i32>,
    clock_offset: i64,
    refreshed_at: Option<i64>,
    ttl_secs: i64,
}

impl RingSnapshot {
    fn empty(ttl_secs: i64) -> Self {
        RingSnapshot {
            entries: Vec::new(),
            revoked: HashSet::new(),
            clock_offset: 0,
            refreshed_at: None,
            ttl_secs,
        }
    }

    /// Refreshed within `SEP10_RING_STALE_SECS`.
    pub fn is_live(&self, now: i64) -> bool {
        self.refreshed_at
            .is_some_and(|r| now.saturating_sub(r) <= SEP10_RING_STALE_SECS)
    }

    fn db_now(&self, now: i64) -> i64 {
        now.saturating_add(self.clock_offset)
    }

    fn grace(&self) -> i64 {
        self.ttl_secs + SEP10_SUPERSEDED_GRACE_MARGIN_SECS
    }

    fn not_revoked(&self) -> impl Iterator<Item = &RingEntry> {
        self.entries
            .iter()
            .filter(|e| !self.revoked.contains(&e.version))
    }

    /// The pending version whose activation instant has passed.
    fn activated_pending(&self, t: i64) -> Option<&RingEntry> {
        self.not_revoked()
            .find(|e| e.state == KeyState::Pending && e.activate_at.is_some_and(|a| a <= t))
    }

    fn effective_active(&self, t: i64) -> Option<&RingEntry> {
        self.activated_pending(t)
            .or_else(|| self.not_revoked().find(|e| e.state == KeyState::Active))
    }

    /// The key that signs new challenges: `None` (→ 503) when the ring is
    /// stale, no key is active, or this replica could not open it.
    pub fn signer(&self, now: i64) -> Option<(i32, Arc<Sep10Key>)> {
        if !self.is_live(now) {
            return None;
        }
        let e = self.effective_active(self.db_now(now))?;
        Some((e.version, e.key.clone()?))
    }

    /// Whether a challenge sourced by `server` may still be verified, and
    /// with which version: the effective active key, a superseded key within
    /// TTL + 120 s of its supersession, never a revoked or unscheduled one.
    pub fn acceptable(&self, server: &[u8; 32], now: i64) -> Option<(i32, Arc<Sep10Key>)> {
        if !self.is_live(now) {
            return None;
        }
        let t = self.db_now(now);
        let e = self.not_revoked().find(|e| e.public == *server)?;
        let ok = match e.state {
            KeyState::Pending => e.activate_at.is_some_and(|a| a <= t),
            KeyState::Active => match self.activated_pending(t) {
                Some(p) => p.activate_at.is_some_and(|a| t <= a + self.grace()),
                None => true,
            },
            KeyState::Superseded => e.superseded_at.is_some_and(|s| t <= s + self.grace()),
        };
        if !ok {
            return None;
        }
        Some((e.version, e.key.clone()?))
    }

    /// Whether this replica holds `version` opened (decrypted and checked
    /// against its public address): the activation handler asks before it
    /// schedules a takeover that could not be served.
    pub fn has_opened(&self, version: i32) -> bool {
        self.not_revoked()
            .any(|e| e.version == version && e.key.is_some())
    }

    /// Any known (non-revoked) server key, whatever its state.
    pub fn is_ring_key(&self, key: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| e.public == *key)
    }
}

/// The shared ring handle (an `Extension`). Readers clone an `Arc` of the
/// latest snapshot; only the poller and the local revoke path replace it.
pub struct Sep10Ring {
    snapshot: RwLock<Arc<RingSnapshot>>,
    ttl_secs: i64,
}

impl Sep10Ring {
    pub fn new(ttl_secs: u64) -> Self {
        let ttl_secs = ttl_secs as i64;
        Sep10Ring {
            snapshot: RwLock::new(Arc::new(RingSnapshot::empty(ttl_secs))),
            ttl_secs,
        }
    }

    pub fn snapshot(&self) -> Arc<RingSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install a poll's view. Revocation is terminal, so a version this
    /// replica has refused stays refused when the poll read the table BEFORE
    /// the revoke committed (a slow key open in between would otherwise bring
    /// the key back until the next poll). Decided under the write lock, so a
    /// revoke and a poll cannot interleave around it. The carry-over ends as
    /// soon as the table stops listing the version.
    fn install_poll(&self, mut snapshot: RingSnapshot) {
        let mut guard = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
        for version in &guard.revoked {
            if snapshot.entries.iter().any(|e| e.version == *version) {
                snapshot.revoked.insert(*version);
            }
        }
        *guard = Arc::new(snapshot);
    }

    /// Refuse `version` on this replica at once (the revoke handler calls this
    /// after its commit; other replicas drop it at their next poll).
    pub fn mark_revoked(&self, version: i32) {
        let mut guard = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
        let mut revoked = guard.revoked.clone();
        revoked.insert(version);
        let next = RingSnapshot {
            entries: guard.entries.clone(),
            revoked,
            clock_offset: guard.clock_offset,
            refreshed_at: guard.refreshed_at,
            ttl_secs: guard.ttl_secs,
        };
        *guard = Arc::new(next);
    }
}

/// Poller state: opened keys (zeroized when dropped) and the negative cache.
#[derive(Default)]
pub struct RingPoller {
    opened: HashMap<i32, Arc<Sep10Key>>,
    /// version → (next attempt at, current backoff), local clock.
    failures: HashMap<i32, (i64, i64)>,
}

impl RingPoller {
    fn may_try(&self, version: i32, now: i64) -> bool {
        self.failures
            .get(&version)
            .is_none_or(|(next_at, _)| now >= *next_at)
    }

    fn record_failure(&mut self, version: i32, now: i64) {
        let backoff = match self.failures.get(&version) {
            Some((_, prev)) => (prev * 2).min(SEP10_DECRYPT_BACKOFF_MAX_SECS),
            None => SEP10_DECRYPT_BACKOFF_MIN_SECS,
        };
        self.failures.insert(version, (now + backoff, backoff));
    }

    async fn open(
        &self,
        src: &dyn KeyRowSource,
        protector: &dyn SeedProtector,
        version: i32,
        public: &[u8; 32],
    ) -> Result<Sep10Key, AppError> {
        let row = src
            .sealed(version)
            .await?
            .ok_or_else(|| AppError::InternalError("sep10 key row vanished".to_string()))?;
        let ciphertext = row.ciphertext.ok_or_else(|| {
            AppError::InternalError("sep10 key material was scrubbed".to_string())
        })?;
        let backend = ProtectorBackend::from_tag(row.backend.trim())
            .ok_or_else(|| AppError::InternalError("corrupt sep10 key record".to_string()))?;
        if backend != protector.backend() {
            return Err(AppError::InternalError(
                "sep10 key protection backend mismatch".to_string(),
            ));
        }
        if crate::validate::decode_stellar_account_id(row.public_address.trim()).ok()
            != Some(*public)
        {
            return Err(AppError::InternalError(
                "sep10 key record changed while loading".to_string(),
            ));
        }
        let raw = protector
            .decrypt_seed(&ProtectedSeed {
                backend,
                ciphertext,
                wrapped_data_key: row.wrapped_data_key,
                nonce: row.nonce,
                key_id: row.key_id.unwrap_or_default(),
                key_version: row.key_version,
            })
            .await?;
        open_sealed(version, raw.as_slice(), public)
    }

    /// One poll: apply due activations, read the table, open any version this
    /// replica has not opened (respecting the negative cache), and install a
    /// new snapshot. Returns how long to sleep before the next poll. A DB
    /// error leaves the previous snapshot in place (it goes stale after
    /// `SEP10_RING_STALE_SECS`).
    pub async fn refresh(
        &mut self,
        ring: &Sep10Ring,
        src: &dyn KeyRowSource,
        protector: &dyn SeedProtector,
        now: i64,
    ) -> u64 {
        if let Err(e) = src.promote_due().await {
            warn!("sep10 ring: activation step failed: {}", e);
        }
        let grace = ring.ttl_secs + SEP10_SUPERSEDED_GRACE_MARGIN_SECS;
        match src
            .scrub_superseded(grace + SEP10_SUPERSEDED_SCRUB_DELAY_SECS)
            .await
        {
            Ok(0) => {}
            Ok(n) => info!(
                "sep10 ring: scrubbed the sealed material of {} superseded signing key(s)",
                n
            ),
            Err(e) => warn!("sep10 ring: scrub step failed: {}", e),
        }
        let (rows, db_now) = match src.list().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "sep10 ring: refresh failed, keeping the previous view: {}",
                    e
                );
                return SEP10_KEY_POLL_SECS;
            }
        };
        let mut wanted = HashSet::new();
        let mut entries = Vec::with_capacity(rows.len());
        for meta in rows {
            let Some(state) = KeyState::from_db(&meta.state) else {
                error!(
                    "sep10 ring: version {} has unknown state {:?}; ignored",
                    meta.version, meta.state
                );
                continue;
            };
            let Ok(public) = crate::validate::decode_stellar_account_id(meta.public_address.trim())
            else {
                error!(
                    "sep10 ring: version {} has a malformed public_address; ignored",
                    meta.version
                );
                continue;
            };
            let needs_material = match state {
                KeyState::Pending | KeyState::Active => true,
                KeyState::Superseded => meta.superseded_at.is_some_and(|s| db_now <= s + grace),
            };
            let mut key = None;
            if needs_material {
                wanted.insert(meta.version);
                key = self.opened.get(&meta.version).cloned();
                if key.is_none() && self.may_try(meta.version, now) {
                    match self.open(src, protector, meta.version, &public).await {
                        Ok(k) => {
                            let k = Arc::new(k);
                            self.opened.insert(meta.version, k.clone());
                            self.failures.remove(&meta.version);
                            info!(
                                "sep10 ring: opened signing key version {} ({})",
                                meta.version, meta.fingerprint
                            );
                            key = Some(k);
                        }
                        Err(e) => {
                            self.record_failure(meta.version, now);
                            error!(
                                "sep10 ring: signing key version {} could not be opened: {}",
                                meta.version, e
                            );
                        }
                    }
                }
            }
            entries.push(RingEntry {
                version: meta.version,
                state,
                public,
                activate_at: meta.activate_at,
                superseded_at: meta.superseded_at,
                key,
            });
        }
        // Versions out of service drop their opened key (zeroized on drop).
        self.opened.retain(|v, _| wanted.contains(v));
        self.failures.retain(|v, _| wanted.contains(v));
        ring.install_poll(RingSnapshot {
            entries,
            revoked: HashSet::new(),
            clock_offset: db_now - now,
            refreshed_at: Some(now),
            ttl_secs: ring.ttl_secs,
        });
        let next_retry = self
            .failures
            .values()
            .map(|(at, _)| (at - now).max(1) as u64)
            .min();
        next_retry.map_or(SEP10_KEY_POLL_SECS, |s| s.min(SEP10_KEY_POLL_SECS))
    }
}

/// The background ring task (spawned only with `SEP10_ENABLED=true`).
pub async fn run(
    ring: Arc<Sep10Ring>,
    pool: PgPool,
    protector: Arc<dyn SeedProtector>,
    cancel: CancellationToken,
) {
    let src = PgKeyRows(pool);
    let mut poller = RingPoller::default();
    loop {
        let wait = poller
            .refresh(&ring, &src, protector.as_ref(), unix_now())
            .await;
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::seed_protect::SecretBytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    pub fn test_key() -> (Sep10Key, [u8; 64]) {
        let (material, _) = generate_material().unwrap();
        let m = *material;
        (Sep10Key::from_material(&m).unwrap(), m)
    }

    #[test]
    fn sealed_key_round_trips_and_never_prints() {
        let (material, public) = generate_material().unwrap();
        let sealed = seal(4, &material);
        assert!(sealed.starts_with(b"impala-sep10-v1\n4\n"));
        assert_eq!(sealed.len(), "impala-sep10-v1\n4\n".len() + 64);
        let key = open_sealed(4, &sealed, &public).unwrap();
        assert_eq!(key.public(), public);
        let sig = key.sign_challenge_hash(&[7u8; 32]);
        assert!(crate::sep10::ed25519_verify(&public, &[7u8; 32], &sig));
        assert_eq!(format!("{key:?}"), "Sep10Key([REDACTED])");
        // The MAC is keyed by the second half and deterministic.
        assert_eq!(key.mac(b"x"), key.mac(b"x"));
        assert_ne!(key.mac(b"x"), key.mac(b"y"));
    }

    #[test]
    fn a_blob_moved_to_another_version_or_row_fails_to_open() {
        let (material, public) = generate_material().unwrap();
        let (_, other_public) = generate_material().unwrap();
        let sealed = seal(1, &material);
        let e = open_sealed(2, &sealed, &public).unwrap_err();
        assert!(e.to_string().contains("binding check"));
        let e = open_sealed(1, &sealed, &other_public).unwrap_err();
        assert!(e.to_string().contains("does not match its record"));
        let mut long = sealed.to_vec();
        long.push(0);
        assert!(open_sealed(1, &long, &public).is_err());
        assert!(!e.to_string().contains(&hex::encode(&material[..8])));
    }

    #[test]
    fn two_generations_differ_in_both_halves() {
        let (a, _) = generate_material().unwrap();
        let (b, _) = generate_material().unwrap();
        assert_ne!(a[..32], b[..32]);
        assert_ne!(a[32..], b[32..]);
    }

    #[test]
    fn ssk_insert_binds_ten_with_one_literal() {
        let cols = SSK_INSERT_SQL
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
            assert!(SSK_INSERT_SQL.contains(&format!("${n}")), "missing ${n}");
        }
        assert!(!SSK_INSERT_SQL.contains("$11"));
        assert!(SSK_INSERT_SQL.contains("($1, 'pending', $2,"));
        // The handler binds exactly ten values to it.
        let src = include_str!("../handlers/admin_sep10.rs");
        let start = src.find("sqlx::query(key::SSK_INSERT_SQL)").unwrap();
        let end = src[start..].find(".execute(").unwrap() + start;
        assert_eq!(src[start..end].matches(".bind(").count(), 10);
    }

    #[test]
    fn mutations_are_guarded() {
        assert!(SSK_SCHEDULE_ACTIVATION_SQL
            .contains("WHERE version = $1 AND state = 'pending' AND activate_at IS NULL"));
        assert!(SSK_REVOKE_SQL.contains("WHERE version = $1 AND state <> 'revoked'"));
        for scrub in [
            "ciphertext = NULL",
            "wrapped_data_key = NULL",
            "nonce = NULL",
            "scrubbed_at = CURRENT_TIMESTAMP",
        ] {
            assert!(SSK_REVOKE_SQL.contains(scrub), "{scrub}");
        }
        assert!(SSK_PROMOTE_SUPERSEDE_SQL.contains("superseded_at = p.activate_at"));
        assert!(SSK_PROMOTE_SUPERSEDE_SQL.contains("activate_at <= CURRENT_TIMESTAMP"));
        assert!(SSK_PROMOTE_ACTIVATE_SQL
            .contains("WHERE state = 'pending' AND activate_at <= CURRENT_TIMESTAMP"));
        assert!(SSK_MATERIAL_SQL.contains("state <> 'revoked'"));
        // The scrub touches superseded rows that still hold material, only
        // after the delay, and clears exactly what a revoke clears.
        assert!(SSK_SCRUB_SUPERSEDED_SQL.contains(
            "WHERE state = 'superseded' AND scrubbed_at IS NULL \
     AND superseded_at < CURRENT_TIMESTAMP - ($1::BIGINT * INTERVAL '1 second')"
        ));
        for scrub in [
            "ciphertext = NULL",
            "wrapped_data_key = NULL",
            "nonce = NULL",
            "scrubbed_at = CURRENT_TIMESTAMP",
        ] {
            assert!(SSK_SCRUB_SUPERSEDED_SQL.contains(scrub), "{scrub}");
        }
        assert!(!SSK_SCRUB_SUPERSEDED_SQL.contains("$2"));
        // Never before the ring has stopped needing the material.
        const { assert!(SEP10_SUPERSEDED_SCRUB_DELAY_SECS > 0) };
    }

    /// Every column the SQL names exists in migration 040.
    #[test]
    fn sql_columns_exist_in_migration_040() {
        let ddl = include_str!("../../migrations/040_sep10_card_keys.sql");
        for col in [
            "version",
            "state",
            "backend",
            "ciphertext",
            "wrapped_data_key",
            "nonce",
            "key_id",
            "key_version",
            "public_address",
            "fingerprint",
            "generated_by",
            "generated_at",
            "activate_at",
            "superseded_at",
            "revoked_at",
            "scrubbed_at",
        ] {
            assert!(ddl.contains(&format!("    {col} ")), "{col}");
        }
        for card_col in [
            "stellar_address",
            "stellar_binding_sig",
            "stellar_proof_sig",
        ] {
            assert!(
                ddl.contains(&format!(
                    "ALTER TABLE card ADD COLUMN IF NOT EXISTS {card_col} "
                )),
                "{card_col}"
            );
        }
        assert!(ddl.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_card_active_stellar_address\n    ON card(stellar_address) WHERE is_delete = FALSE AND stellar_address IS NOT NULL;"
        ));
        // Card key kind only in this phase.
        assert!(!ddl.contains("stellar_login_key"));
    }

    /// The SEP-10 sources never reach a custodial seed, so no bridge-held
    /// custodial key can sign a challenge as a client.
    #[test]
    fn sep10_sources_never_reference_custodial_seed_paths() {
        for (name, src) in [
            ("sep10/mod.rs", include_str!("mod.rs")),
            ("sep10/key.rs", include_str!("key.rs")),
            ("sep10/verify.rs", include_str!("verify.rs")),
            ("sep10/challenge.rs", include_str!("challenge.rs")),
            ("sep10/binding.rs", include_str!("binding.rs")),
            ("sep10/backend.rs", include_str!("backend.rs")),
            (
                "handlers/sep10_auth.rs",
                include_str!("../handlers/sep10_auth.rs"),
            ),
            (
                "handlers/admin_sep10.rs",
                include_str!("../handlers/admin_sep10.rs"),
            ),
        ] {
            let non_test = src.find("#[cfg(test)]").map_or(src, |i| &src[..i]);
            for forbidden in [
                "load_protected_seed",
                "managed_seed",
                "StellarSigner",
                "DalekKeyPair",
            ] {
                assert!(
                    !non_test.contains(forbidden),
                    "{name} references {forbidden}"
                );
            }
        }
    }

    // ── Ring ──────────────────────────────────────────────────────────

    struct FakeRows {
        rows: Mutex<Vec<(KeyMeta, Option<SealedRow>)>>,
        db_offset: i64,
        now: Mutex<i64>,
        fail_list: Mutex<bool>,
    }

    impl FakeRows {
        fn new(now: i64) -> Self {
            FakeRows {
                rows: Mutex::new(Vec::new()),
                db_offset: 0,
                now: Mutex::new(now),
                fail_list: Mutex::new(false),
            }
        }
        fn add(
            &self,
            version: i32,
            state: &str,
            public: &[u8; 32],
            sealed: Option<Vec<u8>>,
            activate_at: Option<i64>,
            superseded_at: Option<i64>,
        ) {
            let address = crate::validate::encode_stellar_account_id(public);
            self.rows.lock().unwrap().push((
                KeyMeta {
                    version,
                    state: state.to_string(),
                    public_address: address.clone(),
                    fingerprint: fingerprint(public),
                    activate_at,
                    superseded_at,
                },
                sealed.map(|c| SealedRow {
                    backend: "vault".to_string(),
                    ciphertext: Some(c),
                    wrapped_data_key: None,
                    nonce: None,
                    key_id: Some("impala-seeds".into()),
                    key_version: Some("1".into()),
                    public_address: address,
                }),
            ));
        }
    }

    #[async_trait]
    impl KeyRowSource for FakeRows {
        async fn promote_due(&self) -> Result<(), AppError> {
            Ok(())
        }
        async fn list(&self) -> Result<(Vec<KeyMeta>, i64), AppError> {
            if *self.fail_list.lock().unwrap() {
                return Err(AppError::InternalError("Database error".into()));
            }
            Ok((
                self.rows
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(m, _)| m.clone())
                    .collect(),
                *self.now.lock().unwrap() + self.db_offset,
            ))
        }
        async fn sealed(&self, version: i32) -> Result<Option<SealedRow>, AppError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|(m, _)| m.version == version)
                .and_then(|(_, s)| {
                    s.as_ref().map(|s| SealedRow {
                        backend: s.backend.clone(),
                        ciphertext: s.ciphertext.clone(),
                        wrapped_data_key: None,
                        nonce: None,
                        key_id: s.key_id.clone(),
                        key_version: s.key_version.clone(),
                        public_address: s.public_address.clone(),
                    })
                }))
        }
    }

    /// The "ciphertext" is the sealed plaintext itself; `fail` makes every
    /// decrypt error. Counts calls.
    pub struct CountingProtector {
        pub calls: AtomicUsize,
        pub fail: bool,
    }

    #[async_trait]
    impl SeedProtector for CountingProtector {
        async fn encrypt_seed(&self, plaintext: &[u8]) -> Result<ProtectedSeed, AppError> {
            Ok(ProtectedSeed {
                backend: ProtectorBackend::Vault,
                ciphertext: plaintext.to_vec(),
                wrapped_data_key: None,
                nonce: None,
                key_id: "impala-seeds".into(),
                key_version: Some("1".into()),
            })
        }
        async fn decrypt_seed(&self, protected: &ProtectedSeed) -> Result<SecretBytes, AppError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(AppError::InternalError("protector down".into()));
            }
            Ok(SecretBytes::new(protected.ciphertext.clone()))
        }
        fn backend(&self) -> ProtectorBackend {
            ProtectorBackend::Vault
        }
    }

    fn protector(fail: bool) -> CountingProtector {
        CountingProtector {
            calls: AtomicUsize::new(0),
            fail,
        }
    }

    /// A ring serving one freshly generated active key (for handler tests).
    pub async fn ring_with_active_key(ttl: u64) -> (Arc<Sep10Ring>, [u8; 32]) {
        let now = unix_now();
        let (material, public) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(
            1,
            "active",
            &public,
            Some(seal(1, &material).to_vec()),
            None,
            None,
        );
        let ring = Arc::new(Sep10Ring::new(ttl));
        RingPoller::default()
            .refresh(&ring, &rows, &protector(false), now)
            .await;
        (ring, public)
    }

    #[tokio::test]
    async fn the_ring_serves_the_active_key_and_refuses_unknown_ones() {
        let now = 1_700_000_000;
        let (m1, p1) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(1, "active", &p1, Some(seal(1, &m1).to_vec()), None, None);
        let ring = Sep10Ring::new(300);
        assert!(
            ring.snapshot().signer(now).is_none(),
            "nothing before the first poll"
        );
        let prot = protector(false);
        let mut poller = RingPoller::default();
        poller.refresh(&ring, &rows, &prot, now).await;
        let snap = ring.snapshot();
        assert_eq!(snap.signer(now).unwrap().0, 1);
        assert_eq!(snap.acceptable(&p1, now).unwrap().0, 1);
        assert!(snap.acceptable(&[9u8; 32], now).is_none());
        assert!(snap.is_ring_key(&p1));
        // Decrypted once; the next poll reuses it.
        poller.refresh(&ring, &rows, &prot, now + 30).await;
        assert_eq!(prot.calls.load(Ordering::SeqCst), 1);
        // A ring that cannot refresh for five minutes goes stale: 503.
        *rows.fail_list.lock().unwrap() = true;
        poller.refresh(&ring, &rows, &prot, now + 60).await;
        let snap = ring.snapshot();
        assert!(snap.signer(now + 30 + 300).is_some());
        assert!(snap.signer(now + 30 + 301).is_none());
        assert!(snap.acceptable(&p1, now + 30 + 301).is_none());
    }

    #[tokio::test]
    async fn activation_switches_at_activate_at_and_the_old_key_keeps_a_grace() {
        let now = 1_700_000_000;
        let (m1, p1) = generate_material().unwrap();
        let (m2, p2) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(1, "active", &p1, Some(seal(1, &m1).to_vec()), None, None);
        rows.add(
            2,
            "pending",
            &p2,
            Some(seal(2, &m2).to_vec()),
            Some(now + 120),
            None,
        );
        let ring = Sep10Ring::new(300);
        RingPoller::default()
            .refresh(&ring, &rows, &protector(false), now)
            .await;
        let snap = ring.snapshot();
        // Before the fence: v1 signs, v2 is not yet acceptable.
        assert_eq!(snap.signer(now + 119).unwrap().0, 1);
        assert!(snap.acceptable(&p2, now + 119).is_none());
        // At the fence, with no new poll: v2 signs, v1 still verifies.
        assert_eq!(snap.signer(now + 120).unwrap().0, 2);
        assert_eq!(snap.acceptable(&p2, now + 120).unwrap().0, 2);
        assert_eq!(snap.acceptable(&p1, now + 120).unwrap().0, 1);
        // v1's grace is TTL + 120 s past the switch (a later poll keeps the
        // ring live; the fake table still shows the pre-promotion states).
        *rows.now.lock().unwrap() = now + 300;
        RingPoller::default()
            .refresh(&ring, &rows, &protector(false), now + 300)
            .await;
        let snap = ring.snapshot();
        assert!(snap.acceptable(&p1, now + 120 + 420).is_some());
        assert!(snap.acceptable(&p1, now + 120 + 421).is_none());
        assert_eq!(snap.signer(now + 541).unwrap().0, 2);
        // An unscheduled pending key is never acceptable.
        let rows = FakeRows::new(now);
        rows.add(3, "pending", &p2, Some(seal(3, &m2).to_vec()), None, None);
        let ring = Sep10Ring::new(300);
        RingPoller::default()
            .refresh(&ring, &rows, &protector(false), now)
            .await;
        assert!(ring.snapshot().acceptable(&p2, now + 10_000).is_none());
        assert!(ring.snapshot().signer(now).is_none());
    }

    #[tokio::test]
    async fn superseded_keys_verify_only_within_their_grace_and_revocation_is_immediate() {
        let now = 1_700_000_000;
        let (m1, p1) = generate_material().unwrap();
        let (m2, p2) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(
            1,
            "superseded",
            &p1,
            Some(seal(1, &m1).to_vec()),
            None,
            Some(now - 100),
        );
        rows.add(2, "active", &p2, Some(seal(2, &m2).to_vec()), None, None);
        let ring = Sep10Ring::new(300);
        RingPoller::default()
            .refresh(&ring, &rows, &protector(false), now)
            .await;
        let snap = ring.snapshot();
        assert_eq!(snap.acceptable(&p1, now).unwrap().0, 1);
        assert!(snap.acceptable(&p1, now + 321).is_none());
        // Revoking on this replica refuses at once, without waiting a poll.
        ring.mark_revoked(2);
        let snap = ring.snapshot();
        assert!(snap.acceptable(&p2, now).is_none());
        assert!(
            snap.signer(now).is_none(),
            "revoked active key: 503 until another activates"
        );
        // A superseded key out of its grace is not even decrypted.
        let rows = FakeRows::new(now);
        rows.add(
            1,
            "superseded",
            &p1,
            Some(seal(1, &m1).to_vec()),
            None,
            Some(now - 10_000),
        );
        let prot = protector(false);
        RingPoller::default()
            .refresh(&Sep10Ring::new(300), &rows, &prot, now)
            .await;
        assert_eq!(prot.calls.load(Ordering::SeqCst), 0);
    }

    /// The revoke handler marks the ring after its commit. A poll whose table
    /// read predates that commit (it was held up opening another key) must
    /// not bring the revoked key back for a poll interval.
    #[tokio::test]
    async fn a_poll_that_read_the_table_before_a_revoke_does_not_undo_it() {
        let now = 1_700_000_000;
        let (m1, p1) = generate_material().unwrap();
        let (m2, p2) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(1, "active", &p1, Some(seal(1, &m1).to_vec()), None, None);
        let ring = Sep10Ring::new(300);
        let mut poller = RingPoller::default();
        poller.refresh(&ring, &rows, &protector(false), now).await;
        assert_eq!(ring.snapshot().signer(now).unwrap().0, 1);

        ring.mark_revoked(1);
        // This poll still sees version 1 as active: its read is the stale one.
        poller
            .refresh(&ring, &rows, &protector(false), now + 1)
            .await;
        let snap = ring.snapshot();
        assert!(snap.signer(now + 1).is_none(), "the revoked key signs");
        assert!(snap.acceptable(&p1, now + 1).is_none());
        assert!(!snap.has_opened(1));

        // The table catches up (revoked rows are not listed) and a new key
        // serves; the carry-over does not outlive the row.
        rows.rows.lock().unwrap().clear();
        rows.add(2, "active", &p2, Some(seal(2, &m2).to_vec()), None, None);
        poller
            .refresh(&ring, &rows, &protector(false), now + 2)
            .await;
        let snap = ring.snapshot();
        assert_eq!(snap.signer(now + 2).unwrap().0, 2);
        assert!(snap.revoked.is_empty());
    }

    /// `has_opened` is what lets activation refuse a key this replica could
    /// not serve.
    #[tokio::test]
    async fn has_opened_says_whether_this_replica_can_serve_a_version() {
        let now = 1_700_000_000;
        let (m1, p1) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(1, "pending", &p1, Some(seal(1, &m1).to_vec()), None, None);

        let opened = Sep10Ring::new(300);
        RingPoller::default()
            .refresh(&opened, &rows, &protector(false), now)
            .await;
        assert!(opened.snapshot().has_opened(1));
        assert!(!opened.snapshot().has_opened(2));

        let unopened = Sep10Ring::new(300);
        RingPoller::default()
            .refresh(&unopened, &rows, &protector(true), now)
            .await;
        assert!(!unopened.snapshot().has_opened(1));
        assert!(!Sep10Ring::new(300).snapshot().has_opened(1));
    }

    /// A tampered or transplanted row never yields a key.
    #[tokio::test]
    async fn a_row_whose_material_does_not_match_its_address_is_refused() {
        let now = 1_700_000_000;
        let (m1, _) = generate_material().unwrap();
        let (_, p_other) = generate_material().unwrap();
        let rows = FakeRows::new(now);
        rows.add(
            1,
            "active",
            &p_other,
            Some(seal(1, &m1).to_vec()),
            None,
            None,
        );
        let ring = Sep10Ring::new(300);
        RingPoller::default()
            .refresh(&ring, &rows, &protector(false), now)
            .await;
        assert!(ring.snapshot().signer(now).is_none());
    }

    /// 1000 concurrent public requests against a failing protector cause at
    /// most one decrypt per backoff window: handlers read the snapshot only,
    /// and the poller backs off 5 s → 10 s → … → 60 s.
    #[tokio::test]
    async fn a_failing_protector_is_called_once_per_backoff_window() {
        let now = 1_700_000_000;
        let (m1, p1) = generate_material().unwrap();
        let rows = Arc::new(FakeRows::new(now));
        rows.add(1, "active", &p1, Some(seal(1, &m1).to_vec()), None, None);
        let ring = Arc::new(Sep10Ring::new(300));
        let prot = Arc::new(protector(true));
        let mut poller = RingPoller::default();
        let wait = poller
            .refresh(&ring, rows.as_ref(), prot.as_ref(), now)
            .await;
        assert_eq!(
            wait, 5,
            "the next poll comes at the end of the backoff window"
        );
        let mut handles = Vec::new();
        for _ in 0..1000 {
            let ring = ring.clone();
            handles.push(tokio::spawn(async move {
                ring.snapshot().signer(now).is_none()
            }));
        }
        for h in handles {
            assert!(h.await.unwrap(), "no key while the protector fails: 503");
        }
        for t in 1..5 {
            poller
                .refresh(&ring, rows.as_ref(), prot.as_ref(), now + t)
                .await;
        }
        assert_eq!(prot.calls.load(Ordering::SeqCst), 1);
        poller
            .refresh(&ring, rows.as_ref(), prot.as_ref(), now + 5)
            .await;
        assert_eq!(prot.calls.load(Ordering::SeqCst), 2);
        // Backoff doubles, capped at 60 s.
        poller
            .refresh(&ring, rows.as_ref(), prot.as_ref(), now + 14)
            .await;
        assert_eq!(prot.calls.load(Ordering::SeqCst), 2);
        poller
            .refresh(&ring, rows.as_ref(), prot.as_ref(), now + 15)
            .await;
        assert_eq!(prot.calls.load(Ordering::SeqCst), 3);
        let mut t = now + 15;
        for _ in 0..10 {
            t += SEP10_DECRYPT_BACKOFF_MAX_SECS;
            poller.refresh(&ring, rows.as_ref(), prot.as_ref(), t).await;
        }
        assert!(poller.failures[&1].1 <= SEP10_DECRYPT_BACKOFF_MAX_SECS);
    }

    /// Generate-only custody: the admin module has no import function or
    /// route, drops the material after sealing, and no response carries it.
    #[test]
    fn signing_key_is_generate_only() {
        let src = include_str!("../handlers/admin_sep10.rs");
        let non_test = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(!non_test.contains("pub async fn import"));
        assert!(non_test.contains("drop(seed);"));
        for forbidden in ["seed:", "private", "ciphertext:", "k_mac"] {
            assert!(!non_test.contains(forbidden), "{forbidden}");
        }
        let main = include_str!("../main.rs");
        for line in main.lines().filter(|l| l.contains("/admin/sep10")) {
            assert!(!line.contains("import"), "no import route: {line}");
        }
        assert_eq!(non_test.matches("pub async fn ").count(), 5);
        // The response models carry public data only.
        let models = include_str!("../models.rs");
        let start = models.find("// ── SEP-10 (040)").unwrap();
        let end = models[start..].find("// ── end SEP-10").unwrap() + start;
        for forbidden in ["seed", "private", "ciphertext", "k_mac", "secret"] {
            assert!(!models[start..end].contains(forbidden), "{forbidden}");
        }
    }
}

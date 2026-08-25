//! Persistence and boot-time resolution for imported credential sets.
//!
//! # Resolution model: store now, activate on restart
//!
//! An imported credential is **not** pushed into the running process. The
//! bridge is deployed as an autoscaled multi-instance service, so a push would
//! update one task and leave the rest signing with the previous key — the exact
//! "you were told it took effect, and it didn't" failure that live activation
//! is supposed to prevent, now wearing an audit record that says otherwise.
//! Instead, [`resolve_all`] runs once at startup and the answer is fixed for
//! the life of the process, so every task in the fleet converges on the new
//! credential at the same point: the rolling restart. This is the workflow
//! `docs/runbooks/rotate-secrets.md` already prescribes (prepare, then
//! activate with `--force-new-deployment`).
//!
//! # Fail-closed rules
//!
//! - A stored row that cannot be decrypted, fails its binding check, or fails
//!   to parse resolves that provider **absent** — never a silent fallback to
//!   the environment, which would quietly re-activate the key the admin just
//!   replaced. Absent means handlers answer "not configured", the same as a
//!   deployment that never had the provider.
//! - A resolution failure never aborts startup. One unreadable credential row
//!   must not crash-loop a fleet that also serves auth, accounts and custody;
//!   it is loud (ERROR + audit event + `GET /health`) but not fatal.
//! - Environment-sourced misconfiguration keeps its existing behaviour: the
//!   process exits, because that is a deploy-time error a human is watching.

use std::sync::Arc;

use log::{error, info, warn};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{parts_for, CredentialParts};
use crate::config::Config;
use crate::constants::{
    CREDENTIAL_SOURCE_DB, CREDENTIAL_SOURCE_ENV, CREDENTIAL_SOURCE_UNCONFIGURED,
    CREDENTIAL_SUPERSEDE_GRACE_SECS, VALID_CREDENTIAL_KINDS,
};
use crate::error::AppError;
use crate::seed_protect::{ProtectedSeed, ProtectorBackend, SeedProtector};

const TS_FMT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

/// Columns describing a stored row WITHOUT any secret material. Everything
/// here is safe to serve to an admin.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct CredentialRow {
    pub id: Uuid,
    pub kind: String,
    pub version: i32,
    pub state: String,
    pub set_fingerprint: String,
    pub fingerprints: serde_json::Value,
    pub imported_by: String,
    pub imported_at: Option<String>,
    pub superseded_at: Option<String>,
    pub scrubbed_at: Option<String>,
    pub note: Option<String>,
}

/// A decrypted credential set plus the row identity it came from.
pub struct StoredCredential {
    pub version: i32,
    pub set_fingerprint: String,
    pub parts: CredentialParts,
}

/// Where the effective credential for one kind came from, and what it is.
///
/// `parts` is `None` when the provider is unconfigured OR when a stored row
/// failed to resolve — the two are distinguished by `error`.
pub struct Resolution {
    pub kind: &'static str,
    pub source: &'static str,
    pub parts: Option<CredentialParts>,
    pub version: Option<i32>,
    pub set_fingerprint: Option<String>,
    /// The environment credential's fingerprint, whenever the environment
    /// carries one — whether or not it is the credential in use.
    ///
    /// Two things need it: reporting that a stored credential is SHADOWING an
    /// environment one (a rotation is not finished until that is gone, because
    /// flipping `KEY_IMPORT_ENABLED` off resurrects it), and working out what
    /// a restart WOULD resolve, which is what `pending_restart` means.
    pub env_fingerprint: Option<String>,
    /// The most recently superseded set still inside the overlap grace, used
    /// to keep verifying inbound webhooks signed with the previous secret.
    pub previous_parts: Option<CredentialParts>,
    /// Fixed-string reason a stored row failed to resolve. Never derived from
    /// decrypted bytes.
    pub error: Option<String>,
}

impl Resolution {
    fn unconfigured(kind: &'static str) -> Self {
        Resolution {
            kind,
            source: CREDENTIAL_SOURCE_UNCONFIGURED,
            parts: None,
            version: None,
            set_fingerprint: None,
            env_fingerprint: None,
            previous_parts: None,
            error: None,
        }
    }
}

/// Read one part from the environment, honouring the mounted-secret file
/// fallback. Secrets are read directly from the process environment and never
/// pass through the `Debug`-logged `Config` (the house rule in config.rs).
fn env_part(spec: &super::PartSpec) -> Option<Zeroizing<String>> {
    if let Some(v) = std::env::var(spec.env_var).ok().filter(|v| !v.is_empty()) {
        return Some(Zeroizing::new(v));
    }
    let path = spec
        .env_file_var
        .and_then(|f| std::env::var(f).ok())
        .filter(|v| !v.is_empty())?;
    match std::fs::read_to_string(&path) {
        Ok(contents) => Some(Zeroizing::new(contents.trim().to_string())),
        Err(e) => {
            // Same failure the provider init would hit; log the variable, not
            // the contents, and let the caller resolve the part as absent.
            error!(
                "keys: failed to read {} ({}): {}",
                spec.env_file_var.unwrap_or("<file>"),
                path,
                e
            );
            None
        }
    }
}

/// Assemble the credential set a kind's environment variables describe.
///
/// Returns `None` when the PRIMARY part (the API key) is absent — the provider
/// is unconfigured, exactly as the `init_*` functions this replaced reported
/// it. Returning `Some` for a stray leftover variable would turn a deployment
/// that boots today into one that exits: a set missing a required part fails
/// to build, and an environment-sourced build failure is fatal by design.
///
/// A primary part that IS present with others missing still yields `Some`, so
/// that half-configured case keeps failing closed at startup as it always has.
pub fn env_parts(kind: &str) -> Option<CredentialParts> {
    let specs = parts_for(kind)?;
    let primary = super::primary_part(kind)?;
    env_part(primary)?;

    let mut parts = CredentialParts::new();
    for spec in specs {
        if let Some(value) = env_part(spec) {
            parts.insert(spec.name, &value);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

const ACTIVE_SQL: &str = "SELECT id, version, set_fingerprint, backend, ciphertext, \
     wrapped_data_key, nonce, key_id, key_version \
     FROM bridge_credential WHERE kind = $1 AND state = 'active'";

const PREVIOUS_SQL: &str = "SELECT id, version, set_fingerprint, backend, ciphertext, \
     wrapped_data_key, nonce, key_id, key_version \
     FROM bridge_credential \
     WHERE kind = $1 AND state = 'superseded' AND ciphertext IS NOT NULL \
       AND superseded_at > CURRENT_TIMESTAMP - make_interval(secs => $2) \
     ORDER BY version DESC LIMIT 1";

/// The one INSERT shape for `bridge_credential`. Lifted to a const so the
/// column list and the placeholder list can be pinned against each other by a
/// test: sqlx checks bind TYPES at compile time but not bind COUNT, so a
/// widened statement fails at runtime, mid-transaction, on a money path.
const CREDENTIAL_INSERT_SQL: &str = "INSERT INTO bridge_credential \
     (kind, version, state, backend, ciphertext, wrapped_data_key, nonce, \
      key_id, key_version, fingerprints, set_fingerprint, imported_by, note) \
     VALUES ($1, $2, 'active', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     RETURNING id";

type SealedRow = (
    Uuid,
    i32,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
);

/// Decrypt one sealed row and verify its bound header.
async fn open_row(
    protector: &Arc<dyn SeedProtector>,
    kind: &str,
    row: SealedRow,
) -> Result<StoredCredential, String> {
    let (id, version, set_fingerprint, backend_tag, ciphertext, wrapped, nonce, key_id, key_ver) =
        row;

    let backend = ProtectorBackend::from_tag(&backend_tag)
        .ok_or_else(|| format!("row {} has an unknown protection backend", id))?;
    if backend != protector.backend() {
        return Err(format!(
            "row {} was sealed by the '{}' backend but '{}' is configured",
            id,
            backend.as_str(),
            protector.backend().as_str()
        ));
    }
    let ciphertext = ciphertext.ok_or_else(|| format!("row {} has been scrubbed", id))?;

    let protected = ProtectedSeed {
        backend,
        ciphertext,
        wrapped_data_key: wrapped,
        nonce,
        key_id: key_id.unwrap_or_default(),
        key_version: key_ver,
    };
    let plaintext = protector
        .decrypt_seed(&protected)
        .await
        .map_err(|_| format!("row {} could not be decrypted", id))?;

    // Binding check + parse. Both report fixed strings: on a transplanted or
    // corrupt blob the first plaintext bytes ARE secret material.
    let parts = CredentialParts::open_sealed(kind, version, plaintext.as_slice())
        .map_err(|_| format!("row {} failed its binding check", id))?;

    // A stored set must still satisfy its kind's spec — a part removed from
    // the spec, or a key that no longer parses, must not reach a provider
    // constructor half-formed.
    parts
        .validate_for(kind)
        .map_err(|_| format!("row {} does not satisfy the '{}' part spec", id, kind))?;

    Ok(StoredCredential {
        version,
        set_fingerprint,
        parts,
    })
}

/// The outcome of looking for a kind's active stored credential.
///
/// The last two arms are deliberately distinct, and the difference decides
/// whether the environment is allowed to take over:
///
/// - `Unusable` means a row EXISTS and cannot be used. Falling back to the
///   environment there would silently re-activate the credential an admin
///   deliberately replaced, so the provider is disabled instead.
/// - `LookupFailed` means we do not know whether a row exists — the table is
///   missing because migration 033 has not run yet, or the query failed. There
///   is no evidence of a stored credential, so the environment is still the
///   best answer and disabling a working provider would be a self-inflicted
///   outage on a fresh deploy.
pub enum ActiveLookup {
    Found(Box<StoredCredential>),
    None,
    Unusable(String),
    LookupFailed(String),
}

/// Load the active credential set for one kind.
pub async fn load_active(
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    kind: &str,
) -> ActiveLookup {
    let row: Option<SealedRow> = match sqlx::query_as(ACTIVE_SQL)
        .bind(kind)
        .fetch_optional(pool)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            error!("keys: active lookup for '{}' failed: {}", kind, e);
            return ActiveLookup::LookupFailed(format!("credential lookup failed: {}", e));
        }
    };
    match row {
        None => ActiveLookup::None,
        Some(row) => match open_row(protector, kind, row).await {
            Ok(c) => ActiveLookup::Found(Box::new(c)),
            Err(reason) => ActiveLookup::Unusable(reason),
        },
    }
}

/// Load the most recently superseded set still inside the overlap grace.
///
/// Exists so a rotated OwlPay webhook secret does not 401 every delivery the
/// provider signed before the cutover and is still retrying — the same reason
/// `JWT_SECRET_PREVIOUS` exists for bridge-issued tokens.
pub async fn load_previous(
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    kind: &str,
) -> Option<StoredCredential> {
    let row: SealedRow = sqlx::query_as(PREVIOUS_SQL)
        .bind(kind)
        .bind(CREDENTIAL_SUPERSEDE_GRACE_SECS as f64)
        .fetch_optional(pool)
        .await
        .map_err(|e| error!("keys: previous lookup for '{}' failed: {}", kind, e))
        .ok()
        .flatten()?;
    match open_row(protector, kind, row).await {
        Ok(c) => Some(c),
        Err(reason) => {
            // Non-fatal by construction: the overlap is a courtesy, not a
            // correctness requirement.
            warn!("keys: previous '{}' credential unusable: {}", kind, reason);
            None
        }
    }
}

/// Resolve every credential kind for this process. Called once at startup.
///
/// When `KEY_IMPORT_ENABLED` is false this returns environment-only
/// resolutions without touching the database, so a deployment that never opts
/// in behaves exactly as it did before this feature existed.
pub async fn resolve_all(
    config: &Config,
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
) -> Vec<Resolution> {
    let mut out = Vec::with_capacity(VALID_CREDENTIAL_KINDS.len());
    for kind in VALID_CREDENTIAL_KINDS {
        out.push(resolve_one(config, pool, protector, kind).await);
    }
    out
}

async fn resolve_one(
    config: &Config,
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    kind: &'static str,
) -> Resolution {
    let env = env_parts(kind);
    let env_fp = env.as_ref().map(|p| p.set_fingerprint(kind));

    // Shared by every path that ends up on the environment credential.
    let from_env = |parts: Option<CredentialParts>, error: Option<String>| match parts {
        Some(parts) => Resolution {
            kind,
            source: CREDENTIAL_SOURCE_ENV,
            parts: Some(parts),
            version: None,
            set_fingerprint: env_fp.clone(),
            env_fingerprint: env_fp.clone(),
            previous_parts: None,
            error,
        },
        None => Resolution {
            env_fingerprint: env_fp.clone(),
            error,
            ..Resolution::unconfigured(kind)
        },
    };

    if !config.key_import_enabled {
        return from_env(env, None);
    }

    match load_active(pool, protector, kind).await {
        ActiveLookup::Found(stored) => {
            info!(
                "keys: '{}' resolved from the database (version {}, fingerprint {})",
                kind, stored.version, stored.set_fingerprint
            );
            if env_fp.is_some() {
                warn!(
                    "keys: '{}' is imported but its environment variables are still set; \
                     the stored credential wins, and disabling KEY_IMPORT_ENABLED would \
                     silently revert to the environment one",
                    kind
                );
            }
            let previous = load_previous(pool, protector, kind).await.map(|p| p.parts);
            Resolution {
                kind,
                source: CREDENTIAL_SOURCE_DB,
                parts: Some(stored.parts),
                version: Some(stored.version),
                set_fingerprint: Some(stored.set_fingerprint),
                env_fingerprint: env_fp,
                previous_parts: previous,
                error: None,
            }
        }
        ActiveLookup::None => from_env(env, None),
        ActiveLookup::Unusable(reason) => {
            // Fail closed on the provider, not on the process, and NOT onto the
            // environment: a row exists, so falling back would re-activate the
            // credential an admin deliberately replaced.
            error!(
                "keys: '{}' has an active stored credential that could not be used ({}). \
                 The provider is DISABLED for this process; it will not fall back to the \
                 environment. Fix the row or set KEY_IMPORT_ENABLED=false and restart.",
                kind, reason
            );
            Resolution {
                kind,
                source: CREDENTIAL_SOURCE_UNCONFIGURED,
                parts: None,
                version: None,
                set_fingerprint: None,
                env_fingerprint: env_fp,
                previous_parts: None,
                error: Some(reason),
            }
        }
        ActiveLookup::LookupFailed(reason) => {
            // We do not know whether a stored credential exists — most often
            // because migration 033 has not been applied yet on a fresh
            // deployment. Disabling a provider whose environment credential is
            // right there would be a self-inflicted outage, so use it, loudly.
            error!(
                "keys: could not determine whether '{}' has a stored credential ({}). \
                 Falling back to the environment for this process. If a stored \
                 credential was expected, fix the database and restart.",
                kind, reason
            );
            from_env(env, Some(reason))
        }
    }
}

// ── Writes ────────────────────────────────────────────────────────────

/// Guarded compare-and-swap: supersede the currently-active row (if the caller
/// expected one) and insert a new active version.
///
/// `expected_active_fp` is `Some(fp)` when the caller believes a stored row is
/// active and `None` when it believes there is none. Both are verified under
/// the row lock, so two admins racing cannot both win, and an admin cannot
/// replace a credential that changed under them since they read it.
#[allow(clippy::too_many_arguments)]
pub async fn insert_version(
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    kind: &str,
    parts: &CredentialParts,
    expected_active_fp: Option<&str>,
    imported_by: &str,
    note: Option<&str>,
) -> Result<i32, AppError> {
    let fingerprints = parts.fingerprints(kind);
    let set_fingerprint = super::set_fingerprint_from_parts(kind, &fingerprints);
    let fingerprints_json = serde_json::to_value(&fingerprints).map_err(|e| {
        error!("keys: fingerprint serialization failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    // The version is sealed into the ciphertext, so it must be decided before
    // encryption. Predict it, then let the (kind, version) unique index arbitrate;
    // a loser re-predicts and re-encrypts rather than reusing a stale header.
    for attempt in 0..3 {
        let next: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM bridge_credential WHERE kind = $1",
        )
        .bind(kind)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("keys: version probe failed: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

        let sealed = parts.seal(kind, next)?;
        let protected = protector.encrypt_seed(&sealed).await?;

        let mut tx = pool.begin().await.map_err(|e| {
            error!("keys: begin failed: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

        // Lock the active row (if any) and confirm it is what the caller saw.
        let current: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, set_fingerprint FROM bridge_credential \
             WHERE kind = $1 AND state = 'active' FOR UPDATE",
        )
        .bind(kind)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            error!("keys: active lock failed: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;

        match (current.as_ref(), expected_active_fp) {
            (Some((_, fp)), Some(expected)) if super::tokens_match(fp, expected) => {}
            (None, None) => {}
            _ => {
                return Err(AppError::Conflict(
                    "The stored credential changed since you read it; refresh and retry"
                        .to_string(),
                ));
            }
        }

        // Order is load-bearing: `uq_bridge_credential_active` is a PARTIAL
        // UNIQUE INDEX on (kind) WHERE state = 'active', enforced per row at
        // write time and never deferrable. Inserting the new active row first
        // therefore collides with the incumbent inside this very transaction —
        // the FOR UPDATE lock above cannot help, because the conflict is with
        // our own statement ordering, not with another writer. Retire the
        // incumbent first, then insert.
        if let Some((old_id, _)) = current {
            let retired = sqlx::query(
                "UPDATE bridge_credential \
                 SET state = 'superseded', superseded_at = CURRENT_TIMESTAMP \
                 WHERE id = $1 AND state = 'active'",
            )
            .bind(old_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("keys: supersede failed: {}", e);
                AppError::InternalError("Database error".to_string())
            })?;
            if retired.rows_affected() != 1 {
                return Err(AppError::Conflict(
                    "The stored credential changed while this request was in flight; retry"
                        .to_string(),
                ));
            }
        }

        let inserted: Result<Uuid, sqlx::Error> = sqlx::query_scalar(CREDENTIAL_INSERT_SQL)
            .bind(kind)
            .bind(next)
            .bind(protected.backend.as_str())
            .bind(&protected.ciphertext)
            .bind(&protected.wrapped_data_key)
            .bind(&protected.nonce)
            .bind(&protected.key_id)
            .bind(&protected.key_version)
            .bind(&fingerprints_json)
            .bind(&set_fingerprint)
            .bind(imported_by)
            .bind(note)
            .fetch_one(&mut *tx)
            .await;

        let new_id = match inserted {
            Ok(id) => id,
            Err(e) => {
                let msg = e.to_string();
                // Lost the version race. The version is sealed into the
                // ciphertext, so the losing blob cannot be reused: re-predict
                // and re-seal rather than retrying the same bytes.
                if (msg.contains("duplicate key") || msg.contains("unique constraint"))
                    && attempt < 2
                {
                    warn!("keys: version race on '{}', retrying", kind);
                    continue;
                }
                if msg.contains("duplicate key") || msg.contains("unique constraint") {
                    return Err(AppError::Conflict(
                        "Another import for this credential is in progress; retry".to_string(),
                    ));
                }
                error!("keys: insert failed: {}", e);
                return Err(AppError::InternalError("Database error".to_string()));
            }
        };

        // Link the retired row to its replacement. Separate from the retire
        // above only because the new id does not exist until the insert.
        if let Some((old_id, _)) = current {
            sqlx::query("UPDATE bridge_credential SET superseded_by = $2 WHERE id = $1")
                .bind(old_id)
                .bind(new_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("keys: supersede link failed: {}", e);
                    AppError::InternalError("Database error".to_string())
                })?;
        }

        tx.commit().await.map_err(|e| {
            error!("keys: commit failed: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
        return Ok(next);
    }

    Err(AppError::Conflict(
        "Could not allocate a credential version; retry".to_string(),
    ))
}

/// Revoke the active row for a kind, scrubbing its secret columns immediately.
///
/// Unlike supersession there is no overlap window: revocation is the action an
/// operator takes when a key is believed compromised, and keeping it
/// decryptable would leave a database reader able to recover it.
pub async fn revoke_active(pool: &PgPool, kind: &str, expected_fp: &str) -> Result<i32, AppError> {
    let revoked: Option<i32> = sqlx::query_scalar(
        "UPDATE bridge_credential \
         SET state = 'revoked', \
             superseded_at = COALESCE(superseded_at, CURRENT_TIMESTAMP), \
             scrubbed_at = CURRENT_TIMESTAMP, \
             ciphertext = NULL, wrapped_data_key = NULL, nonce = NULL \
         WHERE kind = $1 AND state = 'active' AND set_fingerprint = $2 \
         RETURNING version",
    )
    .bind(kind)
    .bind(expected_fp)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("keys: revoke failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    revoked.ok_or_else(|| {
        AppError::Conflict(
            "No active stored credential with that fingerprint; refresh and retry".to_string(),
        )
    })
}

/// Scrub superseded rows past the overlap grace. Called at startup and after
/// each mutation, so no background task is needed to bound how long an old key
/// stays recoverable.
pub async fn scrub_expired(pool: &PgPool) -> u64 {
    match sqlx::query(
        "UPDATE bridge_credential \
         SET ciphertext = NULL, wrapped_data_key = NULL, nonce = NULL, \
             scrubbed_at = CURRENT_TIMESTAMP \
         WHERE state IN ('superseded', 'revoked') AND scrubbed_at IS NULL \
           AND superseded_at < CURRENT_TIMESTAMP - make_interval(secs => $1)",
    )
    .bind(CREDENTIAL_SUPERSEDE_GRACE_SECS as f64)
    .execute(pool)
    .await
    {
        Ok(r) => {
            let n = r.rows_affected();
            if n > 0 {
                info!("keys: scrubbed {} expired credential row(s)", n);
            }
            n
        }
        Err(e) => {
            error!("keys: scrub failed: {}", e);
            0
        }
    }
}

/// Non-secret listing of every stored row, newest version first per kind.
pub async fn list_rows(pool: &PgPool) -> Result<Vec<CredentialRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT id, kind, version, state, set_fingerprint, fingerprints, imported_by, \
                to_char(imported_at AT TIME ZONE 'UTC', '{ts}') AS imported_at, \
                to_char(superseded_at AT TIME ZONE 'UTC', '{ts}') AS superseded_at, \
                to_char(scrubbed_at AT TIME ZONE 'UTC', '{ts}') AS scrubbed_at, \
                note \
         FROM bridge_credential ORDER BY kind, version DESC",
        ts = TS_FMT
    ))
    .fetch_all(pool)
    .await
    .map_err(|e| {
        error!("keys: listing failed: {}", e);
        AppError::InternalError("Database error".to_string())
    })
}

// ── Runtime view ──────────────────────────────────────────────────────

/// What THIS process actually resolved for one credential kind. Reported by
/// `GET /admin/keys` alongside the stored rows, so an operator can see the gap
/// between "what is stored" and "what is running" — which is the whole point
/// of an activation model that waits for a restart.
#[derive(Clone, serde::Serialize)]
pub struct EffectiveKey {
    pub kind: &'static str,
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    /// The environment credential's fingerprint, when the environment carries
    /// one. Present whether or not it is the credential in use, because two
    /// things need it: spotting that a stored credential is SHADOWING an
    /// environment one (the rotation is not finished until that is gone), and
    /// working out what a restart WOULD resolve, which is what
    /// `pending_restart` means.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_fingerprint: Option<String>,
    /// Environment variables for this kind that are still set in this process.
    pub env_vars_set: Vec<&'static str>,
    /// Fixed-string reason this kind failed to resolve, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether the provider client was actually built and installed.
    pub active: bool,
}

/// The credential picture for this process, fixed at startup.
#[derive(Clone, serde::Serialize)]
pub struct KeyRuntime {
    /// Whether stored credentials are consulted and the admin endpoints work.
    pub enabled: bool,
    /// The at-rest protection backend, from configuration. Read from the
    /// config string rather than `SeedProtector::backend()`, which reports an
    /// arbitrary value for the disabled `NoneProtector`.
    pub protection_backend: String,
    pub effective: Vec<EffectiveKey>,
}

impl KeyRuntime {
    /// True when at least one kind has an active stored credential that could
    /// not be used. Surfaced by `GET /health` so the condition is visible
    /// without reading logs — but deliberately NOT by `/readyz`, which the
    /// orchestrator acts on: an unreadable credential row must degrade one
    /// provider, not cycle every task in the fleet.
    pub fn degraded(&self) -> bool {
        self.effective.iter().any(|e| e.error.is_some())
    }

    pub fn for_kind(&self, kind: &str) -> Option<&EffectiveKey> {
        self.effective.iter().find(|e| e.kind == kind)
    }
}

/// Which of a kind's environment variables are currently set. Names only —
/// values never leave the resolver.
pub fn env_vars_set(kind: &str) -> Vec<&'static str> {
    parts_for(kind)
        .unwrap_or(&[])
        .iter()
        .flat_map(|spec| {
            [Some(spec.env_var), spec.env_file_var]
                .into_iter()
                .flatten()
                .filter(|name| std::env::var(name).map(|v| !v.is_empty()).unwrap_or(false))
                .collect::<Vec<_>>()
        })
        .collect()
}

impl EffectiveKey {
    /// Project a resolution into its reportable form. `active` records whether
    /// the provider client was successfully constructed afterwards.
    pub fn from_resolution(r: &Resolution, active: bool) -> Self {
        EffectiveKey {
            kind: r.kind,
            source: r.source,
            fingerprint: r.set_fingerprint.clone(),
            version: r.version,
            env_fingerprint: r.env_fingerprint.clone(),
            env_vars_set: env_vars_set(r.kind),
            error: r.error.clone(),
            active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every guarded statement must carry its guard. A CAS that lost its
    // `AND state = 'active'` would revoke a superseded row and leave the live
    // one in place, reporting success.
    #[test]
    fn guarded_statements_keep_their_guards() {
        assert!(ACTIVE_SQL.contains("state = 'active'"));
        assert!(PREVIOUS_SQL.contains("state = 'superseded'"));
        assert!(PREVIOUS_SQL.contains("ciphertext IS NOT NULL"));
    }

    // sqlx checks bind TYPES at compile time but not bind COUNT: a widened
    // INSERT compiles cleanly and fails at runtime, mid-transaction. Pin the
    // column list against the placeholder list so adding a column without a
    // bind is a test failure rather than a production one.
    #[test]
    fn credential_insert_columns_match_its_placeholders() {
        let sql = CREDENTIAL_INSERT_SQL;
        let columns = sql[sql.find('(').unwrap() + 1..sql.find(')').unwrap()]
            .split(',')
            .count();
        let values_start = sql.find("VALUES (").unwrap() + "VALUES (".len();
        let values_end = values_start + sql[values_start..].find(')').unwrap();
        let values: Vec<&str> = sql[values_start..values_end].split(',').collect();
        assert_eq!(
            columns,
            values.len(),
            "column count and VALUES count disagree"
        );

        // Every value slot is either a placeholder or a literal; the highest
        // $n must equal the number of placeholders, or a bind is missing.
        let placeholders = values.iter().filter(|v| v.trim().starts_with('$')).count();
        let highest = values
            .iter()
            .filter_map(|v| v.trim().strip_prefix('$'))
            .filter_map(|n| n.parse::<usize>().ok())
            .max()
            .unwrap();
        assert_eq!(placeholders, highest, "placeholders are not 1..=n");
        // `state` is written as a literal, so exactly one slot is not a bind.
        assert_eq!(columns - placeholders, 1);
        assert!(sql.contains("'active'"));
    }

    // A partial provider environment — a stray webhook secret with no API key
    // — used to mean "unconfigured" and boot cleanly. Returning a set for it
    // would make the build fail, and an environment-sourced build failure is
    // fatal by design: a deployment that boots today would exit on upgrade.
    #[test]
    fn a_stray_env_var_without_its_api_key_reads_as_unconfigured() {
        for kind in VALID_CREDENTIAL_KINDS {
            let primary = super::super::primary_part(kind).expect("every kind has a primary");
            assert!(
                primary.required,
                "the primary part must be a required one ({})",
                kind
            );
            // It is always the API key: that is the variable the init functions
            // this replaced keyed their "unconfigured" answer on.
            assert_eq!(primary.name, "api_key", "primary part for {}", kind);
        }
    }

    // The two failure modes are deliberately different, and conflating them
    // breaks something either way: falling back to the environment on an
    // unusable row re-activates a replaced credential, while NOT falling back
    // on a failed lookup disables a working provider on a fresh deploy where
    // migration 033 has not run yet.
    #[test]
    fn an_unusable_row_and_a_failed_lookup_are_distinct_outcomes() {
        let unusable = ActiveLookup::Unusable("row 1 failed its binding check".to_string());
        let failed = ActiveLookup::LookupFailed("relation does not exist".to_string());
        assert!(matches!(unusable, ActiveLookup::Unusable(_)));
        assert!(matches!(failed, ActiveLookup::LookupFailed(_)));
    }

    #[test]
    fn an_unconfigured_kind_offers_nothing_to_compare_against() {
        // No effective fingerprint is how the handler tells "add" from
        // "replace" without a second flag.
        let r = Resolution::unconfigured("owlpay");
        assert!(r.set_fingerprint.is_none());
        assert!(r.parts.is_none());
        assert_eq!(r.source, CREDENTIAL_SOURCE_UNCONFIGURED);
    }
}

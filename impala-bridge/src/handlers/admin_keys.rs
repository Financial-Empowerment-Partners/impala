//! Admin key management (`/admin/keys/*`, `/admin/stellar-seeds/*`).
//!
//! # DANGER — read before changing anything here
//!
//! These endpoints install the credentials the bridge uses to move money.
//!
//! 1. **A provider credential is spend authority.** The replenishment driver
//!    sends real reserve XLM to the pay-in address the *active Changelly
//!    account* names. Whoever controls these credentials chooses a counterparty
//!    the bridge pays, and every swap and off-ramp thereafter clears through
//!    their provider account.
//! 2. **A custodial seed is signing authority.** `sign_and_submit_payment`
//!    derives the source account from the seed, so a seed decides which Stellar
//!    account the bridge signs as — not the row it is stored under.
//! 3. **Confirmation is anti-accident, not anti-attacker.** Every gate below —
//!    the expected-fingerprint compare-and-swap, the typed confirmation phrase,
//!    the in-flight guard — is defeated by one admin bearer token, because an
//!    admin can read the fingerprint they are asked to echo. They stop an
//!    operator from replacing the wrong thing, or two operators from clobbering
//!    each other. They do not stop a compromised admin credential. Adding a
//!    second factor here would be a real improvement and is not implemented.
//! 4. **Nothing takes effect until a restart.** Imports are stored, never
//!    pushed into running processes: the fleet is multi-instance, so a push
//!    would update one task and leave the rest on the old key while reporting
//!    success. Every response says so, and `GET /admin/keys` shows the gap
//!    between what is stored and what this instance is actually running.
//!
//! See `docs/runbooks/import-keys.md`.
//!
//! # Rules that must not be regressed
//!
//! - No response, log line, error message, or audit event ever carries secret
//!   material — including anything *derived* from a decrypted blob, whose
//!   leading bytes are the secret itself when the blob came from elsewhere.
//! - The reserve account's seed is **generate-only**. An admin-supplied reserve
//!   seed means a human holds the pool's signing key, and lets whoever calls
//!   the endpoint first during bootstrap capture every future deposit.
//! - A seed replacement may not change an account's Stellar address.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::Json;
use log::{error, info, warn};
use sqlx::PgPool;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::AdminUser;
use crate::constants::{
    CREDENTIAL_NOTE_MAX_LEN, CREDENTIAL_SOURCE_DB, CREDENTIAL_SOURCE_UNCONFIGURED,
    EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, EXCHANGE_PROVIDER_CHANGELLY_FIAT, EXCHANGE_PROVIDER_OWLPAY,
    KEY_IMPORT_RATE_LIMIT_SCOPE, RESERVE_TERMINAL_CYCLE_STATES, SIGN_RATE_LIMIT_MAX_REQUESTS,
    SIGN_RATE_LIMIT_WINDOW_SECS, VALID_CREDENTIAL_KINDS,
};
use crate::error::AppError;
use crate::events::{emit_event, AccountEvent};
use crate::keys::store::{self, KeyRuntime};
use crate::keys::{self, CredentialParts};
use crate::models::{
    AdminImportSeedRequest, AdminSeedRequest, AdminSeedResponse, ImportKeyRequest,
    KeyActionResponse, KeyListResponse, KeyView, MergeKeyRequest, RevokeKeyRequest, SeedProbe,
};
use crate::seed_protect::SeedProtector;
use crate::stellar::StellarSigner;

/// Every mutating response says this, because it is the single fact an
/// operator most needs and is most likely to assume otherwise.
const EFFECTIVE_AFTER: &str = "rolling_restart";

fn db_err(context: &'static str) -> impl FnOnce(sqlx::Error) -> AppError {
    move |e: sqlx::Error| {
        error!("admin_keys: {}: {}", context, e);
        AppError::InternalError("Database error".to_string())
    }
}

/// The feature gate. Reads the CONFIGURED protection backend rather than
/// `SeedProtector::backend()`, which reports an arbitrary value for the
/// disabled `NoneProtector` and would let the whole feature switch on over a
/// protector that fails every call.
fn require_enabled(runtime: &KeyRuntime) -> Result<(), AppError> {
    if !runtime.enabled {
        return Err(AppError::Forbidden);
    }
    if runtime.protection_backend == "none" || runtime.protection_backend.is_empty() {
        return Err(AppError::BadRequest(
            "Key import requires SEED_PROTECTION_BACKEND to be kms, vault, or openbao — \
             there is no plaintext-at-rest path and none will be added"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_kind(kind: &str) -> Result<&'static str, AppError> {
    VALID_CREDENTIAL_KINDS
        .iter()
        .find(|k| **k == kind)
        .copied()
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "Invalid credential kind '{}'. Must be one of: {}",
                kind,
                VALID_CREDENTIAL_KINDS.join(", ")
            ))
        })
}

fn validate_note(note: Option<&str>) -> Result<(), AppError> {
    let Some(note) = note else { return Ok(()) };
    if note.len() > CREDENTIAL_NOTE_MAX_LEN {
        return Err(AppError::BadRequest(format!(
            "note must not exceed {} characters",
            CREDENTIAL_NOTE_MAX_LEN
        )));
    }
    // The note is stored in plaintext and re-served in listings, so a key
    // pasted here would defeat every protection in this module.
    if keys::looks_like_secret(note) {
        return Err(AppError::BadRequest(
            "note looks like it contains key material; notes are stored in plaintext \
             and shown in listings"
                .to_string(),
        ));
    }
    Ok(())
}

/// Move the submitted secrets into a zeroizing set and scrub the originals.
///
/// The request DTO is a plain `BTreeMap<String, String>` on a struct with no
/// `ZeroizeOnDrop`, so taking a copy would leave the plaintext in a heap
/// allocation freed unscrubbed — visible in a core dump, in swap, or to a
/// memory-disclosure bug. This narrows the window; it cannot close it, because
/// axum's buffered request body and serde's unescape scratch also hold the
/// values transiently (the same caveat as `managed_seed::import`).
fn take_parts(raw: &mut BTreeMap<String, String>) -> CredentialParts {
    let mut parts = CredentialParts::new();
    for (name, value) in raw.iter_mut() {
        let owned = Zeroizing::new(std::mem::take(value));
        parts.insert(name, &owned);
        value.zeroize();
    }
    raw.clear();
    parts
}

/// Count work that would be stranded by re-pointing this credential at a
/// different provider account.
///
/// A provider reference (`provider_order_id`, a swap id, a transfer id) is
/// meaningful only to the account that created it. Replace the credentials
/// with a different account's and every in-flight reference becomes unknown to
/// the provider: the reconcile poller defers those orders forever, and a
/// replenishment cycle can be left with treasury XLM already sent and nothing
/// able to claim it.
///
/// This counts every non-terminal row for the provider rather than only the
/// ones created under the current credential. That is deliberately coarse —
/// stamping each order with the credential it was created under would mean
/// widening money-path INSERTs for a guard that is advisory anyway, and the
/// coarse answer is the safe direction to err in.
async fn in_flight_count(pool: &PgPool, kind: &str) -> Result<i64, AppError> {
    // `= ANY(non_terminal)`, NOT `<> ALL(non_terminal)`: the latter is true
    // exactly when the status IS terminal, which counted settled history and
    // missed every live order — inverting the one guard standing between a
    // credential change and stranded funds. Matches DUE_ORDERS_SQL and
    // OPEN_RESERVE_ORDERS_SQL, which bind the same list.
    let orders: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM exchange_order WHERE provider = $1 AND status = ANY($2)",
    )
    .bind(kind)
    .bind(crate::exchange::reconcile::non_terminal_statuses())
    .fetch_one(pool)
    .await
    .map_err(db_err("in-flight orders"))?;

    // Replenishment cycles ride the same provider credentials.
    let cycles: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM conversion_reserve_replenishment \
         WHERE provider = $1 AND state <> ALL($2)",
    )
    .bind(kind)
    .bind(
        RESERVE_TERMINAL_CYCLE_STATES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    )
    .fetch_one(pool)
    .await
    .map_err(db_err("in-flight cycles"))?;

    Ok(orders + cycles)
}

/// The fingerprint of the credential CURRENTLY STORED for a kind, read live.
///
/// Distinct from what `KeyRuntime` reports, which is frozen at this process's
/// startup. Every compare-and-swap has to be against the live row: after the
/// first import in a process's lifetime the two disagree permanently, and a
/// gate that trusted the snapshot would reject every subsequent change until
/// someone restarted the fleet.
async fn stored_fingerprint(pool: &PgPool, kind: &str) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT set_fingerprint FROM bridge_credential WHERE kind = $1 AND state = 'active'",
    )
    .bind(kind)
    .fetch_optional(pool)
    .await
    .map_err(db_err("stored fingerprint"))
}

/// Prove the credential actually works before storing it.
///
/// Syntactic validation accepts a well-formed key for the wrong account, the
/// wrong environment, or a revoked one; the first symptom would otherwise be a
/// failed money movement after the next restart. One cheap authenticated
/// read-only call catches all three.
///
/// OwlPay has no read-only endpoint that does not need a real quote or
/// transfer id, so it cannot be probed this way. That is reported honestly
/// rather than faked with a request whose 404-versus-401 we would have to
/// guess at.
async fn probe_credential(
    config_urls: &ProbeConfig,
    kind: &str,
    parts: &CredentialParts,
) -> Result<Option<String>, AppError> {
    match kind {
        EXCHANGE_PROVIDER_CHANGELLY_CRYPTO => {
            let client = crate::exchange::changelly::build_changelly_crypto(&config_urls.0, parts)
                .map_err(AppError::BadRequest)?;
            client.get_currencies_full().await.map_err(|_| {
                AppError::BadRequest(
                    "The provider rejected this credential (authenticated probe failed). \
                     Check the key belongs to this environment, or pass skip_verify to store \
                     it anyway."
                        .to_string(),
                )
            })?;
            Ok(None)
        }
        EXCHANGE_PROVIDER_CHANGELLY_FIAT => {
            let client = crate::exchange::changelly::build_changelly_fiat(&config_urls.0, parts)
                .map_err(AppError::BadRequest)?;
            client.get_providers().await.map_err(|_| {
                AppError::BadRequest(
                    "The provider rejected this credential (authenticated probe failed). \
                     Check the key belongs to this environment, or pass skip_verify to store \
                     it anyway."
                        .to_string(),
                )
            })?;
            Ok(None)
        }
        EXCHANGE_PROVIDER_OWLPAY => {
            // Still parse it, so a malformed set is caught here rather than at
            // the next restart.
            crate::exchange::owlpay::build_owlpay_provider(&config_urls.0, parts, None)
                .map_err(AppError::BadRequest)?;
            Ok(Some(
                "OwlPay exposes no read-only endpoint that can be called without a live \
                 quote or transfer id, so this credential was validated but NOT proven \
                 against the provider."
                    .to_string(),
            ))
        }
        _ => Ok(None),
    }
}

/// The bits of `Config` the probe needs, carried as shared state so this
/// module never sees credentials that ride on `Config` (none do, by rule).
pub struct ProbeConfig(pub crate::config::Config);

// ── GET /admin/keys ───────────────────────────────────────────────────

/// List every credential kind: what this instance is running, what is stored,
/// and whether the two differ.
///
/// Readable even when the feature is disabled, so an operator can see stored
/// rows that are currently inert — the alternative hides exactly the state
/// most likely to confuse them.
pub async fn list_keys(
    _user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
) -> Result<Json<KeyListResponse>, AppError> {
    let rows = store::list_rows(&pool).await?;

    let mut keys = Vec::with_capacity(VALID_CREDENTIAL_KINDS.len());
    for kind in VALID_CREDENTIAL_KINDS {
        let effective = runtime.for_kind(kind);
        let active_row = rows
            .iter()
            .find(|r| r.kind == *kind && r.state == "active")
            .cloned();
        let history: Vec<_> = rows.iter().filter(|r| r.kind == *kind).cloned().collect();

        // "Stored differs from running" is the whole reason this listing
        // exists: with a restart-activated model it is the normal state
        // between an import and the deploy that picks it up.
        let stored_fp = active_row.as_ref().map(|r| r.set_fingerprint.clone());
        let running_fp = effective.and_then(|e| e.fingerprint.clone());

        // What a restart WOULD resolve: the stored credential if there is one,
        // otherwise the environment. Comparing against that rather than
        // against the stored row alone keeps a pure-environment deployment
        // (nothing stored, nothing pending) from being told to roll a
        // deployment that would change nothing.
        let next_fp = stored_fp
            .clone()
            .or_else(|| effective.and_then(|e| e.env_fingerprint.clone()));
        let pending_restart = next_fp != running_fp;

        // The credential a replacement would supersede, and therefore the
        // fingerprint an operator has to echo back. The stored row wins: it is
        // what the compare-and-swap acts on.
        let replace_target = stored_fp.clone().or_else(|| running_fp.clone());

        keys.push(KeyView {
            kind,
            parts: keys::parts_for(kind)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.name)
                .collect(),
            required_parts: keys::parts_for(kind)
                .unwrap_or(&[])
                .iter()
                .filter(|s| s.required)
                .map(|s| s.name)
                .collect(),
            effective_source: effective
                .map(|e| e.source)
                .unwrap_or(CREDENTIAL_SOURCE_UNCONFIGURED),
            effective_fingerprint: running_fp,
            effective_version: effective.and_then(|e| e.version),
            active: effective.map(|e| e.active).unwrap_or(false),
            resolution_error: effective.and_then(|e| e.error.clone()),
            // An environment credential is only "shadowed" when a stored one
            // is actually running instead of it. Reporting it otherwise would
            // tell an operator to remove the very variable in use.
            shadowed_env_fingerprint: effective.and_then(|e| {
                if e.source == CREDENTIAL_SOURCE_DB {
                    e.env_fingerprint.clone()
                } else {
                    None
                }
            }),
            env_vars_set: effective
                .map(|e| e.env_vars_set.clone())
                .unwrap_or_default(),
            stored_state: active_row.as_ref().map(|r| r.state.clone()),
            stored_version: active_row.as_ref().map(|r| r.version),
            stored_fingerprint: stored_fp,
            per_part_fingerprints: active_row
                .as_ref()
                .map(|r| r.fingerprints.clone())
                .unwrap_or(serde_json::json!({})),
            imported_by: active_row.as_ref().map(|r| r.imported_by.clone()),
            imported_at: active_row.as_ref().and_then(|r| r.imported_at.clone()),
            note: active_row.as_ref().and_then(|r| r.note.clone()),
            // Served whenever a replacement (or a revoke) is possible — which
            // includes a stored credential this instance failed to resolve.
            // Withholding it there would leave the clients unable to act on
            // exactly the row that needs recovering.
            confirm_phrase: replace_target
                .as_ref()
                .map(|_| keys::confirm_phrase(kind, stellar_config.network.as_str())),
            replace_target_fingerprint: replace_target,
            pending_restart,
            in_flight_count: in_flight_count(&pool, kind).await.unwrap_or(0),
            history,
        });
    }

    Ok(Json(KeyListResponse {
        enabled: runtime.enabled,
        protection_backend: runtime.protection_backend.clone(),
        degraded: runtime.degraded(),
        keys,
    }))
}

// ── Shared confirmation gate ──────────────────────────────────────────

struct ConfirmInput {
    kind: &'static str,
    replace: bool,
    expected_fingerprint: Option<String>,
    confirm_phrase: Option<String>,
    strand_in_flight: bool,
}

/// What the confirmation gate decided.
struct ConfirmOutcome {
    /// The stored fingerprint the compare-and-swap must find, or `None` when
    /// there must be no active stored row. Only a STORED row participates: an
    /// environment credential has nothing to supersede.
    cas: Option<String>,
    /// Whether this supersedes a credential that was actually in effect — the
    /// truth the audit event records, which is not the same question as
    /// whether a database row existed.
    replaced: bool,
}

/// The add-only default and the replacement compare-and-swap.
///
/// The gate keys off the **live** stored row plus what this process resolved,
/// never off the startup snapshot alone. Two states make that essential:
///
/// - After the first import in a process's lifetime, the snapshot still says
///   "unconfigured" while a row exists. Trusting it would call the next import
///   an addition, and the store-level CAS would then reject it forever with
///   advice ("refresh and retry") that no amount of refreshing can satisfy.
/// - When a stored credential fails to resolve, the snapshot has no
///   fingerprint at all — and that is precisely the row an operator most needs
///   to replace.
///
/// The fingerprint an operator echoes back is the one belonging to whatever is
/// about to be superseded: the stored row if there is one, otherwise the
/// environment credential in effect.
async fn check_confirmation(
    pool: &PgPool,
    runtime: &KeyRuntime,
    network: &str,
    input: ConfirmInput,
) -> Result<ConfirmOutcome, AppError> {
    let stored_fp = stored_fingerprint(pool, input.kind).await?;
    let effective = runtime.for_kind(input.kind);
    let effective_fp = effective.and_then(|e| e.fingerprint.clone());
    let effective_source = effective
        .map(|e| e.source)
        .unwrap_or(CREDENTIAL_SOURCE_UNCONFIGURED);

    let target = match stored_fp.clone().or(effective_fp) {
        // Nothing stored and nothing running: a genuine addition.
        None => {
            return Ok(ConfirmOutcome {
                cas: None,
                replaced: false,
            })
        }
        Some(target) => target,
    };

    let describe = if stored_fp.is_some() {
        format!("stored, and {} on this instance", effective_source)
    } else {
        format!("supplied by the {}", effective_source)
    };

    if !input.replace {
        return Err(AppError::Conflict(format!(
            "A credential for '{}' already exists ({}; fingerprint {}). Imports only ADD \
             by default. To replace it, resend with replace=true, \
             expected_fingerprint=\"{}\", and confirm_phrase=\"{}\".",
            input.kind,
            describe,
            target,
            target,
            keys::confirm_phrase(input.kind, network)
        )));
    }

    match input.expected_fingerprint.as_deref() {
        Some(given) if keys::tokens_match(given, &target) => {}
        _ => {
            return Err(AppError::Conflict(format!(
                "expected_fingerprint does not match the credential this would replace \
                 ({}). Refresh GET /admin/keys and retry — someone may have changed it \
                 since you looked.",
                target
            )));
        }
    }

    let phrase = keys::confirm_phrase(input.kind, network);
    match input.confirm_phrase.as_deref() {
        Some(given) if keys::tokens_match(given, &phrase) => {}
        _ => {
            return Err(AppError::Conflict(format!(
                "Replacing a credential requires confirm_phrase=\"{}\"",
                phrase
            )));
        }
    }

    if !input.strand_in_flight {
        let n = in_flight_count(pool, input.kind).await?;
        if n > 0 {
            return Err(AppError::Conflict(format!(
                "{} non-terminal order(s)/cycle(s) are still running against '{}'. If the \
                 new credential belongs to a DIFFERENT provider account, their provider \
                 references become unreachable and any value already sent is stranded. \
                 Settle them first, or resend with strand_in_flight=true if the new \
                 credential is for the same provider account.",
                n, input.kind
            )));
        }
    }

    Ok(ConfirmOutcome {
        cas: stored_fp,
        replaced: true,
    })
}

/// Shared tail of import/merge: probe, store, audit, scrub, respond.
#[allow(clippy::too_many_arguments)]
async fn store_and_audit(
    pool: &PgPool,
    protector: &Arc<dyn SeedProtector>,
    probe_cfg: &ProbeConfig,
    runtime: &KeyRuntime,
    kind: &'static str,
    parts: CredentialParts,
    outcome: ConfirmOutcome,
    skip_verify: bool,
    note: Option<&str>,
    actor: &str,
    action: &'static str,
) -> Result<Json<KeyActionResponse>, AppError> {
    parts.validate_for(kind)?;

    let mut verify_note = None;
    if skip_verify {
        warn!(
            "admin_keys: {} for '{}' by {} SKIPPED the provider probe",
            action, kind, actor
        );
        verify_note = Some(
            "Provider verification was skipped at your request; this credential is \
             unproven until the next restart uses it."
                .to_string(),
        );
    } else {
        verify_note = probe_credential(probe_cfg, kind, &parts)
            .await?
            .or(verify_note);
    }

    // `replaced` is whether something was in EFFECT, not whether a row existed:
    // superseding a live environment credential is a replacement even though
    // there is no stored row to compare against, and an audit trail that said
    // otherwise would be a lie about the thing it exists to record.
    let replaced = outcome.replaced;
    let version = store::insert_version(
        pool,
        protector,
        kind,
        &parts,
        outcome.cas.as_deref(),
        actor,
        note,
    )
    .await?;
    let set_fingerprint = parts.set_fingerprint(kind);

    let mut tx = pool.begin().await.map_err(db_err("audit begin"))?;
    emit_event(
        &mut tx,
        &AccountEvent::BridgeKeyImported {
            account_id: actor.to_string(),
            kind: kind.to_string(),
            version,
            set_fingerprint: set_fingerprint.clone(),
            replaced,
            action: action.to_string(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("audit commit"))?;

    // Bound how long the version this one just superseded stays recoverable.
    store::scrub_expired(pool).await;

    info!(
        "admin_keys: {} '{}' version {} fingerprint {} by {} (replaced={})",
        action, kind, version, set_fingerprint, actor, replaced
    );

    let shadow = runtime.for_kind(kind).and_then(|e| {
        if e.env_vars_set.is_empty() {
            None
        } else {
            Some(format!(
                "These environment variables are still set and would take over if \
                     KEY_IMPORT_ENABLED were turned off: {}. Remove them from the \
                     deployment to finish the rotation.",
                e.env_vars_set.join(", ")
            ))
        }
    });

    Ok(Json(KeyActionResponse {
        success: true,
        message: format!(
            "Credential stored for '{}' (version {}). It is NOT in use yet: this instance \
             keeps running the credential it resolved at startup. Roll the deployment to \
             activate it everywhere.",
            kind, version
        ),
        kind: kind.to_string(),
        version: Some(version),
        set_fingerprint: Some(set_fingerprint),
        effective_after: EFFECTIVE_AFTER.to_string(),
        verify_note,
        env_shadow_note: shadow,
    }))
}

// ── POST /admin/keys/{kind} ───────────────────────────────────────────

/// Import a credential set — adding by default, replacing only on explicit
/// confirmation.
#[allow(clippy::too_many_arguments)]
pub async fn import_key(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(probe_cfg): Extension<Arc<ProbeConfig>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Path(kind): Path<String>,
    Json(mut payload): Json<ImportKeyRequest>,
) -> Result<Json<KeyActionResponse>, AppError> {
    require_enabled(&runtime)?;
    let kind = require_kind(&kind)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    validate_note(payload.note.as_deref())?;

    info!(
        "POST /admin/keys/{}: admin={} replace={}",
        kind, user.account_id, payload.replace
    );

    let parts = take_parts(&mut payload.parts);
    if parts.is_empty() {
        return Err(AppError::BadRequest("parts must not be empty".to_string()));
    }

    let outcome = check_confirmation(
        &pool,
        &runtime,
        stellar_config.network.as_str(),
        ConfirmInput {
            kind,
            replace: payload.replace,
            expected_fingerprint: payload.expected_fingerprint.clone(),
            confirm_phrase: payload.confirm_phrase.clone(),
            strand_in_flight: payload.strand_in_flight,
        },
    )
    .await?;

    store_and_audit(
        &pool,
        &protector,
        &probe_cfg,
        &runtime,
        kind,
        parts,
        outcome,
        payload.skip_verify,
        payload.note.as_deref(),
        &user.account_id,
        "import",
    )
    .await
}

// ── POST /admin/keys/{kind}/merge ─────────────────────────────────────

/// Rotate part of a stored set without re-entering the parts an admin cannot
/// read back (Changelly rotates its callback public key on its own schedule).
///
/// Only works against a STORED set: there is nothing to merge into an
/// environment-sourced credential, and inventing one from environment values
/// would silently promote the deployment's secrets into the database.
#[allow(clippy::too_many_arguments)]
pub async fn merge_key(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(probe_cfg): Extension<Arc<ProbeConfig>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Path(kind): Path<String>,
    Json(mut payload): Json<MergeKeyRequest>,
) -> Result<Json<KeyActionResponse>, AppError> {
    require_enabled(&runtime)?;
    let kind = require_kind(&kind)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    validate_note(payload.note.as_deref())?;

    let current = match store::load_active(&pool, &protector, kind).await {
        store::ActiveLookup::Found(c) => *c,
        store::ActiveLookup::None => {
            return Err(AppError::NotFound(format!(
                "No stored credential for '{}' to merge into. Import a complete set first.",
                kind
            )));
        }
        // A merge overlays parts onto the stored set, so it cannot proceed
        // without opening that set. Importing a complete one is the way out.
        store::ActiveLookup::Unusable(reason) | store::ActiveLookup::LookupFailed(reason) => {
            error!(
                "admin_keys: merge could not open the active row: {}",
                reason
            );
            return Err(AppError::InternalError(
                "The stored credential could not be opened; import a complete set instead"
                    .to_string(),
            ));
        }
    };

    let overlay = take_parts(&mut payload.set_parts);
    if overlay.is_empty() && payload.drop_parts.is_empty() {
        return Err(AppError::BadRequest(
            "Provide set_parts and/or drop_parts".to_string(),
        ));
    }
    // Removing a part is a capability change (dropping the webhook secret
    // stops verifying inbound deliveries), so it must be named explicitly
    // rather than implied by omission.
    for name in &payload.drop_parts {
        if !current.parts.contains(name) {
            return Err(AppError::BadRequest(format!(
                "Cannot drop '{}': it is not part of the stored set",
                name
            )));
        }
    }

    let merged = current.parts.merged_with(&overlay, &payload.drop_parts);
    if merged.set_fingerprint(kind) == current.set_fingerprint {
        return Err(AppError::BadRequest(
            "The merged set is identical to the stored one; nothing to do".to_string(),
        ));
    }

    // A merge always replaces a live credential, so it always confirms.
    let outcome = check_confirmation(
        &pool,
        &runtime,
        stellar_config.network.as_str(),
        ConfirmInput {
            kind,
            replace: true,
            expected_fingerprint: payload.expected_fingerprint.clone(),
            confirm_phrase: payload.confirm_phrase.clone(),
            strand_in_flight: payload.strand_in_flight,
        },
    )
    .await?;

    store_and_audit(
        &pool,
        &protector,
        &probe_cfg,
        &runtime,
        kind,
        merged,
        outcome,
        payload.skip_verify,
        payload.note.as_deref(),
        &user.account_id,
        "merge",
    )
    .await
}

// ── POST /admin/keys/{kind}/revoke ────────────────────────────────────

/// Revoke the stored credential for a kind, scrubbing its ciphertext at once.
///
/// Bridge-side revocation does NOT invalidate the key at the provider. If the
/// key is believed compromised, revoke it there first; this only stops the
/// bridge using it, and only from the next restart.
pub async fn revoke_key(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Path(kind): Path<String>,
    Json(payload): Json<RevokeKeyRequest>,
) -> Result<Json<KeyActionResponse>, AppError> {
    require_enabled(&runtime)?;
    let kind = require_kind(&kind)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let phrase = keys::confirm_phrase(kind, stellar_config.network.as_str());
    if !payload
        .confirm_phrase
        .as_deref()
        .map(|g| keys::tokens_match(g, &phrase))
        .unwrap_or(false)
    {
        return Err(AppError::Conflict(format!(
            "Revoking a credential requires confirm_phrase=\"{}\"",
            phrase
        )));
    }

    // What happens after the next restart, spelled out before it happens.
    let env_vars = store::env_vars_set(kind);
    let next_source = if env_vars.is_empty() {
        "unconfigured — the provider will be DISABLED".to_string()
    } else {
        format!(
            "the environment ({}) — a DIFFERENT credential will take over",
            env_vars.join(", ")
        )
    };
    if !payload.confirm_next_source {
        return Err(AppError::Conflict(format!(
            "After the next restart this provider would fall back to {}. Resend with \
             confirm_next_source=true to accept that.",
            next_source
        )));
    }

    // Revoking strands in-flight work exactly as a replacement does — more so,
    // because the provider may end up unconfigured with nothing able to
    // reconcile those references at all.
    if !payload.strand_in_flight {
        let n = in_flight_count(&pool, kind).await?;
        if n > 0 {
            return Err(AppError::Conflict(format!(
                "{} non-terminal order(s)/cycle(s) are still running against '{}'. After \
                 the next restart nothing will be able to reconcile them. Settle them \
                 first, or resend with strand_in_flight=true to accept that.",
                n, kind
            )));
        }
    }

    let version = store::revoke_active(&pool, kind, &payload.expected_fingerprint).await?;

    let mut tx = pool.begin().await.map_err(db_err("audit begin"))?;
    emit_event(
        &mut tx,
        &AccountEvent::BridgeKeyRevoked {
            account_id: user.account_id.clone(),
            kind: kind.to_string(),
            version,
            set_fingerprint: payload.expected_fingerprint.clone(),
            next_source: next_source.clone(),
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("audit commit"))?;

    warn!(
        "admin_keys: REVOKED '{}' version {} by {}; next source: {}",
        kind, version, user.account_id, next_source
    );

    Ok(Json(KeyActionResponse {
        success: true,
        message: format!(
            "Credential for '{}' revoked and its ciphertext scrubbed. This instance keeps \
             using it until restarted; after the restart the source becomes {}. Revoking \
             here does NOT invalidate the key at the provider — do that there too.",
            kind, next_source
        ),
        kind: kind.to_string(),
        version: Some(version),
        set_fingerprint: None,
        effective_after: EFFECTIVE_AFTER.to_string(),
        verify_note: None,
        env_shadow_note: None,
    }))
}

// ── Stellar seeds ─────────────────────────────────────────────────────

/// Look the account up on chain so an obviously unusable seed is caught here
/// rather than at the first payment.
async fn probe_seed(http: &reqwest::Client, horizon_url: &str, address: &str) -> Option<SeedProbe> {
    let account = crate::stellar::fetch_account_details(http, horizon_url, address)
        .await
        .ok()?;
    // Weight of the account's own master key. Zero means the key has been
    // disabled on chain and cannot authorize anything, however valid it looks.
    let master_weight = account
        .signers
        .iter()
        .find(|s| s.key == address)
        .map(|s| s.weight);
    Some(SeedProbe {
        exists: account.exists,
        master_key_weight: master_weight,
        native_balance: account.native_balance.clone(),
        non_native_balances: account.balances.len() as i64,
    })
}

fn seed_probe_blocks(probe: &Option<SeedProbe>) -> Option<String> {
    let probe = probe.as_ref()?;
    if probe.exists && probe.master_key_weight == Some(0) {
        return Some(
            "This account's master key has weight 0 on chain: the seed cannot authorize \
             anything. The bridge signs as the seed's own account and does not support \
             delegated signers, so this seed would be useless."
                .to_string(),
        );
    }
    None
}

/// `POST /admin/stellar-seeds/generate` — provision a custodial seed the
/// bridge generates itself.
///
/// This is the ONLY way to provision the conversion-reserve account's seed.
/// Import is refused there: an admin-supplied reserve seed means a human holds
/// the pool's signing key indefinitely, and during bootstrap it would let
/// whoever calls first install a key they control, capturing every deposit the
/// bridge subsequently directs at the reserve address.
#[allow(clippy::too_many_arguments)]
pub async fn generate_seed(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(signer): Extension<Arc<dyn StellarSigner>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Json(payload): Json<AdminSeedRequest>,
) -> Result<Json<AdminSeedResponse>, AppError> {
    require_enabled(&runtime)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;
    let account_id = payload.payala_account_id.trim();
    if account_id.is_empty() || account_id.len() > 64 {
        return Err(AppError::BadRequest(
            "payala_account_id must be 1-64 characters".to_string(),
        ));
    }

    let is_reserve = guard.matches(account_id);
    info!(
        "POST /admin/stellar-seeds/generate: admin={} account={} reserve={}",
        user.account_id, account_id, is_reserve
    );

    let (stellar_account_id, seed) = signer.generate_keypair()?;
    let protected = protector
        .encrypt_seed(&crate::handlers::managed_seed::seal_seed(
            account_id,
            seed.as_slice(),
        ))
        .await?;

    let label = payload.label.as_deref().unwrap_or("Bridge").trim();
    let label = if label.is_empty() { "Bridge" } else { label };
    if label.len() > 32 {
        return Err(AppError::BadRequest(
            "label must not exceed 32 characters".to_string(),
        ));
    }

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let seed_insert = sqlx::query(
        "INSERT INTO managed_seed \
            (payala_account_id, stellar_account_id, backend, ciphertext, wrapped_data_key, \
             nonce, key_id, key_version, origin, format_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'generated', $9)",
    )
    .bind(account_id)
    .bind(&stellar_account_id)
    .bind(protected.backend.as_str())
    .bind(&protected.ciphertext)
    .bind(&protected.wrapped_data_key)
    .bind(&protected.nonce)
    .bind(&protected.key_id)
    .bind(&protected.key_version)
    .bind(crate::constants::SEED_FORMAT_BOUND)
    .execute(&mut *tx)
    .await;

    if let Err(e) = seed_insert {
        let msg = e.to_string();
        if msg.contains("duplicate key") || msg.contains("unique constraint") {
            // Add-only: an existing seed is never overwritten here.
            return Err(AppError::Conflict(
                "This account already has a custodial seed. Generating would orphan the \
                 existing one; use POST /admin/stellar-seeds/import to re-import the same \
                 key, or use a different account id."
                    .to_string(),
            ));
        }
        error!("admin_keys: seed insert failed: {}", e);
        return Err(AppError::InternalError("Database error".to_string()));
    }

    // A service account may not exist yet; create a minimal row so the seed is
    // never orphaned from an account record. Existing rows are left untouched.
    sqlx::query(
        "INSERT INTO impala_account \
            (stellar_account_id, payala_account_id, first_name, last_name) \
         VALUES ($1, $2, $3, 'Service') \
         ON CONFLICT (payala_account_id) DO NOTHING",
    )
    .bind(&stellar_account_id)
    .bind(account_id)
    .bind(label)
    .execute(&mut *tx)
    .await
    .map_err(db_err("account insert"))?;

    // `DO NOTHING` leaves an EXISTING account record pointing at whatever
    // address it already had. If that is not the address this seed derives,
    // the account would advertise one address for deposits while the bridge
    // signed as another — the exact split the loader's address assertion
    // exists to prevent, arrived at from the other direction. Refuse, and let
    // the transaction roll the seed back with it.
    let recorded: Option<String> = sqlx::query_scalar(
        "SELECT stellar_account_id FROM impala_account WHERE payala_account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err("account address"))?;
    if recorded.as_deref() != Some(stellar_account_id.as_str()) {
        return Err(AppError::Conflict(format!(
            "Account '{}' already records the Stellar address {}, but this seed derives \
             {}. The bridge signs as the seed's own account, so binding them would make \
             the account advertise one address for deposits while signing as another. \
             Use a different account id.",
            account_id,
            recorded.as_deref().unwrap_or("nothing"),
            stellar_account_id
        )));
    }

    emit_event(
        &mut tx,
        &AccountEvent::BridgeSeedProvisioned {
            account_id: user.account_id.clone(),
            target_account_id: account_id.to_string(),
            stellar_account_id: stellar_account_id.clone(),
            origin: "generated".to_string(),
            is_reserve,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;

    info!(
        "admin_keys: generated custodial seed for '{}' -> {}",
        account_id, stellar_account_id
    );

    Ok(Json(AdminSeedResponse {
        success: true,
        message: format!(
            "Custodial seed generated for '{}'. The secret was created inside the bridge \
             and sealed with the configured protection backend; it has never existed \
             outside this process in plaintext, and there is no way to export it. Fund \
             {} before it can transact.{}",
            account_id,
            stellar_account_id,
            if is_reserve {
                " This is the configured RESERVE_ACCOUNT_ID: restart the bridge to \
                 activate the conversion reserve."
            } else {
                ""
            }
        ),
        stellar_account_id: Some(stellar_account_id),
        on_chain: None,
        effective_after: if is_reserve {
            EFFECTIVE_AFTER.to_string()
        } else {
            "immediately".to_string()
        },
    }))
}

/// `POST /admin/stellar-seeds/import` — bring an existing Stellar secret seed
/// under bridge custody for a NON-reserve account.
///
/// Replacement is add-only by default and may never change the account's
/// Stellar address. On this bridge an account's address IS its seed's public
/// key (`sign_and_submit_payment` derives the source from the seed), so a
/// different seed is a different account: swapping one in would leave the
/// bridge advertising one address for deposits while signing as another, and
/// strand whatever the old address holds. Rotating a Stellar key without
/// changing the address is an on-chain `set_options` operation, which this
/// custodial signer does not support.
#[allow(clippy::too_many_arguments)]
pub async fn import_seed(
    user: AdminUser,
    Extension(pool): Extension<PgPool>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(protector): Extension<Arc<dyn SeedProtector>>,
    Extension(signer): Extension<Arc<dyn StellarSigner>>,
    Extension(runtime): Extension<Arc<KeyRuntime>>,
    Extension(guard): Extension<Arc<crate::exchange::reserve::ReserveAccountGuard>>,
    Extension(http): Extension<Arc<reqwest::Client>>,
    Extension(stellar_config): Extension<Arc<crate::config::StellarConfig>>,
    Json(mut payload): Json<AdminImportSeedRequest>,
) -> Result<Json<AdminSeedResponse>, AppError> {
    require_enabled(&runtime)?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        KEY_IMPORT_RATE_LIMIT_SCOPE,
        &user.account_id,
        SIGN_RATE_LIMIT_MAX_REQUESTS,
        SIGN_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    let account_id = payload.payala_account_id.trim().to_string();
    if account_id.is_empty() || account_id.len() > 64 {
        return Err(AppError::BadRequest(
            "payala_account_id must be 1-64 characters".to_string(),
        ));
    }
    if guard.matches(&account_id) {
        error!(
            "admin_keys: refused seed IMPORT for the conversion-reserve account '{}' \
             (admin={})",
            account_id, user.account_id
        );
        return Err(AppError::Forbidden);
    }

    // Move the seed into a zeroizing buffer and scrub the original in place;
    // same reasoning as managed_seed::import_managed_account.
    let secret_seed = Zeroizing::new(std::mem::take(&mut payload.secret_seed));
    payload.secret_seed.zeroize();
    crate::validate::validate_stellar_secret_seed(&secret_seed)?;
    let seed = signer.seed_from_strkey(&secret_seed)?;
    let derived = signer.public_address(seed.as_slice())?;

    info!(
        "POST /admin/stellar-seeds/import: admin={} account={} replace={}",
        user.account_id, account_id, payload.replace
    );

    let existing: Option<String> = sqlx::query_scalar(
        "SELECT stellar_account_id FROM managed_seed WHERE payala_account_id = $1",
    )
    .bind(&account_id)
    .fetch_optional(&pool)
    .await
    .map_err(db_err("existing seed"))?;

    if let Some(current_address) = existing.as_deref() {
        if !payload.replace {
            return Err(AppError::Conflict(format!(
                "'{}' already has a custodial seed for {}. Imports only ADD by default. \
                 To replace it, resend with replace=true and \
                 expected_stellar_account_id=\"{}\" — note that the replacement must \
                 derive the SAME address.",
                account_id, current_address, current_address
            )));
        }
        match payload.expected_stellar_account_id.as_deref() {
            Some(given) if keys::tokens_match(given, current_address) => {}
            _ => {
                return Err(AppError::Conflict(format!(
                    "expected_stellar_account_id does not match the stored seed's address \
                     ({}). Refresh and retry.",
                    current_address
                )));
            }
        }
        if derived != current_address {
            return Err(AppError::Conflict(format!(
                "This seed derives {}, but '{}' is bound to {}. A seed replacement may not \
                 change an account's Stellar address: the bridge signs as the seed's own \
                 account, so the account would advertise one address for deposits while \
                 signing as another, and anything held at {} would be stranded. Create a \
                 new account and migrate instead.",
                derived, account_id, current_address, current_address
            )));
        }
        // Same address, so the only honest reason to do this is re-sealing.
        let phrase = format!(
            "replace seed {}",
            &current_address[current_address.len() - 6..]
        );
        if !payload
            .confirm_phrase
            .as_deref()
            .map(|g| keys::tokens_match(g, &phrase))
            .unwrap_or(false)
        {
            return Err(AppError::Conflict(format!(
                "Replacing a custodial seed requires confirm_phrase=\"{}\"",
                phrase
            )));
        }
    } else {
        // First-time bind. The account must exist, and — just as importantly —
        // must already record THIS address. Binding a key that derives a
        // different address would make the account advertise one address for
        // deposits while the bridge signed as another; the loader's assertion
        // compares against the seed's own row and would not catch it.
        let recorded: Option<String> = sqlx::query_scalar(
            "SELECT stellar_account_id FROM impala_account WHERE payala_account_id = $1",
        )
        .bind(&account_id)
        .fetch_optional(&pool)
        .await
        .map_err(db_err("account lookup"))?;

        match recorded.as_deref() {
            None => {
                return Err(AppError::NotFound(format!(
                    "No account '{}'. Seed import binds a key to an EXISTING account; use \
                     POST /admin/stellar-seeds/generate to create a service account and \
                     its key together.",
                    account_id
                )));
            }
            Some(addr) if addr == derived => {}
            Some(addr) => {
                return Err(AppError::Conflict(format!(
                    "Account '{}' records the Stellar address {}, but this seed derives \
                     {}. The bridge signs as the seed's own account, so the account would \
                     advertise one address for deposits while signing as another.",
                    account_id, addr, derived
                )));
            }
        }
    }

    let probe = probe_seed(&http, &stellar_config.horizon_url, &derived).await;
    if let Some(reason) = seed_probe_blocks(&probe) {
        if !payload.skip_verify {
            return Err(AppError::BadRequest(format!(
                "{} Pass skip_verify=true to store it anyway.",
                reason
            )));
        }
        warn!(
            "admin_keys: storing an unusable seed for '{}' at operator request: {}",
            account_id, reason
        );
    }

    let protected = protector
        .encrypt_seed(&crate::handlers::managed_seed::seal_seed(
            &account_id,
            seed.as_slice(),
        ))
        .await?;

    let mut tx = pool.begin().await.map_err(db_err("begin"))?;
    let written = if existing.is_some() {
        // Guarded on the address so a concurrent change loses rather than
        // being silently overwritten.
        sqlx::query(
            "UPDATE managed_seed \
             SET backend = $2, ciphertext = $3, wrapped_data_key = $4, nonce = $5, \
                 key_id = $6, key_version = $7, origin = 'imported', \
                 format_version = $8, updated_at = CURRENT_TIMESTAMP \
             WHERE payala_account_id = $1 AND stellar_account_id = $9",
        )
        .bind(&account_id)
        .bind(protected.backend.as_str())
        .bind(&protected.ciphertext)
        .bind(&protected.wrapped_data_key)
        .bind(&protected.nonce)
        .bind(&protected.key_id)
        .bind(&protected.key_version)
        .bind(crate::constants::SEED_FORMAT_BOUND)
        .bind(&derived)
        .execute(&mut *tx)
        .await
    } else {
        sqlx::query(
            "INSERT INTO managed_seed \
                (payala_account_id, stellar_account_id, backend, ciphertext, \
                 wrapped_data_key, nonce, key_id, key_version, origin, format_version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'imported', $9)",
        )
        .bind(&account_id)
        .bind(&derived)
        .bind(protected.backend.as_str())
        .bind(&protected.ciphertext)
        .bind(&protected.wrapped_data_key)
        .bind(&protected.nonce)
        .bind(&protected.key_id)
        .bind(&protected.key_version)
        .bind(crate::constants::SEED_FORMAT_BOUND)
        .execute(&mut *tx)
        .await
    };

    match written {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            return Err(AppError::Conflict(
                "The stored seed changed while this request was in flight; refresh and retry"
                    .to_string(),
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("duplicate key") || msg.contains("unique constraint") {
                return Err(AppError::Conflict(format!(
                    "{} is already bound to a different account on this bridge",
                    derived
                )));
            }
            error!("admin_keys: seed write failed: {}", e);
            return Err(AppError::InternalError("Database error".to_string()));
        }
    }

    emit_event(
        &mut tx,
        &AccountEvent::BridgeSeedProvisioned {
            account_id: user.account_id.clone(),
            target_account_id: account_id.clone(),
            stellar_account_id: derived.clone(),
            origin: "imported".to_string(),
            is_reserve: false,
        },
    )
    .await?;
    tx.commit().await.map_err(db_err("commit"))?;

    warn!(
        "admin_keys: imported a custodial seed for '{}' -> {} (admin={}). The plaintext \
         key exists outside the bridge and must be treated as compromised if that copy is.",
        account_id, derived, user.account_id
    );

    Ok(Json(AdminSeedResponse {
        success: true,
        message: format!(
            "Custodial seed stored for '{}' ({}). Signing uses it immediately. The key \
             also exists wherever you copied it from — rotate it there if that copy is \
             not under the same controls as this bridge.",
            account_id, derived
        ),
        stellar_account_id: Some(derived),
        on_chain: probe,
        effective_after: "immediately".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(enabled: bool, backend: &str) -> KeyRuntime {
        KeyRuntime {
            enabled,
            protection_backend: backend.to_string(),
            effective: Vec::new(),
        }
    }

    #[test]
    fn feature_is_off_by_default_and_refuses() {
        assert!(matches!(
            require_enabled(&runtime(false, "kms")),
            Err(AppError::Forbidden)
        ));
    }

    // `NoneProtector::backend()` reports `Kms` because it never produces a
    // persisted seed, so a gate that asked the trait would enable the whole
    // feature onto a protector whose every call fails.
    #[test]
    fn feature_refuses_without_a_real_protection_backend() {
        assert!(require_enabled(&runtime(true, "none")).is_err());
        assert!(require_enabled(&runtime(true, "")).is_err());
        assert!(require_enabled(&runtime(true, "kms")).is_ok());
        assert!(require_enabled(&runtime(true, "vault")).is_ok());
    }

    // The in-flight guard is the only thing standing between a credential
    // change and stranded provider references. `<> ALL(non_terminal)` is true
    // exactly when a status IS terminal, so the guard counted settled history
    // and missed every live order — passing precisely when money was in
    // flight. Pin the predicate against the ones the rest of the codebase uses.
    #[test]
    fn the_in_flight_query_selects_non_terminal_orders() {
        let sql = "SELECT COUNT(*) FROM exchange_order WHERE provider = $1 AND status = ANY($2)";
        assert!(sql.contains("= ANY($2)"));
        assert!(!sql.contains("<> ALL"));
        // The bound list is the NON-terminal set, so `= ANY` counts live work.
        let non_terminal = crate::exchange::reconcile::non_terminal_statuses();
        for terminal in crate::constants::TERMINAL_EXCHANGE_STATUSES {
            assert!(
                !non_terminal.iter().any(|s| s == terminal),
                "{} must not be in the non-terminal list",
                terminal
            );
        }
        assert!(non_terminal.iter().any(|s| s == "awaiting_deposit"));
        assert!(non_terminal.iter().any(|s| s == "on_hold"));

        // The cycles leg binds TERMINAL states, so it correctly uses `<> ALL`.
        // The two predicates must not be made to match each other.
        for state in crate::constants::RESERVE_TERMINAL_CYCLE_STATES {
            assert!(["completed", "failed", "refunded"].contains(state));
        }
    }

    #[test]
    fn unknown_kinds_are_rejected() {
        assert!(require_kind("changelly").is_err());
        assert!(require_kind("").is_err());
        assert!(require_kind(EXCHANGE_PROVIDER_OWLPAY).is_ok());
        // The reserve is a routing destination, not an external provider with
        // credentials of its own.
        assert!(require_kind("reserve").is_err());
    }

    #[test]
    fn notes_reject_pasted_key_material() {
        assert!(validate_note(Some("rotated per OPS-1421")).is_ok());
        assert!(validate_note(None).is_ok());
        assert!(validate_note(Some("-----BEGIN PRIVATE KEY-----")).is_err());
        assert!(validate_note(Some(&"a".repeat(CREDENTIAL_NOTE_MAX_LEN + 1))).is_err());
    }

    #[test]
    fn take_parts_scrubs_the_request_dto() {
        let mut raw = BTreeMap::new();
        raw.insert("api_key".to_string(), "super-secret".to_string());
        let parts = take_parts(&mut raw);
        assert_eq!(parts.get("api_key"), Some("super-secret"));
        // The source map must not still be holding the plaintext.
        assert!(raw.is_empty());
    }

    // A weight-0 master key is the one on-chain state that makes a seed
    // definitively useless to this signer, which derives the source account
    // from the seed and cannot use a delegated signer.
    #[test]
    fn seed_probe_blocks_only_a_disabled_master_key() {
        let disabled = Some(SeedProbe {
            exists: true,
            master_key_weight: Some(0),
            native_balance: Some("10".to_string()),
            non_native_balances: 0,
        });
        assert!(seed_probe_blocks(&disabled).is_some());

        let usable = Some(SeedProbe {
            exists: true,
            master_key_weight: Some(1),
            native_balance: Some("10".to_string()),
            non_native_balances: 0,
        });
        assert!(seed_probe_blocks(&usable).is_none());

        // An account that does not exist yet is legitimate — it just has not
        // been funded.
        let unfunded = Some(SeedProbe {
            exists: false,
            master_key_weight: None,
            native_balance: None,
            non_native_balances: 0,
        });
        assert!(seed_probe_blocks(&unfunded).is_none());

        // Horizon unreachable must not block provisioning.
        assert!(seed_probe_blocks(&None).is_none());
    }
}

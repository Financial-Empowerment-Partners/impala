//! Account & transaction state-change events for the admin webhook feed.
//!
//! Events are appended to the durable `event_outbox` table (the canonical feed),
//! and a background worker (`admin_webhook_delivery`) fans them out to registered
//! admin webhooks as **HMAC-SHA256-signed** POSTs. Payloads deliberately exclude
//! secrets/PII (no MFA secret, no raw device token).

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{Postgres, Transaction};

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

/// A backend state change worth surfacing to admins.
#[derive(Debug, Clone)]
pub enum AccountEvent {
    AccountCreated {
        account_id: String,
        stellar_account_id: String,
    },
    AccountUpdated {
        account_id: String,
        fields: Vec<String>,
    },
    TransactionCreated {
        account_id: String,
        btxid: String,
        stellar_tx_id: Option<String>,
        payala_tx_id: Option<String>,
    },
    CardRegistered {
        account_id: String,
        card_id: String,
    },
    CardDeleted {
        account_id: String,
        card_id: String,
    },
    MfaEnrolled {
        account_id: String,
        mfa_type: String,
    },
    /// An SMS notification destination was confirmed by its recipient. Carries
    /// the row id only — never the number.
    NotifyMobileVerified {
        account_id: String,
        notify_id: i32,
    },
    DeviceTokenRegistered {
        account_id: String,
        platform: String,
    },
    DeviceTokenDeleted {
        account_id: String,
    },
    ExchangeOrderCreated {
        account_id: String,
        order_id: String,
        provider: String,
        direction: String,
        from_currency: String,
        to_currency: String,
        amount_from: String,
    },
    ExchangeOrderUpdated {
        account_id: String,
        order_id: String,
        provider: String,
        status: String,
        provider_status: String,
    },
    // Conversion-reserve events. Payloads carry currencies, minor-unit
    // amounts, and statuses only — never pay-in/payout addresses, memos, or
    // beneficiary details (module privacy rule below).
    ReserveDepositMatched {
        account_id: String,
        order_id: String,
        currency: String,
        amount_minor: i64,
    },
    /// An admin added (or re-asserted) a trustline on the reserve account —
    /// the one on-chain operation the reserve signs that moves no money.
    /// Public identities only (asset code, issuer, tx hash); `account_id` is
    /// the acting admin.
    ReserveTrustlineAdded {
        account_id: String,
        currency: String,
        asset_code: String,
        asset_issuer: String,
        stellar_tx_hash: String,
    },
    ReserveFulfilled {
        account_id: String,
        order_id: String,
        currency: String,
        amount_minor: i64,
    },
    /// A payout could not be completed automatically; funds are frozen for
    /// admin resolution (`reason` = submit_failed|stale_intent|max_attempts).
    ReservePayoutPending {
        account_id: String,
        order_id: String,
        reason: String,
    },
    ReserveDisbursementPending {
        account_id: String,
        order_id: String,
        amount_usd_cents: i64,
    },
    ReserveOrderExpired {
        account_id: String,
        order_id: String,
    },
    /// Stray inflow to the reserve account (late/underpaid/unknown memo).
    /// account_id is the reserve account: stray funds have no known owner.
    ReserveUnmatchedDeposit {
        account_id: String,
        currency: String,
        amount_minor: i64,
        reason: String,
    },
    /// Per-tick roll-up of stray inflows whose individual
    /// `reserve.unmatched_deposit` events were suppressed by the per-sender
    /// feed budget (a dust flood): `count` rows totalling `amount_minor` from
    /// `senders` distinct payers. Every one of them is still individually
    /// recorded in the unmatched queue and the journal — only the feed is
    /// throttled. account_id is the reserve account; no addresses, as
    /// everywhere.
    ReserveUnmatchedDepositSummary {
        account_id: String,
        currency: String,
        count: i64,
        amount_minor: i64,
        senders: i64,
    },
    /// `available` crossed below the admin-set low-water mark.
    ReserveLowWater {
        account_id: String,
        currency: String,
        available_minor: i64,
        low_water_minor: i64,
    },
    /// Admin edited a reserve policy. account_id is the acting admin.
    ReservePolicyUpdated {
        account_id: String,
        provider: String,
        enabled: bool,
        threshold_usd_cents: i64,
    },
    /// A stranded deposit was queued for return to its payer.
    ReserveRefundQueued {
        account_id: String,
        refund_id: String,
        currency: String,
        amount_minor: i64,
        reason: String,
    },
    /// A refund settled on-chain.
    ReserveRefundSent {
        account_id: String,
        refund_id: String,
        currency: String,
        amount_minor: i64,
    },
    /// A refund could not be completed automatically and is waiting on an
    /// admin (`reason` = rejected|submit_unknown|stale_claim).
    ReserveRefundFailed {
        account_id: String,
        refund_id: String,
        reason: String,
    },
    /// Admin-recorded manual ledger entry. account_id is the acting admin.
    ReserveEntryRecorded {
        account_id: String,
        currency: String,
        kind: String,
        amount_minor: i64,
    },
    /// An account's role was changed by an admin. Role grants are governance
    /// over spend-adjacent authority (treasurer, key-custodian), so they get
    /// the same feed visibility as key operations. `account_id` is the TARGET
    /// account; the acting admin rides in `actor`.
    RoleChanged {
        account_id: String,
        actor: String,
        old_role: String,
        new_role: String,
    },
    // Bridge credential/key management. account_id is the acting admin.
    // Payloads carry FINGERPRINTS and identities only — never key material,
    // and never anything derived from a decrypted blob.
    /// A provider credential set was stored (`action` = import | merge).
    BridgeKeyImported {
        account_id: String,
        kind: String,
        version: i32,
        set_fingerprint: String,
        /// Whether this superseded a credential that was already in effect.
        replaced: bool,
        action: String,
    },
    /// A stored provider credential was revoked and its ciphertext scrubbed.
    BridgeKeyRevoked {
        account_id: String,
        kind: String,
        version: i32,
        set_fingerprint: String,
        /// What the provider falls back to after the next restart.
        next_source: String,
    },
    /// A custodial Stellar seed was provisioned by an admin
    /// (`origin` = generated | imported). The public address is not a secret.
    BridgeSeedProvisioned {
        account_id: String,
        target_account_id: String,
        stellar_account_id: String,
        origin: String,
        /// Whether the target is the configured conversion-reserve account —
        /// the single highest-value key in the deployment.
        is_reserve: bool,
    },
    // Custodial conservation controls (037). Payloads carry ids, statuses
    // and minor-unit amounts only — never a destination, memo, Stellar hash,
    // signable or signature (pinned by `custodial_payloads_never_carry_
    // addresses_or_hashes`). account_id is the beneficiary (the owner of
    // the custodial account) for payment events and the acting admin for
    // policy events.
    /// A custodial payment intent settled on-chain and its ledger row exists
    /// (`resolution` = submit_ok | sweep_settled | admin_complete).
    CustodialPaymentSettled {
        account_id: String,
        intent_id: String,
        btxid: String,
        origin: String,
        amount_minor: i64,
        asset_code: String,
        resolution: String,
    },
    /// A custodial submit's outcome is unknown; the intent is frozen for
    /// resolution by hash (sweep or admin) and will never be resubmitted.
    CustodialPaymentAmbiguous {
        account_id: String,
        intent_id: String,
        origin: String,
        amount_minor: i64,
        asset_code: String,
    },
    /// The custodial brake was pulled. account_id is the acting admin.
    CustodyPaused {
        account_id: String,
        reason: String,
    },
    /// The custodial brake was released (governance). `forced` = resumed
    /// while ambiguous intents were still open.
    CustodyResumed {
        account_id: String,
        forced: bool,
    },
    /// Custodial caps edited. account_id is the acting admin.
    CustodyPolicyUpdated {
        account_id: String,
        per_tx_max_stroops: i64,
        per_account_daily_max_stroops: i64,
        require_idempotency_key: bool,
    },
    /// A per-account custodial daily override was set or cleared (None).
    CustodyAccountLimitUpdated {
        account_id: String,
        target_account_id: String,
        custodial_daily_max_stroops: Option<i64>,
    },
    /// An admin resolved a submitted/ambiguous intent (`action` =
    /// complete | fail; `resolution` = admin_complete | admin_fail).
    CustodyIntentResolved {
        account_id: String,
        intent_id: String,
        action: String,
        resolution: String,
    },
    /// The daily reconciliation found a chain-legged reserve bucket outside
    /// its drift tolerance while Horizon was fresh. account_id is the
    /// reserve account (or "bridge" when no reserve is configured).
    ReserveDrift {
        account_id: String,
        currency: String,
        ledger_total_minor: i64,
        onchain_minor: i64,
        drift_minor: i64,
        tolerance_minor: i64,
        snapshot_id: String,
    },
    /// A reconciliation snapshot was recorded (`kind` = daily | manual).
    ReconciliationSnapshotRecorded {
        account_id: String,
        snapshot_id: String,
        kind: String,
        complete: bool,
        drift_detected: bool,
        invariants_ok: bool,
        horizon_fresh: bool,
    },
    /// A Payala sync batch was applied for `account_id` (counts only: no
    /// amounts, memos, ids or digests — the mirror is unverified data and
    /// the outbox must not become a second copy of it).
    PayalaSyncBatchApplied {
        account_id: String,
        batch_id: String,
        sync_mode: String,
        item_count: i64,
        applied_count: i64,
        duplicate_count: i64,
        conflicting_count: i64,
    },
}

impl AccountEvent {
    /// Stable dotted event-type string (also used for webhook event filtering).
    pub fn event_type(&self) -> &'static str {
        match self {
            AccountEvent::AccountCreated { .. } => "account.created",
            AccountEvent::AccountUpdated { .. } => "account.updated",
            AccountEvent::TransactionCreated { .. } => "transaction.created",
            AccountEvent::CardRegistered { .. } => "card.registered",
            AccountEvent::CardDeleted { .. } => "card.deleted",
            AccountEvent::MfaEnrolled { .. } => "mfa.enrolled",
            AccountEvent::NotifyMobileVerified { .. } => "notify.mobile_verified",
            AccountEvent::DeviceTokenRegistered { .. } => "device_token.registered",
            AccountEvent::DeviceTokenDeleted { .. } => "device_token.deleted",
            AccountEvent::ExchangeOrderCreated { .. } => "exchange.order_created",
            AccountEvent::ExchangeOrderUpdated { .. } => "exchange.order_updated",
            AccountEvent::ReserveDepositMatched { .. } => "reserve.deposit_matched",
            AccountEvent::ReserveTrustlineAdded { .. } => "reserve.trustline_added",
            AccountEvent::ReserveFulfilled { .. } => "reserve.fulfilled",
            AccountEvent::ReservePayoutPending { .. } => "reserve.payout_pending",
            AccountEvent::ReserveDisbursementPending { .. } => "reserve.disbursement_pending",
            AccountEvent::ReserveOrderExpired { .. } => "reserve.order_expired",
            AccountEvent::ReserveUnmatchedDeposit { .. } => "reserve.unmatched_deposit",
            AccountEvent::ReserveUnmatchedDepositSummary { .. } => {
                "reserve.unmatched_deposit_summary"
            }
            AccountEvent::ReserveLowWater { .. } => "reserve.low_water",
            AccountEvent::ReservePolicyUpdated { .. } => "reserve.policy_updated",
            AccountEvent::ReserveRefundQueued { .. } => "reserve.refund_queued",
            AccountEvent::ReserveRefundSent { .. } => "reserve.refund_sent",
            AccountEvent::ReserveRefundFailed { .. } => "reserve.refund_failed",
            AccountEvent::ReserveEntryRecorded { .. } => "reserve.entry_recorded",
            AccountEvent::RoleChanged { .. } => "account.role_changed",
            AccountEvent::BridgeKeyImported { .. } => "bridge.key_imported",
            AccountEvent::BridgeKeyRevoked { .. } => "bridge.key_revoked",
            AccountEvent::BridgeSeedProvisioned { .. } => "bridge.seed_provisioned",
            AccountEvent::CustodialPaymentSettled { .. } => "custodial.payment_settled",
            AccountEvent::CustodialPaymentAmbiguous { .. } => "custodial.payment_ambiguous",
            AccountEvent::CustodyPaused { .. } => "custody.paused",
            AccountEvent::CustodyResumed { .. } => "custody.resumed",
            AccountEvent::CustodyPolicyUpdated { .. } => "custody.policy_updated",
            AccountEvent::CustodyAccountLimitUpdated { .. } => "custody.account_limit_updated",
            AccountEvent::CustodyIntentResolved { .. } => "custody.intent_resolved",
            AccountEvent::ReserveDrift { .. } => "reserve.drift",
            AccountEvent::ReconciliationSnapshotRecorded { .. } => {
                "reconciliation.snapshot_recorded"
            }
            AccountEvent::PayalaSyncBatchApplied { .. } => "payala.sync_batch_applied",
        }
    }

    pub fn account_id(&self) -> &str {
        match self {
            AccountEvent::AccountCreated { account_id, .. }
            | AccountEvent::AccountUpdated { account_id, .. }
            | AccountEvent::TransactionCreated { account_id, .. }
            | AccountEvent::CardRegistered { account_id, .. }
            | AccountEvent::CardDeleted { account_id, .. }
            | AccountEvent::MfaEnrolled { account_id, .. }
            | AccountEvent::NotifyMobileVerified { account_id, .. }
            | AccountEvent::DeviceTokenRegistered { account_id, .. }
            | AccountEvent::DeviceTokenDeleted { account_id }
            | AccountEvent::ExchangeOrderCreated { account_id, .. }
            | AccountEvent::ExchangeOrderUpdated { account_id, .. }
            | AccountEvent::ReserveDepositMatched { account_id, .. }
            | AccountEvent::ReserveTrustlineAdded { account_id, .. }
            | AccountEvent::ReserveFulfilled { account_id, .. }
            | AccountEvent::ReservePayoutPending { account_id, .. }
            | AccountEvent::ReserveDisbursementPending { account_id, .. }
            | AccountEvent::ReserveOrderExpired { account_id, .. }
            | AccountEvent::ReserveUnmatchedDeposit { account_id, .. }
            | AccountEvent::ReserveUnmatchedDepositSummary { account_id, .. }
            | AccountEvent::ReserveLowWater { account_id, .. }
            | AccountEvent::ReservePolicyUpdated { account_id, .. }
            | AccountEvent::ReserveRefundQueued { account_id, .. }
            | AccountEvent::ReserveRefundSent { account_id, .. }
            | AccountEvent::ReserveRefundFailed { account_id, .. }
            | AccountEvent::ReserveEntryRecorded { account_id, .. }
            | AccountEvent::RoleChanged { account_id, .. }
            | AccountEvent::BridgeKeyImported { account_id, .. }
            | AccountEvent::BridgeKeyRevoked { account_id, .. }
            | AccountEvent::BridgeSeedProvisioned { account_id, .. }
            | AccountEvent::CustodialPaymentSettled { account_id, .. }
            | AccountEvent::CustodialPaymentAmbiguous { account_id, .. }
            | AccountEvent::CustodyPaused { account_id, .. }
            | AccountEvent::CustodyResumed { account_id, .. }
            | AccountEvent::CustodyPolicyUpdated { account_id, .. }
            | AccountEvent::CustodyAccountLimitUpdated { account_id, .. }
            | AccountEvent::CustodyIntentResolved { account_id, .. }
            | AccountEvent::ReserveDrift { account_id, .. }
            | AccountEvent::ReconciliationSnapshotRecorded { account_id, .. }
            | AccountEvent::PayalaSyncBatchApplied { account_id, .. } => account_id,
        }
    }

    /// Event-specific data. **Never** includes secrets/PII: no MFA secret, no raw
    /// device token (only its platform), no card private material (pubkeys are
    /// public), and no exchange pay-in/payout addresses or memos (currencies,
    /// amounts and statuses only).
    pub fn data(&self) -> Value {
        match self {
            AccountEvent::AccountCreated {
                stellar_account_id, ..
            } => json!({ "stellar_account_id": stellar_account_id }),
            AccountEvent::AccountUpdated { fields, .. } => json!({ "fields": fields }),
            AccountEvent::TransactionCreated {
                btxid,
                stellar_tx_id,
                payala_tx_id,
                ..
            } => json!({
                "btxid": btxid,
                "stellar_tx_id": stellar_tx_id,
                "payala_tx_id": payala_tx_id,
            }),
            AccountEvent::RoleChanged {
                actor,
                old_role,
                new_role,
                ..
            } => json!({
                "actor": actor,
                "old_role": old_role,
                "new_role": new_role,
            }),
            AccountEvent::CardRegistered { card_id, .. } => json!({ "card_id": card_id }),
            AccountEvent::CardDeleted { card_id, .. } => json!({ "card_id": card_id }),
            AccountEvent::MfaEnrolled { mfa_type, .. } => json!({ "mfa_type": mfa_type }),
            AccountEvent::NotifyMobileVerified { notify_id, .. } => {
                json!({ "notify_id": notify_id })
            }
            AccountEvent::DeviceTokenRegistered { platform, .. } => {
                json!({ "platform": platform })
            }
            AccountEvent::DeviceTokenDeleted { .. } => json!({}),
            AccountEvent::ExchangeOrderCreated {
                order_id,
                provider,
                direction,
                from_currency,
                to_currency,
                amount_from,
                ..
            } => json!({
                "order_id": order_id,
                "provider": provider,
                "direction": direction,
                "from_currency": from_currency,
                "to_currency": to_currency,
                "amount_from": amount_from,
            }),
            AccountEvent::ExchangeOrderUpdated {
                order_id,
                provider,
                status,
                provider_status,
                ..
            } => json!({
                "order_id": order_id,
                "provider": provider,
                "status": status,
                "provider_status": provider_status,
            }),
            AccountEvent::ReserveDepositMatched {
                order_id,
                currency,
                amount_minor,
                ..
            }
            | AccountEvent::ReserveFulfilled {
                order_id,
                currency,
                amount_minor,
                ..
            } => json!({
                "order_id": order_id,
                "currency": currency,
                "amount_minor": amount_minor,
            }),
            AccountEvent::ReservePayoutPending {
                order_id, reason, ..
            } => json!({ "order_id": order_id, "reason": reason }),
            AccountEvent::ReserveDisbursementPending {
                order_id,
                amount_usd_cents,
                ..
            } => json!({ "order_id": order_id, "amount_usd_cents": amount_usd_cents }),
            AccountEvent::ReserveOrderExpired { order_id, .. } => {
                json!({ "order_id": order_id })
            }
            AccountEvent::ReserveUnmatchedDeposit {
                currency,
                amount_minor,
                reason,
                ..
            } => json!({
                "currency": currency,
                "amount_minor": amount_minor,
                "reason": reason,
            }),
            AccountEvent::ReserveUnmatchedDepositSummary {
                currency,
                count,
                amount_minor,
                senders,
                ..
            } => json!({
                "currency": currency,
                "count": count,
                "amount_minor": amount_minor,
                "senders": senders,
            }),
            AccountEvent::ReserveLowWater {
                currency,
                available_minor,
                low_water_minor,
                ..
            } => json!({
                "currency": currency,
                "available_minor": available_minor,
                "low_water_minor": low_water_minor,
            }),
            AccountEvent::ReservePolicyUpdated {
                provider,
                enabled,
                threshold_usd_cents,
                ..
            } => json!({
                "provider": provider,
                "enabled": enabled,
                "threshold_usd_cents": threshold_usd_cents,
            }),
            AccountEvent::ReserveRefundQueued {
                refund_id,
                currency,
                amount_minor,
                reason,
                ..
            } => json!({
                "refund_id": refund_id,
                "currency": currency,
                "amount_minor": amount_minor,
                "reason": reason,
            }),
            AccountEvent::ReserveRefundSent {
                refund_id,
                currency,
                amount_minor,
                ..
            } => json!({
                "refund_id": refund_id,
                "currency": currency,
                "amount_minor": amount_minor,
            }),
            AccountEvent::ReserveTrustlineAdded {
                currency,
                asset_code,
                asset_issuer,
                stellar_tx_hash,
                ..
            } => json!({
                "currency": currency,
                "asset_code": asset_code,
                "asset_issuer": asset_issuer,
                "stellar_tx_hash": stellar_tx_hash,
            }),
            AccountEvent::ReserveRefundFailed {
                refund_id, reason, ..
            } => json!({ "refund_id": refund_id, "reason": reason }),
            AccountEvent::ReserveEntryRecorded {
                currency,
                kind,
                amount_minor,
                ..
            } => json!({
                "currency": currency,
                "kind": kind,
                "amount_minor": amount_minor,
            }),
            AccountEvent::BridgeKeyImported {
                kind,
                version,
                set_fingerprint,
                replaced,
                action,
                ..
            } => json!({
                "kind": kind,
                "version": version,
                "set_fingerprint": set_fingerprint,
                "replaced": replaced,
                "action": action,
                "effective_after": "rolling_restart",
            }),
            AccountEvent::BridgeKeyRevoked {
                kind,
                version,
                set_fingerprint,
                next_source,
                ..
            } => json!({
                "kind": kind,
                "version": version,
                "set_fingerprint": set_fingerprint,
                "next_source": next_source,
            }),
            AccountEvent::BridgeSeedProvisioned {
                target_account_id,
                stellar_account_id,
                origin,
                is_reserve,
                ..
            } => json!({
                "target_account_id": target_account_id,
                "stellar_account_id": stellar_account_id,
                "origin": origin,
                "is_reserve": is_reserve,
            }),
            AccountEvent::CustodialPaymentSettled {
                intent_id,
                btxid,
                origin,
                amount_minor,
                asset_code,
                resolution,
                ..
            } => json!({
                "intent_id": intent_id,
                "btxid": btxid,
                "origin": origin,
                "amount_minor": amount_minor,
                "asset_code": asset_code,
                "resolution": resolution,
            }),
            AccountEvent::CustodialPaymentAmbiguous {
                intent_id,
                origin,
                amount_minor,
                asset_code,
                ..
            } => json!({
                "intent_id": intent_id,
                "origin": origin,
                "amount_minor": amount_minor,
                "asset_code": asset_code,
            }),
            AccountEvent::CustodyPaused { reason, .. } => json!({ "reason": reason }),
            AccountEvent::CustodyResumed { forced, .. } => json!({ "forced": forced }),
            AccountEvent::CustodyPolicyUpdated {
                per_tx_max_stroops,
                per_account_daily_max_stroops,
                require_idempotency_key,
                ..
            } => json!({
                "per_tx_max_stroops": per_tx_max_stroops,
                "per_account_daily_max_stroops": per_account_daily_max_stroops,
                "require_idempotency_key": require_idempotency_key,
            }),
            AccountEvent::CustodyAccountLimitUpdated {
                target_account_id,
                custodial_daily_max_stroops,
                ..
            } => json!({
                "target_account_id": target_account_id,
                "custodial_daily_max_stroops": custodial_daily_max_stroops,
            }),
            AccountEvent::CustodyIntentResolved {
                intent_id,
                action,
                resolution,
                ..
            } => json!({
                "intent_id": intent_id,
                "action": action,
                "resolution": resolution,
            }),
            AccountEvent::ReserveDrift {
                currency,
                ledger_total_minor,
                onchain_minor,
                drift_minor,
                tolerance_minor,
                snapshot_id,
                ..
            } => json!({
                "currency": currency,
                "ledger_total_minor": ledger_total_minor,
                "onchain_minor": onchain_minor,
                "drift_minor": drift_minor,
                "tolerance_minor": tolerance_minor,
                "snapshot_id": snapshot_id,
            }),
            AccountEvent::ReconciliationSnapshotRecorded {
                snapshot_id,
                kind,
                complete,
                drift_detected,
                invariants_ok,
                horizon_fresh,
                ..
            } => json!({
                "snapshot_id": snapshot_id,
                "kind": kind,
                "complete": complete,
                "drift_detected": drift_detected,
                "invariants_ok": invariants_ok,
                "horizon_fresh": horizon_fresh,
            }),
            AccountEvent::PayalaSyncBatchApplied {
                batch_id,
                sync_mode,
                item_count,
                applied_count,
                duplicate_count,
                conflicting_count,
                ..
            } => json!({
                "batch_id": batch_id,
                "sync_mode": sync_mode,
                "item_count": item_count,
                "applied_count": applied_count,
                "duplicate_count": duplicate_count,
                "conflicting_count": conflicting_count,
            }),
        }
    }
}

/// Append an event to the durable outbox within an existing transaction, so the
/// event is committed atomically with the state change (no lost/phantom events).
pub async fn emit_event(
    tx: &mut Transaction<'_, Postgres>,
    event: &AccountEvent,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO event_outbox (event_type, account_id, payload) VALUES ($1, $2, $3)")
        .bind(event.event_type())
        .bind(event.account_id())
        .bind(event.data())
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            log::error!("emit_event: failed to insert outbox row: {}", e);
            AppError::InternalError("Database error".to_string())
        })?;
    Ok(())
}

/// Compute the webhook signature: `hex(HMAC_SHA256(secret, "{timestamp}.{body}"))`.
///
/// Receivers recompute this over the raw request body + `X-Impala-Timestamp`
/// header and compare in constant time, rejecting timestamps outside a ~5 minute
/// replay window.
pub fn sign(secret: &[u8], timestamp: i64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_and_account_id_map_correctly() {
        let e = AccountEvent::AccountUpdated {
            account_id: "acct-1".into(),
            fields: vec!["nickname".into()],
        };
        assert_eq!(e.event_type(), "account.updated");
        assert_eq!(e.account_id(), "acct-1");
        assert_eq!(e.data(), json!({ "fields": ["nickname"] }));
    }

    #[test]
    fn notify_mobile_verified_payload_never_carries_the_number() {
        // The phone number is subscriber PII and this payload fans out to
        // every registered admin webhook. The row id is enough to correlate.
        let e = AccountEvent::NotifyMobileVerified {
            account_id: "acct-1".into(),
            notify_id: 42,
        };
        assert_eq!(e.event_type(), "notify.mobile_verified");
        assert_eq!(e.account_id(), "acct-1");
        let data = e.data();
        assert_eq!(data, json!({ "notify_id": 42 }));
        assert!(data.get("mobile").is_none());
    }

    #[test]
    fn mfa_payload_never_leaks_secret() {
        let e = AccountEvent::MfaEnrolled {
            account_id: "acct-1".into(),
            mfa_type: "totp".into(),
        };
        let data = e.data();
        assert_eq!(data, json!({ "mfa_type": "totp" }));
        assert!(data.get("secret").is_none());
    }

    #[test]
    fn device_token_payload_never_leaks_token() {
        let e = AccountEvent::DeviceTokenRegistered {
            account_id: "acct-1".into(),
            platform: "android".into(),
        };
        let data = e.data();
        assert_eq!(data, json!({ "platform": "android" }));
        assert!(data.get("token").is_none());
    }

    #[test]
    fn exchange_order_created_payload_never_leaks_addresses() {
        let e = AccountEvent::ExchangeOrderCreated {
            account_id: "acct-1".into(),
            order_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            provider: "changelly_crypto".into(),
            direction: "crypto_to_crypto".into(),
            from_currency: "xlm".into(),
            to_currency: "usdcxlm".into(),
            amount_from: "125.5".into(),
        };
        assert_eq!(e.event_type(), "exchange.order_created");
        assert_eq!(e.account_id(), "acct-1");
        let data = e.data();
        assert_eq!(
            data,
            json!({
                "order_id": "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f",
                "provider": "changelly_crypto",
                "direction": "crypto_to_crypto",
                "from_currency": "xlm",
                "to_currency": "usdcxlm",
                "amount_from": "125.5",
            })
        );
        for pii in [
            "payin_address",
            "payin_extra_id",
            "payout_address",
            "payout_extra_id",
            "refund_address",
            "memo",
        ] {
            assert!(data.get(pii).is_none(), "{} must not be in payload", pii);
        }
    }

    #[test]
    fn exchange_order_updated_payload_never_leaks_addresses() {
        let e = AccountEvent::ExchangeOrderUpdated {
            account_id: "acct-1".into(),
            order_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            provider: "owlpay".into(),
            status: "completed".into(),
            provider_status: "completed".into(),
        };
        assert_eq!(e.event_type(), "exchange.order_updated");
        assert_eq!(e.account_id(), "acct-1");
        let data = e.data();
        assert_eq!(
            data,
            json!({
                "order_id": "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f",
                "provider": "owlpay",
                "status": "completed",
                "provider_status": "completed",
            })
        );
        for pii in [
            "payin_address",
            "payout_address",
            "payout_extra_id",
            "transfer_instructions",
            "memo",
        ] {
            assert!(data.get(pii).is_none(), "{} must not be in payload", pii);
        }
    }

    #[test]
    fn unmatched_deposit_summary_carries_aggregates_and_no_addresses() {
        // The summary exists to throttle a dust flood's feed; it must not
        // smuggle the payer addresses the per-row events also omit.
        let e = AccountEvent::ReserveUnmatchedDepositSummary {
            account_id: "svc-reserve".into(),
            currency: "XLM".into(),
            count: 997,
            amount_minor: 100_697,
            senders: 2,
        };
        assert_eq!(e.event_type(), "reserve.unmatched_deposit_summary");
        assert_eq!(e.account_id(), "svc-reserve");
        let data = e.data();
        assert_eq!(
            data,
            json!({ "currency": "XLM", "count": 997, "amount_minor": 100_697, "senders": 2 })
        );
        for pii in ["sender_address", "sender_muxed", "memo", "addresses"] {
            assert!(data.get(pii).is_none(), "{} must not be in payload", pii);
        }
    }

    /// No string value anywhere in a payload may look like a Stellar
    /// address (56 chars starting with G) or a transaction hash (64 lowercase
    /// hex): the outbox fans out to every registered admin webhook.
    fn assert_no_ledger_pointers(v: &Value) {
        match v {
            Value::String(s) => {
                assert!(
                    !(s.len() == 56 && s.starts_with('G')),
                    "payload carries an address-shaped value: {}",
                    s
                );
                assert!(
                    !(s.len() == 64
                        && s.chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())),
                    "payload carries a hash-shaped value: {}",
                    s
                );
            }
            Value::Array(items) => items.iter().for_each(assert_no_ledger_pointers),
            Value::Object(map) => map.values().for_each(assert_no_ledger_pointers),
            _ => {}
        }
    }

    #[test]
    fn custodial_payloads_never_carry_addresses_or_hashes() {
        let settled = AccountEvent::CustodialPaymentSettled {
            account_id: "acct-1".into(),
            intent_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            btxid: "0b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            origin: "sign".into(),
            amount_minor: 12_500_000,
            asset_code: "XLM".into(),
            resolution: "submit_ok".into(),
        };
        let ambiguous = AccountEvent::CustodialPaymentAmbiguous {
            account_id: "acct-1".into(),
            intent_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            origin: "sign".into(),
            amount_minor: 12_500_000,
            asset_code: "XLM".into(),
        };
        let resolved = AccountEvent::CustodyIntentResolved {
            account_id: "admin-1".into(),
            intent_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            action: "complete".into(),
            resolution: "admin_complete".into(),
        };
        assert_eq!(settled.event_type(), "custodial.payment_settled");
        assert_eq!(ambiguous.event_type(), "custodial.payment_ambiguous");
        assert_eq!(resolved.event_type(), "custody.intent_resolved");
        for e in [settled, ambiguous, resolved] {
            let data = e.data();
            for forbidden in [
                "destination",
                "memo",
                "stellar_hash",
                "source_account",
                "signable",
                "signature",
            ] {
                assert!(
                    data.get(forbidden).is_none(),
                    "{} must not be in payload",
                    forbidden
                );
            }
            assert_no_ledger_pointers(&data);
        }
        // The helper itself must catch the shapes it exists for.
        let addr = Value::String(format!("G{}", "A".repeat(55)));
        assert!(std::panic::catch_unwind(|| assert_no_ledger_pointers(&addr)).is_err());
        let hash = Value::String("ab".repeat(32));
        assert!(std::panic::catch_unwind(|| assert_no_ledger_pointers(&hash)).is_err());
    }

    #[test]
    fn custody_policy_payloads_carry_settings_only() {
        let e = AccountEvent::CustodyAccountLimitUpdated {
            account_id: "admin-1".into(),
            target_account_id: "acct-2".into(),
            custodial_daily_max_stroops: None,
        };
        assert_eq!(e.event_type(), "custody.account_limit_updated");
        assert_eq!(
            e.data(),
            json!({ "target_account_id": "acct-2", "custodial_daily_max_stroops": null })
        );
        let e = AccountEvent::CustodyPaused {
            account_id: "admin-1".into(),
            reason: "incident".into(),
        };
        assert_eq!(e.data(), json!({ "reason": "incident" }));
        let e = AccountEvent::CustodyResumed {
            account_id: "admin-1".into(),
            forced: true,
        };
        assert_eq!(e.data(), json!({ "forced": true }));
    }

    #[test]
    fn reconciliation_payloads_carry_ids_and_minor_units_only() {
        let e = AccountEvent::ReserveDrift {
            account_id: "svc-reserve".into(),
            currency: "XLM".into(),
            ledger_total_minor: 100,
            onchain_minor: 90,
            drift_minor: -10,
            tolerance_minor: 5,
            snapshot_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
        };
        assert_eq!(e.event_type(), "reserve.drift");
        assert_no_ledger_pointers(&e.data());
        assert!(e.data().get("stellar_address").is_none());
        let e = AccountEvent::ReconciliationSnapshotRecorded {
            account_id: "bridge".into(),
            snapshot_id: "9b2f7a04-2f2a-4d4e-9c1e-1a2b3c4d5e6f".into(),
            kind: "daily".into(),
            complete: true,
            drift_detected: false,
            invariants_ok: true,
            horizon_fresh: true,
        };
        assert_eq!(e.event_type(), "reconciliation.snapshot_recorded");
        assert!(
            e.data().get("payload").is_none(),
            "the report body never rides the feed"
        );
    }

    /// Every event-type string that existed before 037 must still be
    /// produced by its variant: the outbox is an append-only contract
    /// (webhook subscribers filter on these exact strings).
    #[test]
    fn sync_batch_payload_carries_counts_only() {
        let ev = AccountEvent::PayalaSyncBatchApplied {
            account_id: "acct".to_string(),
            batch_id: "8d1b2c1e-4d3f-4b1e-9d2c-0c1a2b3c4d5e".to_string(),
            sync_mode: "reserve".to_string(),
            item_count: 3,
            applied_count: 2,
            duplicate_count: 1,
            conflicting_count: 0,
        };
        assert_eq!(ev.event_type(), "payala.sync_batch_applied");
        assert_eq!(ev.account_id(), "acct");
        let data = ev.data();
        let obj = data.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "applied_count",
                "batch_id",
                "conflicting_count",
                "duplicate_count",
                "item_count",
                "sync_mode"
            ]
        );
        for forbidden in [
            "amount",
            "memo",
            "net_deltas",
            "digest",
            "payala_tx_id",
            "transactions",
            "balance",
        ] {
            assert!(
                !data.to_string().contains(forbidden),
                "sync batch payload must not carry {}",
                forbidden
            );
        }
        // Every count is a plain integer, never a money string.
        for k in [
            "item_count",
            "applied_count",
            "duplicate_count",
            "conflicting_count",
        ] {
            assert!(obj[k].is_i64(), "{} must be an integer count", k);
        }
        assert_no_ledger_pointers(&data);
    }

    #[test]
    fn event_type_vocabulary_is_append_only() {
        const FROZEN: &[&str] = &[
            "account.created",
            "account.updated",
            "transaction.created",
            "card.registered",
            "card.deleted",
            "mfa.enrolled",
            "notify.mobile_verified",
            "device_token.registered",
            "device_token.deleted",
            "exchange.order_created",
            "exchange.order_updated",
            "reserve.deposit_matched",
            "reserve.trustline_added",
            "reserve.fulfilled",
            "reserve.payout_pending",
            "reserve.disbursement_pending",
            "reserve.order_expired",
            "reserve.unmatched_deposit",
            "reserve.unmatched_deposit_summary",
            "reserve.low_water",
            "reserve.policy_updated",
            "reserve.refund_queued",
            "reserve.refund_sent",
            "reserve.refund_failed",
            "reserve.entry_recorded",
            "account.role_changed",
            "bridge.key_imported",
            "bridge.key_revoked",
            "bridge.seed_provisioned",
        ];
        assert_eq!(FROZEN.len(), 29);
        let src = include_str!("events.rs");
        let event_type_fn = src
            .find("pub fn event_type(&self)")
            .expect("event_type present");
        let body = &src[event_type_fn..];
        let body = &body[..body.find("\n    }\n").expect("fn end")];
        for t in FROZEN {
            assert!(
                body.contains(&format!("=> \"{}\"", t)) || body.contains(&format!("\"{}\"\n", t)),
                "event type {} no longer produced by event_type()",
                t
            );
        }
        let mut seen = std::collections::HashSet::new();
        for line in body.lines() {
            if let Some(start) = line.find("=> \"") {
                let rest = &line[start + 4..];
                let end = rest.find('"').expect("closing quote");
                assert!(
                    seen.insert(rest[..end].to_string()),
                    "duplicate event type {}",
                    &rest[..end]
                );
            }
        }
    }

    #[test]
    fn sign_is_deterministic_and_changes_with_inputs() {
        let secret = b"shhh-very-secret";
        let a = sign(secret, 1_700_000_000, "{\"x\":1}");
        let b = sign(secret, 1_700_000_000, "{\"x\":1}");
        assert_eq!(a, b, "same inputs => same signature");
        assert_eq!(a.len(), 64, "hex sha256 is 64 chars");
        assert_ne!(
            a,
            sign(secret, 1_700_000_001, "{\"x\":1}"),
            "timestamp matters"
        );
        assert_ne!(a, sign(secret, 1_700_000_000, "{\"x\":2}"), "body matters");
        assert_ne!(
            a,
            sign(b"other", 1_700_000_000, "{\"x\":1}"),
            "secret matters"
        );
    }

    #[test]
    fn sign_matches_known_vector() {
        // Fixed external vectors (computed independently with Python's hmac +
        // hashlib). These pin the wire format byte-identically across sha2/hmac
        // crate upgrades — webhook receivers verify against this exact value.
        assert_eq!(
            sign(b"key", 1, "body"),
            "91b5374b153842ad05b2c4eab9349b8321b14703165bd3fb8b034dfb8be98ae5"
        );
        assert_eq!(
            sign(b"shhh-very-secret", 1_700_000_000, "{\"x\":1}"),
            "77e18a0dd1a0698c1d963420492966388e474f2cdb2241340e70f1f948fe1de0"
        );
        // and the streaming construction matches the concatenated form
        let mut mac = HmacSha256::new_from_slice(b"key").unwrap();
        mac.update(b"1.body");
        assert_eq!(
            sign(b"key", 1, "body"),
            hex::encode(mac.finalize().into_bytes())
        );
    }
}

/**
 * DOM-free logic for the custody console (custodial payment brake, caps,
 * intents, reconciliation snapshots).
 *
 * Everything here is pure so the parts an operator relies on to read the
 * page correctly — which caps are unconfigured, what an intent status means
 * for the money, what a refusal code means for the client — are unit-tested
 * without a browser. `custody.js` renders what these functions decide and
 * nothing else.
 *
 * One rule shapes the module: **this file never reconstructs a value the
 * bridge will compare against.** The resume confirmation phrase arrives in
 * `GET /admin/custody/policy` (`resume_phrase`); a client that built it
 * itself could drift from the bridge and hand operators a phrase that is
 * always rejected.
 *
 * @module CustodyView
 */
var CustodyView = (function () {
    'use strict';

    /** Every refusal code the custodial paths answer with (bridge constant). */
    var REFUSAL_CODES = [
        'custodial_paused', 'custodial_unconfigured', 'custodial_tx_limit',
        'custodial_daily_limit', 'custodial_account_frozen', 'idempotency_conflict',
        'idempotency_key_required', 'payment_in_flight', 'payment_rejected'
    ];

    /** Non-terminal intent statuses (bridge constant). */
    var OPEN_STATUSES = ['prepared', 'submitted', 'ambiguous'];

    /**
     * The policy card's rows, in reading order. A cap of 0 is UNCONFIGURED
     * (custodial signing refuses), never "unlimited" — and it must read
     * that way.
     * @param {Object} view - CustodialPolicyView from GET /admin/custody/policy.
     * @returns {Array<{label: string, value: string, cls: string}>}
     */
    function policyRows(view) {
        if (!view) return [];
        var rows = [];
        rows.push(view.paused
            ? { label: 'State', value: 'PAUSED' + (view.pause_reason ? ' — ' + view.pause_reason : ''), cls: 'error' }
            : { label: 'State', value: view.configured ? 'running' : 'refusing (unconfigured)', cls: view.configured ? 'ok' : 'pending' });
        if (view.paused) {
            rows.push({ label: 'Paused by', value: (view.paused_by || '?') + (view.paused_at ? ' at ' + view.paused_at : ''), cls: 'neutral' });
        }
        rows.push(capRow('Per-transaction cap', view.per_tx_max_stroops));
        rows.push(capRow('Per-account daily cap', view.per_account_daily_max_stroops));
        rows.push({
            label: 'Idempotency key',
            value: view.require_idempotency_key ? 'required from clients' : 'optional (bridge mints one)',
            cls: view.require_idempotency_key ? 'ok' : 'neutral'
        });
        var open = view.open_intents || {};
        var ambiguous = open.ambiguous || 0;
        rows.push({
            label: 'Open intents',
            value: (open.prepared || 0) + ' prepared, ' + (open.submitted || 0) + ' submitted, ' + ambiguous + ' ambiguous',
            cls: ambiguous > 0 ? 'error' : 'neutral'
        });
        rows.push({ label: 'Last updated', value: (view.updated_at || '—') + (view.updated_by ? ' by ' + view.updated_by : ''), cls: 'neutral' });
        return rows;
    }

    function capRow(label, stroops) {
        if (typeof stroops !== 'number' || stroops <= 0) {
            return { label: label, value: 'unconfigured (0) — signing refuses', cls: 'pending' };
        }
        return { label: label, value: String(stroops) + ' stroops', cls: 'ok' };
    }

    /**
     * Badge class for an intent status.
     *
     * `ambiguous` is red because the money's fate is unknown until the sweep
     * or an admin resolves it by hash; `submitted` is amber (in flight).
     * @param {string} status
     * @returns {string} 'ok' | 'error' | 'pending' | 'neutral'
     */
    function intentBadge(status) {
        if (status === 'settled') return 'ok';
        if (status === 'ambiguous' || status === 'rejected') return 'error';
        if (status === 'submitted' || status === 'prepared') return 'pending';
        return 'neutral';
    }

    /** Whether an intent can still be resolved by an admin (submitted/ambiguous). */
    function isResolvable(status) {
        return status === 'submitted' || status === 'ambiguous';
    }

    /**
     * Operator-facing text for a refusal code from the custodial paths.
     * Unknown codes render as themselves — never mislabelled.
     * @param {string} code
     * @returns {string}
     */
    function refusalText(code) {
        switch (code) {
            case 'custodial_paused': return 'Custodial payments are paused by an operator.';
            case 'custodial_unconfigured': return 'Custodial caps are not set (0 = unconfigured); set both caps to enable signing.';
            case 'custodial_tx_limit': return 'The amount exceeds the per-transaction cap.';
            case 'custodial_daily_limit': return 'The account has reached its rolling 24h spend cap.';
            case 'custodial_account_frozen': return 'This account is frozen (per-account limit 0).';
            case 'idempotency_conflict': return 'That idempotency key was already used for a different payment.';
            case 'idempotency_key_required': return 'This bridge requires clients to send an idempotency key.';
            case 'payment_in_flight': return 'A payment from this account is still unresolved; wait for it to settle.';
            case 'payment_rejected': return 'The network definitively rejected the payment; nothing landed.';
            default: return String(code || 'unknown');
        }
    }

    /**
     * Whether resuming needs the `force` flag: any ambiguous intent means
     * money with an unknown fate, and reopening then is the double-pay moment.
     * @param {Object} view - CustodialPolicyView
     * @returns {boolean}
     */
    function resumeNeedsForce(view) {
        return !!(view && view.open_intents && view.open_intents.ambiguous > 0);
    }

    /**
     * Badge for a reconciliation snapshot row. `attested` is the bridge's
     * own verdict (fresh AND complete AND invariants ok); nothing is
     * softened here.
     * @param {Object} row - ReconciliationSnapshotListItem
     * @returns {{label: string, cls: string}}
     */
    function snapshotBadge(row) {
        if (!row) return { label: 'unknown', cls: 'neutral' };
        if (row.attested) return { label: 'attested', cls: 'ok' };
        if (row.drift_detected) return { label: 'drift', cls: 'error' };
        if (!row.horizon_fresh) return { label: 'horizon lagging', cls: 'pending' };
        if (!row.complete) return { label: 'incomplete', cls: 'pending' };
        return { label: 'invariants failed', cls: 'error' };
    }

    /**
     * Validate a typed stroop amount (integer minor units, no floats).
     * @param {string} input
     * @returns {{ok: boolean, value: (number|null), error: (string|null)}}
     */
    function validateStroops(input) {
        var s = String(input == null ? '' : input).trim();
        if (!/^\d+$/.test(s)) {
            return { ok: false, value: null, error: 'Enter a whole number of stroops' };
        }
        var n = parseInt(s, 10);
        if (!isFinite(n) || n > Number.MAX_SAFE_INTEGER) {
            return { ok: false, value: null, error: 'Amount is too large' };
        }
        return { ok: true, value: n, error: null };
    }

    return {
        REFUSAL_CODES: REFUSAL_CODES,
        OPEN_STATUSES: OPEN_STATUSES,
        policyRows: policyRows,
        intentBadge: intentBadge,
        isResolvable: isResolvable,
        refusalText: refusalText,
        resumeNeedsForce: resumeNeedsForce,
        snapshotBadge: snapshotBadge,
        validateStroops: validateStroops
    };
})();

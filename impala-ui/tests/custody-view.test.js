import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { loadScript } from './helpers/load-script.js';

// custody-view.js is DOM-free so the rules an operator reads the money
// brake by — unconfigured caps, intent statuses, refusal codes — are
// testable exactly like keys-view.js.
let CustodyView;
beforeAll(() => {
    CustodyView = loadScript('custody-view.js', 'CustodyView');
});

const here = dirname(fileURLToPath(import.meta.url));

function policy(overrides) {
    return Object.assign({
        paused: false,
        paused_by: null,
        paused_at: null,
        pause_reason: null,
        per_tx_max_stroops: 50000000,
        per_account_daily_max_stroops: 500000000,
        require_idempotency_key: false,
        configured: true,
        updated_by: 'ops-1',
        updated_at: '2026-09-05T00:00:00Z',
        open_intents: { prepared: 0, submitted: 0, ambiguous: 0 },
        resume_phrase: 'resume custody testnet'
    }, overrides || {});
}

describe('policyRows', () => {
    it('reads a 0 cap as unconfigured, never unlimited', () => {
        const rows = CustodyView.policyRows(policy({ per_tx_max_stroops: 0, configured: false }));
        const state = rows.find((r) => r.label === 'State');
        expect(state.value).toContain('refusing');
        const cap = rows.find((r) => r.label === 'Per-transaction cap');
        expect(cap.value).toContain('unconfigured');
        expect(cap.cls).toBe('pending');
    });

    it('renders a paused policy red with its reason and actor', () => {
        const rows = CustodyView.policyRows(policy({ paused: true, pause_reason: 'incident 12', paused_by: 'ops-2', paused_at: 'now' }));
        expect(rows[0]).toEqual({ label: 'State', value: 'PAUSED — incident 12', cls: 'error' });
        expect(rows[1].value).toContain('ops-2');
    });

    it('flags open ambiguous intents', () => {
        const rows = CustodyView.policyRows(policy({ open_intents: { prepared: 0, submitted: 1, ambiguous: 2 } }));
        const open = rows.find((r) => r.label === 'Open intents');
        expect(open.cls).toBe('error');
        expect(open.value).toBe('0 prepared, 1 submitted, 2 ambiguous');
        expect(CustodyView.policyRows(null)).toEqual([]);
    });
});

describe('intentBadge', () => {
    it('reads ambiguous as red: unknown fate is money at risk', () => {
        expect(CustodyView.intentBadge('settled')).toBe('ok');
        expect(CustodyView.intentBadge('ambiguous')).toBe('error');
        expect(CustodyView.intentBadge('rejected')).toBe('error');
        expect(CustodyView.intentBadge('submitted')).toBe('pending');
        expect(CustodyView.intentBadge('prepared')).toBe('pending');
        expect(CustodyView.intentBadge('bogus')).toBe('neutral');
    });

    it('only submitted and ambiguous intents are resolvable', () => {
        expect(CustodyView.isResolvable('submitted')).toBe(true);
        expect(CustodyView.isResolvable('ambiguous')).toBe(true);
        for (const s of ['prepared', 'settled', 'rejected']) {
            expect(CustodyView.isResolvable(s)).toBe(false);
        }
    });
});

describe('refusalText', () => {
    it('names every code the bridge pins, and echoes unknown codes verbatim', () => {
        for (const code of CustodyView.REFUSAL_CODES) {
            const text = CustodyView.refusalText(code);
            expect(text.length).toBeGreaterThan(10);
            expect(text).not.toBe(code);
        }
        expect(CustodyView.refusalText('something_new')).toBe('something_new');
        expect(CustodyView.refusalText(undefined)).toBe('unknown');
    });

    it('matches the bridge constant list exactly', () => {
        // CUSTODIAL_REFUSAL_CODES in impala-bridge/src/constants.rs.
        const src = readFileSync(resolve(here, '..', '..', 'impala-bridge', 'src', 'constants.rs'), 'utf8');
        const start = src.indexOf('pub const CUSTODIAL_REFUSAL_CODES');
        const body = src.slice(start, src.indexOf('];', start));
        const codes = [...body.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
        expect(codes).toEqual(CustodyView.REFUSAL_CODES);
    });
});

describe('resumeNeedsForce / snapshotBadge / validateStroops', () => {
    it('resume needs force only while ambiguous intents exist', () => {
        expect(CustodyView.resumeNeedsForce(policy())).toBe(false);
        expect(CustodyView.resumeNeedsForce(policy({ open_intents: { ambiguous: 1 } }))).toBe(true);
        expect(CustodyView.resumeNeedsForce(null)).toBe(false);
    });

    it('snapshot badge never softens the bridge verdict', () => {
        expect(CustodyView.snapshotBadge({ attested: true })).toEqual({ label: 'attested', cls: 'ok' });
        expect(CustodyView.snapshotBadge({ attested: false, drift_detected: true, horizon_fresh: true, complete: true }))
            .toEqual({ label: 'drift', cls: 'error' });
        expect(CustodyView.snapshotBadge({ attested: false, drift_detected: false, horizon_fresh: false, complete: true }))
            .toEqual({ label: 'horizon lagging', cls: 'pending' });
        expect(CustodyView.snapshotBadge({ attested: false, drift_detected: false, horizon_fresh: true, complete: false }))
            .toEqual({ label: 'incomplete', cls: 'pending' });
        expect(CustodyView.snapshotBadge({ attested: false, drift_detected: false, horizon_fresh: true, complete: true, invariants_ok: false }))
            .toEqual({ label: 'invariants failed', cls: 'error' });
    });

    it('validates stroops as whole integers', () => {
        expect(CustodyView.validateStroops('0')).toEqual({ ok: true, value: 0, error: null });
        expect(CustodyView.validateStroops(' 250000000 ').value).toBe(250000000);
        expect(CustodyView.validateStroops('1.5').ok).toBe(false);
        expect(CustodyView.validateStroops('-1').ok).toBe(false);
        expect(CustodyView.validateStroops('').ok).toBe(false);
        expect(CustodyView.validateStroops('99999999999999999999').ok).toBe(false);
    });
});

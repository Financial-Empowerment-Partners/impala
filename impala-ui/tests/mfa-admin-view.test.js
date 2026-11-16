import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// mfa-admin-view.js decides everything the MFA page's session-assurance and
// admin per-account panels show and send (docs/mfa-card-pin-biometrics.md §5).
let V;
beforeAll(() => {
    V = loadScript('mfa-admin-view.js', 'MfaAdminView');
});

describe('normalizeStatus', () => {
    it('reads the status payload and tolerates missing fields', () => {
        const s = V.normalizeStatus({
            amr: ['sc', 'pin', 'mfa'], auth_time: 1000, mfa: true,
            required: true, required_by_role: false, satisfied: true, max_age_secs: 43200
        });
        expect(s.amr).toEqual(['sc', 'pin', 'mfa']);
        expect(s.mfa).toBe(true);
        expect(s.required).toBe(true);
        expect(s.satisfied).toBe(true);
        expect(s.maxAgeSecs).toBe(43200);
    });

    it('is null/empty for an unreadable payload (older bridge)', () => {
        const s = V.normalizeStatus(null);
        expect(s.amr).toEqual([]);
        expect(s.mfa).toBeNull();
        expect(s.required).toBeNull();
        expect(s.authTime).toBeNull();
    });

    it('drops non-string amr entries', () => {
        expect(V.normalizeStatus({ amr: ['sc', 5, null, 'pin'] }).amr).toEqual(['sc', 'pin']);
    });
});

describe('factorChips', () => {
    it('labels known factors and skips the derived mfa marker', () => {
        const chips = V.factorChips(['sc', 'pin', 'mfa']);
        expect(chips.map((c) => c.label)).toEqual(['Card', 'Card PIN']);
    });
    it('shows an unknown token raw on a neutral badge', () => {
        const chips = V.factorChips(['sc', 'webauthn']);
        expect(chips[1]).toEqual({ label: 'webauthn', cls: 'neutral' });
    });
    it('only emits whitelisted badge classes', () => {
        const allowed = ['ok', 'error', 'pending', 'info', 'neutral', 'warning'];
        V.factorChips(['pwd', 'fed', 'sc', 'pin', 'otp', 'dev', 'bio', 'weird'])
            .forEach((c) => expect(allowed).toContain(c.cls));
    });
});

describe('sessionSummary', () => {
    it('is calm when the account is not required to be multi-factor', () => {
        const sum = V.sessionSummary(V.normalizeStatus({ required: false, mfa: false }));
        expect(sum.needsStepUp).toBe(false);
        expect(sum.badge.cls).toBe('neutral');
    });
    it('asks for a step-up when required and not satisfied', () => {
        const sum = V.sessionSummary(V.normalizeStatus({ required: true, satisfied: false, mfa: false }));
        expect(sum.needsStepUp).toBe(true);
        expect(sum.badge.cls).toBe('warning');
    });
    it('is satisfied when required and multi-factor', () => {
        const sum = V.sessionSummary(V.normalizeStatus({ required: true, satisfied: true, mfa: true }));
        expect(sum.needsStepUp).toBe(false);
        expect(sum.badge.cls).toBe('ok');
    });
});

describe('normalizeAccountMfa + accountFactorSummary', () => {
    it('summarises factor kinds and whether the account can be multi-factor', () => {
        const acct = V.normalizeAccountMfa({
            account_id: 'a1', mfa_required: true, totp_enrolled: true, cards: 2,
            device_keys: [{ key_id: 'k1', label: 'Pixel', platform: 'android', user_verification: 'biometric', created_at_unix: 10 }]
        });
        expect(acct.deviceKeys).toHaveLength(1);
        const fs = V.accountFactorSummary(acct);
        expect(fs.factorKinds).toBe(3); // totp + cards + device key
        expect(fs.canBeMfa).toBe(true);
    });

    it('flags an account with fewer than two factor kinds', () => {
        const acct = V.normalizeAccountMfa({ account_id: 'a2', mfa_required: false, totp_enrolled: false, cards: 1, device_keys: [] });
        const fs = V.accountFactorSummary(acct);
        expect(fs.factorKinds).toBe(1);
        expect(fs.canBeMfa).toBe(false);
    });

    it('shows "no factors" when none are enrolled', () => {
        const fs = V.accountFactorSummary(V.normalizeAccountMfa({ account_id: 'a3', cards: 0, device_keys: [] }));
        expect(fs.chips[0].label).toBe('no factors enrolled');
        expect(fs.canBeMfa).toBe(false);
    });

    it('marks a malformed device_keys list', () => {
        expect(V.normalizeAccountMfa({ device_keys: 'nope' }).deviceKeysMalformed).toBe(true);
        expect(V.normalizeAccountMfa({ device_keys: [] }).deviceKeysMalformed).toBe(false);
    });
});

describe('request bodies and error handling', () => {
    it('builds a TOTP step-up body with a trimmed code', () => {
        expect(V.totpStepUpBody('  123456 ')).toEqual({ mfa_type: 'totp', code: '123456' });
    });
    it('takes the new token pair of a bearer step-up, and nothing from a cookie session', () => {
        // Bearer: the bridge re-issues the session as a new family and revokes the one that asked.
        expect(V.stepUpTokens({ success: true, amr: ['otp', 'pwd', 'mfa'], temporal_token: 't.t.t', refresh_token: 'r.r.r' }))
            .toEqual({ temporal: 't.t.t', refresh: 'r.r.r' });
        expect(V.stepUpTokens({ success: true, temporal_token: 't.t.t' })).toEqual({ temporal: 't.t.t', refresh: null });
        // Cookie session: upgraded in place, no tokens in the answer.
        expect(V.stepUpTokens({ success: true, amr: ['fed', 'otp', 'mfa'] })).toBeNull();
        expect(V.stepUpTokens({ temporal_token: null, refresh_token: null })).toBeNull();
        expect(V.stepUpTokens({ temporal_token: '', refresh_token: 'r.r.r' })).toBeNull();
        expect(V.stepUpTokens({ temporal_token: 7 })).toBeNull();
        expect(V.stepUpTokens(null)).toBeNull();
        expect(V.stepUpTokens(undefined)).toBeNull();
    });

    it('says a refused step-up code plainly, and that a code works once', () => {
        const refused = Object.assign(new Error('Unauthorized'), { status: 401, code: 'unauthorized' });
        expect(V.stepUpErrorMessage(refused)).toMatch(/not accepted/);
        expect(V.stepUpErrorMessage(refused)).toMatch(/works once/);
        expect(V.stepUpErrorMessage(Object.assign(new Error('x'), { status: 429 }))).toMatch(/Too many attempts/);
        // anything else falls back to the generic action message
        const other = Object.assign(new Error('Bridge is down'), { status: 503 });
        expect(V.stepUpErrorMessage(other)).toBe(V.actionErrorMessage(other));
    });
    it('asks before the mandate changes, in both directions, and warns when the account cannot be multi-factor yet', () => {
        const on = V.mandateConfirm(true, true);
        expect(on.title).toBe('Require MFA?');
        expect(on.message).toMatch(/signed out everywhere/);
        expect(on.message).not.toMatch(/locked out/);
        const risky = V.mandateConfirm(true, false);
        expect(risky.message).toMatch(/signed out everywhere/);
        expect(risky.message).toMatch(/fewer than two factor kinds/);
        expect(risky.message).toMatch(/locked out/);
        // an unknown factor count is treated as the risky case, never as the calm one
        expect(V.mandateConfirm(true, undefined).message).toMatch(/locked out/);
        const off = V.mandateConfirm(false, true);
        expect(off.title).toBe('Lift the MFA requirement?');
        expect(off.message).toMatch(/signed out everywhere/);
        expect(V.mandateConfirm('yes', true).title).toBe('Lift the MFA requirement?');
    });
    it('builds a policy body', () => {
        expect(V.policyBody(true)).toEqual({ required: true });
        expect(V.policyBody('yes')).toEqual({ required: false });
    });
    it('classifies load errors', () => {
        expect(V.classifyLoadError({ status: 403 }).kind).toBe('forbidden');
        expect(V.classifyLoadError({ status: 404 }).kind).toBe('notfound');
        expect(V.classifyLoadError({ status: 500, message: 'boom' })).toEqual({ kind: 'error', message: 'boom' });
    });
    it('explains a step-up / reauth error', () => {
        expect(V.actionErrorMessage({ code: 'mfa_reauth_required' })).toMatch(/fresh multi-factor/);
        expect(V.actionErrorMessage({ status: 401 })).toMatch(/not accepted/);
    });
    it('detects an mfa_required error by code or message', () => {
        expect(V.isMfaRequired({ code: 'mfa_required' })).toBe(true);
        expect(V.isMfaRequired({ status: 403, message: 'x mfa_required y' })).toBe(true);
        expect(V.isMfaRequired({ status: 403, message: 'forbidden' })).toBe(false);
        expect(V.isMfaRequired(null)).toBe(false);
    });
});

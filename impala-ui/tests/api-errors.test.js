import { describe, it, expect, beforeAll } from 'vitest';
import { loadScript } from './helpers/load-script.js';

// api.js touches no browser globals at module load (the BASE getter is lazy),
// so it loads cleanly under Node and its pure error helpers can be exercised.
let API;
beforeAll(() => {
    API = loadScript('api.js', 'API');
});

function envelope(message, code) {
    return JSON.stringify({ error: { code: code || 'err', message: message } });
}

describe('API.extractErrorMessage — structured envelope', () => {
    it('surfaces the envelope message verbatim', () => {
        expect(API.extractErrorMessage(400, envelope("Admins cannot delete their own account")))
            .toBe('Admins cannot delete their own account');
    });

    it('does NOT mangle the word "delete" (no SQL filtering on envelopes)', () => {
        const msg = API.extractErrorMessage(409, envelope('Cannot delete/demote the last remaining admin'));
        expect(msg).toBe('Cannot delete/demote the last remaining admin');
        expect(msg).not.toContain('[filtered]');
    });

    it('keeps reflected input intact (e.g. invalid role/status)', () => {
        expect(API.extractErrorMessage(400, envelope("Invalid role 'superuser'")))
            .toBe("Invalid role 'superuser'");
    });

    it('takes precedence over the friendly status map', () => {
        expect(API.extractErrorMessage(403, envelope('Admin role required')))
            .toBe('Admin role required');
    });

    it('strips HTML tags from envelope messages', () => {
        expect(API.extractErrorMessage(400, envelope('<b>bad</b> role')))
            .toBe('bad role');
    });

    it('truncates very long envelope messages to ~200 chars', () => {
        const long = 'x'.repeat(300);
        const out = API.extractErrorMessage(400, envelope(long));
        expect(out.length).toBe(203); // 200 chars + '...'
        expect(out.endsWith('...')).toBe(true);
    });
});

describe('API.extractErrorMessage — non-enveloped fallback', () => {
    it('uses the friendly status map for known codes', () => {
        expect(API.extractErrorMessage(500, 'internal boom')).toBe('Server error');
        expect(API.extractErrorMessage(409, 'not json')).toBe('Conflict');
        expect(API.extractErrorMessage(403, 'plain forbidden')).toBe('Permission denied');
    });

    it('still SQL-filters non-enveloped bodies (leak defense)', () => {
        // Unknown status → no status-map hit → raw-body sanitization applies.
        const out = API.extractErrorMessage(418, 'DELETE FROM users WHERE 1=1');
        expect(out).toContain('[filtered]');
    });

    it('handles a missing/empty body', () => {
        expect(API.extractErrorMessage(500, '')).toBe('Server error');
        expect(API.extractErrorMessage(418, '')).toMatch(/Request failed/);
    });
});

describe('API.sanitizeErrorMessage — 409 added to the fallback map', () => {
    it('maps 409 to a friendly default', () => {
        expect(API.sanitizeErrorMessage(409, 'whatever')).toBe('Conflict');
    });
});

describe('API.parseJwt — base64url payloads', () => {
    // Build a JWT whose payload base64url contains '-' and '_' (chars that
    // plain atob rejects). {"sub":"a>>>?","role":"admin"} base64-encodes with
    // '+' and '/', which base64url renders as '-' and '_'.
    function b64url(obj) {
        const std = Buffer.from(JSON.stringify(obj)).toString('base64');
        return std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    it('decodes a payload containing base64url - and _', () => {
        const payload = { sub: 'a>>>?', role: 'admin', exp: 9999999999 };
        const token = 'h.' + b64url(payload) + '.s';
        const decoded = API.parseJwt(token);
        expect(decoded).not.toBeNull();
        expect(decoded.role).toBe('admin');
        expect(decoded.sub).toBe('a>>>?');
    });

    it('decodes a payload needing re-padding', () => {
        const token = 'h.' + b64url({ a: 1 }) + '.s'; // short payload, no padding
        expect(API.parseJwt(token)).toEqual({ a: 1 });
    });

    it('returns null on a malformed token', () => {
        expect(API.parseJwt('not-a-jwt')).toBeNull();
        expect(API.parseJwt('')).toBeNull();
    });
});

describe('API.classifyRefreshResponse — only a verdict on the token ends the session', () => {
    // clients-5: any !res.ok used to wipe both stored tokens, so a 502 from
    // Nginx mid-roll or the 500 the bridge returns on a Redis outage logged
    // the operator out with a valid 14-day refresh token in hand.
    it('401 is fatal: the bridge judged the refresh token', () => {
        expect(API.classifyRefreshResponse(401, { error: { code: 'unauthorized', message: 'Unauthorized' } }))
            .toBe('fatal');
        expect(API.classifyRefreshResponse(401, null)).toBe('fatal');
    });

    it('a 2xx carrying a temporal token is ok', () => {
        expect(API.classifyRefreshResponse(200, { success: true, temporal_token: 't1', refresh_token: 'r1' }))
            .toBe('ok');
        expect(API.classifyRefreshResponse(200, { temporal_token: 't1' })).toBe('ok');
    });

    it('a 2xx without a temporal token is fatal (malformed success)', () => {
        expect(API.classifyRefreshResponse(200, { success: false, message: 'nope' })).toBe('fatal');
        expect(API.classifyRefreshResponse(200, null)).toBe('fatal');
        expect(API.classifyRefreshResponse(200, { temporal_token: '' })).toBe('fatal');
        expect(API.classifyRefreshResponse(200, { temporal_token: 42 })).toBe('fatal');
    });

    it('outages, rate limits and network failures are retryable (tokens stay)', () => {
        // The bridge answers 500 on a Redis outage precisely so clients keep
        // their tokens (redis_helpers.rs: "Infrastructure failure, NOT a
        // revoked token").
        expect(API.classifyRefreshResponse(500, { error: { code: 'internal_error', message: 'Service temporarily unavailable' } }))
            .toBe('retryable');
        expect(API.classifyRefreshResponse(502, null)).toBe('retryable'); // Nginx, bridge rolling
        expect(API.classifyRefreshResponse(503, null)).toBe('retryable');
        expect(API.classifyRefreshResponse(504, null)).toBe('retryable');
        expect(API.classifyRefreshResponse(429, null)).toBe('retryable');
        expect(API.classifyRefreshResponse(0, null)).toBe('retryable');   // fetch itself failed
    });

    it('other 4xx are not a verdict on the token either', () => {
        for (const status of [400, 403, 404, 405, 409, 422]) {
            expect(API.classifyRefreshResponse(status, null)).toBe('retryable');
        }
    });
});

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

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';

// Behavioural coverage for the refresh path (clients-5): api.js is loaded
// into a vm context with localStorage, fetch, window.location and (when a
// test wants it) navigator.locks stubbed, then driven exactly like the pages
// drive it — through API.get. The classifier's table is covered in
// api-errors.test.js; this file checks what the request path DOES with each
// verdict: which tokens survive, whether the tab is bounced to login, and
// which requests go out.
const here = dirname(fileURLToPath(import.meta.url));
const code = readFileSync(resolve(here, '../html/js/api.js'), 'utf8');

const NOW = Math.floor(Date.now() / 1000);
const FUTURE = NOW + 24 * 3600;
const PAST = NOW - 10;

/** A syntactically valid JWT (signature never checked client-side). */
function jwt(exp, tag) {
    const b64url = (s) => Buffer.from(s).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return b64url('{"alg":"HS256","typ":"JWT"}') + '.' +
        b64url(JSON.stringify({ sub: 'alice', exp, tag })) + '.sig';
}

const R0 = jwt(FUTURE, 'r0');
const R1 = jwt(FUTURE, 'r1');
const T_STALE = jwt(PAST, 't-stale');
const T_LIVE = jwt(FUTURE, 't-live');
const T1 = jwt(FUTURE, 't1');

function makeStorage(initial) {
    const map = new Map(Object.entries(initial || {}));
    return {
        getItem: (k) => (map.has(k) ? map.get(k) : null),
        setItem: (k, v) => map.set(k, String(v)),
        removeItem: (k) => map.delete(k),
    };
}

function jsonResponse(body, status = 200) {
    return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve(body),
        text: () => Promise.resolve(JSON.stringify(body)),
    };
}

/** What Nginx returns when the bridge behind it is down: HTML, not JSON. */
function htmlResponse(status) {
    return {
        ok: false,
        status,
        headers: { get: () => 'text/html' },
        json: () => Promise.reject(new SyntaxError('Unexpected token <')),
        text: () => Promise.resolve('<html>bad gateway</html>'),
    };
}

const unauthorized = () => jsonResponse({ error: { code: 'unauthorized', message: 'Unauthorized' } }, 401);
const rotated = () => jsonResponse({ success: true, message: 'Tokens issued', refresh_token: R1, temporal_token: T1 });

/**
 * Fresh vm context. `fetchImpl(url, opts, calls)` scripts the bridge;
 * `locks` (optional) stands in for navigator.locks.
 */
function loadApi({ storage, fetch: fetchImpl, locks }) {
    const calls = [];
    const ctx = {
        localStorage: storage,
        sessionStorage: makeStorage(),
        crypto: { getRandomValues: (arr) => arr.fill(7) },
        window: { location: { href: '' } },
        atob: (s) => Buffer.from(s, 'base64').toString('binary'),
        setTimeout: (fn) => fn(), // collapse GET retry backoff
        fetch: (url, opts) => {
            calls.push({ url, opts });
            return fetchImpl(url, opts, calls);
        },
    };
    if (locks) ctx.navigator = { locks };
    vm.createContext(ctx);
    vm.runInContext(code, ctx);
    return { API: ctx.API, calls, ctx };
}

/** The rejection of `p` (errors cross the vm realm, so no instanceof). */
async function rejection(p) {
    try {
        await p;
    } catch (e) {
        return e;
    }
    throw new Error('expected the promise to reject');
}

const tokenCalls = (calls) => calls.filter((c) => c.url === '/api/token');

describe('refresh under an outage keeps the stored tokens (clients-5)', () => {
    const expiredSession = () => makeStorage({ refresh_token: R0, temporal_token: T_STALE });

    it('503 from Nginx during a bridge roll: tokens kept, retryable error, no redirect', async () => {
        const storage = expiredSession();
        const { API, calls, ctx } = loadApi({ storage, fetch: () => Promise.resolve(htmlResponse(503)) });

        const err = await rejection(API.get('/account'));
        expect(err.retryable).toBe(true);
        expect(err.status).toBe(503);
        expect(err.message).toBe('Bridge unavailable, please retry');
        expect(storage.getItem('refresh_token')).toBe(R0);
        expect(storage.getItem('temporal_token')).toBe(T_STALE);
        expect(ctx.window.location.href).toBe('');
        expect(calls.map((c) => c.url)).toEqual(['/api/token']);
    });

    it('500 (the bridge on a Redis outage) keeps tokens', async () => {
        const storage = expiredSession();
        const outage = jsonResponse({ error: { code: 'internal_error', message: 'Service temporarily unavailable' } }, 500);
        const { API, ctx } = loadApi({ storage, fetch: () => Promise.resolve(outage) });

        const err = await rejection(API.get('/account'));
        expect(err.retryable).toBe(true);
        expect(storage.getItem('refresh_token')).toBe(R0);
        expect(ctx.window.location.href).toBe('');
    });

    it('429 keeps tokens', async () => {
        const storage = expiredSession();
        const { API } = loadApi({ storage, fetch: () => Promise.resolve(jsonResponse({}, 429)) });

        const err = await rejection(API.get('/account'));
        expect(err.retryable).toBe(true);
        expect(storage.getItem('refresh_token')).toBe(R0);
    });

    it('a network failure keeps tokens', async () => {
        const storage = expiredSession();
        const { API, ctx } = loadApi({ storage, fetch: () => Promise.reject(new TypeError('Failed to fetch')) });

        const err = await rejection(API.get('/account'));
        expect(err.retryable).toBe(true);
        expect(err.status).toBe(0);
        expect(storage.getItem('refresh_token')).toBe(R0);
        expect(ctx.window.location.href).toBe('');
    });

    it('401 on the refresh clears both tokens and bounces to login', async () => {
        const storage = expiredSession();
        const { API, ctx } = loadApi({ storage, fetch: () => Promise.resolve(unauthorized()) });

        const err = await rejection(API.get('/account'));
        expect(err.message).toBe('Session expired');
        expect(err.retryable).toBeUndefined();
        expect(storage.getItem('refresh_token')).toBeNull();
        expect(storage.getItem('temporal_token')).toBeNull();
        expect(ctx.window.location.href).toBe('index.html?reason=expired');
    });

    it('a 200 without a temporal token is treated as final', async () => {
        const storage = expiredSession();
        const { API, ctx } = loadApi({ storage, fetch: () => Promise.resolve(jsonResponse({ success: false, message: 'nope' })) });

        const err = await rejection(API.get('/account'));
        expect(err.message).toBe('Session expired');
        expect(storage.getItem('refresh_token')).toBeNull();
        expect(ctx.window.location.href).toBe('index.html?reason=expired');
    });

    it('a successful refresh stores the rotated pair and completes the request', async () => {
        const storage = expiredSession();
        const { API, calls } = loadApi({
            storage,
            fetch: (url) => Promise.resolve(url === '/api/token' ? rotated() : jsonResponse({ ok: true })),
        });

        const out = await API.get('/account');
        expect(out).toEqual({ ok: true });
        expect(storage.getItem('refresh_token')).toBe(R1);
        expect(storage.getItem('temporal_token')).toBe(T1);
        expect(calls.map((c) => c.url)).toEqual(['/api/token', '/api/account']);
        expect(JSON.parse(calls[0].opts.body)).toEqual({ refresh_token: R0 });
        expect(calls[1].opts.headers.Authorization).toBe('Bearer ' + T1);
    });
});

describe('401 self-heal (temporal token revoked or rotated elsewhere)', () => {
    const liveSession = () => makeStorage({ refresh_token: R0, temporal_token: T_LIVE });

    it('a refresh outage during self-heal keeps tokens, surfaces retryable, and does not retry the GET', async () => {
        const storage = liveSession();
        const { API, calls, ctx } = loadApi({
            storage,
            fetch: (url) => Promise.resolve(url === '/api/token' ? htmlResponse(502) : unauthorized()),
        });

        const err = await rejection(API.get('/account'));
        expect(err.retryable).toBe(true);
        expect(storage.getItem('refresh_token')).toBe(R0);
        expect(storage.getItem('temporal_token')).toBe(T_LIVE);
        expect(ctx.window.location.href).toBe('');
        // No GET retry with the stale token after the failed refresh — that
        // would 401 again and bounce the tab.
        expect(calls.map((c) => c.url)).toEqual(['/api/account', '/api/token']);
    });

    it('a refresh the bridge rejects during self-heal ends the session', async () => {
        const storage = liveSession();
        const { API, ctx } = loadApi({ storage, fetch: () => Promise.resolve(unauthorized()) });

        const err = await rejection(API.get('/account'));
        expect(err.message).toBe('Unauthorized');
        expect(storage.getItem('refresh_token')).toBeNull();
        expect(ctx.window.location.href).toBe('index.html?reason=expired');
    });

    it('a successful self-heal retries the request once with the new token', async () => {
        const storage = liveSession();
        let accountHits = 0;
        const { API, calls, ctx } = loadApi({
            storage,
            fetch: (url) => {
                if (url === '/api/token') return Promise.resolve(rotated());
                accountHits++;
                return Promise.resolve(accountHits === 1 ? unauthorized() : jsonResponse({ ok: true }));
            },
        });

        const out = await API.get('/account');
        expect(out).toEqual({ ok: true });
        expect(calls.map((c) => c.url)).toEqual(['/api/account', '/api/token', '/api/account']);
        expect(calls[2].opts.headers.Authorization).toBe('Bearer ' + T1);
        expect(ctx.window.location.href).toBe('');
    });

    it('a second 401 after a good refresh ends the session', async () => {
        const storage = liveSession();
        const { API, calls, ctx } = loadApi({
            storage,
            fetch: (url) => Promise.resolve(url === '/api/token' ? rotated() : unauthorized()),
        });

        const err = await rejection(API.get('/account'));
        expect(err.message).toBe('Unauthorized');
        expect(calls.map((c) => c.url)).toEqual(['/api/account', '/api/token', '/api/account']);
        expect(ctx.window.location.href).toBe('index.html?reason=expired');
    });
});

describe('cross-tab refresh serialization', () => {
    /** navigator.locks stand-in; `beforeRun` simulates what a sibling tab did while we waited. */
    function fakeLocks(beforeRun) {
        const names = [];
        return {
            names,
            request: (name, fn) => {
                names.push(name);
                if (beforeRun) beforeRun();
                return Promise.resolve().then(fn);
            },
        };
    }

    it('takes the Web Lock and adopts a sibling tab\'s rotated pair without a network refresh', async () => {
        const storage = makeStorage({ refresh_token: R0, temporal_token: T_STALE });
        const locks = fakeLocks(() => {
            // The sibling rotated the family (R0 -> R1, fresh T1) first.
            storage.setItem('refresh_token', R1);
            storage.setItem('temporal_token', T1);
        });
        const { API, calls } = loadApi({
            storage,
            locks,
            fetch: (url) => Promise.resolve(url === '/api/token' ? unauthorized() : jsonResponse({ ok: true })),
        });

        const out = await API.get('/account');
        expect(out).toEqual({ ok: true });
        expect(locks.names).toEqual(['impala-refresh']);
        // Replaying R0 would have been "reuse" and revoked the whole family.
        expect(tokenCalls(calls)).toHaveLength(0);
        expect(calls[0].opts.headers.Authorization).toBe('Bearer ' + T1);
    });

    it('does NOT adopt when the stored refresh token is the one it was about to use (no loop on a revoked token)', async () => {
        // The temporal token is within its lifetime but the family was
        // revoked server-side: "unexpired" must not count as "newer".
        const storage = makeStorage({ refresh_token: R0, temporal_token: T_STALE });
        const locks = fakeLocks(null);
        const { API, calls, ctx } = loadApi({ storage, locks, fetch: () => Promise.resolve(unauthorized()) });

        const err = await rejection(API.get('/account'));
        expect(err.message).toBe('Session expired');
        expect(tokenCalls(calls)).toHaveLength(1);
        expect(JSON.parse(tokenCalls(calls)[0].opts.body)).toEqual({ refresh_token: R0 });
        expect(storage.getItem('refresh_token')).toBeNull();
        expect(ctx.window.location.href).toBe('index.html?reason=expired');
    });

    it('refreshes with the sibling\'s newer refresh token when its temporal token is already stale', async () => {
        const storage = makeStorage({ refresh_token: R0, temporal_token: T_STALE });
        const locks = fakeLocks(() => {
            storage.setItem('refresh_token', R1);
            storage.setItem('temporal_token', T_STALE);
        });
        const { API, calls } = loadApi({
            storage,
            locks,
            fetch: (url) => Promise.resolve(url === '/api/token' ? rotated() : jsonResponse({ ok: true })),
        });

        await API.get('/account');
        expect(tokenCalls(calls)).toHaveLength(1);
        // Our own R0 was burned by the sibling's rotation; only R1 is live.
        expect(JSON.parse(tokenCalls(calls)[0].opts.body)).toEqual({ refresh_token: R1 });
    });

    it('a sibling logout while waiting for the lock ends this tab\'s session', async () => {
        const storage = makeStorage({ refresh_token: R0, temporal_token: T_STALE });
        const locks = fakeLocks(() => {
            storage.removeItem('refresh_token');
            storage.removeItem('temporal_token');
        });
        const { API, calls, ctx } = loadApi({ storage, locks, fetch: () => Promise.resolve(rotated()) });

        const err = await rejection(API.get('/account'));
        expect(err.message).toBe('Session expired');
        expect(tokenCalls(calls)).toHaveLength(0);
        expect(ctx.window.location.href).toBe('index.html?reason=expired');
    });

    it('falls back to the per-tab single flight when Web Locks is unavailable', async () => {
        const storage = makeStorage({ refresh_token: R0, temporal_token: T_STALE });
        let release;
        const gate = new Promise((r) => { release = r; });
        const { API, calls } = loadApi({
            storage,
            fetch: (url) => {
                if (url === '/api/token') return gate.then(() => rotated());
                return Promise.resolve(jsonResponse({ ok: true }));
            },
        });

        const both = Promise.all([API.get('/a'), API.get('/b')]);
        release();
        await both;
        expect(tokenCalls(calls)).toHaveLength(1);
        expect(calls.filter((c) => c.url !== '/api/token').map((c) => c.opts.headers.Authorization))
            .toEqual(['Bearer ' + T1, 'Bearer ' + T1]);
    });

    it('a retryable failure under the lock releases the single flight for the next attempt', async () => {
        const storage = makeStorage({ refresh_token: R0, temporal_token: T_STALE });
        let attempts = 0;
        const { API, calls } = loadApi({
            storage,
            locks: fakeLocks(null),
            fetch: (url) => {
                if (url !== '/api/token') return Promise.resolve(jsonResponse({ ok: true }));
                attempts++;
                return Promise.resolve(attempts === 1 ? htmlResponse(503) : rotated());
            },
        });

        const err = await rejection(API.get('/account'));
        expect(err.retryable).toBe(true);
        // The operator retries: the refresh token is still there and works.
        const out = await API.get('/account');
        expect(out).toEqual({ ok: true });
        expect(tokenCalls(calls)).toHaveLength(2);
    });
});

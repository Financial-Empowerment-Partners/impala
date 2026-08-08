// SKIPPED — this suite specifies a cookie-session/CSRF surface that api.js does
// not implement.
//
// It exercises API.buildHeaders / API.setSession / X-CSRF-Token, none of which
// exist in html/js/api.js: the UI authenticates every mutation with a bearer
// token, and `rawPost` (the only credentials:'same-origin' path) is used solely
// for body-credentialed login endpoints. Bearer requests carry no ambient
// credential, so they are not CSRF-reachable, and the bridge enforces CSRF only
// on its cookie path (impala-bridge/src/auth.rs) where it fails closed. There
// is therefore no vulnerability here — only an unimplemented mode.
//
// The suite never ran: vitest's `include` matched `tests/**` and this file
// lives in `test/`. It is marked skipped rather than deleted so the intent
// survives, and skipped rather than silently excluded so it is visible in test
// output. Un-skip it if/when cookie-session support lands in api.js.
//
// See also the module docstring in html/js/api.js, which used to advertise a
// "CSRF self-heal" that was never implemented.
import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import vm from 'node:vm'

// api.js ships as a browser IIFE global. Load it into a vm context with the
// browser APIs it touches stubbed out, then drive it like the pages do.
const here = dirname(fileURLToPath(import.meta.url))
const code = readFileSync(resolve(here, '../html/js/api.js'), 'utf8')

function makeStorage() {
  const map = new Map()
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, String(v)),
    removeItem: (k) => map.delete(k),
  }
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  }
}

/** Build a fresh vm context with a scripted fetch and return {API, calls}. */
function loadApi(fetchImpl) {
  const calls = []
  const ctx = {
    localStorage: makeStorage(),
    sessionStorage: makeStorage(),
    crypto: { getRandomValues: (arr) => arr.fill(7) },
    window: { location: { href: '' } },
    setTimeout: (fn) => fn(), // collapse retry backoff delays
    fetch: (url, opts) => {
      calls.push({ url, opts })
      return fetchImpl(url, opts, calls)
    },
  }
  vm.createContext(ctx)
  vm.runInContext(code, ctx)
  return { API: ctx.API, calls, ctx }
}

describe.skip('API.buildHeaders', () => {
  const { API } = loadApi(() => Promise.reject(new Error('no fetch expected')))

  it('adds X-CSRF-Token on mutating methods when a token is present', () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const headers = API.buildHeaders(method, 'tok123', 'nonce')
      expect(headers['X-CSRF-Token']).toBe('tok123')
    }
  })

  it('never adds X-CSRF-Token on GET/HEAD', () => {
    for (const method of ['GET', 'HEAD']) {
      const headers = API.buildHeaders(method, 'tok123', 'nonce')
      expect(headers['X-CSRF-Token']).toBeUndefined()
    }
  })

  it('always carries the nonce and JSON content type', () => {
    const headers = API.buildHeaders('GET', null, 'abc')
    expect(headers['X-Request-Nonce']).toBe('abc')
    expect(headers['Content-Type']).toBe('application/json')
  })
})

describe.skip('session cache', () => {
  let API
  beforeEach(() => {
    ;({ API } = loadApi(() => Promise.resolve(jsonResponse({}))))
  })

  it('setSession/getCachedUser roundtrip', () => {
    API.setSession({ account_id: 'alice', is_admin: true, csrf_token: 'c1' })
    expect(API.getCachedUser()).toEqual({ account_id: 'alice', is_admin: true })
  })

  it('clearSession empties the cache', () => {
    API.setSession({ account_id: 'alice', is_admin: false, csrf_token: 'c1' })
    API.clearSession()
    expect(API.getCachedUser()).toBeNull()
  })
})

describe.skip('request CSRF behavior', () => {
  it('GET sends no CSRF header and never fetches /session/me', async () => {
    const { API, calls } = loadApi(() =>
      Promise.resolve(jsonResponse({ ok: true }))
    )
    await API.get('/account')
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('/api/account')
    expect(calls[0].opts.headers['X-CSRF-Token']).toBeUndefined()
    expect(calls[0].opts.credentials).toBe('same-origin')
  })

  it('POST carries the in-memory CSRF token after setSession', async () => {
    const { API, calls } = loadApi(() =>
      Promise.resolve(jsonResponse({ ok: true }))
    )
    API.setSession({ account_id: 'alice', is_admin: false, csrf_token: 'tok9' })
    await API.post('/notify', { x: 1 })
    expect(calls).toHaveLength(1)
    expect(calls[0].opts.headers['X-CSRF-Token']).toBe('tok9')
  })

  it('POST without a cached token rehydrates from /session/me first', async () => {
    const { API, calls } = loadApi((url) => {
      if (url === '/api/session/me') {
        return Promise.resolve(
          jsonResponse({ account_id: 'alice', is_admin: false, csrf_token: 'fresh' })
        )
      }
      return Promise.resolve(jsonResponse({ ok: true }))
    })
    await API.post('/notify', { x: 1 })
    expect(calls.map((c) => c.url)).toEqual(['/api/session/me', '/api/notify'])
    expect(calls[1].opts.headers['X-CSRF-Token']).toBe('fresh')
  })

  it('self-heals once on 403 by refetching the CSRF token', async () => {
    let notifyAttempts = 0
    const { API, calls } = loadApi((url) => {
      if (url === '/api/session/me') {
        return Promise.resolve(
          jsonResponse({ account_id: 'alice', is_admin: false, csrf_token: 'fresh' })
        )
      }
      notifyAttempts++
      if (notifyAttempts === 1) {
        return Promise.resolve(jsonResponse({ error: 'csrf' }, 403))
      }
      return Promise.resolve(jsonResponse({ ok: true }))
    })
    API.setSession({ account_id: 'alice', is_admin: false, csrf_token: 'stale' })
    const result = await API.post('/notify', { x: 1 })
    expect(result).toEqual({ ok: true })
    expect(calls.map((c) => c.url)).toEqual([
      '/api/notify',
      '/api/session/me',
      '/api/notify',
    ])
    expect(calls[2].opts.headers['X-CSRF-Token']).toBe('fresh')
  })

  it('401 clears the session cache and redirects to login', async () => {
    const { API, ctx } = loadApi(() =>
      Promise.resolve(jsonResponse({ error: 'unauthorized' }, 401))
    )
    API.setSession({ account_id: 'alice', is_admin: false, csrf_token: 'c' })
    await expect(API.get('/account')).rejects.toThrow('Unauthorized')
    expect(API.getCachedUser()).toBeNull()
    expect(ctx.window.location.href).toBe('index.html')
  })
})

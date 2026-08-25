# Runbook — Deploying the admin UI

**Audience:** anyone shipping `impala-ui` to an environment, or changing which
bridge it talks to.

**Prerequisites:** somewhere to serve static files; a reachable bridge; if you
use SSO, admin access to the IdP to register a redirect URI.

**Read this first:** the UI has **no deployment pipeline and no Terraform.**
Both of its CI workflows (`impala-ui.yml`, `ci-ui.yml`) only lint and test —
eslint, Vitest, html-validate — and no `.tf` file references the UI at all.
Every environment's UI is placed by hand or by something outside this repo. Plan accordingly — there is no "roll back the UI"
button, and no pipeline will catch a bad `config.js`.

**See also:** [`deploy.md`](./deploy.md) for the bridge,
[`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md) §6
for a worked S3 + CloudFlare hosting setup,
[`deploy-okta-sso-admin-ui-cloudflare.md`](./deploy-okta-sso-admin-ui-cloudflare.md)
for turning on Okta.

---

## 1. What you are deploying

Static files. No build step, no transpilation, no bundler. `html/` is the
artifact: vanilla JS modules in the IIFE pattern, Foundation 6.8.1 and jQuery
3.7.1 **vendored** under `html/vendor/`, and an nginx config that serves them
and proxies the API.

The Node toolchain exists only for linting and tests:

```
cd impala-ui
npm install
npm test          # vitest
npm run lint      # eslint
```

Neither produces a deployable artifact. `html/` is already the artifact.

## 2. Choose a hosting shape

| Shape | When | Notes |
|---|---|---|
| **nginx container** (`impala-ui/Dockerfile`) | You want the two-bridge `/api/<network>` proxying to keep working | Bakes `html/` + `nginx.conf` into `nginx:1.27-alpine`. Push to a registry, run behind your load balancer |
| **Object storage + CDN** (S3 + CloudFlare) | Simplest for a single-bridge environment | No proxy, so the UI must reach the bridge cross-origin — see §5 |
| **Local compose** | Development | Mounts `html/` and `nginx.conf` into stock `nginx:1.30-alpine` so edits are live. See [`deploy-local-stack.md`](./deploy-local-stack.md) |

> The Dockerfile and the compose file pin **different nginx versions** (1.27 vs
> 1.30). Compose does not build the Dockerfile — it mounts volumes instead — so
> the two are independent. Do not assume testing under compose has exercised the
> image you ship.

## 3. Point it at a bridge

`html/config.js` is the entire per-environment configuration surface. It is
deliberately a plain file loaded before everything else, so operators can edit
it **without a rebuild**:

```js
window.IMPALA_CONFIG = {
    networks: {
        testnet: { base: '/api/testnet', label: 'Testnet' },
        mainnet: { base: '/api/mainnet', label: 'Mainnet' }
    },
    default: 'testnet'
};
```

There are no build-time substitutions and no environment variables. Whatever is
in this file is what the browser uses.

- Deploying a **single-bridge** environment? Reduce `networks` to the one you
  actually serve and set `default` to it. Leaving a `mainnet` entry pointing at
  a path that 404s gives operators a selector that silently fails.
- The `base` values are paths the UI will call. With the nginx shape they are
  proxied; with the object-storage shape they must be absolute URLs to the
  bridge, and CORS applies (§5).

**Verify after every deploy** that `config.js` is the one you meant — it is the
easiest file to leave stale, and nothing validates it.

## 4. The nginx shape: upstreams resolve at startup

`nginx.conf` defines three upstreams:

| Location | Upstream |
|---|---|
| `/api/testnet/` | `testnet-bridge:8080` |
| `/api/mainnet/` | `mainnet-bridge:8080` |
| `/api/` | `impala-bridge:8080` (single-bridge fallback) |

These are literal hostnames, so **nginx resolves all three when it loads the
config**. If any one of them does not resolve, nginx will not start — the
failure is at boot, not on the first request, and it takes down the whole UI
including the two networks that were fine.

Locally this is solved by giving the single bridge container `testnet-bridge`
and `mainnet-bridge` as network aliases. In a real environment, either provide
all three names, or edit `nginx.conf` to define only the upstreams that exist.

Each bridge serves exactly one Stellar network. Confirm the wiring after
deploying — the network selector calls the public `GET /network`, which reports
`testnet` or `pubnet`, so a mislabeled proxy is visible:

```
curl -sf https://admin.example.com/api/mainnet/network | jq
```

## 5. CORS, CSP and the origin

**With the nginx shape** the UI and the API share an origin, so there is no CORS
involved and `connect-src 'self'` suffices.

**With the object-storage shape** the browser calls the bridge cross-origin, so
the bridge's `CORS_ALLOWED_ORIGINS` must name the UI origin exactly, and the
CSP's `connect-src` must allow the bridge origin. Neither is optional.

> **A wildcard CORS origin is a hard startup failure on `pubnet`.** The bridge
> exits at boot rather than serve a wildcard on mainnet; on testnet it is
> allowed with an info log. Do not reach for `*` to make a UI work.

The shipped CSP is strict and worth preserving:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'self' http://localhost:8200;
frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

- `script-src 'self'` with no inline scripts is what makes the localStorage
  token trade-off (§6) acceptable. Do not add `'unsafe-inline'`.
- `connect-src ... http://localhost:8200` exists for the **local** OpenBao test
  IdP. Remove it in any real environment.
- The other headers set alongside it: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy: camera=(), microphone=(), geolocation=()`.

> **nginx `add_header` inheritance is a trap.** Directives are inherited from a
> parent context *only if the child sets none*. A single `add_header` in a
> `server` or `location` block silently drops every inherited one — including
> the CSP. The TLS server template in `nginx.conf` repeats the full set for
> exactly this reason. If you add a header anywhere, re-add all of them.

TLS: the file ships a commented-out `listen 443 ssl` template. Enabling it means
mounting `fullchain.pem` + `privkey.pem` at `/etc/nginx/certs/`, mapping the
port, uncommenting the block, and running `nginx -t` before reload. HSTS is
commented out deliberately — it is wrong on a plain-HTTP listener.

## 6. Authentication and tokens

Login is three steps against the bridge:

1. `POST /authenticate` — validate credentials
2. `POST /token` — exchange username+password for a **14-day refresh token**
3. `POST /token` — exchange the refresh token for a **1-hour temporal token**

Subsequent requests send `Authorization: Bearer <temporal_token>`. On expiry or
a 401 the UI refreshes, and redirects to login if that fails.

Tokens live in `localStorage`, **namespaced per network** — `temporal_token::mainnet`,
`refresh_token::testnet` — because a JWT issued by one bridge is not valid at
another. The active network is `localStorage['impala_network']`; the theme is
`impala_theme`.

> **localStorage is a deliberate trade-off, not an oversight.** Any script
> running in the page's origin can read it, so an XSS hole is token theft. The
> mitigations are the strict CSP, the vendored+SRI third-party assets, and
> systematic HTML-escaping of server-derived values. Weakening any of those
> changes the risk calculus. httpOnly cookies would need bridge-side changes
> (cookie issuance plus a CSRF strategy) and are tracked as a follow-up.

Sessions idle out client-side after **15 minutes**, with a warning at 13.

## 7. SSO

The web SSO flow is a **public PKCE client** — the bridge holds no OIDC client
secret. Register this redirect URI with the IdP, exactly:

```
https://<ui-origin>/sso-callback.html
```

It is derived at runtime from `window.location.origin`, so every distinct origin
the UI is served from (apex vs `www`, staging vs prod, a preview URL) needs its
own registration.

The login page renders one button per **enabled** provider, discovered from the
bridge. If a provider you expect is missing, ask the bridge:

```
curl -sf https://<bridge>/auth/providers | jq
curl -sf https://<bridge>/auth/sso/okta/config | jq
```

`{"enabled": false}` means the bridge's discovery/JWKS fetch failed at startup —
a bridge-side problem, not a UI one. IdP key rotations need no redeploy; the
bridge refreshes JWKS on a timer and on an unknown `kid`.

## 8. Roles are server-driven

The bridge is the source of truth; the role rides in the JWT's `role` claim and
the UI only reflects it.

| Role | Permissions |
|---|---|
| `view-only` | view_accounts, view_mfa, view_transactions, view_cards |
| `device` | + create_transactions, manage_cards |
| `token` | + manage_accounts, manage_mfa, review_transactions |
| `admin` | + manage_roles, delete_accounts, sync_profile |

Elements carrying `data-permission="..."` are hidden when the current user lacks
the permission. **This is presentation, not enforcement** — the bridge
re-authorizes every request. A token with no `role` claim resolves to
`view-only`, fail-closed.

Grants take effect at the target's **next token refresh**. "I was made an admin
but the UI still hides everything" is almost always a stale token: log out and
back in.

## 9. Verify a deploy

```
curl -sfI https://<ui-origin>/                      # 200, and check the CSP header is present
curl -sf  https://<ui-origin>/config.js             # the config you intended
curl -sf  https://<ui-origin>/api/<network>/network  # nginx shape: proxy reaches the right bridge
```

Then in a browser, with devtools open: load the login page, confirm **no CSP
violations** in the console, log in, confirm the network selector shows the
right label, and confirm an admin sees admin-only controls.

## Gotchas

- **Replacing a vendored asset breaks the page.** `html/vendor/` files carry
  upstream SRI `sha384` hashes in their tags. Anything other than the exact
  upstream artifact is refused by the browser. Update the hash when you update
  the file.
- **There is no cache-busting.** Filenames are stable, so a CDN or browser can
  serve an old `config.js` or module after a deploy. Purge the CDN and
  hard-reload before concluding a change did not land.
- **No rollback path exists.** Keep the previous `html/` tree, or a tagged
  image, so "put back what was there" is possible.
- **`/api/` is a fallback, not a default.** With the two-bridge config in place,
  the UI calls `/api/<network>/`. The bare `/api/` location only serves clients
  configured to use it.
- **The bridge's error envelope is what the UI surfaces.** An HTML error page
  from a proxy is not that envelope; if the UI shows an unhelpful failure,
  check whether the response even reached the bridge. See
  [`triage.md`](./triage.md).

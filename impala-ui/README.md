# Impala UI

Web admin dashboard for the Impala bridge service. Provides a real account-management
console, transaction review (flag / annotate), MFA enrollment, transaction submission,
smartcard registration, directory force-sync, on-chain account refresh, a
conversion-reserve console, a bridge-key console, and server-driven role-based access
control (seven roles) for Stellar/Payala bridge operations.

## Running

```bash
docker compose up    # Nginx on port 3000, proxies /api/<network>/* to the matching bridge
```

Requires the `impala-bridge_default` Docker network (created by impala-bridge's `docker compose up`).

For local development without Docker, serve the `html/` directory with any HTTP server and
configure API proxying manually:

```bash
python3 -m http.server 8000 -d html/
```

## Tooling

A small Node toolchain exists for linting and unit tests (production is pure static files —
no build step):

```bash
npm install
npm test          # vitest (Roles, Router nav, Theme, KeysView, ReserveMath, Validate, NetConfig, TxFilter, …)
npm run lint      # eslint (flat config in eslint.config.js)
```

## Architecture

Vanilla JavaScript SPA using Foundation 6.8.1 CSS framework. No build step or transpilation — static HTML/CSS/JS served by Nginx. All JS modules use the IIFE (Immediately Invoked Function Expression) pattern exposing a single named global. Foundation 6.8.1 and jQuery 3.7.1 are vendored under `html/vendor/` (no CDN dependency); the `integrity` attributes on their tags carry the upstream SRI sha384 hashes, so replacing a vendored file with anything other than the exact upstream artifact will make browsers refuse to load it.

### Module Structure

| Module | Purpose |
|--------|---------|
| `config.js` | Runtime, ops-editable network config (`window.IMPALA_CONFIG`); loads first |
| `api.js` | HTTP client; dynamic per-network base path + per-network JWT token namespacing |
| `theme.js` | Light/dark theme: follows the OS `prefers-color-scheme` by default; an explicit toggle choice persists in `localStorage` (`impala_theme`) and wins |
| `roles.js` | Server-driven RBAC: reads the `role` claim from the JWT; seven-role permission table (ladder + treasurer / key-custodian / auditor), pinned against `tests/fixtures/role-capabilities.json` shared with the bridge; unknown roles fail closed to `view-only` for authorization, with `rawUserRole` kept for honest display |
| `auth.js` | Login/logout flow (3-step: authenticate → refresh token → temporal token) |
| `net-config.js` | Pure network-resolution helpers (base/key resolution, token key namespacing) |
| `net.js` | Network selector UI (top bar + login), live-network confirmation via `GET /network` |
| `validate.js` | Reusable form-field validators |
| `paginate.js` | Pagination controls (client slicing + server-paged control rendering) |
| `modal.js` | Framework-free accessible modal dialog |
| `drawer.js` | Framework-free accessible side drawer (account detail) |
| `tx-filter.js` | Pure `GET /transactions` query-string builder |
| `router.js` | Role-aware nav bar with hamburger collapse (privileged links after a separator), `[data-permission]` gating, `requirePermission` in-page denial, read-only banner, severity-split toasts (errors assertive + persistent, notices polite + auto-dismiss) |
| `session-timer.js` | Idle warning + auto-logout |
| `accounts.js` | Account console: list, search, drawer detail, role grant, sync, on-chain, CRUD |
| `transactions.js` | Transaction submission + server-backed review log (flag/status/note) |
| `mfa.js` | MFA enrollment (TOTP/SMS) and verification |
| `cards.js` | Smartcard registration and deactivation |
| `dashboard.js` | System version/health display and session info |
| `reserve.js` | Conversion-reserve console: buckets + drift, policies, forecast chart, work queues, ledger, unmatched deposits; read-only for auditors |
| `reserve-math.js` | Pure (DOM-free) formatting, validation and chart-geometry helpers for the reserve page |
| `keys.js` | Bridge-key console: per-provider running vs stored credential, import / merge / revoke, custodial-seed endpoints; read-only for auditors |
| `keys-view.js` | Pure (DOM-free) decision logic for the keys console (confirmation rules; never reconstructs server-compared values) |
| `admin.js` | Read-only Roles & Permissions reference (any `view_roles` holder) |
| `sso-auth.js` | Multi-provider OIDC SSO (Okta / Auth0 / Duo) — Authorization Code + PKCE login, one button per enabled provider |

### Two-bridge network routing

Each bridge deployment serves a **single** Stellar network, so the dashboard targets testnet or
mainnet by routing `/api/<network>/*` to the matching bridge. The network set and base paths live
in `html/config.js` (`window.IMPALA_CONFIG`) and can be edited by operators without a rebuild.

- The active network is persisted under `localStorage['impala_network']`.
- Because JWTs issued by one bridge are **not** portable to another, tokens are **namespaced per
  network**: `api.js` stores/reads them under keys like `temporal_token::mainnet` /
  `refresh_token::testnet` (see `net-config.js#tokenKey`).
- The top-bar (and login-page) network selector lets the user switch networks. Switching to a
  bridge the user is **not** authenticated on redirects to the login page; otherwise it reloads so
  the page re-fetches against the new bridge.
- The selector calls the public `GET /network` endpoint to confirm the proxy actually serves the
  network its label claims (the bridge reports `testnet` or `pubnet`).

`nginx.conf` defines `location /api/testnet/` → `testnet-bridge:8080` and `location /api/mainnet/`
→ `mainnet-bridge:8080`, plus a legacy default `location /api/` → `impala-bridge:8080` for
single-bridge / local-dev setups.

### Authentication & Token Flow

1. `POST /api/<network>/authenticate` — validate credentials (unauthenticated)
2. `POST /api/<network>/token` — obtain a 14-day refresh token (username + password)
3. `POST /api/<network>/token` — obtain a 1-hour temporal token (refresh token)
4. All subsequent requests use `Authorization: Bearer <temporal_token>`
5. Automatic refresh on expiry or 401. Only a refresh the bridge *rejects* (401) ends the
   session and redirects to login; a refresh that cannot reach a healthy bridge (5xx, 429,
   network failure) keeps the stored tokens and rejects with a retryable "bridge unavailable"
   error. Tabs serialize refreshes through the Web Locks API so a rotated refresh token is
   never replayed (the bridge revokes the whole family on replay); see
   `API.classifyRefreshResponse` in `api.js`.

### Token Storage Trade-off

JWTs (the 14-day refresh token and 1-hour temporal token) are stored in `localStorage`. This is a deliberate trade-off:

- **Risk**: any script that executes in the page's origin can read `localStorage`, so an XSS hole here is token theft.
- **Mitigations in place**: a strict Content-Security-Policy (`script-src 'self'`, no inline scripts, no third-party origins — see `nginx.conf`), all third-party assets vendored with SRI integrity hashes, and systematic HTML-escaping of every server- or user-derived value rendered via `innerHTML` (`js/escape-html.js` plus per-module helpers).
- **Why not httpOnly cookies**: the bridge issues tokens in JSON response bodies and authenticates via the `Authorization: Bearer` header; moving to httpOnly session cookies needs bridge-side changes (cookie issuance, CSRF strategy for cookie-authenticated requests). Tracked as a follow-up — until then, localStorage + the mitigations above is the accepted posture.

### Role-Based Access Control

Authorization is **server-driven**: the bridge is the source of truth and encodes the account's
role in the JWT's `role` claim. The UI reads that claim (via `API.parseJwt`) and gates UI elements
accordingly; there is no client-side role store anymore. UI permissions are display gating only —
the bridge enforces its capability matrix on every request, and both tables assert against the
same checked-in fixture (`tests/fixtures/role-capabilities.json`, also compiled into the bridge's
tests) so they cannot drift apart silently. Tokens without a `role` claim (legacy) resolve to the
least-privileged `view-only` role (fail-closed).

Seven roles: the original ladder plus three lateral privileged roles (specializations of the
admin surface — none includes another; admin remains the superset):

| Role | Permissions |
|------|-------------|
| view-only | view_accounts, view_mfa, view_transactions, view_cards |
| device | + create_transactions, manage_cards |
| token | + manage_accounts, manage_mfa |
| treasurer | base views + view_reserve, manage_reserve, view_roles |
| key-custodian | base views + view_accounts_list, view_keys, manage_keys, view_roles |
| auditor | read-only: base views + view_accounts_list, view_reserve, view_keys, view_roles |
| admin | everything, incl. governance: manage_roles, delete_accounts, sync_profile, review_transactions |

Role grants are performed server-side from the **Accounts** page (open an account → Role grant →
`PUT /admin/accounts/:id/role`). A grant revokes the target's existing sessions and tokens, so
the new role applies at their next sign-in. HTML elements with `data-permission="..."` attributes
are hidden when the current user lacks the permission; JS-rendered controls check
`Roles.currentUserHasPermission(...)`; whole pages guard with `Router.requirePermission`, which
renders an in-page explanation (role badge + missing permission) instead of silently redirecting.
Pages a role can view but not act on (Reserve/Keys for auditors) render fully with the actions
removed and a read-only banner naming the roles the actions require.

**Deploy skew** (bridge rolled ahead of the UI): a role this build does not know authorizes as
`view-only` (fail-closed) but is never mislabelled — the nav and account badges show the raw
claim on a neutral badge, and the Accounts drawer's role-grant select refuses to overwrite an
unknown role (a disabled "update the UI before changing it" option) so an admin cannot
accidentally demote a role they cannot see. Accounts on the `ADMIN_ACCOUNT_IDS` allowlist carry
an "effective admin" warning badge, because the env override outranks their stored role at token
issuance.

### Theming

A light/dark theme toggle (sun/moon) lives in the top bar. Three-state: with no stored choice the
UI follows the operating system's `prefers-color-scheme` (tracking live OS changes); an explicit
toggle choice is persisted in `localStorage['impala_theme']` and wins from then on. The stylesheet
uses a two-tier token system — a fixed brand ramp plus semantic surface tokens on `:root`, with a
single dark override block keyed off `[data-theme="dark"]` (`color-scheme` is set alongside it so
native controls match).

### Pages

| Page | URL | Access |
|------|-----|--------|
| Login | `index.html` | Public |
| Dashboard | `dashboard.html` | Authenticated |
| Accounts | `accounts.html` | view_accounts (console is admin-centric) |
| MFA | `mfa.html` | view_mfa / manage_mfa |
| Transactions | `transactions.html` | view_transactions / create_transactions / review_transactions |
| Cards | `cards.html` | view_cards / manage_cards |
| Reserve | `reserve.html` | view_reserve (admin, treasurer; auditor read-only) |
| Keys | `keys.html` | view_keys (admin, key-custodian; auditor read-only) |
| Admin | `admin.html` | admin only (read-only roles reference; others get the in-page denial) |

### Deployment

Nginx proxies `/api/<network>/*` requests to the matching bridge (configured in `nginx.conf`).
Static files are served from the container's `/usr/share/nginx/html` directory.

# Impala UI

Web admin dashboard for the Impala bridge service. Provides account management, MFA enrollment, transaction submission, smartcard registration, and role-based access control for Stellar/Payala bridge operations.

## Running

```bash
docker compose up    # Nginx on port 3000, proxies /api/* to impala-bridge:8080
```

Requires the `impala-bridge_default` Docker network (created by impala-bridge's `docker compose up`).

For local development without Docker, serve the `html/` directory with any HTTP server and configure API proxying manually:

```bash
python3 -m http.server 8000 -d html/
```

## Architecture

Vanilla JavaScript SPA using Foundation 6.8.1 CSS framework. No build step or transpilation — static HTML/CSS/JS served by Nginx. Foundation 6.8.1 and jQuery 3.7.1 are vendored under `html/vendor/` (no CDN dependency); the `integrity` attributes on their tags carry the upstream SRI sha384 hashes, so replacing a vendored file with anything other than the exact upstream artifact will make browsers refuse to load it.

### Module Structure

All JS modules use the IIFE (Immediately Invoked Function Expression) pattern for encapsulation:

| Module | Purpose |
|--------|---------|
| `api.js` | HTTP client with automatic JWT token management and refresh |
| `auth.js` | Login/logout flow (3-step: authenticate → refresh token → temporal token) |
| `roles.js` | Client-side RBAC with 4 roles: view-only, device, token, admin |
| `router.js` | Navigation bar, permission enforcement via `[data-permission]` attributes, toast notifications |
| `accounts.js` | Account search, create, update |
| `mfa.js` | MFA enrollment (TOTP/SMS) and verification |
| `cards.js` | Smartcard registration and deactivation with confirmation modal |
| `transactions.js` | Transaction submission with session-scoped log (sessionStorage) |
| `dashboard.js` | System version/health display and session info |
| `admin.js` | Role assignment and management (admin-only) |

### Authentication & Token Flow

1. `POST /api/authenticate` — validate credentials (unauthenticated)
2. `POST /api/token` — obtain 30-day refresh token (username + password)
3. `POST /api/token` — obtain 1-hour temporal token (refresh token)
4. All subsequent requests use `Authorization: Bearer <temporal_token>`
5. Automatic refresh on expiry or 401 → redirect to login

### Token Storage Trade-off

JWTs (the 14-day refresh token and 1-hour temporal token) are stored in `localStorage`. This is a deliberate trade-off:

- **Risk**: any script that executes in the page's origin can read `localStorage`, so an XSS hole here is token theft.
- **Mitigations in place**: a strict Content-Security-Policy (`script-src 'self'`, no inline scripts, no third-party origins — see `nginx.conf`), all third-party assets vendored with SRI integrity hashes, and systematic HTML-escaping of every server- or user-derived value rendered via `innerHTML` (`js/escape-html.js` plus per-module helpers).
- **Why not httpOnly cookies**: the bridge issues tokens in JSON response bodies and authenticates via the `Authorization: Bearer` header; moving to httpOnly session cookies needs bridge-side changes (cookie issuance, CSRF strategy for cookie-authenticated requests). Tracked as a follow-up — until then, localStorage + the mitigations above is the accepted posture.

### Role-Based Access Control

Roles and permissions are stored in `localStorage`. The first user to log in is automatically bootstrapped as admin.

| Role | Permissions |
|------|-------------|
| view-only | view_accounts, view_mfa, view_transactions, view_cards |
| device | + create_transactions, manage_cards |
| token | + manage_accounts, manage_mfa |
| admin | + manage_roles (all permissions) |

HTML elements with `data-permission="..."` attributes are hidden when the current user lacks the required permission.

### Pages

| Page | URL | Access |
|------|-----|--------|
| Login | `index.html` | Public |
| Dashboard | `dashboard.html` | Authenticated |
| Accounts | `accounts.html` | view_accounts / manage_accounts |
| MFA | `mfa.html` | view_mfa / manage_mfa |
| Transactions | `transactions.html` | create_transactions |
| Cards | `cards.html` | view_cards / manage_cards |
| Admin | `admin.html` | admin only |

### Deployment

Nginx proxies `/api/*` requests to `impala-bridge:8080` (configured in `nginx.conf`). Static files are served from the container's `/usr/share/nginx/html` directory.

# Runbook — Okta SSO for the impala-ui admin dashboard (local Nginx · AWS S3+ALB · CloudFlare Access)

**Audience:** an operator turning on **Okta SSO** for the admin dashboard. The Okta code path is
**already implemented** on both sides — the browser PKCE flow in `impala-ui/html/js/sso-auth.js`
(+ `sso-callback.html`) and the token validation / account provisioning in the bridge
(`impala-bridge/src/okta.rs`, `src/handlers/okta.rs`). This guide is **configuration + deployment**,
not code.

**Scope.** Okta tenant + app + custom‑authorization‑server setup (shared), then two serving paths —
the local `docker compose` Nginx stack and the AWS S3 + ALB stack — plus an optional **CloudFlare
Access** edge gate that uses **Okta as its IdP**. Okta **coexists** with username/password login
(the "Sign in with Okta" button appears alongside the password form when the bridge reports Okta
enabled). No code changes.

**Complements:** read these first —
- [`deploy.md`](./deploy.md) — the steady‑state bridge image build / rollout loop.
- [`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md) — hosts the
  static UI on **S3 (§6)** and stands up the **CloudFlare edge (§7)**. This guide layers the Okta +
  CloudFlare‑Access pieces on top of that topology.

---

## 0. What the repo provides vs. what this guide adds

| Piece | Status in repo | This guide |
|---|---|---|
| Front‑end Okta **PKCE public client** (`sso-auth.js`, `sso-callback.html`, button in `index.html`) | ✅ implemented, no SDK, no secret | Configure Okta to match |
| Bridge Okta **JWKS validation + auto‑provision** (`okta.rs`, `handlers/okta.rs`) | ✅ RS256, `iss`+`aud` checks, first‑account‑admin | Supply correct env |
| Bridge Okta env (`OKTA_ISSUER_URL` / `OKTA_CLIENT_ID` / `OKTA_JWKS_REFRESH_SECS`) | ✅ read (`config.rs`); compose passes 2 through (`docker-compose.yml:77‑78`); ❌ **not in Terraform** | §3 local / **§4 `ecs.tf` edit** |
| Okta tenant: **custom AS + SPA app + Trusted Origins** | ❌ | **§2 — you create** |
| CloudFlare **Access app + Okta IdP** | ❌ zero CloudFlare in repo | **§5 — you add it** |
| Okta **group → role** mapping | ❌ none; manual promote only | **§6** |
| `CORS_ALLOWED_ORIGINS` / `PUBLIC_ENDPOINT` on the ECS task | ❌ insecure defaults (`*` / `http://localhost:8080`) | **§4 — you set them** |

### Target topology

```
Local (docker compose — same origin):
  browser ──► localhost:3000  (nginx, impala-ui) ──┬── static UI (html/)
                                                   └── /api/<net>/*  ──► impala-bridge:8080
  browser ⇄ Okta  /authorize + /token  (Authorization Code + PKCE, no secret)

AWS + CloudFlare Access (split origin):
  ┌──────────────────── CloudFlare (edge TLS · DNS · WAF) ────────────────────┐
  │  admin.<domain>  ──►[ CF Access gate ⇄ Okta IdP ]──►  S3 static UI origin  │
  │  api.<domain>    ─────────(not Access-gated)────────►  ALB :443 ──► bridge │
  └────────────────────────────────────────────────────────────────────────────┘
  browser ⇄ Okta /authorize + /token (PKCE) ──► POST /auth/sso/okta ──► bridge mints its own JWT pair
```

> The edge gate and the app login are **two independent layers** (§5d): passing CloudFlare Access
> does **not** produce a bridge session — the user still logs into the app to get a JWT.

---

## 1. Prerequisites

- **Okta:** admin access to an Okta org, and the user (or Okta group) that should administer the
  dashboard.
- **CloudFlare (for §5 only):** the zone on CloudFlare with **Zero Trust** enabled, and an API
  token / dashboard access to create Access apps and IdPs.
- **AWS path (for §4/§5):** the sibling runbook's S3 UI origin + ALB (with an ACM cert on
  `api.<domain>`) + CloudFlare base already applied — see
  [`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md) §6/§7.
- Decide the **admin hostname** now (e.g. `admin.<domain>`). It appears verbatim in the Okta
  redirect URI, the Okta Trusted Origin, the bridge `CORS_ALLOWED_ORIGINS`, and the CloudFlare
  Access app.
- Tools for verification: `curl`, `jq`, and (AWS path) `aws` CLI + `terraform >= 1.5`.

---

## 2. Okta setup (SHARED — do this once, both paths depend on it)

This is where first deployments succeed or fail. The bridge validates the Okta **access token** as
an **RS256 JWT** with `iss == OKTA_ISSUER_URL` and `aud == OKTA_CLIENT_ID`
(`okta.rs::try_validate_with_jwks`, lines ~322‑324). Two Okta settings must line up for that to pass.

### 2a. Custom Authorization Server (and the audience)

Create or reuse a **custom** authorization server — **Security → API → Authorization Servers**. Use
the built‑in `default` one (`https://<org>.okta.com/oauth2/default`) or **Add Authorization Server**.
Set its **Audience** field to the **SPA app's Client ID** (you create the app in 2b — come back and
paste it here). Note the **Issuer URI**; it becomes `OKTA_ISSUER_URL`.

> **Callout — the #1 first‑deploy failure.** Do **not** use Okta's *org* authorization server
> (bare issuer `https://<org>.okta.com`, no `/oauth2/...`): it issues **opaque** access tokens the
> bridge cannot JWT‑validate. And by default a custom AS stamps the access‑token `aud` as
> `api://default`, **not** your client ID. The bridge checks `aud == OKTA_CLIENT_ID`, so you must set
> the **custom AS Audience = the SPA Client ID string**. Symptom if wrong: Okta login *looks*
> successful, then `POST /auth/sso/okta` returns **401** (`aud`/`iss` mismatch) or the token is opaque.
> The Admin Console exposes a **single** Audience value per AS, so this one‑to‑one mapping is the
> clean, no‑code path. (This conflates access‑token and ID‑token audience semantics — see §8.)

### 2b. SPA (public PKCE) application

**Applications → Create App Integration → OIDC → Single‑Page Application.**
- Grant types: **Authorization Code** (add **Refresh Token** if you want silent renewal).
- **Client authentication: None** (this forces PKCE — the dashboard sends no secret).
- **Sign‑in redirect URIs** (exact match, case‑sensitive — register every origin you'll serve from):
  - `https://<admin-host>/sso-callback.html` (AWS/prod)
  - `http://localhost:3000/sso-callback.html` (local dev — Okta permits `http` **only** for
    localhost)
- Copy the **Client ID** → this is `OKTA_CLIENT_ID`, and it must equal the 2a **Audience**.

> The redirect URI the browser sends is computed as `window.location.origin + '/sso-callback.html'`
> (`sso-auth.js`), so it must match the served origin exactly — no wildcards, no trailing‑slash
> drift.

### 2c. Trusted Origins (CORS) — easy to miss, breaks the flow if skipped

`sso-auth.js` performs the PKCE code→token exchange with a **direct browser `fetch()` of Okta's
`/token` endpoint** (`handleCallback()`). That is a cross‑origin call from your UI host to
`https://<org>.okta.com`, so Okta must allow it.

**Security → API → Trusted Origins → Add Origin**, type **CORS** (and Redirect), for **each** UI
origin:
- `http://localhost:3000`
- `https://<admin-host>`

> This is required **even on the local same‑origin Nginx path** — serving the UI and the bridge from
> the same origin removes the *bridge* CORS concern, but the browser→Okta `/token` fetch is still
> cross‑origin to Okta. Symptom if missed: the callback page loads, then the token POST fails with a
> browser CORS error ("No 'Access-Control-Allow-Origin' header") and login dies at the last step.

### 2d. Env mapping recap

| Bridge env var | Value | Notes |
|---|---|---|
| `OKTA_ISSUER_URL` | the **custom AS** Issuer URI (2a) | HTTPS only; unset ⇒ Okta disabled. Drives both the browser's `/authorize`+`/token` (via `/auth/sso/okta/config`) and the bridge `iss` check. |
| `OKTA_CLIENT_ID` | the **SPA** Client ID (2b) | Used as the JWT **audience**; must equal the 2a Audience. |
| `OKTA_JWKS_REFRESH_SECS` | optional, default **3600** | `DEFAULT_JWKS_REFRESH_SECS` (`constants.rs:87`). Background JWKS refresh; on‑miss one‑shot refresh also happens. |

There is **no `OKTA_CLIENT_SECRET`** — the dashboard is a public PKCE client and the bridge reads no
Okta secret (see §8).

> **Multi-provider note.** Okta is one provider in a config-driven OIDC registry
> (`impala-bridge/src/oidc.rs`). The `OKTA_*` vars above still work on their own (they synthesize
> a single `okta` provider), but to run several IdPs set `SSO_PROVIDERS=okta,auth0,duo` and give
> each provider `{NAME}_ISSUER_URL` / `{NAME}_CLIENT_ID` / `{NAME}_AUDIENCE` / `{NAME}_TOKEN_KIND`.
> **Auth0** needs `AUTH0_AUDIENCE` = the API identifier (not the client id) and its issuer keeps a
> trailing slash; **Duo SSO** uses `DUO_TOKEN_KIND=id`. All share the same
> `/auth/sso/:provider` flow and the single `sso-callback.html`. See
> [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) and `CLAUDE.md`.

---

## 3. Local same‑origin Nginx path (`:3000`)

The local `impala-bridge/docker-compose.yml` already passes `OKTA_ISSUER_URL` / `OKTA_CLIENT_ID`
through from the host env (`docker-compose.yml:77‑78`, empty by default). Export them and start the
stack:

```bash
export OKTA_ISSUER_URL="https://<org>.okta.com/oauth2/default"   # the custom AS issuer from §2a
export OKTA_CLIENT_ID="<spa-client-id>"                          # from §2b
just up          # brings up the bridge stack (creates impala-bridge_default) then the UI nginx :3000
```

Verify the **bridge** picked up the config (it's published on the host at `:8080`, so this bypasses
Nginx routing):

```bash
curl -fsS http://localhost:8080/auth/sso/okta/config | jq
# → { "enabled": true, "issuer": "...", "client_id": "...",
#     "authorization_endpoint": "...", "token_endpoint": "...", "scopes": [...] }
```

Then open `http://localhost:3000` — the **"Sign in with Okta"** button appears once
`GET /api/<net>/auth/sso/okta/config` reports `enabled: true`, and a click round‑trips through Okta to
`dashboard.html`.

> **Local routing quirk (expect a 502 otherwise).** The default `impala-ui/html/config.js` targets
> the `testnet` network, whose base is `/api/testnet`, and `nginx.conf` proxies `/api/testnet/*` to
> an upstream named **`testnet-bridge`** — which the single‑bridge local compose (service name
> `impala-bridge`) does **not** run. For local Okta testing either **curl the bridge directly** as
> above, or point a network's `base` at the legacy `/api` fallback (which Nginx proxies to
> `impala-bridge:8080`) in `config.js`:
> ```js
> window.IMPALA_CONFIG = {
>   networks: { local: { base: '/api', label: 'Local' } },
>   default: 'local'
> };
> ```
> Then reload `http://localhost:3000` and the Okta button + login will work end‑to‑end.

> The compose only wires `OKTA_ISSUER_URL` / `OKTA_CLIENT_ID`; to override the JWKS refresh interval
> locally, add `OKTA_JWKS_REFRESH_SECS: ${OKTA_JWKS_REFRESH_SECS:-3600}` to the `impala-bridge`
> service env. `OKTA_ISSUER_URL` must be **HTTPS** (the Okta issuer always is).

---

## 4. AWS split‑origin path (S3 UI at `admin.<domain>` + ALB API at `api.<domain>`)

Assumes the sibling runbook's S3 UI origin and ALB are already stood up. Here the UI and API are on
**different origins**, so bridge CORS is now in play.

### 4a. Inject Okta env + set the public origin (edit `terraform/ecs.tf`)

The stock `ecs.tf` injects **none** of the Okta vars and sets neither `CORS_ALLOWED_ORIGINS` (code
default `*`) nor `PUBLIC_ENDPOINT` (default `http://localhost:8080`). Extend **both** the server and
worker task definitions' `environment = concat([...])` lists (mirrors the sibling runbook §4a):

```hcl
# add to the server (and worker) `environment` list in terraform/ecs.tf
{ name = "OKTA_ISSUER_URL",       value = "https://<org>.okta.com/oauth2/default" },  # §2a issuer
{ name = "OKTA_CLIENT_ID",        value = "<spa-client-id>" },                        # §2b, == AS audience
{ name = "OKTA_JWKS_REFRESH_SECS", value = "3600" },                                  # optional
{ name = "PUBLIC_ENDPOINT",       value = "https://api.<domain>" },
{ name = "CORS_ALLOWED_ORIGINS",  value = "https://admin.<domain>" },
```

> **Security note.** Leaving `CORS_ALLOWED_ORIGINS=*` is logged as a warning at bridge startup and is
> not acceptable behind a real UI origin. Set it to the exact `https://admin.<domain>`. These values
> live in the task definition — they cannot be supplied out‑of‑band, so this `ecs.tf` edit is
> required for a correct cross‑origin front end. The Okta values here are non‑secret (the client ID
> and issuer are already exposed to the browser via `/auth/sso/okta/config`), so plain `environment` is
> fine — no Secrets Manager entry needed.

### 4b. Point the UI at the cross‑origin API base (`impala-ui/html/config.js`)

Because the UI is served from `admin.<domain>` but the API is `api.<domain>`, set an **absolute**
base (edit before `aws s3 sync`ing the bundle):

```js
window.IMPALA_CONFIG = {
  networks: { mainnet: { base: 'https://api.<domain>', label: 'Production' } },
  default: 'mainnet'
};
```

### 4c. Confirm the Okta registrations for this host

From §2, make sure Okta has both, for `https://admin.<domain>`:
- Sign‑in **redirect URI** `https://admin.<domain>/sso-callback.html` (§2b)
- **Trusted Origin (CORS)** `https://admin.<domain>` (§2c) — mandatory for the cross‑origin
  browser→Okta `/token` fetch.

### 4d. Deploy

```bash
cd terraform
terraform plan  -var-file=<env>.tfvars -var "jwt_secret=$JWT_SECRET" -out plan.tfplan   # expect only task-def env diffs
terraform apply plan.tfplan                                                             # ECS rolls server+worker

aws s3 sync impala-ui/html/ s3://<ui-bucket>/ --delete --cache-control 'public,max-age=300'
```

---

## 5. CloudFlare Access with Okta as the IdP (optional edge gate)

This puts a **CloudFlare Access** gate in front of `admin.<domain>`, authenticating users against
**Okta at the edge**, on top of the app‑level `/auth/sso/okta` login. It is defense‑in‑depth, not a
replacement — read §5d before relying on it.

### 5a. Add Okta as an IdP in Zero Trust

CloudFlare Access needs its **own** Okta app — a **confidential Web application** (client secret),
separate from the SPA app in §2b:

1. In Okta, **Create App Integration → OIDC → Web Application**; sign‑in redirect URI
   `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`. Copy its **Client ID + Client
   Secret**. Add a **groups claim** (filter regex `.*`) so CloudFlare policies can match Okta groups.
2. In **CloudFlare Zero Trust → Settings → Authentication → Login methods → Add → Okta**, paste the
   Okta org URL + that Web app's Client ID/Secret.

### 5b. Create the self‑hosted Access application

**Zero Trust → Access → Applications → Add → Self‑hosted**, hostname `admin.<domain>`. Add an
**Allow** policy scoped to your admin group / email domain (e.g. `emails ending in @<domain>` or the
Okta group). Select the Okta IdP from 5a.

### 5c. Do **not** gate the API host

Gate **only** `admin.<domain>`. Leave `api.<domain>` orange‑cloud proxied but **not** Access‑gated —
protect it with the bridge's own JWT auth + AWS WAF (`terraform/waf.tf`) + the ALB security group
locked to CloudFlare's published IP ranges (sibling runbook §7).

> **Why:** the `CF_Authorization` cookie CloudFlare Access issues is scoped to the **protected
> hostname** (`admin.<domain>`), not shared to `api.<domain>`. Gating the API host would block the
> UI's own XHRs and lock out the Android app (which can't do interactive IdP login). If you ever must
> gate the API, non‑browser callers need a **service token** (`CF-Access-Client-Id` /
> `CF-Access-Client-Secret`) with a Service Auth policy plus "Bypass OPTIONS to origin" for CORS
> preflights — avoidable cost.

### 5d. The two‑layer trade‑off (document this for your users)

- CloudFlare Access authenticates at the **edge** and mints **its own** JWT (`CF_Authorization`
  cookie / `Cf-Access-Jwt-Assertion` header). It does **not** create a bridge session.
- The user therefore still logs into the **app** (Okta button or password) to obtain the bridge's
  refresh+temporal JWT pair. That's **two layers**.
- The second hop is normally **silent**: passing the edge gate created an Okta SSO session, and the
  app's `/authorize` redirect (same Okta org, no `prompt=login`) reuses it — the user clicks the
  Okta button and is bounced straight back with a code, no second password entry. Caveats: only in
  the **same browser** with a live Okta session; a **password** login bypasses Okta at the app layer
  but is **still edge‑gated**, so that user authenticates once at the edge (Okta) and once to the app
  (password).

### 5e. (Optional) validate the CloudFlare Access JWT at the origin

For strict origin trust you can validate `Cf-Access-Jwt-Assertion` (per‑app `aud`, `iss` = your team
domain, keys at `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`). Note the **S3 website
origin cannot** run that check, so the **ALB‑SG‑locked‑to‑CloudFlare** control remains the real
origin guard for the API, and CloudFlare Access itself is the guard for the UI host.

### The two Okta apps at a glance

| Purpose | Okta app type | Client auth | Redirect URI registered in Okta |
|---|---|---|---|
| impala‑ui app `/auth/sso/okta` (§2b) | **Single‑Page App** (public, PKCE) | **None** (no secret) | `https://admin.<domain>/sso-callback.html` (+ `http://localhost:3000/sso-callback.html`) |
| CloudFlare Access IdP (§5a) | **Web Application** (confidential) | **Client secret** | `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback` |

You cannot reuse the SPA public client for CloudFlare Access — CloudFlare needs a confidential client
and its own callback.

---

## 6. Role bootstrap & promotion

Authorization is server‑driven: `impala_account.role` is embedded in the JWT `role` claim.

- The **first account ever inserted** — through **any** path, including Okta auto‑provision — is
  promoted to `admin` by a `BEFORE INSERT` trigger (`migrations/019_add_account_role.sql`). Every
  **later** Okta user auto‑provisions as **`view-only`**.
- There is **no Okta‑group → role mapping**. To promote an Okta user, an existing admin calls
  `PUT /admin/accounts/:id/role`; the new role takes effect at the target's next token refresh.

> **Bootstrap the intended admin deliberately** *before* opening Okta to the org — otherwise whoever
> signs in first silently becomes admin and everyone else is stuck `view-only`. Confirm at least one
> admin exists:
> ```sql
> SELECT count(*) FROM impala_account WHERE role='admin';
> ```

---

## 7. Smoke tests

```bash
# Bridge picked up Okta config (per network base on the AWS path):
curl -fsS https://api.<domain>/auth/sso/okta/config | jq '.enabled'      # true
curl -fsS https://api.<domain>/healthz                               # 200
curl -fsS https://api.<domain>/version | jq                          # build matches the deploy
```

In the browser at `https://admin.<domain>` (AWS + CloudFlare Access):
1. **Edge gate:** an unauthenticated visit redirects to CloudFlare Access → Okta login (proves §5).
2. **App login:** the **"Sign in with Okta"** button completes — typically with no second password
   prompt (SSO reuse, §5d) — and the token exchange succeeds (proves the §2c Trusted Origin).
3. `POST /auth/sso/okta` returns the bridge JWT pair; you land on `dashboard.html` with the role‑gated
   nav matching your account's role (§6).
4. **Coexistence:** username/password login still works (and is still edge‑gated).

Local (`http://localhost:3000`, no CloudFlare) — same app‑login check without the edge gate; see the
§3 routing‑quirk note.

---

## 8. Gaps & caveats

- **AS‑audience = client‑ID is semantically odd.** The bridge validates the *access* token with
  `aud == OKTA_CLIENT_ID`, which is ID‑token convention. It works only because you set the custom AS
  Audience to the client ID (§2a). A future maintainer changing the AS audience will break every
  login. If the bridge is ever reworked to validate against a real resource audience, revisit this.
- **No group → role mapping.** Okta groups are ignored for RBAC; roles are assigned in‑app via
  `PUT /admin/accounts/:id/role` (§6).
- **Two Okta apps of different types** are required for the CloudFlare‑Access topology (§5, table) —
  a public SPA app and a confidential Web app — you cannot share one.
- **Do not Access‑gate the API host** — the `CF_Authorization` cookie is per‑host (§5c).
- **Non‑browser clients** (the Android app, server‑to‑server) can't pass an interactive edge gate; if
  the API host were ever gated they'd need service tokens.
- **`OKTA_ISSUER_URL` pointed at the org server → opaque tokens → 401.** Always use a custom AS
  (§2a).
- **Trusted‑Origin (CORS) is the most‑missed step** and fails silently‑looking (§2c) — required even
  locally.
- **Logout is two‑layer.** `Auth.logout()` clears the app JWT only; it ends **neither** the
  CloudFlare Access session **nor** the Okta SSO session (no app‑side Okta SLO). To fully sign out,
  clear the Okta session (and the CloudFlare Access session) too.
- **`config.js` needs an absolute API base** on the split‑origin AWS path (§4b); the default relative
  `/api/<net>` only works behind the same‑origin Nginx proxy.
- **`ecs.tf` edits are net‑new** (§4a) — there is no Okta Terraform variable and no UI IaC in the
  repo today.
- **Stale `OKTA_CLIENT_SECRET` references.** `docs/runbooks/rotate-secrets.md`,
  `docs/runbooks/incident-response.md`, and `terraform/README.md` mention an Okta client secret, but
  the bridge (`okta.rs` / `config.rs`) **reads none** — the web flow is a public PKCE client. There
  is nothing to rotate for the current deployment; treat those references as N/A unless a confidential
  client is introduced.

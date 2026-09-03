# Runbook — Bringing up the local stack (bridge + UI + CLI)

**Audience:** anyone standing up Impala on a laptop — new joiners, people
reproducing a bug, people rehearsing an operation before doing it for real.

**Prerequisites:** Docker with Compose v2; `just` (optional but assumed below);
Go 1.26+ for `impalactl`. No AWS account, no Vault licence, no Stellar funds
beyond testnet friendbot.

**What you get:** a bridge on `:8080`, the admin UI on `:3000`, Postgres,
Redis, and an OpenBao dev server on `:8200` acting as both the seed-protection
(Transit) backend and a local OIDC test IdP.

**See also:** for a real environment, [`deploy.md`](./deploy.md) (steady-state
rollout), [`deploy-staging-openbao-kms-cloudflare.md`](./deploy-staging-openbao-kms-cloudflare.md),
[`deploy-production-vault-kms-ldap.md`](./deploy-production-vault-kms-ldap.md).

---

## 1. Start it

Order matters — the UI joins the bridge's Docker network by name, so the bridge
stack must exist first. `just up` does both in the right order:

```
just up          # bridge stack, then UI on :3000
just logs        # tail the bridge
just down        # stop both
```

Equivalent by hand:

```
docker compose -f impala-bridge/docker-compose.yml up -d
docker compose -f impala-ui/docker-compose.yml up -d
```

The bridge waits on healthchecks for Postgres and Redis, and on `openbao-init`
completing — a one-shot container that enables the Transit engine, creates the
`impala-seeds` key, and bootstraps OpenBao as an OIDC IdP, writing
`sso-config.json` into a shared volume that the bridge reads via `CONFIG_FILE`.

> **`network impala-bridge_default declared as external, but could not be
> found`** means you started the UI first. Start the bridge stack and retry.
> The network name is pinned in the bridge compose file precisely so it stays
> stable if directories are renamed.

## 2. Verify

```
curl -sf localhost:8080/health | jq      # status, database, redis
curl -sf localhost:8080/version | jq     # build info + schema version
curl -sf localhost:8080/network | jq     # confirms testnet
open http://localhost:3000               # admin UI
```

`/health` is the useful one. `/healthz` is an unconditional 200 and proves only
that the listener is up; `/readyz` returns a bare status code with **no body**.

With `impalactl`:

```
cd impalactl && go build -o impalactl .
./impalactl health
```

The default endpoint is already `http://localhost:8080`, and loopback is exempt
from the plain-HTTP refusal, so no flags are needed.

## 3. Create the first account — it becomes admin

**The first account ever inserted is promoted to `admin` by a database
trigger**, whatever path creates it (`create_account`, SSO auto-provision, or
`managed-account` generate/import). The advisory lock in the trigger serializes
the empty-table check, so two concurrent first-inserts cannot both win.

The local stack ships with `ALLOW_OPEN_REGISTRATION` unset, so the simplest
route is to create the account and then log in.

```
./impalactl account generate --account alice --first-name Ada --last-name Lovelace
./impalactl login --username alice
./impalactl whoami          # expect role=admin for the first account
```

If you need a second admin, grant the role from the UI's Accounts page
(`PUT /admin/accounts/{account_id}/role`), or add the id to `ADMIN_ACCOUNT_IDS` — an
allowlist that overrides the database role at token issuance. The allowlist is
the escape hatch when you have locked yourself out of the console.

> **A role change signs the target out on the spot** — the bridge revokes
> their tokens and sessions with the grant. `impalactl login` again to
> receive the new role.

> **`ALLOW_OPEN_REGISTRATION=true` is not a convenience toggle.** With it on,
> `POST /authenticate` will set a password on *any* existing account that has no
> credentials yet — including custodial and SSO-only accounts. The bridge logs a
> warning at startup when it is on. Leave it off.

## 4. What is and is not wired locally

| Capability | Local status |
|---|---|
| Custodial seeds | **Works** — OpenBao Transit, `SEED_PROTECTION_BACKEND=openbao` |
| SSO | **Works** — OpenBao acts as the OIDC IdP; see [`test-sso-openbao-local.md`](./test-sso-openbao-local.md) |
| Exchange providers | **Off** — credential env vars are empty, so `/exchange/*` answers 400 |
| Conversion reserve | **Off** — needs `RESERVE_ACCOUNT_ID` and a funded account |
| Notifications | **Off** — no SQS/SES/Twilio/FCM |
| Metrics | **Off** — no `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Logs | See below — this one bites |

### Logs

The bridge logs through the `log` crate to **syslog** (tag `impala-bridge`)
unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set. The container image has no syslog
socket, so in practice the local stack prints

```
Failed to connect to syslog: <err>, falling back to stderr
```

and then installs **no logger at all** — despite what that message says. `just
logs` will show you container output and panics, but not the application's
`info!`/`warn!`/`error!` lines.

To actually see application logs locally, set `OTEL_EXPORTER_OTLP_ENDPOINT` on
the bridge service (any OTLP collector will do) — that path installs
`tracing-subscriber` and writes to stdout as well as exporting. There is no
`RUST_LOG`; the level is `DEBUG_MODE` (`true` → debug, else info).

This is the single most common source of "the bridge is doing nothing and
saying nothing" locally. See [`triage.md`](./triage.md) §0.

## 5. Migrations locally

Two mechanisms exist and they are easy to confuse:

- **Local compose:** Postgres applies `./migrations` itself via
  `docker-entrypoint-initdb.d` — but **only when initializing an empty data
  directory**. An existing `pgdata` volume silently skips them.
- **Real deployments:** a one-off task with `RUN_MODE=migrate`, which runs
  `sqlx::migrate!` against `./migrations`.

So after pulling a branch that adds a migration, an existing local volume will
not have it. Either reset the volume:

```
docker compose -f impala-bridge/docker-compose.yml down -v   # destroys local data
just up
```

or run the migrator against the running database:

```
docker compose -f impala-bridge/docker-compose.yml run --rm \
  -e RUN_MODE=migrate impala-bridge
```

> `down -v` deletes the Postgres volume **and** the OpenBao bootstrap volume.
> That is fine locally — the OIDC client is re-minted on the next `up` — but it
> means every custodial seed you created is gone, because the Transit key that
> sealed them was ephemeral too.

## 6. The two-bridge routing model

The UI is static files behind nginx, which proxies `/api/<network>/*` to a
per-network bridge:

- `/api/testnet/` → `testnet-bridge:8080`
- `/api/mainnet/` → `mainnet-bridge:8080`
- `/api/` → `impala-bridge:8080` (single-bridge fallback)

nginx resolves those upstream names **at startup**, so all three must exist or
nginx will not start. Locally, the single bridge container carries
`testnet-bridge` and `mainnet-bridge` as Docker network aliases, which is why
one container satisfies all three.

Each bridge serves exactly one Stellar network, and JWTs are not portable
between bridges, so the UI namespaces tokens per network in `localStorage`
(`temporal_token::mainnet`, `refresh_token::testnet`). Switching networks in the
top bar when you are not authenticated on the target bridge redirects to login.
That is correct behavior, not a bug.

## 7. Tests and linting

```
just test           # every sub-project
just test-bridge    # cargo test
just test-cli       # go test ./...
just test-ui        # vitest
just lint           # rustfmt + clippy + terraform + soroban
just fmt
```

`just build-cli` produces the `impalactl` binary.

## 8. Where the bridge reads its configuration

Three loaders, and they do not see the same file:

- **The binary** (`cargo run`, a bare `impala-bridge`) loads a `.env` from
  the working directory at startup — a development convenience; it never
  overrides a variable that is already set in the environment, and real
  deployments set the process environment (ECS task definitions) and ship no
  `.env`. `impala-bridge/.env.example` is the template; `src/config.rs` is
  the full surface.
- **Your shell** does not read `.env` for you. For `impalactl`, `curl`, or a
  `cargo run` with overrides, export it first:
  ```
  set -a; source impala-bridge/.env; set +a
  ```
- **Compose** substitutes `${VAR:-default}` from your shell and from a `.env`
  next to the compose file (`--env-file` to point elsewhere), but a value
  reaches the container **only if the bridge service's `environment:` map
  names it**. That map is explicit and short: `RESERVE_ACCOUNT_ID`,
  `RESERVE_USDC_ISSUER` and the other `RESERVE_*` knobs, `KEY_IMPORT_ENABLED`,
  `ADMIN_ACCOUNT_IDS`, `CORS_ALLOWED_ORIGINS`, and `TRUSTED_PROXY_HOPS` are
  **not** in it today. Exporting them or writing them to `.env` changes
  nothing inside the container; add `RESERVE_ACCOUNT_ID: ${RESERVE_ACCOUNT_ID:-}`
  (and so on) to the `impala-bridge` service in
  `impala-bridge/docker-compose.yml` — and read the set-but-empty gotcha
  below first: an empty default shadows the same key in `CONFIG_FILE`, so add
  only the variables you are actually setting. `TRUSTED_PROXY_HOPS` deserves
  a real value here: it defaults to `1` (the ALB in front of a real
  deployment), and a bridge exposed directly — this stack — should run with
  `0` so a client-supplied `X-Forwarded-For` is ignored.

## Gotchas

- **The default `JWT_SECRET` is a literal placeholder** shipped in the compose
  file. It is fine locally and catastrophic anywhere else. Nothing stops you
  from pointing this stack at a real database — the endpoint check in
  `impalactl` is the only guard, so keep an eye on which bridge you are
  authenticated against.
- **A set-but-empty environment variable shadows the config file.** Env wins
  over `CONFIG_FILE` *including when it is the empty string*. The bridge compose
  file deliberately does **not** list `SSO_PROVIDERS`/`OPENBAO_*` with empty
  defaults for this reason. If you add them "for documentation", local SSO
  breaks.
- **The UI Dockerfile is not what compose uses.** Compose mounts `html/` and
  `nginx.conf` into a stock `nginx:1.30-alpine` so edits are live without a
  rebuild; the Dockerfile (which bakes them into `nginx:1.27-alpine`) is for
  building a deployable image. The two pin different nginx versions.
- **Custodial operations need OpenBao up.** If `openbao-init` failed, the bridge
  exits at boot with `Failed to initialize seed protector`.
- **Testnet only.** `STELLAR_NETWORK` defaults to `testnet`. `impalactl transfer
  send` proceeds without confirmation on testnet and demands a typed `yes`
  anywhere else — do not train yourself on the testnet behavior.

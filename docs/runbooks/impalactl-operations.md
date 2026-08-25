# Runbook — Operating the bridge with `impalactl`

**Audience:** operators managing accounts, roles and money-moving credentials
from a terminal or a script.

**Prerequisites:** Go 1.26+ to build; network reach to the bridge; an account on
the target bridge. Admin operations need the `admin` role.

**See also:** [`impalactl/README.md`](../../impalactl/README.md) is the command
reference. This runbook is the *task* view: the sequences worth following
exactly, and the places where the order matters. Key imports have their own
danger briefing in [`import-keys.md`](./import-keys.md) — **read it before your
first import.**

---

## 1. Install and point it at a bridge

```
cd impalactl && go build -o impalactl .
```

Resolution is **flag → environment → default** for all three connection
settings:

| Setting | Flag | Environment | Default |
|---|---|---|---|
| Endpoint | `--endpoint <url>` | `IMPALA_ENDPOINT` | `http://localhost:8080` |
| Token | `--token <jwt>` | `IMPALA_TOKEN` | stored credentials |
| Timeout | `--timeout <dur>` | — | `30s` |

Confirm you are talking to the bridge you think you are — this needs no
credentials, and it is the cheapest way to avoid acting on the wrong
deployment:

```
impalactl --endpoint https://bridge.example.com health
```

`health` prints the bridge's health, version **and Stellar network**. Check the
network line every time. A testnet and a mainnet bridge look identical
otherwise.

> **Plain HTTP to anything but loopback is refused** unless you pass
> `--insecure-http` (or set `IMPALA_ALLOW_HTTP`). The refusal is the feature:
> credentials would travel in cleartext.

Global flags may appear before or after the command — `impalactl --json account
list` and `impalactl account list --json` are identical. Every subcommand
accepts `--help`.

## 2. Authenticate

```
impalactl login --username alice
```

The password comes from `$IMPALA_PASSWORD`, a no-echo prompt, or stdin —
**never from argv**, which other processes and your shell history can read.

Credentials land in `$XDG_CONFIG_HOME/impalactl/credentials.json` with `0600`
inside a `0700` directory (override the directory with `$IMPALA_CONFIG_DIR`).

Two properties that matter operationally:

- **Credentials are endpoint-scoped.** They record the bridge that issued them.
  Pointing `--endpoint` elsewhere fails loudly rather than leaking a production
  token into a test deployment.
- **Refresh tokens are single-use.** The bridge rotates them and treats a replay
  as theft, revoking the whole token family. `impalactl` persists each
  replacement before use and serializes rotation between concurrent invocations
  with a lock file — so parallel scripts do not lock each other out. If you copy
  a `credentials.json` between machines and both use it, expect the family to be
  revoked. That is working as intended.

```
impalactl whoami          # account, role, expiry — read locally, no network
impalactl logout          # revoke this token
impalactl logout --all    # revoke every token and session for the account
```

**For CI, skip the store entirely:**

```
export IMPALA_TOKEN="$(vault kv get -field=token secret/impala/ci)"
impalactl account list
```

> `login --json` prints the raw token pair. Piping it into a CI transcript
> publishes a credential.

## 3. Account lifecycle

Three ways to create an account; pick by who holds the key.

```
# (a) Link a Stellar address the user already controls. The bridge never
#     holds a key for it.
impalactl account create \
  --stellar G... --account alice \
  --first-name Ada --last-name Lovelace --affiliation "Analytical Engines"

# (b) Custodial, bridge-generated. The seed is created server-side, sealed by
#     the configured backend, and NEVER returned. Prefer this.
impalactl account generate --account alice --first-name Ada --last-name Lovelace

# (c) Custodial, from a seed you already hold. The seed is read from
#     $IMPALA_SECRET_SEED, a no-echo prompt, or stdin — never argv.
impalactl account import --account alice --first-name Ada --last-name Lovelace
```

`--first-name` and `--last-name` are required; `--middle-name`, `--nickname`,
`--affiliation` and `--gender` are optional. `--account` defaults to the
logged-in account.

> **Prefer (b) over (c).** A generated seed has never existed outside the
> bridge. An imported one still exists wherever you copied it from, and that
> copy is now spend authority — put it under the same controls or destroy it.

Inspect:

```
impalactl account show G...              # the bridge's record
impalactl account onchain G...           # live Horizon balances, sequence, signers
impalactl account reserves alice         # Payala reserve balances
impalactl account list --search ada      # admin; paginated
impalactl account list --page 2 --per-page 50
```

`--per-page` is capped at 100.

> `account show` and `account onchain` answer different questions. When they
> disagree — the bridge's record versus the chain — that is the interesting
> case, and usually a sync problem rather than a data-loss one. Force a
> reconcile with `impalactl sync force G...` (admin; takes the **Stellar
> address**, not the Payala account id).

## 4. Roles

Roles are server-side and land in the JWT's `role` claim. The four values,
least to most privileged:

| Role | Adds |
|---|---|
| `view-only` | view accounts, MFA, transactions, cards |
| `device` | + create transactions, manage cards |
| `token` | + manage accounts, manage MFA, review transactions |
| `admin` | + manage roles, delete accounts, sync profiles — everything |

Granting is an admin operation on the bridge (`PUT
/admin/accounts/{account_id}/role`, driven from the admin UI's Accounts page).

**A grant takes effect at the target's next token refresh, not immediately.**
Someone promoted to `admin` keeps hitting 403 until their token turns over.
Have them run `impalactl logout` and log in again, or wait out the temporal
token. `impalactl whoami` shows the role actually present in the stored token,
which is the fastest way to tell "not granted" from "granted but not refreshed".

> **Unknown or missing role fails closed to `view-only`.** Tokens minted before
> the role claim existed have no role and are treated as least-privileged. After
> deploying the role migrations, every existing session must refresh. On an
> existing database the migration promotes the earliest account to `admin`;
> confirm at least one admin exists before relying on the console:
> `SELECT count(*) FROM impala_account WHERE role='admin'`.

## 5. Bridge keys — provider credentials

**Read [`import-keys.md`](./import-keys.md) first.** A provider credential is
spend authority: the replenishment driver sends real reserve XLM to the pay-in
address the active provider account names.

The three credential kinds and their parts:

| Kind | Required parts | Optional |
|---|---|---|
| `owlpay` | `api_key` | `webhook_secret` |
| `changelly_crypto` | `api_key`, `private_key` (RSA hex) | — |
| `changelly_fiat` | `api_key`, `private_key` (RSA PEM) | `callback_public_key` |

### See what is in effect

```
impalactl keys list
```

This is the command to run before and after every change. It reports, per kind:
what the **running** processes resolved, what is **stored**, and the **gap**
between them (`pending_restart`).

### Import

```
impalactl keys import changelly_crypto \
    --part-file private_key=/run/secrets/changelly.hex
# api_key is prompted for, no-echo
```

Part values reach the CLI three ways, and **never through argv**:

1. `--part-file <name>=<path>` — the only way to pass a multi-line PEM
2. `$IMPALA_KEY_<KIND>_<PART>` — e.g. `IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY`
3. a no-echo prompt

> The CLI's `--help` text says `$IMPALA_KEY_<PART>` without the kind. **That
> text is wrong** — the kind is included. It is there deliberately: a shared
> `IMPALA_KEY_API_KEY` would let a value exported for one provider be submitted
> to another, and both would accept it, because both are well-formed opaque
> strings.

Useful flags:

| Flag | Effect |
|---|---|
| `--replace` | Required if anything is already in effect. Also prompts for a confirmation phrase |
| `--confirm-phrase <s>` | Supply that phrase non-interactively |
| `--note <s>` | Operator note, **stored in plaintext** and shown in listings |
| `--skip-verify` | Store without proving the credential against the provider. Avoid |
| `--strand-in-flight` | Accept stranding in-flight orders when the new credential belongs to a different provider account |

### The two rules people get wrong

1. **Imports only add.** If anything is in effect — *including a credential the
   deployment supplies through environment variables* — the command refuses
   until you pass `--replace` and type the exact phrase the bridge names. That
   phrase includes the network, which is what catches the right key in the wrong
   environment.

2. **Nothing takes effect until the bridge restarts.** Credentials resolve once
   per process, so the whole fleet switches together rather than one task at a
   time. `keys list` showing `pending_restart` is the normal state between an
   import and the deploy that activates it — not a failure.

### Revoke

```
impalactl keys revoke owlpay
```

Scrubs the stored ciphertext. **It does not revoke anything at the provider**,
and it does not remove environment variables — if the deployment still sets
`OWLPAY_API_KEY`, the fleet reverts to it on the next restart.

A rotation is finished only when: the provider has revoked the old key, the
stored credential is replaced, **and the old environment variable is gone**.

### Custodial seeds

```
impalactl stellar-seed generate --account bridge-reserve --label "conversion reserve"
impalactl stellar-seed import   --account svc-payouts
```

`generate` returns only the public address — the seed never reaches the CLI.
**It is the only way to seed the conversion reserve**, which is deliberately not
importable.

`import` accepts `--replace`, and a replacement **must derive the same Stellar
address**; pass `--expected-address <G...>` to assert what the stored seed
currently derives. This is not a formality: the signer derives a transaction's
source account from the seed, not from the database row, so a seed silently
swapped for another would change which account the bridge signs as.

## 6. Transfers — the irreversible one

```
impalactl transfer send --to G... --amount 12.5 --memo rent
impalactl transfer send --account alice --to G... --amount 12.5 --fee 500 --yes
```

`transfer send` prints the bridge URL and the Stellar network to stderr before
doing anything. On testnet it proceeds. On any other network it demands a typed
`yes` at an interactive terminal, and **refuses outright when non-interactive
unless `--yes` is passed**. A scripted mainnet payment has to opt in
deliberately rather than by forgetting which bridge it was pointed at.

`transfer record` is bookkeeping only — nothing goes on-chain.

## 7. Activity and audit

```
impalactl activity list --status escalated --flagged true
impalactl activity show <btxid>
impalactl activity review <btxid> --status escalated --flagged --note "duplicate?"
impalactl activity events --since 42
```

> **`activity review` is a full replacement of the review record.** Anything you
> do not pass is reset. Read the current state with `activity show` first.

`activity events` is the admin audit feed and prints the cursor to use next, so
a poller is just:

```
cursor=0
while :; do
  cursor=$(impalactl activity events --since "$cursor" --json | jq '.events[-1].id // '"$cursor")
  sleep 30
done
```

After any key operation, confirm it landed in the audit trail: look for
`bridge.key_imported`, `bridge.key_revoked` and `bridge.seed_provisioned`
events, and investigate any nobody can account for.

## 8. Offline Payala batches

```
impalactl sync payala --file batch.json
cat batch.json | impalactl sync payala --file -
```

Amounts are signed integers in **minor units**; the sign is the direction
(`+` incoming, `-` outgoing). Parsing is strict — an unrecognized field is
rejected rather than silently dropped, because a dropped `amount` or `currency`
would corrupt the ledger.

Batches are idempotent per `(account, payala_tx_id)`. Re-submitting is safe and
is reported as `duplicates`.

> **`conflicting` is not routine idempotency.** It means a replayed id arrived
> with a *different* stored amount or currency. It is always warned about on
> stderr. Treat it as a ledger-integrity signal and stop.

## 9. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime failure — API error, validation failure, or degraded health |
| `2` | Usage error — unknown command, missing or invalid flag |

API errors keep the bridge's code and message:
`error: [403 forbidden] Access denied`. A 429 appends `(retry after Ns)`.

> **`[502 http_error]` means you never reached the bridge** — the CLI fell back
> to a raw body because the response was not the bridge's error envelope, so
> something in front of it (ALB, CloudFlare, a proxy) answered. See
> [`triage.md`](./triage.md).

## Gotchas

- **Client-side validation is convenience, not a boundary.** Address, seed and
  amount checks mirror the bridge's so mistakes fail before a round trip. The
  bridge re-validates everything and is the only authority on authorization.
- **`sync force` takes the Stellar address; `sync profile` takes the Payala
  account id.** They look interchangeable and are not.
- **`sync profile` only works for LDAP-sourced profiles.**
- **A custodial seed never reaches this CLI** on `account generate` or
  `stellar-seed generate`, and `transfer send` signs server-side. Only
  `account import` and `stellar-seed import` send a seed, and they send it once.
- **Prefer the CLI to the admin UI for key material.** The UI can do the same
  things, but a key pasted into a browser is exposed to extensions, autofill and
  session restore.

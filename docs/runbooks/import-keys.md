# Runbook — Importing bridge keys

**Audience:** engineer provisioning or rotating the credentials impala-bridge
uses to move money. Import, rotate, revoke and seed provisioning require the
**admin or key-custodian** role; auditors can additionally read the key
inventory (`GET /admin/keys` — fingerprints and metadata, never material).

**Read the danger section before you use these endpoints.** They are the most
powerful surface the bridge exposes.

---

## The danger

### 1. A provider credential is spend authority

This is the one people miss. It is not "an API key for a read-only
integration" — it decides **who the bridge pays**.

The replenishment driver (`src/exchange/replenish.rs`) sells accumulated XLM
back into USDC by creating a swap at Changelly and then **sending real reserve
XLM to the pay-in address the provider returns**. That address is chosen by
whichever Changelly account the active credential belongs to.

Import a credential for a Changelly account you do not control, and you have
handed that account's owner a say in where the pool's XLM goes. The bridge
pins the swap's *output* address and *refund* address to its own reserve
account, so the obvious theft does not work — but every swap and every
off-ramp now clears through a counterparty someone else chose, at a spread
they set, and a provider account that simply stalls will drive cycles into
`frozen`, stranding reserve XLM in `held` with no retry.

### 2. A custodial seed is signing authority

`sign_and_submit_payment` derives the transaction's **source account from the
seed**, not from the database row the seed is stored under. A seed decides
which Stellar account the bridge signs as. That is why:

- the loader asserts the decrypted seed derives the address its row claims,
  and refuses to sign on a mismatch;
- new seed ciphertexts are sealed under a header naming the account they
  belong to, so a blob copied between rows will not open;
- a seed replacement may never change an account's Stellar address.

### 3. Confirmation stops accidents, not attackers

Everything these endpoints ask for — echoing the current fingerprint, typing a
confirmation phrase, acknowledging in-flight orders — is defeated by a single
admin or key-custodian bearer token, because either role can read the
fingerprint they are asked to echo from `GET /admin/keys`.

These gates exist so that an operator does not replace the wrong credential,
and so two operators do not clobber each other. **They are not a barrier
against a compromised admin or key-custodian credential.** A second factor on
this surface would be a real improvement; it is not implemented. Treat admin
and key-custodian credentials accordingly.

### 4. Nothing takes effect until a rolling restart

Credentials are resolved **once per process**, at startup. An import is stored
and validated; the running instances keep using what they resolved when they
booted.

This is deliberate. The bridge is autoscaled and multi-instance, so pushing a
credential into the process that happened to serve the request would update one
task and leave the rest on the old key — while the response and the audit event
both said it had taken effect. Waiting for the restart means every task
switches at the same moment.

`GET /admin/keys` reports `pending_restart` for exactly this gap. It is the
normal state between an import and the deploy that activates it.

### 5. A browser is a bad place to hold a private key

The admin UI can import keys, and it warns about this. A key pasted into a
browser is exposed to extensions, autofill, session restore, and anything that
can read the page. Prefer `impalactl`, which reads a secret from a file, from
stdin, or from a no-echo prompt — and never from argv, which every process on
the machine can read.

### 6. The bridge is not the only place a key exists

- An **imported** key still exists wherever you copied it from. If that copy is
  not under the same controls as the bridge, rotate it.
- Revoking a credential here does **not** revoke it at the provider. If a key
  is compromised, revoke it at the provider first, then here.
- A database snapshot plus a KMS grant (or a Vault token) yields every stored
  credential. Superseded versions stay decryptable for a bounded overlap —
  seven days — so in-flight webhooks still verify; after that they are
  scrubbed. Revocation scrubs immediately.
- That overlap ends for a **running** process when the process restarts, not
  when the scrub happens: the previous webhook secret was loaded at startup
  like every other credential. Scrubbing bounds what a *future* process can
  load. To end an overlap early, roll the deployment.

### 7. Fingerprints are derived from key material

`GET /admin/keys` returns one-way digests, and they fan out to admin webhooks
in audit events. RSA keys are fingerprinted through their **public** half, so
no digest of private material exists anywhere. Opaque API keys and webhook
secrets have no public counterpart and are hashed directly: someone who can
read a fingerprint can confirm a *guess* of the underlying value. That is
acceptable for high-entropy provider-issued material and would not be for a
low-entropy secret — do not extend this scheme to one.

---

## Enabling

Off by default. With it off, provider secrets come from the environment exactly
as they always have, the admin endpoints refuse, and stored credentials are not
even read.

```
KEY_IMPORT_ENABLED=true
SEED_PROTECTION_BACKEND=kms          # or vault / openbao — never none
KMS_SEED_KEY_ID=arn:aws:kms:...      # or VAULT_ADDR + VAULT_TRANSIT_KEY
```

There is no plaintext-at-rest path and none will be added: the feature refuses
to run with `SEED_PROTECTION_BACKEND=none`.

The flag is also the **break-glass switch**. Turn it off and restart, and the
whole fleet reverts to environment credentials — which is exactly why a
rotation is not finished until the old environment variable is gone (see
"Finishing a rotation").

---

## What can be imported

| Kind | Parts | Notes |
|---|---|---|
| `owlpay` | `api_key`, `webhook_secret` (optional) | No read-only endpoint exists to probe against; validated but not proven |
| `changelly_crypto` | `api_key`, `private_key` | Private key is hex-encoded PKCS#8 DER |
| `changelly_fiat` | `api_key`, `private_key`, `callback_public_key` (optional) | Private key is PEM (PKCS#1 or PKCS#8) |

Custodial Stellar seeds go through `/admin/stellar-seeds/*` instead — they live
in `managed_seed`, which the conversion reserve and the custodial signing
endpoints read directly.

---

## Importing a provider credential

### With impalactl (preferred)

```
# See what is running, what is stored, and whether they differ.
impalactl keys list

# Import. The private key must come from a file — it is multi-line, and both
# the prompt and the stdin fallback read a single line.
impalactl keys import changelly_crypto \
    --part-file private_key=/run/secrets/changelly-private-key.hex \
    --note "OPS-1421 initial provisioning"
```

`api_key` is prompted for without echo, or taken from
`$IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY`. Every part follows the same order:
`--part-file`, then `$IMPALA_KEY_<KIND>_<PART>`, then a no-echo prompt. The
kind is in the variable name on purpose — a shared `IMPALA_KEY_API_KEY` would
let a value exported for one provider be submitted to another silently, and
neither side could tell, because both are well-formed opaque strings.

The CLI prints the bridge URL and Stellar network before sending anything. On
any network other than testnet it also requires a typed `yes` (or `--yes` for
scripted use). **Read that line.** The commonest mistake with credentials is
the right key in the wrong environment.

### With the API directly

```
POST /admin/keys/changelly_crypto
{ "parts": { "api_key": "...", "private_key": "..." },
  "note": "OPS-1421 initial provisioning" }
```

### With the admin UI

Keys → the provider's card → **Import**. Read the danger banner at the top of
the page first, and see §5 above.

---

## Replacing a credential

**Imports only add by default.** If anything is already in effect for that kind
— including a credential the deployment supplies through environment variables,
which has no stored row but is very much live — the request is refused with
`409` and a description of what is there.

To replace it you must supply three things together:

1. `replace: true`;
2. `expected_fingerprint` — the fingerprint of the credential being
   superseded, echoed back. `GET /admin/keys` serves it as
   `replace_target_fingerprint`: the stored credential if there is one,
   otherwise whatever this instance is running. The two differ between an
   import and the deploy that activates it, so read the field rather than
   choosing. This is a compare-and-swap: two operators racing cannot both win,
   and you cannot blind-replace something you never looked at;
3. `confirm_phrase` — exactly `replace {kind} {network}`, typed out. It is
   deliberately *not* the fingerprint, which is on screen and copyable; naming
   the network is what catches the wrong-environment mistake.

The bridge serves the exact phrase in `GET /admin/keys`, so clients never
compose it themselves and cannot drift from the server.

```
impalactl keys list        # read the confirm phrase and fingerprint
impalactl keys import changelly_crypto --replace \
    --part-file private_key=/run/secrets/new-key.hex
# → prompts: Type "replace changelly_crypto pubnet" to confirm:
```

### The in-flight guard

A replacement is refused while non-terminal orders or replenishment cycles are
running against that provider. A provider reference (a swap id, a transfer id)
is meaningful only to the account that created it: point the bridge at a
different provider account and the reconcile poller defers those orders
forever, and a cycle can be left with treasury XLM already sent and nothing
able to claim it.

Settle them first. If the new credential is for the **same provider account**
— a key rotation rather than an account change — pass `strand_in_flight: true`
(`--strand-in-flight`) to say so.

Revocation carries the same guard, and more starkly: once the credential stops
being used the provider may be unconfigured entirely, leaving nothing able to
reconcile those references at all.

### Rotating one part

A stored secret cannot be read back, so rotating one part would otherwise mean
re-entering the others. `POST /admin/keys/{kind}/merge` overlays the parts you
supply onto the stored set:

```
POST /admin/keys/changelly_fiat/merge
{ "set_parts": { "callback_public_key": "-----BEGIN PUBLIC KEY-----..." },
  "expected_fingerprint": "...", "confirm_phrase": "replace changelly_fiat pubnet" }
```

Merge only works against a **stored** set. There is nothing to merge into an
environment-sourced credential, and synthesising one would silently promote the
deployment's secrets into the database.

---

## Finishing a rotation

Storing the credential is step one of three.

1. **Import**, as above.
2. **Roll the deployment** so every task resolves the new credential:
   ```
   aws ecs update-service --cluster impala-bridge \
       --service impala-bridge-server --force-new-deployment
   ```
   Confirm with `impalactl keys list`: `pending_restart` should be gone and the
   effective fingerprint should match the stored one.
3. **Remove the old environment variable** from the task definition and the
   secret manager. Until you do, `GET /admin/keys` reports it as *shadowed*,
   and turning `KEY_IMPORT_ENABLED` off would silently re-activate it — a key
   you may have rotated *away from* precisely because it was compromised.

Then revoke the old key at the provider.

---

## Revoking

```
impalactl keys revoke changelly_crypto
```

Marks the stored credential revoked and scrubs its ciphertext immediately
(unlike supersession, which keeps the previous version decryptable for the
overlap window).

Before it acts, the CLI prints what the provider falls back to **after the next
restart** — the environment credential, or nothing at all — and the API refuses
without `confirm_next_source: true`. Revocation quietly handing the money path
back to an older key is the surprise worth naming out loud.

**Revoking here does not revoke at the provider.** Do that there.

---

## Custodial Stellar seeds

### Generating (the only way to provision the reserve)

```
impalactl stellar-seed generate --account bridge-reserve --label "Reserve"
```

The bridge creates the key itself, seals it, and returns only the public
`G...` address. The secret never exists outside the process in plaintext and
there is no way to export it.

**Import is refused for the configured `RESERVE_ACCOUNT_ID`**, and that is
deliberate. An operator-supplied reserve seed means a person holds the pool's
signing key indefinitely; and during bootstrap it would let whoever calls first
install a key *they* control, capturing every deposit the bridge subsequently
directs at the reserve address. Disaster recovery restores the database row,
not the plaintext key.

### Bootstrapping the reserve

`init_conversion_reserve` needs a `managed_seed` row for `RESERVE_ACCOUNT_ID`.
There used to be no supported way to create one: the user-facing
`/managed-account/generate` refuses for exactly that account.

With `KEY_IMPORT_ENABLED=true`, a bridge configured with `RESERVE_ACCOUNT_ID`
but no seed starts **armed but inactive**: it logs loudly, `GET /health`
reports the state, no order diverts to the reserve, and no payout can be
signed. The account stays quarantined from `/managed-account/*` throughout —
that guard reads configuration, not the live reserve handle, precisely so it
stays armed during this window.

1. `impalactl stellar-seed generate --account <RESERVE_ACCOUNT_ID>`
2. Fund the returned `G...` address (base reserve, plus a USDC trustline).
3. Restart the bridge. The reserve initializes.

With the flag off, the old behaviour is unchanged: the bridge refuses to start.

### Importing an existing seed

```
IMPALA_SECRET_SEED=... impalactl stellar-seed import --account svc-payouts
```
…or omit the variable and let it prompt without echo.

Two rules:

- **Never for the reserve account** (above).
- **A replacement may not change the account's Stellar address.** On this
  bridge an account's address *is* its seed's public key, so a different seed
  is a different account: the bridge would advertise one address for deposits
  while signing as another, and anything held at the old address would be
  stranded. Rotating a Stellar key without changing the address is an on-chain
  `set_options` operation, which this custodial signer does not support —
  create a new account and migrate.

The bridge looks the account up on Horizon first and refuses a master key with
**weight 0**: it can authorize nothing, however valid the strkey looks. An
account that does not exist yet is fine — it simply has not been funded.

---

## When something is wrong

### `GET /health` reports `key_resolution: degraded`

A stored credential could not be opened at startup, so that provider is
**disabled on that instance**. It deliberately did **not** fall back to the
environment — that would silently re-activate the credential someone replaced.

`/readyz` stays green on purpose: the orchestrator acts on readiness, and one
unreadable credential row must degrade a provider rather than cycle every task
in the fleet.

Likely causes, in order:

1. **The KMS key or Vault token is unavailable.** Fix the access, restart.
2. **`SEED_PROTECTION_BACKEND` changed** between the import and the restart. A
   credential sealed by one backend cannot be opened by another. Change it
   back, or re-import under the new one.
3. **The row was tampered with.** The bound header names the kind and version
   it belongs to; a blob moved between rows fails the check. Treat as an
   incident — see `incident-response.md`.

Break glass: set `KEY_IMPORT_ENABLED=false` and restart to revert the whole
fleet to environment credentials.

### `GET /health` is fine but a provider is disabled

Check `impalactl keys list`. Either nothing is configured for that kind, or the
credential is stored but not yet activated (`pending_restart`) — roll the
deployment.

### An operator replaced the wrong credential

Nothing has taken effect yet unless a restart has happened since. Re-import the
correct credential (the previous version is still listed in the history, but
its plaintext is not recoverable — you need the original key material) and do
not roll the deployment until `keys list` shows the right fingerprint stored.

If a restart already happened, the money path is running on the wrong key:
treat it as a Sev 2, re-import, and roll immediately.

### Suspected credential compromise

1. **Revoke at the provider first.** Bridge-side revocation does not invalidate
   the key upstream.
2. `impalactl keys revoke <kind>` — scrubs the stored ciphertext immediately.
3. Remove the corresponding environment variables from the task definition and
   the secret manager, or `KEY_IMPORT_ENABLED=false` will resurrect them.
4. Import the replacement and roll the deployment.
5. Check `GET /admin/events` for `bridge.key_imported` /
   `bridge.key_revoked` / `bridge.seed_provisioned` events you did not expect.
6. Follow `incident-response.md` for forensic capture.

---

## Audit

Every mutation emits an event into the admin outbox and fans out to registered
admin webhooks:

| Event | Payload |
|---|---|
| `bridge.key_imported` | kind, version, set fingerprint, whether it replaced something, import vs merge |
| `bridge.key_revoked` | kind, version, fingerprint, what the provider falls back to |
| `bridge.seed_provisioned` | target account, Stellar address, generated vs imported, whether it is the reserve |

`account_id` on all three is the **acting operator** (admin or key-custodian).
Payloads carry fingerprints and public identities only — never key material,
and never anything derived from a decrypted blob.

---

## See also

- `rotate-secrets.md` — rotating everything that is *not* imported this way
  (JWT secret, database, Redis, Twilio, SES, FCM, Vault/OpenBao).
- `conversion-reserve.md` — what the reserve seed signs for.
- `incident-response.md` — severity guide and forensic capture.

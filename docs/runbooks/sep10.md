# Runbook — SEP-10 sign-in with card keys

**Audience:** engineer turning on SEP-10 (Stellar Web Authentication) for
Impala cards whose applet carries a Stellar key (applet 0.3+). Generating,
activating and revoking the SEP-10 signing key require the **admin or
key-custodian** role (`manage_keys`); auditors can read the inventory
(`read_keys`).

**Status (2026-11).** Card key kind only, **testnet only**: the bridge refuses
to boot with `SEP10_ENABLED=true` on any other network. Phone and wallet keys
(`stellar_login_key`, enrollment, link challenges, restricted tokens) are a
later phase of `docs/sep10-authentication.md` and are **not** built. The binding
contract for this phase is [`docs/sep10-card-keys.md`](../sep10-card-keys.md);
the API and the dashboard screens are explained field by field in
[`docs/sep10-api-and-admin-ui.md`](../sep10-api-and-admin-ui.md). This runbook
is the procedure. Every step below can also be done on the dashboard's Keys
page ("From the dashboard", further down).

---

## What it is

A card registered with its Stellar address (`POST /card` with
`stellar_address`, `stellar_binding_sig`, `stellar_proof_sig`, or
`PUT /card/stellar-key` for a card that was registered before it was
personalized, which is what the issuance tool does as its last step) can sign
in with a standard SEP-10 challenge instead of `SIGN_AUTH`:

1. `GET /.well-known/stellar.toml` → `NETWORK_PASSPHRASE`, `SIGNING_KEY`,
   `WEB_AUTH_ENDPOINT`;
2. `GET /auth/sep10?account=G…` → a challenge transaction signed by the
   bridge's SEP-10 signing key;
3. the card signs it (`SIGN_SEP10`); the app appends the signature;
4. `POST /auth/sep10 {"transaction": "…"}` → `{token, success, message,
   temporal_token, refresh_token}` — **exactly** the session `POST /auth/card`
   mints for that card's account (same role derivation, same token pair;
   `token == temporal_token`).

**Privileged accounts are not served.** When the role the session would
carry holds any capability (admin, including `ADMIN_ACCOUNT_IDS`; treasurer;
key-custodian; auditor), `POST /auth/sep10` answers the generic 401 and mints
nothing: this route is public, wildcard-CORS and a tap without a PIN, so it
never hands out reserve, key or oversight authority. Those cards keep signing
in with `POST /auth/card`; the app falls back to it in the same tap. The
admin dashboard says so on such an account's card list.

Every Stellar key that is registered leaves `card.stellar_key_registered
{card_id}` in the event outbox (a second way to sign in as the account).

The bridge verifies the card's two cross-signatures once, at registration:
the card's P-256 key vouches for the Stellar key (`bindingSig` over `SKEY_A`),
and the Stellar key proves possession bound to that account and card
(`proofSig` over `SKEY_B`). A failure is 400 `invalid_stellar_binding`; an
address already on another active card is 409 `stellar_address_in_use`.

## What the Stellar address on a card can and cannot do

- **It can** sign SEP-10 challenges for this bridge, and nothing else: the
  applet parses every transaction it is asked to sign and refuses anything that
  is not a sequence-number-0, manage-data-only challenge addressed to its own
  key. Sequence 0 means no network will ever accept the transaction.
- **It cannot** authorize a payment, change signers, or sign any ledger
  transaction. **Never fund a card's Stellar address**: nothing can ever sign a
  transaction that spends from it. Funds sent there are lost.
- It is **not** the account's money address (`impala_account.stellar_account_id`)
  and the bridge never reads it for payments or transaction ownership.
- Signing a challenge needs **no PIN** in this phase (parity with `SIGN_AUTH`).
  Anyone holding the card in the NFC field can sign in as its holder, exactly
  as with card login today. Moving stored value still needs `SIGN_TRANSFER_V2`
  with the user PIN.
- Deleting the card (`DELETE /card`) stops future SEP-10 sign-ins with it at
  once (unknown card → 401). It does not revoke sessions already minted (the
  same pre-existing gap as card login; use `POST /logout/all` or an account
  epoch bump).

## The signing key

One Ed25519 key per deployment (per network), plus a 32-byte MAC key that binds
every challenge nonce to the key version. Both are **generate-only**: created
inside the bridge, sealed together by the seed protector (KMS / Vault /
OpenBao), never imported, never exported. No response, log line or event
carries key bytes; events carry fingerprints and versions only.

The key moves no funds: the server account is never funded and must never be
added as a signer anywhere (runbook rule). A compromise of a replica's memory
yields a key that can mint TTL-exact challenges and nothing else — it cannot
forge a card's signature.

States: `pending` → (activate) → `active` → `superseded` (still verifies its
own in-flight challenges for TTL + 120 s) — and `revoked` at any time (refused
at once, material scrubbed).

Each replica's key ring polls `sep10_signing_key` every 30 s and decrypts each
version **once** (never per request); a failing protector is retried with
backoff 5 s → 60 s. A ring that cannot read the table for 5 minutes goes stale
and the public routes answer 503.

## Prerequisites

- Migration `040_sep10_card_keys.sql` applied **before** rolling the binary
  (`RUN_MODE=migrate`). It is additive: the `sep10_signing_key` table plus three
  nullable `card` columns and a partial unique index.
- `SEED_PROTECTION_BACKEND` = `kms`, `vault` or `openbao`, and
  `KEY_IMPORT_ENABLED=true` for `generate` (the same gate as
  `/admin/card-issuer/generate`; see `import-keys.md`).
- A **dedicated host per network** for the bridge (`api-testnet.<domain>`),
  proxying the host root — including `/.well-known/stellar.toml` — to the
  bridge. The shared `/api/<network>/` path on the UI origin is unsupported:
  home_domain = web_auth_domain = that host.
- `STELLAR_NETWORK=testnet` set **explicitly** and the testnet passphrase.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SEP10_ENABLED` | `false` | Mount `/.well-known/stellar.toml` and `GET`/`POST /auth/sep10` and run the key ring. Off: nothing is validated and the bridge behaves exactly as before |
| `SEP10_WEB_AUTH_ENDPOINT` | — (mandatory) | `https://<host>/auth/sep10`, canonical (lowercase, no default port, no trailing slash). `http` only for `localhost`, `127.0.0.1`, `10.0.2.2`. Host ≤ 59 bytes |
| `SEP10_CHALLENGE_TTL_SECS` | `300` | 60–900. Exactly `maxTime − minTime` of every challenge |
| `SEP10_CHALLENGE_GLOBAL_MAX` | `600` | Challenges per 60 s across all sources, then 503 |
| `SEP10_KEY_ACTIVATION_DELAY_SECS` | `120` | 120–86400. How far ahead `activate` schedules the swap |

Boot refuses when enabled and: the endpoint is missing or malformed;
`PUBLIC_ENDPOINT` is set with a different `host[:port]`;
`SEED_PROTECTION_BACKEND=none`; an SSO provider is named `sep10*`; the network
is not explicitly testnet; or `sep10_signing_key` is missing (migration not
run).

Limits (fixed): 30/60 s per client source (shared `preauth_src`, IPv6 by /64),
10/60 s per G after a verified signature, lockout of `(sep10:G, source)` after 5
bad client signatures over live challenges for 15 minutes, 16 KiB body, 10 s
timeout.

## Roll out

```bash
NETWORK=testnet
BRIDGE=https://api-testnet.example.com
```

1. **Migrate.** `RUN_MODE=migrate` with the new image.
2. **Roll the binary with `SEP10_ENABLED=false`** (the admin routes are always
   mounted; the public ones are not).
3. **Generate** (pending; serves nothing yet):

   ```bash
   curl -sS -X POST "$BRIDGE/admin/sep10/signing-keys/generate" \
     -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' -d '{}'
   # 201 {"version":1,"state":"pending","public_address":"G…","fingerprint":"…"}
   # 409 pending_key_exists while another version is pending
   ```

   Event: `custody.sep10_key_generated {version, fingerprint}`.
4. **Activate** — `confirm_supersede` is `none` for the first key, otherwise
   the active key's fingerprint from the inventory. On a bridge that already
   runs with `SEP10_ENABLED=true` (a rotation, or a roll-out in the other
   order), first wait until the replica has opened the new key, or the call
   answers 409 `sep10_key_not_opened`:

   ```bash
   until curl -sS "$BRIDGE/admin/sep10/signing-keys" -H "Authorization: Bearer $OPERATOR_TOKEN" \
     | jq -e '.key_ring_live != true or (.keys[] | select(.version == 1) | .opened == true)' >/dev/null
   do sleep 5; done        # at most one key-ring poll (30 s); with SEP-10 off there is no ring to wait for
   ```

   ```bash
   curl -sS -X POST "$BRIDGE/admin/sep10/signing-keys/1/activate" \
     -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
     -d "{\"confirm_supersede\":\"none\",\"confirm_phrase\":\"activate sep10-signing $NETWORK\"}"
   # {"version":1,"state":"pending","activate_at":"2026-11-12T10:02:00+00:00"}
   ```

   Event: `custody.sep10_key_activated`. The key takes over at `activate_at`
   (DB clock) on every replica at once. The swap is applied by the key rings,
   which run only with `SEP10_ENABLED=true`: at this point of a first roll-out
   the inventory keeps showing `pending` (with its `activate_at`) until step 5,
   and the first poll after enabling promotes it.
5. **Enable.** Set `SEP10_ENABLED=true` and `SEP10_WEB_AUTH_ENDPOINT`, roll.
6. **Verify:**

   ```bash
   curl -sS "$BRIDGE/.well-known/stellar.toml"
   curl -sS "$BRIDGE/admin/sep10/signing-keys" -H "Authorization: Bearer $OPERATOR_TOKEN" \
     | jq '{enabled, home_domain, registered_card_keys, active: [.keys[] | select(.state=="active") | .version]}'
   curl -sSi "$BRIDGE/auth/sep10?account=GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7" | grep -i access-control
   ```

   `SIGNING_KEY` must equal the activated `public_address`; every response
   (including errors) must carry `Access-Control-Allow-Origin: *`.

## Rotate

Generate a new version, then activate it with the **current** active
fingerprint:

```bash
FP=$(curl -sS "$BRIDGE/admin/sep10/signing-keys" -H "Authorization: Bearer $OPERATOR_TOKEN" \
  | jq -r '.keys[] | select(.state=="active") | .fingerprint')
curl -sS -X POST "$BRIDGE/admin/sep10/signing-keys/generate" -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' -d '{}'
curl -sS -X POST "$BRIDGE/admin/sep10/signing-keys/2/activate" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"confirm_supersede\":\"$FP\",\"confirm_phrase\":\"activate sep10-signing $NETWORK\"}"
```

The delay (≥ two ring polls plus the toml `max-age`) means no client fetches a
new-key toml and an old-key challenge from different replicas. The old key
stays `superseded` and keeps verifying challenges it issued for TTL + 120 s.
One hour after that the key rings scrub its sealed material by themselves
(the row and its public data stay); revoking it earlier scrubs it at once.

`activate` answers **409 `sep10_key_not_opened`** while the replica that
serves the call has not opened the new version yet. Its key ring polls every
30 s, so right after `generate` this is normal: wait and retry. If it
persists, the replicas cannot unseal the new key (the seed protector's
permissions, see the `sep10 ring:` log lines). Do not work around it: once a
key is activated the previous one is `superseded` for good, and a key nobody
can open would leave SEP-10 at 503 until yet another key is generated and
activated.

## Inventory and card keys

`GET /admin/sep10/signing-keys` (`read_keys`) returns the status object:
`enabled`, `home_domain` / `web_auth_endpoint` (`null` when not configured),
`network` (the word the confirm phrases use), `network_passphrase`,
`challenge_ttl_secs`, `registered_card_keys` (active cards with a Stellar
address) and `keys` (newest version first: state, public address,
fingerprint, who generated it and the four instants). It works with
`SEP10_ENABLED=false`.

Two fields say what **the replica that answered** can serve right now:

| Field | `true` | `false` | `null` |
|---|---|---|---|
| `key_ring_live` | Its key ring read the key table within the last 5 minutes | Stale: that replica answers 503 on the public routes (check its database connection) | It runs no key ring (`SEP10_ENABLED=false`) |
| `keys[].opened` | It holds that version decrypted: a pending one can be activated there, the active one is being served | A pending version: `activate` answers 409 there. The active version: that replica answers 503 (check its seed protector) | No key ring, or the version is revoked |

Behind a load balancer each call reaches one replica, so ask several times
(or each replica directly) before concluding that all of them serve.

```bash
curl -sS "$BRIDGE/admin/sep10/signing-keys" -H "Authorization: Bearer $OPERATOR_TOKEN" \
  | jq '{enabled, key_ring_live, keys: [.keys[] | {version, state, opened, activate_at}]}'
```

`GET /admin/accounts/{account_id}/cards` (`read_accounts`) lists an account's
cards, newest first (at most 100), with `active`, `created_at`, `deleted_at`
and `stellar_address` (`null` for a card without a Stellar key) — use it to
see whether a holder's card was registered with its Stellar key.

## From the dashboard

The Keys page's panel **SEP-10 signing key (card sign-in)** drives the same
routes (admin or key-custodian; an auditor sees it read-only):

1. **Generate a signing key…** creates the pending key (step 3 above).
2. Wait until its row no longer says "This bridge instance has not opened it
   yet" (reload; at most 30 s). **Activate…** is disabled until then.
3. **Activate…**: the dialog names the key it supersedes and asks for the
   phrase `activate sep10-signing <network>` (step 4).
4. When the row's badge reads **active**, the line **This instance** must read
   "key ring live; the active key is open: serving SEP-10" (step 6). A stale
   key ring or an active key that instance cannot open is shown as a notice.
5. **Revoke…** on a row asks for `revoke sep10-signing <network> v<version>`
   and says what revoking that particular key does.

The Accounts page lists a holder's cards with their Stellar addresses (the
`GET /admin/accounts/{account_id}/cards` call above). What the page cannot do:
turn SEP-10 on or off, and change the endpoint or the limits; those are
settings of the bridge. Screens, notices and refusals:
[`docs/sep10-api-and-admin-ui.md`](../sep10-api-and-admin-ui.md), section 5.

## Revoke (incident)

```bash
curl -sS -X POST "$BRIDGE/admin/sep10/signing-keys/1/revoke" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"confirm_phrase\":\"revoke sep10-signing $NETWORK v1\"}"
# {"version":1,"state":"revoked"}
```

Refused at once on the replica that served the call, within one poll (30 s) on
the others; the sealed material is scrubbed in the same statement. Revoking the
**active** key leaves SEP-10 answering 503 until another key is generated and
activated — the app then falls back to `SIGN_AUTH`. Revocation does not end
sessions already minted (they are ordinary card sessions: use the usual
account-level revocation).

## Roll back

1. Set `SEP10_ENABLED=false` and roll. The public routes disappear (404); the
   app falls back to `SIGN_AUTH` card login on the same tap.
2. A full binary rollback is safe: migration 040 is additive, the old binary
   ignores the new columns and table, and sessions minted through SEP-10 are
   ordinary house tokens.

Never "un-apply" 040: sqlx records applied versions and checksums.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Boot exits naming `SEP10_*`, `PUBLIC_ENDPOINT`, `STELLAR_NETWORK` or `SEED_PROTECTION_BACKEND` | The boot gate above; the message names the fix |
| Boot exits: `sep10_signing_key is not readable` | Migration 040 not run |
| `503 sep10_unavailable` on every public route | No active key, the active key revoked, the ring stale (DB unreachable > 5 min), or this replica could not decrypt the key (protector) — check `sep10 ring:` log lines and the key states in `GET /admin/sep10/signing-keys` |
| `503` on `GET /auth/sep10` only, intermittently | Global challenge ceiling (`SEP10_CHALLENGE_GLOBAL_MAX`) |
| `401` on POST for a card that works with `SIGN_AUTH` | The card's Stellar key is not registered (re-run the issuance tool, or let the holder's app register it at the next card login: `PUT /card/stellar-key`), the account holds a privileged role (by design, see above), or the challenge expired, was already used, or was issued by a revoked key |
| `409 sep10_key_not_opened` on activate | This replica's key ring has not opened the version yet (wait one poll: `opened` in the inventory turns `true`), or cannot (protector permissions) |
| `409 pending_key_exists` on generate | One pending version at a time: activate or revoke it first |
| `429` on generate, activate or revoke | The key-custody budget: 5 calls per 60 s per operator, shared with the other custody writes (provider credentials `/admin/keys/*`, custodial seeds `/admin/stellar-seeds/*`, the card issuer key `/admin/card-issuer/generate` and card certificates `/admin/cards/{card_id}/certificate`). Wait for the `Retry-After` and repeat; a script that provisions several keys or cards in a row has to pace itself (the demo's `seed.sh` and scenario 05 do) |
| `403` on generate | `KEY_IMPORT_ENABLED` is not `true` on this bridge. `400` there names a missing seed protection backend |
| `429` on POST | The `(G, source)` lockout after 5 bad signatures, or a budget |
| `500` on POST | Redis or Postgres unavailable — fail closed, never a 401 |
| `400 invalid_stellar_binding` on `POST /card` | Partial fields, a non-UUID account, a card id that is not 32 hex, a compressed EC key, or cross-signatures that do not verify for this account/card/EC key |
| `409 stellar_address_in_use` on `POST /card` | The address is on another active card; delete that card first |

Metrics: `auth.token_exchange{provider="sep10"}`, `sep10.challenges{purpose}`,
`sep10.rejections{reason}` (`malformed`, `not_issued`, `expired`, `mac`,
`server_signature`, `bad_master_signature`, `unknown_signer`, `ineligible`,
`privileged`, `replay`). No metric carries an address.

## Local end-to-end test

The bridge's in-process test
`handlers::sep10_auth::tests::a_card_key_signs_in_with_exactly_the_card_session`
runs GET → client signature → POST → tokens → replay with a software key. For a
live run against a local bridge (`cargo run`, Postgres + Redis + OpenBao from
`docker compose up postgres redis openbao openbao-init`):

```bash
cd impala-bridge
export DATABASE_URL=postgresql://postgres:password@localhost:5432/impala
export REDIS_URL=redis://:password@localhost:6379
export JWT_SECRET=change-me-in-production-this-is-only-for-local-dev!!!
export SEED_PROTECTION_BACKEND=openbao BAO_ADDR=http://127.0.0.1:8200 \
       BAO_TOKEN=dev-root-token BAO_TRANSIT_KEY=impala-seeds
export KEY_IMPORT_ENABLED=true STELLAR_NETWORK=testnet TRUSTED_PROXY_HOPS=0
export PUBLIC_ENDPOINT=http://127.0.0.1:8080
export SEP10_ENABLED=true SEP10_WEB_AUTH_ENDPOINT=http://127.0.0.1:8080/auth/sep10
RUN_MODE=migrate cargo run && cargo run
```

(For the Android emulator use `10.0.2.2:8080` in both `PUBLIC_ENDPOINT` and
`SEP10_WEB_AUTH_ENDPOINT`.) Then, with an operator token: generate, activate
with `confirm_supersede: "none"`, wait for `activate_at` (+ up to 30 s for the
ring poll), check the toml, register a 0.3 card with its Stellar fields, and
sign in from the app.

The demo kit does all of this by script, and checks every answer: its stack
runs with SEP-10 on, `seed.sh` generates and activates the key, and the
scenarios issue a card with its Stellar key (05), sign it in from the real
app on an emulator (07), walk the public API and the refusals with curl and
the app's flow classes (12), and sign the same card in at a third-party
SEP-10 server (13). See [`demo/README.md`](../../demo/README.md).

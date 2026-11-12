# SEP-10 on the Impala bridge: API and admin dashboard guide

**Audience:** developers who sign a card (or test a client) in through the bridge's SEP-10 endpoint,
and operators who run it from the admin API or the dashboard.

**Status (2026-11).** SEP-10 (Stellar Web Authentication) is implemented for one kind of key: the
Ed25519 "Stellar key" an Impala card holds (applet 0.3). It is **testnet only** and **off by default**
(`SEP10_ENABLED`). The legacy card login (`SIGN_AUTH`, `POST /auth/card`) is unchanged and always
available.

| If you want | Read |
|---|---|
| the bytes every component must agree on (card, SDK, library, bridge, app) | [`sep10-card-keys.md`](sep10-card-keys.md) |
| to turn SEP-10 on, rotate or revoke its signing key, with the commands | [`runbooks/sep10.md`](runbooks/sep10.md) |
| every route with its schema | [`../impala-bridge/openapi.yaml`](../impala-bridge/openapi.yaml) |
| to see it run end to end, against the bridge and against a third-party server | [`../demo/README.md`](../demo/README.md), scenarios 05, 07, 12 and 13 |
| which cards can hold a Stellar key | [`../impala-card/README.md`](../impala-card/README.md), "Platform dependencies" |

## 1. The surface at a glance

| Route | Who calls it | Auth | Purpose |
|---|---|---|---|
| `GET /.well-known/stellar.toml` | any SEP-10 client | none | Discovery: the signing key, the endpoint, the network |
| `GET /auth/sep10` | any SEP-10 client | none | Issue a challenge for an account |
| `POST /auth/sep10` | any SEP-10 client | the signed challenge | Exchange it for the bridge's tokens |
| `POST /card` | the card holder (app, issuance tool) | bearer, owner | Register a card, optionally with its Stellar key |
| `PUT /card/stellar-key` | the card holder (app, issuance tool) | bearer, owner | Attach the Stellar key to an already registered card |
| `GET /admin/sep10/signing-keys` | operator, dashboard | `ReadKeys` | Status: configuration, key versions, what this instance can serve |
| `POST /admin/sep10/signing-keys/generate` | operator, dashboard | `ManageKeys` | Create a pending signing key |
| `POST /admin/sep10/signing-keys/{version}/activate` | operator, dashboard | `ManageKeys` | Schedule it to take over |
| `POST /admin/sep10/signing-keys/{version}/revoke` | operator, dashboard | `ManageKeys` | Refuse it at once and scrub it |
| `GET /admin/accounts/{account_id}/cards` | operator, dashboard | `ReadAccounts` | An account's cards and their Stellar addresses |

The three public routes exist only while `SEP10_ENABLED=true` (otherwise they are 404: the router
has no such routes). The card and admin routes are always mounted, so cards can be registered with
their keys and a signing key can be prepared before the endpoint is switched on.

## 2. Signing in: the public API

```
 client (phone + card)                                   bridge
   │  GET /.well-known/stellar.toml  ───────────────────►  SIGNING_KEY, WEB_AUTH_ENDPOINT, NETWORK_PASSPHRASE
   │  GET /auth/sep10?account=G…     ───────────────────►  a transaction signed by SIGNING_KEY (the challenge)
   │  check the challenge, then the card signs it (SIGN_SEP10)
   │  POST /auth/sep10 {transaction} ───────────────────►  verify: issued by me, signed by G, G is a registered card
   │  ◄─────────────────────────────  {token, temporal_token, refresh_token, …}
   │  Authorization: Bearer <temporal_token>  on every later request
```

### 2.1 Discovery: `GET /.well-known/stellar.toml`

```
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
SIGNING_KEY = "GD6KTACDWOPP3O5UA7ROUCNLIJKOVMCSL6ZMX5FK7KTMZ5337XBWSWIX"
WEB_AUTH_ENDPOINT = "https://api-testnet.example.com/auth/sep10"
```

Three strict `KEY = "value"` lines, `text/plain`, `Cache-Control: max-age=60`. `SIGNING_KEY` is
always the key that signs challenges right now (it follows a key rotation by itself).
`WEB_AUTH_ENDPOINT` is the operator's `SEP10_WEB_AUTH_ENDPOINT`, and its `host[:port]` is the
bridge's **home domain**. 503 `sep10_unavailable` while no key is in service.

The file is served at the host root, so the bridge needs a host of its own per network. A bridge
published under a path of another origin (the dashboard's `/api/testnet/`) cannot offer SEP-10.

### 2.2 The challenge: `GET /auth/sep10`

| Parameter | | |
|---|---|---|
| `account` | required | A checksum-valid `G…` account id. `M…` (muxed) is refused, and so is the bridge's own signing key |
| `home_domain` | optional | Must equal the bridge's home domain when present |
| `memo` | not supported | Any value is refused with 400 |
| `client_domain` | optional | Accepted and ignored |

Answers: 200; 400 `bad_request` for a parameter; 429 `rate_limited` for the per-source budget;
503 `sep10_unavailable` while no key is in service or the global ceiling is reached (section 2.7).

```json
{ "transaction": "AAAAAgAAAAD…", "network_passphrase": "Test SDF Network ; September 2015" }
```

`Cache-Control: no-store`. The bridge stores nothing per challenge: the nonce inside carries a MAC
that lets the bridge recognise its own challenges later. Any checksum-valid account gets one, whether
or not a card is registered for it, so the route says nothing about who is registered.

`transaction` is a base64 Stellar transaction envelope with exactly this content:

| Field | Value |
|---|---|
| Source account | the bridge's signing key (`SIGNING_KEY`) |
| Sequence number | `0`. No Stellar network accepts a transaction with sequence 0, which is what makes signing it safe |
| Fee | `200` (never charged) |
| Time bounds | `[now, now + SEP10_CHALLENGE_TTL_SECS]`, 300 s by default |
| Memo | none |
| Operation 1 | manage-data, **sourced by the client's account**, name `"<home domain> auth"`, value: a 64-character nonce |
| Operation 2 | manage-data, sourced by the signing key, name `web_auth_domain`, value: the home domain |
| Signatures | exactly one, the signing key's |

`demo/scripts/sep10-challenge.py <base64>` prints these fields as JSON with nothing but the Python
standard library; it is a quick way to look at a challenge from any SEP-10 server.

### 2.3 Before signing, and what is signed

A client must check the challenge before it lets a key sign it. `Sep10Challenge.verify` in the card
SDK (`com.impala.sdk.stellar`) is that check, and the only way to obtain something the card flow will
sign: source account = the `SIGNING_KEY` from stellar.toml, sequence 0, time bounds that hold now, no
memo, manage-data operations only, the first one sourced by the client's own key and named
`"<home domain> auth"`, every other one sourced by the server, `web_auth_domain` equal to the
endpoint's host, and exactly one signature that verifies as the server's.

The card then checks again, on the card: `SIGN_SEP10` takes the transaction itself, parses it, and
signs only a sequence-0, manage-data-only transaction whose first operation is sourced by the card's
own key. The host never supplies a hash. What is signed is the standard Stellar signature payload:

```
signature = Ed25519( SHA-256( SHA-256(network passphrase) ‖ 00 00 00 02 ‖ transaction bytes ) )
```

The client appends it to the envelope as a second decorated signature (hint = the last four bytes of
its public key) and posts the result.

### 2.4 The token: `POST /auth/sep10`

`{"transaction": "<base64>"}` as JSON, or `transaction=<base64>` as
`application/x-www-form-urlencoded`. At most 8192 characters; the whole body at most 16 KiB.

```json
{
  "token": "eyJ…",
  "success": true,
  "message": "SEP-10 authentication successful",
  "refresh_token": "eyJ…",
  "temporal_token": "eyJ…"
}
```

| Field | |
|---|---|
| `token` | SEP-10's field. Byte-identical to `temporal_token` |
| `temporal_token` | The bridge's session token, valid one hour: `Authorization: Bearer …` on every request |
| `refresh_token` | Valid 14 days: `POST /token {"refresh_token": …}` returns a new temporal token and rotates the refresh token |

This is **the same session `POST /auth/card` mints** for that card's account: same role, same
lifetimes, same revocation (an auth-epoch bump of the account ends it; `POST /logout/all` does that
for the holder).

### 2.5 Who gets a token

The bridge decides in this order (before all of it, an instance whose key ring is stale answers
503). Only one of these failures counts toward a lockout.

| # | Check | Failure | Counted |
|---|---|---|---|
| 1 | Per-source request budget | 429 | |
| 2 | The envelope decodes strictly (base64, one v1 transaction, nothing after it) | 400 | |
| 3 | It is a challenge this bridge issued, still inside its time bounds (the nonce's MAC, the names, the server signature) | 401 | no |
| 4 | The `(account, source)` pair is not locked out | 429 | |
| 5 | The client account's own signature over the transaction verifies | 401 | **yes**: 5 failures lock the pair for 15 minutes |
| 6 | Per-account budget (10 per 60 s) | 429 | |
| 7 | An **active card** is registered with this Stellar address | 401 | no |
| 8 | The account's role holds **no privileged capability** | 401 | no |
| 9 | The challenge has not been used before (single-use, by transaction hash) | 401 | no |

Rule 8 is deliberate. This route is public, readable from any web origin, and a card tap is a single
factor without a PIN, so it never hands out reserve, key or oversight authority: an account whose role
is admin (including `ADMIN_ACCOUNT_IDS`), treasurer, key-custodian or auditor is answered with the
same generic 401 as an unknown card, and its card signs in with `POST /auth/card`.

All 401s are identical (`{"error":{"code":"unauthorized",…}}`), so the answer never tells an
outsider which rule failed, and rules 7 and 8 are reached only by someone who holds the key.

### 2.6 Errors and what a client should do

Errors use the bridge's envelope, `{"error": {"code": "…", "message": "…"}}`, not SEP-10's bare
`{"error": "…"}`.

| Status | Code | Meaning | Client |
|---|---|---|---|
| 400 | `bad_request` | Malformed parameter, envelope or body (the POST takes JSON or a form, nothing else) | A bug: report it |
| 401 | `unauthorized` | One of rules 3, 5, 7, 8, 9 | Fall back to the legacy card challenge (the key may not be registered, or the account is privileged) |
| 404 | none (no body) | The bridge does not offer SEP-10 | Fall back to the legacy card challenge |
| 408 | | The request took longer than 10 s | Stop and show it; the holder taps again |
| 413 | | Body over 16 KiB | A bug |
| 429 | `rate_limited` | A budget or the lockout; `Retry-After` in seconds | Stop and show it. **Never** a reason to fall back |
| 500 | `internal_error` | Redis or the database is unavailable. The bridge fails closed: this is never turned into a 401 | Stop and show it |
| 503 | `sep10_unavailable` | No key in service, this instance's key ring is stale, or the global challenge ceiling | Fall back to the legacy card challenge |

`CardSignIn` in impala-lib implements exactly this table (`CardSignIn.fallbackFor`): three reasons
to fall back, in the same tap, and everything else is an error the user sees.

### 2.7 Limits

| Limit | Value |
|---|---|
| Requests per client source (shared with the other pre-authentication routes; IPv6 by /64) | 30 per 60 s |
| Challenges across all sources | `SEP10_CHALLENGE_GLOBAL_MAX` per 60 s (default 600), then 503 |
| Token requests per account, after a verified signature | 10 per 60 s |
| Lockout of an `(account, source)` pair | 5 bad signatures over live challenges, 15 minutes |
| Challenge lifetime | `SEP10_CHALLENGE_TTL_SECS` (default 300; 60 to 900) |
| Body / `transaction` | 16 KiB / 8192 characters |
| Request timeout | 10 s, then 408 |

### 2.8 Browsers

Every response of the three routes, errors included, carries `Access-Control-Allow-Origin: *`,
without credentials, as SEP-10 requires: a web wallet on any origin can run the exchange. That is
safe for the same reason rule 8 exists: the only thing the exchange accepts is a signature by a
registered card's key, and the routes read no cookie and no `Authorization` header.

### 2.9 Where the bridge differs from other SEP-10 servers

| Topic | Bridge |
|---|---|
| The token | The bridge's own session JWT: `sub` is the Impala account id, not the `G…` address. Only this bridge accepts it |
| Who can sign in | Keys registered on an active card. There is no on-ledger signer check: a card key can never sign a ledger transaction, so its account can never change its signers |
| Lifetime | 300 s (SEP-10 recommends 900) |
| Not offered | Muxed accounts, memos, `client_domain` verification |
| Errors | The bridge's error envelope |

In the other direction nothing is special: the card signs a standard SEP-10 challenge, and the same
card signs in at servers nobody here wrote (demo scenario 13 does it at the SDF reference anchor).

### 2.10 Worked example with curl

Against the demo stack (`demo/`), whose bridge names itself `10.0.2.2:$BRIDGE_PORT` (the Android
emulator's name for the host). From the host the same listener is `127.0.0.1`, hence `--connect-to`:

```bash
HOME_DOMAIN=10.0.2.2:8080
c() { curl -sS --connect-to "$HOME_DOMAIN:127.0.0.1:8080" "$@"; }

c "http://$HOME_DOMAIN/.well-known/stellar.toml"
c "http://$HOME_DOMAIN/auth/sep10?account=$CARD_G" | jq -r .transaction > challenge.b64
python3 demo/scripts/sep10-challenge.py "$(cat challenge.b64)" | jq .    # what the card is asked to sign

# returned unsigned, the challenge is refused, and the refusal says nothing more:
c -X POST "http://$HOME_DOMAIN/auth/sep10" -H 'Content-Type: application/json' \
  -d "{\"transaction\":\"$(cat challenge.b64)\"}"
# {"error":{"code":"unauthorized","message":"…"}}
```

Signing needs the card. In code that is three calls (impala-lib, `com.payala.impala`):

```kotlin
val client = Sep10Client(homeDomain, networkPassphrase, HttpSep10Transport())
val signIn = CardSignIn(client) { wireCardId -> fetchLegacyChallenge(wireCardId) }   // the fallback
when (val result = signIn.signIn(session)) {                                         // card in the field
    is CardSignInResult.Sep10 -> useTokens(result.tokenJson)             // POST /auth/sep10 answered
    is CardSignInResult.Legacy -> exchangeAtAuthCard(result.signatureHex) // POST /auth/card, as before
}
```

## 3. Registering a card's Stellar key

A Stellar address becomes a way to sign in only after the bridge has verified two signatures the
card made at personalization, over messages the bridge rebuilds itself:

- the card's P-256 key vouches for the Stellar key (`bindingSig`), and
- the Stellar key proves possession, bound to this account and this card (`proofSig`).

So an address cannot be registered for another account or card, and a registered key is always one
that a personalized Impala card holds. `GET_STELLAR_KEY` on the card returns all three values; the
SDK's `StellarCardKey` and the app's Card Lab show them.

### 3.1 `POST /card`, with the key

Three optional fields, all present or all absent:

```json
{
  "account_id": "00112233-4455-6677-8899-aabbccddeeff",
  "card_id": "ea94fa5b0f6b2abc1626bc50c0bd5e17",
  "ec_pubkey": "042b495a…",
  "stellar_address": "GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF",
  "stellar_binding_sig": "304502202b49…",
  "stellar_proof_sig": "6da881be…"
}
```

| Field | Form |
|---|---|
| `stellar_address` | `G…`, 56 characters, checksum-valid |
| `stellar_binding_sig` | lowercase hex of the DER signature, **trimmed to its own length** (`2 + second byte`), 16 to 144 characters. The card returns it in a zero-padded 72-byte slot; trailing bytes are refused |
| `stellar_proof_sig` | lowercase hex, 128 characters |

| Answer | |
|---|---|
| 200 | Registered. Events `card.registered` and, with the key, `card.stellar_key_registered` |
| 400 `invalid_stellar_binding` | Partial or malformed fields, an account id that is not a UUID or a card id that is not 16 bytes, or signatures that do not verify for this account, card and EC key |
| 403 `forbidden` | `account_id` is not the caller's own account. There is no admin bypass |
| 409 `stellar_address_in_use` | The address is on another active card |
| 429 `rate_limited` | More than 10 card requests per minute for the account |

A request without the three fields behaves exactly as before SEP-10.

One known gap, older than SEP-10: registering a card id that is already registered answers 500
`internal_error`, not a 409. A client that repeats a registration should treat the card as
registered and go on (the issuance tool does, and then sends `PUT /card/stellar-key`, which is safe
to repeat).

### 3.2 `PUT /card/stellar-key`, afterwards

For a card that was registered before it was personalized, which is the normal issuance order: the
issuer certifies a registered card, the card is personalized with that certificate, and only then
do the two signatures exist.

```json
{ "card_id": "…", "stellar_address": "G…", "stellar_binding_sig": "…", "stellar_proof_sig": "…" }
```

| Case | Answer |
|---|---|
| The caller's active card has no Stellar key yet and the signatures verify | 200, stored; event `card.stellar_key_registered` |
| The card already has this address | 200, nothing changes (safe to repeat) |
| The card has another address | 409 `stellar_key_already_set`: a card's key never changes |
| The address is on another active card | 409 `stellar_address_in_use` |
| Signatures do not verify | 400 `invalid_stellar_binding` |
| No active card with this id belongs to the caller | 404 |

Who calls it: the issuance tool, as its last step (and again on every re-run, so a lost call repairs
itself), and the Android app, once, after a card whose key the bridge did not know signed in the
legacy way.

### 3.3 Seeing what is registered

`GET /admin/accounts/{account_id}/cards` (section 4.4), the dashboard's Accounts page (section 5.3),
and the event feed: `card.stellar_key_registered` carries the card id (a card's key never changes,
so the card row answers which address it is).

## 4. The admin API

### 4.1 Who may call what

No new role or capability: the signing key is key custody, the card list is an accounts read.

| Route | Capability | admin | key-custodian | auditor | treasurer |
|---|---|---|---|---|---|
| `GET /admin/sep10/signing-keys` | `ReadKeys` | yes | yes | yes | no |
| `POST …/generate`, `…/activate`, `…/revoke` | `ManageKeys` | yes | yes | no | no |
| `GET /admin/accounts/{account_id}/cards` | `ReadAccounts` | yes | yes | yes | no |

### 4.2 The status object: `GET /admin/sep10/signing-keys`

```json
{
  "enabled": true,
  "home_domain": "api-testnet.example.com",
  "web_auth_endpoint": "https://api-testnet.example.com/auth/sep10",
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "challenge_ttl_secs": 300,
  "registered_card_keys": 4,
  "key_ring_live": true,
  "keys": [
    { "version": 2, "state": "pending", "public_address": "G…", "fingerprint": "…",
      "generated_by": "…", "generated_at": "2026-11-12T10:00:00+00:00",
      "activate_at": null, "superseded_at": null, "revoked_at": null, "opened": true },
    { "version": 1, "state": "active", "public_address": "G…", "fingerprint": "…",
      "generated_by": "…", "generated_at": "2026-11-01T09:00:00+00:00",
      "activate_at": "2026-11-01T09:05:00+00:00", "superseded_at": null, "revoked_at": null, "opened": true }
  ]
}
```

| Field | |
|---|---|
| `enabled` | `SEP10_ENABLED` on the instance that answered. The route works either way |
| `home_domain`, `web_auth_endpoint` | `null` when no valid endpoint is configured |
| `network` | `testnet` or `pubnet`: the word the confirmation phrases use |
| `challenge_ttl_secs` | `maxTime − minTime` of every challenge |
| `registered_card_keys` | Active cards with a Stellar address |
| `key_ring_live` | Whether the answering instance's key ring has read the key table within the last five minutes. `false`: that instance answers 503 on the public routes. `null`: it runs no key ring (SEP-10 off) |
| `keys[]` | Newest version first |
| `keys[].state` | `pending`, `active`, `superseded` or `revoked` |
| `keys[].activate_at` | Set once a pending key has been activated: the instant it takes over |
| `keys[].opened` | Whether the answering instance holds this key open (decrypted once by its key ring). `false` on a pending key: `activate` would be refused there. `false` on the active key: that instance answers 503. On a superseded key it turns `false` once the key's overlap is over. `null`: no key ring, or the key is revoked |

`opened` and `key_ring_live` describe **one instance**, the one that answered. Behind a load
balancer, ask more than once. No field ever carries key material: a public address and a
fingerprint are all there is.

### 4.3 The signing key's life

```
            generate                    activate                   at activate_at
   (none) ───────────► pending ───────────────────► pending ─────────────────────► active
                          │      (activate_at set:   + activate_at                    │ a newer key takes over
                          │       "scheduled")                                        ▼
                          │                                                      superseded  (verifies its own
                          └───────────── revoke at any time ──────────────►        challenges for TTL + 120 s;
                                                                          revoked   material scrubbed 1 h later)
```

**`POST /admin/sep10/signing-keys/generate`** (body `{}`) → 201
`{version, state: "pending", public_address, fingerprint}`. The key is created inside the bridge and
sealed by the seed protector together with the secret that authenticates its challenges. It cannot
be imported and is never returned.

| Refusal | |
|---|---|
| 403 | `KEY_IMPORT_ENABLED` is off on this bridge |
| 400 | No seed protection backend (`SEED_PROTECTION_BACKEND=none`) |
| 409 `pending_key_exists` | One pending key at a time: activate or revoke it first |
| 429 | The key-custody budget: 5 calls per 60 s per operator, shared with the other custody writes (provider credentials, custodial seeds, the card issuer key and card certificates). `Retry-After` says how long to wait |

**`POST /admin/sep10/signing-keys/{version}/activate`**

```json
{ "confirm_supersede": "<fingerprint of the active key, or none>", "confirm_phrase": "activate sep10-signing testnet" }
```

→ 200 `{version, state: "pending", activate_at}`. The key takes over at `activate_at`
(`SEP10_KEY_ACTIVATION_DELAY_SECS` from now, 120 s at least, by the database clock), on every
instance at the same instant, and the key it replaces becomes `superseded`. `confirm_supersede` is a
compare-and-set: if another operator rotated in the meantime, the fingerprint no longer matches.

| Refusal | |
|---|---|
| 404 | No such version |
| 409 | Not pending, already scheduled, or a wrong confirmation (the message names what to send) |
| 409 `sep10_key_not_opened` | The instance that served the call has not opened the key yet. Its key ring reads new keys every 30 s: wait until `opened` is `true`, then retry. If it never becomes `true`, the instances cannot unseal the key (the protector's permissions). The refusal exists because `superseded` is final: a key nobody can open must never replace one that works. An instance with SEP-10 off runs no key ring and cannot make this check (`opened` is `null` there) |
| 429 | The key-custody budget |

**`POST /admin/sep10/signing-keys/{version}/revoke`**

```json
{ "confirm_phrase": "revoke sep10-signing testnet v1" }
```

→ 200 `{version, state: "revoked"}`. Refused at once on the instance that served the call and within
one key-ring poll (30 s) on the others; the sealed material is scrubbed in the same statement.
Revoking the active key leaves SEP-10 at 503 until another key is active; cards then sign in the
legacy way. Revoking never ends sessions already opened: they are ordinary sessions.

Two things happen without a call:

- **Promotion.** The switch at `activate_at` is applied by the key rings, which run only while
  SEP-10 is enabled. With SEP-10 off everywhere a scheduled key stays `pending` and takes over at the
  first poll after SEP-10 is enabled.
- **Scrubbing.** A superseded key loses its sealed material one hour after its grace has passed.

### 4.4 An account's cards: `GET /admin/accounts/{account_id}/cards`

```json
{ "cards": [
  { "card_id": "ea94fa5b…", "active": true, "created_at": "2026-11-12T10:00:00+00:00",
    "deleted_at": null, "stellar_address": "GDLS7C3F…" } ] }
```

Newest first, at most 100, deleted cards included (`active: false`). `stellar_address` is `null`
for a card without a Stellar key. An unknown account answers `{"cards": []}`; an account id longer
than 64 characters answers 400.

### 4.5 What the bridge records

| Where | What |
|---|---|
| Event outbox (`GET /admin/events`, webhooks) | `custody.sep10_key_generated`, `custody.sep10_key_activated`, `custody.sep10_key_revoked` (version and fingerprint, never the address); `card.stellar_key_registered` (the card id) |
| Log | `sep10: card key G… signed in; tokens issued for account_id=…`; `sep10: account_id=… holds a privileged role; SEP-10 sign-in refused`; `sep10 ring: …` for the key ring |
| Metrics | `auth.token_exchange{provider="sep10"}`, `sep10.challenges`, `sep10.rejections{reason}` with `malformed`, `not_issued`, `expired`, `mac`, `server_signature`, `bad_master_signature`, `unknown_signer`, `ineligible`, `privileged`, `replay`. No metric carries an address |

There is no event per sign-in, as for every other login path.

## 5. The admin dashboard

Three pages take part. Each is shown or hidden by the role in the operator's session, and the bridge
enforces the same rule on every request (the dashboard's gating is display only).

| Page | Shows | Needs |
|---|---|---|
| **Keys** → *SEP-10 signing key (card sign-in)* | Status, notices, every key version | `view_keys` (admin, key-custodian, auditor) |
| the same panel's *Generate*, *Activate*, *Revoke* | | `manage_keys` (admin, key-custodian) |
| **Cards** → *Register Card* → *Stellar key (SEP-10)* | Three optional fields | `manage_cards` (device, admin) |
| **Accounts** → an account → *Cards* | The account's cards with their Stellar addresses | `view_accounts_list` (admin, auditor, key-custodian) |

### 5.1 The signing-key panel

**The status block** is the status object in words:

| Line | Reads |
|---|---|
| SEP-10 | `enabled` / `disabled` / `not reported` |
| Network | The network word and its passphrase |
| Home domain, Web-auth endpoint | Or `not configured` |
| Challenge lifetime | For example `300 s (5 min)` |
| Cards with a Stellar key | How many active cards can sign in with SEP-10 |
| In service | The active key: version, full address, full fingerprint |
| This instance | What the bridge instance that answered can do right now: `key ring live; the active key is open: serving SEP-10`, or why not |

**Notices** appear above the table when something needs attention:

| Notice | Meaning | Do |
|---|---|---|
| SEP-10 is off on this bridge | `SEP10_ENABLED` is false | A bridge setting and a restart, not a button. Generate and activate a key first |
| SEP-10 is enabled but no signing key is active | Sign-in answers 503 | Generate and activate a key |
| The key ring of the bridge instance that answered is stale | That instance has not read the key table for five minutes and answers 503 | Check its database connection |
| The bridge instance that answered could not open the active key | It answers 503 | Check its seed protector; its log lines start `sep10 ring:` |
| The web-auth endpoint is not configured | Clients cannot discover SEP-10 | Set `SEP10_WEB_AUTH_ENDPOINT` |
| The bridge reported N active keys | Should never happen; activation is disabled | Investigate before any action |
| The bridge did not report a usable network name | The phrases cannot be built; activate and revoke are unavailable | Update the bridge or the dashboard |
| The bridge did not report whether SEP-10 is enabled; the bridge returned no readable key list | A bridge and dashboard that do not match | Deploy matching versions; no key action is offered meanwhile |

**The table** has one row per key version, newest first: state, full public address, full
fingerprint, who generated it and when, and the three instants.

| Badge | The row says |
|---|---|
| pending | Generated, not in service. If this instance has not opened it yet, the row says so and *Activate* is disabled until it has |
| activation scheduled | Activated; takes over at the time shown, on every instance together |
| activating | Its activation time has passed; instances sign with it, and the list shows it active after the next poll. With SEP-10 off, the row says it goes into service when SEP-10 is enabled |
| active | Signs the challenges and is published in stellar.toml |
| superseded | Replaced; challenges it signed are still accepted for a short overlap |
| revoked | Never accepted again |
| (any other word) | A state this dashboard does not know: shown as reported, no action offered |

**Actions** each open a dialog. *Activate* and *Revoke* also need a typed phrase, which names the
network the bridge reported, never the dashboard's own network selector.

1. **Generate a signing key…** Creates the pending key, after one confirmation. Disabled, with
   the reason, while another pending key exists.
2. **Activate…** on a pending key. The dialog shows the key, and the key it will supersede with
   its fingerprint (sent with the request, so a concurrent rotation is refused). Type
   `activate sep10-signing <network>`. Just after generating, the button is disabled for up to
   30 seconds with "This bridge instance has not opened it yet": reload, then activate.
3. **Revoke…** on any key that is not revoked, styled as destructive. The dialog says what
   revoking this particular key does (the active key: sign-in stops until another is active). Type
   `revoke sep10-signing <network> v<version>`.

A first roll-out on the dashboard is therefore: *Generate*, wait for the row to lose its "not opened
yet" line, *Activate*, wait for the badge to read **active** (the activation delay plus one poll),
then check that *This instance* reads "serving SEP-10".

### 5.2 Registering a card with its Stellar key

**Cards** → *Register Card*. Below the EC key, the group *Stellar key (SEP-10)* takes the three
values of section 3.1, all or none:

- the address is checked in the browser the way the bridge checks it (length, alphabet, version
  byte, checksum);
- a binding signature pasted as the card's zero-padded 72-byte slot is refused with the number of
  characters to keep;
- signatures are sent as lowercase hex;
- the two refusals specific to the group get their own messages (the signatures do not verify for
  this account and card; the address is on another active card).

The bridge registers a card only under the account you are signed in as, and the form says so.
Without the group, the request is byte for byte what it was before SEP-10. A card issued with the
issuance tool needs none of this: the tool registers the key itself.

### 5.3 An account's cards

**Accounts** → open an account → *Cards*: each card's full id, an `active` or `deleted` badge (with
the deletion time), the creation date, and the Stellar address with a **SEP-10** badge when the card
can sign in that way. Under the cards of an account with a privileged role that has such a card,
the list adds: "This account holds a privileged role, so the bridge refuses SEP-10 sign-in for it.
Its cards sign in with the legacy card challenge." A bridge older than the route shows "This bridge
does not list an account's cards".

### 5.4 What the dashboard does not do

- Turn SEP-10 on or off, or change the endpoint, lifetime or limits: bridge settings.
- Attach a Stellar key to a card that is already registered (`PUT /card/stellar-key`): the issuance
  tool and the holder's app do that.
- Show or end sessions: they are ordinary bridge sessions (roles and account deletion end them).
- Show any secret. It never receives one.

## 6. Troubleshooting

| You see | Usually |
|---|---|
| 404 on the three public routes | `SEP10_ENABLED` is off, or the bridge is published under a path instead of a host root |
| 503 `sep10_unavailable` everywhere | No active key yet (after *Activate*: wait for the delay), the active key was revoked, or the answering instance has `key_ring_live: false` / `opened: false` |
| 401 for a card that signs in the legacy way | Its Stellar key is not registered (re-run the issuance tool, or sign in once with the app), or the account holds a privileged role (by design) |
| 409 `sep10_key_not_opened` on *Activate* | Wait one key-ring poll; if it persists, the seed protector |
| 429 on generate / activate / revoke | Five custody writes per minute per operator, counted together with seed, issuer-key and card-certificate calls; wait for `Retry-After` |
| The app says the server's challenge could not be verified | The app's home domain is not the bridge's (`SEP10_WEB_AUTH_ENDPOINT` host and port), or the networks differ. It does not fall back, on purpose |

More, with the commands: [`runbooks/sep10.md`](runbooks/sep10.md).

# SEP-10 with card-held keys — binding contract

> **Status: implemented (2026-11), verified on the simulator and against the
> SDF reference anchor; not yet run on a physical card (§9).** This document
> is the byte-level contract between the JavaCard applet, the card SDK,
> impala-lib, the Android demo and impala-bridge for signing in with a Stellar
> key that lives on the Impala card. It extends [`sep10-authentication.md`](sep10-authentication.md)
> (Part A: bridge SEP-10 for phone and wallet keys, still design-only) with a
> third key kind, the **card**, and implements the public SEP-10 endpoint for
> that kind. Where the two documents disagree about card keys, this one wins.

## 1. What changes, in one page

- The applet (version **0.3**) generates a second, **Ed25519** key on the card
  at `INITIALIZE`. Its public key is a Stellar account id (`G…`). The existing
  P-256 key, `SIGN_AUTH`, the transfer protocol and everything Payala relies on
  are unchanged.
- The card signs **only SEP-10 challenge transactions**. It parses the
  transaction itself and refuses anything that is not a sequence-number-0,
  manage-data-only challenge addressed to its own key (§3.3). It never signs a
  hash supplied by the host, so the key cannot authorize a payment or any
  other ledger transaction. **Never fund a card's Stellar address**: nothing
  can sign a transaction that would spend from it.
- Two static cross-signatures, made on the card at personalization, bind the
  two keys to each other and to the card's account (§3.2). The bridge verifies
  both when the card is registered.
- The bridge serves a standard SEP-10 endpoint (`/.well-known/stellar.toml`,
  `GET`/`POST /auth/sep10`). A valid challenge signed by a registered card's
  Stellar key yields the **same session as `POST /auth/card`**.
- impala-lib picks the mechanism per card: a card that advertises a Stellar
  key signs in with SEP-10; any other card uses `SIGN_AUTH`. The app falls
  back to `SIGN_AUTH` when the server does not offer SEP-10 or does not know
  the card's Stellar key.
- No PIN is required to sign a challenge (parity with `SIGN_AUTH`). §8 plans
  the user-PIN and biometric options.
- A card is registered with the bridge before it is personalized when the
  issuer certifies it, and its cross-signatures exist only afterwards, so the
  bridge also has `PUT /card/stellar-key` to attach a verified Stellar key to
  a card that is already registered (§6).

## 2. Names and constants

| Name | Value |
|---|---|
| Applet version (`GET_VERSION`) | major 0, minor **3** |
| `INS_GET_STELLAR_KEY` | `0x37` |
| `INS_SIGN_SEP10` | `0x38` |
| `PFLAG_STELLAR_KEY` (`GET_PERSONALIZATION` flags) | `0x80` |
| SKEY domain tag | ASCII `IMPALA-SKEY:` (12 bytes) |
| Ed25519 engine id | `0x01` soft (JC 3.0.5), `0x02` native (JC 3.1 EdDSA) |
| `SEP10_MAX_TX_LENGTH` | 640 bytes |
| `SEP10_MAX_OPERATIONS` | 5 |

New status words:

| SW | Name | Meaning |
|---|---|---|
| `0x623C` | `STELLAR_KEY_MISSING` | The card has no Stellar key (legacy build, or the platform lacks the primitives) |
| `0x6240` | `SEP10_MALFORMED` | Not the XDR shape in §3.3 (bad length, padding, type tag, muxed account, memo, trailing bytes) |
| `0x6241` | `SEP10_SEQUENCE_NOT_ZERO` | `seqNum != 0` |
| `0x6242` | `SEP10_NOT_MANAGE_DATA` | An operation is not `MANAGE_DATA`, or the count is 0 or above the maximum |
| `0x6243` | `SEP10_WRONG_ACCOUNT` | The first operation is not sourced by this card's key, a later one is, or the transaction source is this card's key |
| `0x6244` | `SEP10_NOT_AUTH_CHALLENGE` | The first operation's key does not end in `" auth"`, or it has no value |
| `0x6245` | `SEP10_NO_TIME_BOUNDS` | Preconditions are not `PRECOND_TIME`, or `maxTime == 0` |

## 3. Card

### 3.1 Key

- Generated on the card at `INITIALIZE`, never imported, never exported.
  `TERMINATE` clears it together with the P-256 key (the terminated flag is
  committed first, as for the P-256 key: a card torn between the two steps
  still holds the key but refuses every signing command).
- Two interchangeable engines behind one applet-internal API, chosen at build
  time (`-Papplet.ed25519=soft|native|none`). Which card platform each CAP
  loads on, the optional algorithms each engine asks the card for, the memory
  it takes and where JavaCard 3.2 stands are listed in `impala-card/README.md`,
  "Platform dependencies: JavaCard 3.0.5, 3.1 and 3.2":
  - **soft** (default, JavaCard 3.0.5): the scalar multiplication runs in the
    card's ECDH engine on the Weierstrass form of Curve25519
    (`ALG_EC_SVDP_DH_PLAIN_XY`, custom domain parameters); SHA-512 is the
    card's; the conversion to the Edwards encoding and the arithmetic modulo
    the group order are applet code. Signatures are RFC 8032 Ed25519. The
    secret scalar comes from the platform's key generation on that curve and
    is uniform in `[1, L − 1]` (not derived from a seed, not clamped). The
    nonce is hedged: `r = SHA-512(prefix ‖ Z ‖ M) mod L` with 32 fresh random
    bytes `Z` per signature. A verifier cannot tell the difference; signing
    the same challenge twice gives two different valid signatures, which
    removes what the fault attacks on deterministic EdDSA rely on; a failed
    RNG leaves the RFC's deterministic nonce. Before it generates the key, the
    engine runs a known-answer test of the whole public-key path (the RFC
    8032 TEST 1 scalar through the card's ECDH and the applet's conversion
    must give that vector's public key).
  - **native** (JavaCard 3.1 and 3.2): the platform's EdDSA over
    `NamedParameterSpec.ED25519` keys. Platforms offer pure Ed25519 in more
    than one way, so at install the engine tries three requests in order:
    `Signature.SIG_CIPHER_EDDSA` with `MessageDigest.ALG_NULL` (what the 3.2
    API text prescribes), `SIG_CIPHER_EDDSA` with `ALG_SHA_512` (the 3.1 text
    left the digest constant open), and the per-curve cipher
    `SIG_CIPHER_EDDSA_ED25519` (value 15) that 3.2 adds, with `ALG_NULL`. It
    keeps the first one that verifies the RFC 8032 section 7.1 TEST 2 vector
    and, with that vector's private key loaded, signs the same message into a
    signature that verifies (so both directions are proven, not only
    verification). If none does, there is no engine. The CAP is converted for
    JavaCard 3.1, whose API does not have the 3.2 name: the engine passes the
    value, and a card that does not know it answers `NO_SUCH_ALGORITHM`. The
    engine id a card reports is `native` whichever request was kept. The
    card's own key is generated afterwards and never signs a test message.
    Nonces are the platform's (RFC 8032 deterministic), without the hedging of
    the software engine.
  - **none**: no Stellar key; the card behaves as a legacy card.
- A card whose platform lacks the primitives of its engine installs and works
  as a legacy card (`PFLAG_STELLAR_KEY` clear, `0x623C`): the engine cannot be
  created at install, or key generation fails at `INITIALIZE` (the software
  engine checks there that the known answer comes out and that the ECDH path
  reproduces the platform's own public point). The Stellar key is the last
  thing the applet allocates at install, after the secure channel and every
  buffer the legacy functions need, so a card short of memory loses the
  Stellar key and nothing else.
- The software engine does not have the side-channel and fault hardening of a
  platform signature primitive (the final `S = r + k·a` is applet bytecode
  with the scalar in transient memory). The key is a sign-in credential; it
  must never hold value.

### 3.2 Cross-signatures (made once, at `PERSONALIZE` part C)

```
SKEY_A = "IMPALA-SKEY:" ‖ 0x01 ‖ accountId(16) ‖ cardId(16) ‖ ed25519Pub(32)        77 bytes
SKEY_B = "IMPALA-SKEY:" ‖ 0x02 ‖ accountId(16) ‖ cardId(16) ‖ ecPub(65, 04‖X‖Y)    110 bytes

bindingSig = ECDSA-P256-SHA256(card EC key, SKEY_A)    DER, in a zero-padded 72-byte slot
proofSig   = Ed25519(card Stellar key, SKEY_B)         64 bytes, pure Ed25519 over the message
```

`bindingSig` says "the card key vouches for this Stellar key"; `proofSig` is
proof of possession of the Stellar key, bound to the account and card, so a
Stellar address cannot be registered under another account or card.

The card writes both to their slots before the personalization transaction
and reports them only once `personalized` is set (they read as zeros until
then), so the atomic commit of part C does not grow. `accountId` is the one
part A staged, which is the one the commit makes the card's. A signing failure
fails part C (`0x6683`). The Stellar key signs exactly two kinds of message:
this 110-byte one, once, and the 32-byte hash of a validated challenge.

### 3.3 Commands

**`GET_STELLAR_KEY` (`00 37 00 00`)** — CLA `0x00` only, every state.
Response (169 bytes): `engine(1) ‖ ed25519Pub(32) ‖ bindingSig(72) ‖ proofSig(64)`.
Both signature fields are all-zero until the card is personalized. `0x623C`
when the card has no Stellar key.

**`SIGN_SEP10` (`00 38 P1 00`)** — CLA `0x00` only. Not terminated,
provisioning gate, personalized, Stellar key present.

| P1 | Data | Effect |
|---|---|---|
| `0x00` BEGIN | `networkId(32) ‖ tx bytes` | Clears the stage, stores the network id and the first bytes |
| `0x01` CONTINUE | `tx bytes` | Appends |
| `0x02` FINISH | `tx bytes` (the card accepts none; the SDK always sends at least one) | Appends, validates, signs. Response: `signature(64)` |

`0x6985` for CONTINUE/FINISH without BEGIN; `0x6700` when BEGIN is shorter than
33 bytes or the transaction exceeds 640 bytes; `0x6A86` for another P1 or a
non-zero P2. A staged challenge survives exactly one thing, the next part
being accepted: the card takes the stage out of service at the start of every
command and only a BEGIN or CONTINUE that succeeds puts it back. Any other
command, any refusal (including one made before the handler runs: a wrong
CLA, a short data field, a guard) and any error leave nothing staged, and a
FINISH consumes it. The stage is `CLEAR_ON_DESELECT`.

The bytes are a Stellar `Transaction` (XDR, the `tx` member of a v1 envelope,
without envelope tag and without signatures). The card accepts exactly:

```
sourceAccount   00000000 ‖ key(32)                      key != card key           else 6240 / 6243
fee             uint32                                  any
seqNum          int64                                   == 0                      else 6241
cond            00000001 ‖ minTime(8) ‖ maxTime(8)      maxTime != 0              else 6245
memo            00000000                                MEMO_NONE                 else 6240
operations      count(4)                                1..5                      else 6242
  each:  00000001 ‖ 00000000 ‖ source(32)               source account present, ed25519
         0000000A                                       MANAGE_DATA               else 6242
         nameLen(4) ‖ name ‖ zero pad to 4              1..64
         00000000  |  00000001 ‖ valLen(4) ‖ value ‖ zero pad to 4   0..64
  op[0]: source == card key (6243); name ends with " auth", length >= 6, value present and non-empty (6244)
  op[i>0]: source != card key (6243)
ext             00000000
(end of data)                                           no trailing bytes         else 6240
```

It then computes `hash = SHA-256(networkId ‖ 00000002 ‖ tx bytes)` and returns
the Ed25519 signature of the 32-byte hash, which is a Stellar signature for
that transaction on that network. Because `seqNum == 0`, no network accepts
the transaction.

## 4. Card SDK (`impala-card/sdk`, commonMain)

- `Constants`, `ApduNames` (`GET_STELLAR_KEY` read-only; `SIGN_SEP10` refused in
  read-only sessions), `ImpalaChallengeException` for `0x6240`–`0x6245`,
  `CardError.ChallengeRefused(sw)` (message key `card_error_challenge_refused`).
- `ImpalaSDK.getStellarKey(): StellarCardKey?` (`null` on `0x623C` / `0x6D00`),
  `ImpalaSDK.signSep10(networkId, tx): ByteArray` (BEGIN carries the network id
  and up to 223 transaction bytes, then parts of up to 255; the last byte is
  always left for FINISH, so no part is a command without a data field; a
  transaction above 640 bytes is refused before anything is sent).
- `models.StellarCardKey`: `engine`, `engineName`, `publicKey`, `address`
  (`G…`), `bindingSignature` (trimmed DER) and `proofSignature`, both `null`
  until the card is personalized, `isBound`, and the two message builders
  `bindingMessage(accountId, cardId, stellarPublicKey)` /
  `proofMessage(accountId, cardId, ecPublicKey)`.
- `CardPersonalization.stellarKey` from flag `0x80`, `CardIdentity.hasStellarKey`.
  `CardIdentity.read` sends the same four commands as before.
- Package `com.impala.sdk.stellar` (no platform crypto; SHA-256 and base64 from
  okio):

```kotlin
object StrKey {                       // G… = base32(0x30 ‖ key32 ‖ crc16-xmodem LE), 56 chars
    fun encodeAccountId(publicKey: ByteArray): String
    fun decodeAccountId(address: String): ByteArray        // IllegalArgumentException when invalid
    fun isValidAccountId(address: String): Boolean
}
fun interface Ed25519Verifier { fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean }

class Sep10Expectation(
    val serverSigningKey: ByteArray,          // 32 bytes, from stellar.toml SIGNING_KEY
    val networkPassphrase: String,
    val homeDomain: String,                   // op[0] key must be "<homeDomain> auth"
    val webAuthDomain: String,                // a web_auth_domain op, when present, must carry this value
    val clientKey: ByteArray,                 // 32 bytes: the card's Stellar key
    val minTimeGraceSeconds: Long = 300,
    val maxLifetimeSeconds: Long = 900
)
class Sep10Challenge {                        // only obtainable from verify()
    val transactionBytes: ByteArray           // the exact Transaction slice of the envelope
    val networkId: ByteArray                  // SHA-256(passphrase)
    val hash: ByteArray                       // SHA-256(networkId ‖ 00000002 ‖ transactionBytes)
    val minTime: Long; val maxTime: Long
    fun signedEnvelope(clientSignature: ByteArray): String   // base64, client DecoratedSignature appended (hint = key[28..32])
    companion object {
        fun verify(envelopeBase64: String, expect: Sep10Expectation, nowEpochSeconds: Long, verifier: Ed25519Verifier): Sep10Challenge
    }
}
class Sep10Exception(val reason: Reason, message: String) : Exception(message)
```

`Sep10Challenge.verify` is the SEP-10 client check: v1 envelope, exact end of
data, source = server key, sequence 0, time bounds (`minTime - grace <= now <=
maxTime`, lifetime `<= maxLifetimeSeconds`), no memo, every operation
manage-data, op[0] sourced by the client key with key `"<homeDomain> auth"` and
a 64-byte value, every other operation sourced by the server key, a
`web_auth_domain` operation equal to the expected domain when present, and
**exactly one** signature, which verifies as the server key's over the hash.

- `flows/Sep10Flow.sign(sdk, cardKey, challenge, verifier): String` — sends the
  bytes to the card, verifies the returned signature under the card's key and
  returns the signed envelope. A challenge above 640 bytes is refused before
  any command; a signature that does not verify under `cardKey` never leaves
  the flow.

## 5. impala-lib (`com.payala.impala`)

- `stellar.Ed25519` (an `Ed25519Verifier` in `java.math.BigInteger`, RFC 8032
  verification with canonical-encoding checks; verification only, so it runs
  on API 24), `stellar.StellarToml` (strict `KEY = "value"` lines),
  `stellar.Sep10Transport` + `HttpSep10Transport`, `stellar.Sep10Client`
  (`stellar.toml` → challenge → `Sep10Challenge.verify` → submit).
- `card.CardAuthenticator`: `mechanism(session)` returns
  `CardAuthMechanism.SEP10` when the card advertises a Stellar key, else
  `LEGACY`; `stellarKey(session)`; `signSep10(session, cardKey, challenge)`;
  `signChallenge` (legacy) unchanged.
- `card.CardSignIn(sep10Client?, legacyChallenge)` is the compatibility layer:
  `signIn(session)` returns `CardSignInResult.Sep10(identity, stellarAddress,
  tokenJson)` when SEP-10 ran to the end, or `CardSignInResult.Legacy(identity,
  signatureHex, fallback)` with the legacy signature to exchange at
  `POST /auth/card`. `CardSignIn.fallbackFor(failure)` is the whole fallback
  rule (§7).
- `card.CardStellarKeys.bindingVerifies` / `proofVerifies`: the two
  cross-signature checks, locally.
- `card.CardInspector` reads `GET_STELLAR_KEY` for a card that advertises a
  key (a card without one is not asked) and reports the address, the engine
  and whether both cross-signatures verify.

## 6. Bridge (`impala-bridge`), card key kind

The public surface, challenge shape, verifier layers, signing-key custody and
limits follow `sep10-authentication.md` §4, §7 (layers 1–3), §8 and §9. The
differences for this phase:

| Topic | This phase |
|---|---|
| Identity source | The active `card` row whose `stellar_address` equals the signing key. No `stellar_login_key` tables, no enrollment routes, no link challenges |
| Session | Exactly what `POST /auth/card` mints for that card's account (`auth::issuance_role` → `jwt::encode_token_pair`), returned as `{token, success, message, temporal_token, refresh_token}` with `token == temporal_token`. No restricted audience in this phase |
| Privileged accounts | Refused. When the role the session would carry holds any capability (`auth::role_is_privileged`: admin, which includes `ADMIN_ACCOUNT_IDS`, treasurer, key-custodian, auditor) the answer is the generic 401, after the signature check, not counted, with the challenge not consumed. This keeps the rule of `sep10-authentication.md` D2 for the one thing it protected here: a public, wildcard-CORS, single-factor route never hands out reserve, key or oversight authority. Such a card signs in with `POST /auth/card`, which the client reaches through its `NOT_REGISTERED` fallback (§7) |
| Audit trail | `card.stellar_key_registered {card_id}` in the event outbox whenever a card gains its Stellar key: with `card.registered` at `POST /card`, alone at `PUT /card/stellar-key`, in the same transaction as the write |
| Ledger rule | None. A card key can never sign a ledger transaction, so an account at that address can never change its signers |
| Lockout / limits | `preauth_src` per source; lockout id `sep10:{G}` counted only for a failed master signature over a live issued challenge; scope `sep10` per G after a verified signature |
| Unknown or deleted card | Generic 401, not counted. The lookup compares as `$1::bpchar` so that it uses the partial unique index (a `text` parameter against the `CHAR(56)` column would scan the table) |
| Networks | Testnet only in this phase: `SEP10_ENABLED=true` refuses to boot unless `STELLAR_NETWORK=testnet` is set explicitly. Lifting the gate is a deliberate later step (§9) |

**Migration `040_sep10_card_keys.sql`** (additive, run before the binary):
the `sep10_signing_key` table of `sep10-authentication.md` §6.1, plus

```sql
ALTER TABLE card ADD COLUMN IF NOT EXISTS stellar_address CHAR(56)
    CHECK (stellar_address IS NULL OR stellar_address ~ '^G[A-Z2-7]{55}$');
ALTER TABLE card ADD COLUMN IF NOT EXISTS stellar_binding_sig VARCHAR(144);
ALTER TABLE card ADD COLUMN IF NOT EXISTS stellar_proof_sig CHAR(128);
CREATE UNIQUE INDEX IF NOT EXISTS uq_card_active_stellar_address
    ON card(stellar_address) WHERE is_delete = FALSE AND stellar_address IS NOT NULL;
```

**`POST /card`** gains three optional fields, all present or all absent:

| Field | Form |
|---|---|
| `stellar_address` | `G…`, 56 characters, checksum-valid |
| `stellar_binding_sig` | lowercase hex of the trimmed DER `bindingSig` (16–144 hex characters) |
| `stellar_proof_sig` | lowercase hex of `proofSig` (128 hex characters) |

The bridge rebuilds `SKEY_A` and `SKEY_B` from the request's `account_id` (as
16 RFC-4122 bytes), `card_id` (16 bytes), `ec_pubkey` and the decoded address,
and verifies `bindingSig` under `ec_pubkey` and `proofSig` under the Stellar
key. A failure is 400 `invalid_stellar_binding`; an address already active on
another card is 409 `stellar_address_in_use`. Requests without the fields
behave exactly as before.

**`PUT /card/stellar-key`** `{card_id, stellar_address, stellar_binding_sig,
stellar_proof_sig}` (the holder's own token) attaches a Stellar key to a card
that is already registered. It exists because of the issuance order: the
issuer certifies a registered card, the card is personalized with that
certificate, and only then do the cross-signatures exist. The bridge verifies
both over messages rebuilt from the caller's account, the card id and the
`ec_pubkey` stored on the row; nothing but the address and the signatures is
taken from the request.

| Case | Answer |
|---|---|
| The caller's active card, no Stellar key yet, signatures verify | 200, key stored (one guarded `UPDATE … AND stellar_address IS NULL`) |
| The card already has this address | 200, nothing changes (a repeat is safe) |
| The card already has another address | 409 `stellar_key_already_set`: a card's key never changes |
| The address is active on another card | 409 `stellar_address_in_use` |
| Signatures do not verify, or a field is malformed | 400 `invalid_stellar_binding` |
| No active card with this id belongs to the caller | 404 |

The issuance tool (`impala-card/tools/issue`) calls it as its last step, also
on a re-run of an already issued card, so a lost call is repaired by running
the tool again.

**Routes** (mounted only when `SEP10_ENABLED=true`; own sub-router with
wildcard CORS, 16 KiB body limit and 10 s timeout):

- `GET /.well-known/stellar.toml` → `NETWORK_PASSPHRASE`, `SIGNING_KEY`, `WEB_AUTH_ENDPOINT`.
- `GET /auth/sep10?account=G…[&home_domain=…]` → `{"transaction": "<base64>", "network_passphrase": "…"}`.
  Sequence 0, fee 200, `PRECOND_TIME [now, now + TTL]`, no memo, two
  operations: `"<home_domain> auth"` sourced by `G` with the 64-character
  MAC-bound nonce, and `web_auth_domain` sourced by the server key; one
  signature, the server's.
- `POST /auth/sep10` `{"transaction": "<base64>"}` (JSON or form) → tokens.

### 6.1 Admin API (used by the admin dashboard)

Always mounted (the key must exist before SEP-10 is enabled). Capabilities are
the existing ones; the role matrix does not change. The guide for people who
call these routes or use the dashboard built on them, with every field,
refusal and screen, is [`sep10-api-and-admin-ui.md`](sep10-api-and-admin-ui.md);
this section is the contract.

| Route | Extractor | Body → Response |
|---|---|---|
| `GET /admin/sep10/signing-keys` | `Privileged<ReadKeys>` | → the status object below |
| `POST /admin/sep10/signing-keys/generate` | `Privileged<ManageKeys>` | `{}` → 201 `{version, state: "pending", public_address, fingerprint}`; 409 `pending_key_exists` |
| `POST /admin/sep10/signing-keys/{version}/activate` | `Privileged<ManageKeys>` | `{confirm_supersede: "<active fingerprint>" \| "none", confirm_phrase: "activate sep10-signing {network}"}` → `{version, state, activate_at}` |
| `POST /admin/sep10/signing-keys/{version}/revoke` | `Privileged<ManageKeys>` | `{confirm_phrase: "revoke sep10-signing {network} v{version}"}` → `{version, state: "revoked"}` |
| `GET /admin/accounts/{account_id}/cards` | `Privileged<ReadAccounts>` | → `{"cards": [card…]}`, newest first, at most 100 |

```json
{
  "enabled": true,
  "home_domain": "api-testnet.example.org",
  "web_auth_endpoint": "https://api-testnet.example.org/auth/sep10",
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "challenge_ttl_secs": 300,
  "registered_card_keys": 3,
  "key_ring_live": true,
  "keys": [
    {"version": 2, "state": "pending", "public_address": "G…", "fingerprint": "…",
     "generated_by": "…", "generated_at": "2026-11-12T10:00:00Z",
     "activate_at": null, "superseded_at": null, "revoked_at": null, "opened": true}
  ]
}
```

`key_ring_live` and `keys[].opened` describe the **instance that answered**,
not the deployment. `key_ring_live` is `true` while that instance's key ring
has read the key table within the last five minutes (`false`: it answers 503
on the public routes), and `null` when it runs no key ring (SEP-10 off).
`opened` is `true` when that ring holds the version open: `false` on a
pending version means `activate` would be refused there, `false` on the
active version means that instance answers 503; `null` without a key ring and
for a revoked version. Both are append-only additions for operators and the
dashboard; neither carries key material.

Three rules of the key lifecycle that the routes enforce or the key ring
applies:

- **Activation is refused until the key can be served.** On a replica that
  runs a key ring, `activate` answers 409 `sep10_key_not_opened` until that
  ring has opened the version (it polls every 30 s). The key it supersedes
  cannot come back, so a key the replicas cannot unseal must never be
  scheduled. A replica with `SEP10_ENABLED=false` runs no ring and does not
  refuse.
- **The swap is applied by the key rings.** With SEP-10 off on every replica,
  a scheduled version stays `pending` past `activate_at` and is promoted at
  the first poll of the first replica that enables SEP-10.
- **Old material is scrubbed.** A revoke scrubs the sealed material in the
  same statement. A superseded version loses it one hour after its grace
  (TTL + 120 s) has passed; the row and its public data stay.

`home_domain` and `web_auth_endpoint` are `null` when the endpoint is not
configured; `network` is the same word the confirm phrases use;
`registered_card_keys` counts active cards with a Stellar address; `keys` is
newest version first. A card object is `{"card_id", "active", "created_at",
"deleted_at", "stellar_address"}` with `stellar_address` `null` for a card
without a Stellar key. No response carries key material beyond the public
address and the fingerprint.

## 7. Android demo

- `BuildConfig.SEP10_HOME_DOMAIN` per flavor: `TESTNET_SEP10_HOME_DOMAIN` /
  `LIVE_SEP10_HOME_DOMAIN` in `local.properties`, defaulting to the host and
  port of the bridge base URL, so SEP-10 is what a Stellar card uses whenever
  the bridge offers it. Setting the property to an empty value turns SEP-10
  off for that build. `http` is used only for `localhost`, `127.0.0.1` and
  `10.0.2.2`. The home domain must equal the authority of the bridge's
  `SEP10_WEB_AUTH_ENDPOINT`.
- Card sign-in (`CardSignIn`, called from `LoginViewModel.signInWithCardTap`):
  when the tapped card advertises a Stellar key and the build has a home
  domain, the app runs the whole SEP-10 exchange with the card in the field.
  The fallback to `SIGN_AUTH`, in the same tap, has exactly three cases:

  | Case | `Sep10Fallback` |
  |---|---|
  | The build has no home domain | `NOT_CONFIGURED` |
  | `stellar.toml` is missing (404) or lacks `WEB_AUTH_ENDPOINT` / `SIGNING_KEY`, or the server answers 404 or 503 | `NOT_OFFERED` |
  | `POST /auth/sep10` answers 401 (the card's Stellar key is not registered, or the account holds a privileged role, which SEP-10 never serves) | `NOT_REGISTERED` |

  Everything else stops the login and is shown: a 429 as the lockout it is, a
  transport failure, a challenge that fails the client checks (wrong signing
  key, wrong network, wrong domain, expired) and a challenge the card itself
  refuses. A failed check is never turned into a quiet downgrade. The stored
  auth provider stays `card`.
- Card registration reads the Stellar key in the same tap and sends the three
  fields when the card has them and both signatures verify locally.
- After a `NOT_REGISTERED` fallback, when the legacy login succeeds, the app
  registers the key the tap read (`PUT /card/stellar-key`, under the session
  the card just opened, before the login completes; at most 4 s). The card's
  next login then uses SEP-10. A failure of this step is logged and does not
  affect the login.
- The Card Lab shows the Stellar address, the engine and the two
  cross-signature checks.
- End to end. The demo kit (`demo/`) runs the bridge with SEP-10 on and a home
  domain the emulator can reach (`10.0.2.2:<port>`), and its scenarios drive
  this section for real: the tnet app on an emulator signs in with a card
  whose Stellar key the bridge issued and registered (scenario 07, asserted on
  the app's Activity Log and on the bridge's log), the same flow classes run
  on the JVM against the bridge with both engines, a card without a Stellar
  key and an operator's card (scenario 12, `CardSep10E2ETest`), and against
  third-party SEP-10 servers (scenario 13, `CardSep10ThirdPartyE2ETest`).
  The lanes are `:app:e2eTnetDebug -Pe2e.tests=<class>`; see
  `impala-android-demo/app/src/e2e/README.md`.

## 8. Planned: user PIN and biometrics for SEP-10 signing

Not built in this phase; the protocol leaves room for all three.

1. **Card-enforced user PIN.** A personalization flag (`FLAG_INSTALL_SEP10_PIN`,
   install TLV) makes `SIGN_SEP10` FINISH answer `0x6982` unless the user PIN
   was verified in the same session (`VERIFY_PIN`, P2 `0x82`); the retry
   counter and block rules are the existing ones. `GET_PERSONALIZATION` gains a
   flag so impala-lib asks for the PIN before the tap. The bridge learns that a
   PIN was used from a second certified statement, not from the client: the
   card adds a `card_auth_method` manage-data operation check, or the session
   is minted with an `amr` value only when the card's registration records the
   PIN policy. Steps: applet flag and gate; SDK `signSep10(pin = …)`;
   impala-lib prompt; bridge `amr`; tests for wrong PIN, blocked PIN and
   PIN-less cards.
2. **Phone-side biometric gate.** `BiometricPrompt` (class 3) before the app
   arms the tap sheet for sign-in. It protects against someone else using the
   holder's phone with the holder's card; it is an app policy, not a card or
   bridge guarantee. Steps: setting in the app, prompt before `arm`, no change
   to card or bridge.
3. **Second factor from the phone's secure hardware.** The device-key design of
   `sep10-authentication.md` §10 (Android Keystore Ed25519, biometric-bound)
   becomes a step-up: the bridge issues one challenge with two client
   operations and requires both the card's and the device key's signatures.
   Steps: finish Part A phases 1–3, add a two-signer challenge purpose, add a
   biometric-capable card (`javacardx.biometry`) as an alternative where the
   match happens on the card.

## 9. Verification, and what has not been verified

What the tests establish (all without hardware):

| Claim | Evidence |
|---|---|
| The software engine produces RFC 8032 Ed25519 | `Ed25519SoftTest`: the RFC's section 7.1 vectors byte for byte (hedging off), JDK verification of card-generated and injected keys, big-number routines against `BigInteger` |
| The native engine selects pure Ed25519 or nothing | `Ed25519NativeTest` and `CardPlatformTest` over the simulated platforms of `:jcardsim-jc31`: digest constant `ALG_NULL` only, `ALG_SHA_512` only, the JavaCard 3.2 per-curve cipher only, both ciphers, not pure, pure verification with non-pure signing, no private-key import, none |
| The software engine exists only where every primitive it needs does | `CardPlatformTest`: simulated JavaCard 3.0.5 cards without `ALG_EC_SVDP_DH_PLAIN_XY`, without SHA-512, without AES-256 key objects, refusing custom curve parameters, computing on them wrongly but consistently (only the known-answer test catches that one), or short of transient memory |
| A card is a CAP on hardware, and the outcome is the documented one for each pair | `CardHardwareInteropTest`: the real applet, each CAP variant on each simulated card model from JavaCard 3.0.5 to 3.2 (Stellar key with the expected engine, or a legacy card on which `SIGN_AUTH` still works), a CAP refused by hardware of an earlier level, and the transient memory each variant takes |
| A staged challenge does not outlive a refused or unrelated command | `StellarKeyInteropTest` (another command, an unknown instruction, the secured CLA inside an open secure channel) |
| A privileged account gets no session from SEP-10 | bridge `sep10_auth` tests (every role with a capability: 401, nothing minted, nothing counted, challenge not consumed) and the order tripwire |
| The card signs a SEP-10 challenge for its key and nothing else | `Sep10ValidatorTest` (every rule's status word, every truncation, every single-bit change and 20 000 random mutations against an independent parser), `StellarKeyInteropTest` (the applet under jcardsim, both engines: staging, limits, gates, reset, termination) |
| The cross-signatures bind keys, account and card | `StellarKeyInteropTest`, bridge `sep10::binding` tests, the shared vectors below |
| Card, SDK and bridge agree on the bytes | Shared vectors (`scripts/check-shared-vectors.sh`): a challenge built by the bridge's own code is verified by the SDK codec and signed by the applet (`BridgeVectorTest`); that signed envelope and the applet's registration signatures pass the bridge's verifier (`sep10::card_vectors`) |
| It is SEP-10 as others implement it | `CardSep10LiveTest` (opt-in, `IMPALA_SEP10_LIVE=1`): the applet under jcardsim, each engine, signs in at the SDF reference anchor `testanchor.stellar.org` and receives its token. Demo scenario 13 does the same with the card the bridge issued, and shows the token opening a protected SEP-24 route there (403 without it, 200 with it) |
| The bridge endpoint and the Android client work together on a live stack | Demo scenarios, against the bridge in a container with Postgres, Redis and OpenBao (run 2026-11-12, all passing): 05 (the issuance tool registers the key through `PUT /card/stellar-key`; one `card.stellar_key_registered`, repeat-safe), 07 (the tnet app on an API 34 emulator signs in through SEP-10; the bridge logs the sign-in), 12 (discovery, challenge shape read by an independent XDR reader, refusals, CORS, both engines, single use, a forged signature, a legacy card, a privileged account refused and falling back, the events and the admin API), `seed.sh` (generate, wait for `opened`, activate, promotion at `activate_at`) |
| Legacy cards and servers keep working | `CardSignInTest`, `CardSep10LoginTest` (each fallback case, and each case that must not fall back), the unchanged `SIGN_AUTH` tests |
| All three CAP variants convert and pass the off-card verifier | `./gradlew :applet:buildJavacard [-Papplet.ed25519=native|none]`, in CI |

Not verified, and to be done before any real use:

1. **No physical card has run this code.** Unknown until measured: whether a
   given JavaCard 3.0.5 product accepts the custom curve parameters and offers
   `ALG_EC_SVDP_DH_PLAIN_XY` and SHA-512 (if not, the card installs as a
   legacy card, by design), how long a software signature takes (estimated at
   seconds), whether the reader-side timeout and the card's waiting-time
   extension cover it, and how much transient memory is left (the feature uses
   about 1.2 KB: a 672-byte challenge stage and a 481-byte work area).
2. **The native engine has only run on simulated platforms**, JavaCard 3.1
   and 3.2 alike. The card models of the simulator describe what a platform
   may do; they are not products. The self-test at install is what makes a
   mismatch harmless (a legacy card), but it has not met a real 3.1 or 3.2
   card, and the reading of the 3.2 per-curve cipher (`ALG_NULL`, `PAD_NULL`)
   is the API text's, not a card's.
3. **The live runs so far are the demo's.** There the card is the applet on
   jcardsim behind a TCP socket and the phone is an emulator, on one host,
   with one bridge replica. Not exercised: a second replica (the activation
   fence, a revoke seen by the other replica's poll), a signing-key rotation
   under load, and NFC timing. The bridge's opt-in database lane
   (`RUN_DB_TESTS=1 cargo test --test db`) holds the SQL of migration 040 and
   of `PUT /card/stellar-key` and was not run as such; the demo executed the
   same migration and statements against a real Postgres.
4. **Testnet only.** The bridge refuses to enable SEP-10 on pubnet in this
   phase. Lift that gate only after items 1 to 3 and a security review of the
   software engine on the chosen card product.

Known limits, accepted for this phase:

- **The global challenge ceiling is a lever.** `GET /auth/sep10` stops with
  503 once `SEP10_CHALLENGE_GLOBAL_MAX` (default 600) challenges were issued
  in a minute, and each source may ask for 30, so about twenty sources (one
  IPv6 /56) can hold SEP-10 sign-in down. Cards then sign in with the legacy
  challenge (a 503 is the "not offered" fallback), so card login as a whole
  stays up. Raise the ceiling for a larger deployment; it bounds work, not
  state (a challenge stores nothing).
- **Replay protection assumes replica clocks within 120 s.** The single-use
  claim lives until `maxTime + 120 s` by the claiming replica's clock. A
  replica that lags further behind would still accept the signed challenge
  after the claim expired. Keep NTP healthy; the bound is
  `SEP10_CLAIM_MARGIN_SECS`.
- **Deleting a card does not end sessions it already opened** (the same as
  for the legacy card login): temporal tokens run out within the hour, a
  refresh token lives until the account's auth epoch is bumped. For a lost
  card, delete the card and end the account's sessions (`POST /logout/all`
  by the holder, or a role change or account deletion by an admin).
- **The native engine's nonces are not hedged**, and neither engine has been
  evaluated against side channels or fault injection on a real card.


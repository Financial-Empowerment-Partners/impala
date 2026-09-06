# Impala APDU Command Reference

Applet 0.2 / transfer protocol v1 (applet 0.1 = protocol v0, retired).

Package AID: `0102030405060708`, applet instance AID `01020304050607080102`
(defaults in `applet/build.xml`; live builds override both via
`-Papplet.aid` / `-Papplet.aid.app`). Commands are ISO 7816-4 APDUs.
`0x9000` is success.

This document is derived from the dispatch logic in
`impala-card/applet/src/jvmMain/java/com/impala/applet/ImpalaApplet.java`
(`process()`) and `Constants.java` / SDK `Constants.kt`. When in doubt, the
applet source is authoritative. `ApduDocTest` and `ApduDocDriftTest`
(`sdk/src/jvmTest`) pin this table, the dispatch switch, both `Constants`
files and the status words the applet throws to each other.

<!-- claim-count: apdu-app-ins=20 apdu-scp03-ins=6 apdu-undispatched=5 -->

## Command classes (CLA)

The applet dispatches on CLA before INS:

- **`CLA=0x00`** — all application commands (the table below).
- **`CLA=0x80`** — GlobalPlatform SCP03 channel setup ONLY:
  `INITIALIZE UPDATE` (0x50) and `EXTERNAL AUTHENTICATE` (0x82). Every other
  INS at CLA 0x80 answers `0x6D00`.
- **`CLA=0x84`** — SCP03-secured commands: the C-MAC is verified and the
  payload unwrapped, then the INS is dispatched. `PROVISION_PIN` (0x70),
  `APPLET_UPDATE` (0x71), `PERSONALIZE` (0x72) and `TERMINATE` (0x73) are
  reachable **only** through this path — the plain CLA 0x80 dispatch for them
  was removed (per-command MACs are mandatory). Any application command may
  also be sent secured; its response is then R-MAC/R-ENC wrapped.

**Secured payload caps** (the C-MAC input is built in the 260-byte APDU
buffer): a secured command carries at most **113 plaintext bytes** without
C-DEC and **111 with C-DEC**; secured **responses** are at most **111
plaintext bytes**. `SIGN_TRANSFER_V2` (0x30, 209-byte response),
`VERIFY_TRANSFER_V2` (0x31, 209-byte tail), `GET_PERSONALIZATION` (0x34,
159 bytes) and `GET_LAST_TRANSFER` (0x36, 132 bytes) therefore refuse the
secured CLA with `0x6E00` — they are **CLA 0x00 only**.

## Application commands (CLA 0x00)

| INS | Name | P1 / P2 | Data | Response | Auth |
|---|---|---|---|---|---|
| `0x02` | NOP | 0/0 | — | — | none |
| `0x04` | GET_BALANCE | 0/0 | — | 8-byte int64 balance (big-endian, lowest denomination) | none |
| `0x16` | GET_ACCOUNT_ID | 0/0 | — | 16-byte account UUID | none |
| `0x18` | VERIFY_PIN | 0/pinType | PIN digits (P2=`0x81`: 8-digit master PIN, P2=`0x82`: 4-digit user PIN) | — (`0x69C0`+tries-remaining on failure) | not terminated |
| `0x19` | UPDATE_USER_PIN | 0/0 | 4-digit new user PIN (all-zeros rejected, `0x6691`) | — | master PIN verified this session (`0x6985` otherwise); not terminated |
| `0x1E` | GET_USER_DATA | 0/0 | — | accountId (16B) ‖ cardId (16B) ‖ full name (UTF-8, variable) | none |
| `0x1F` | SET_FULL_NAME | 0/0 | UTF-8 name, ≤ 128 bytes (`0x6C03` if longer) | — | none (only: not terminated) |
| `0x20` | GET_FULL_NAME | 0/0 | — | UTF-8 name (variable) | none |
| `0x21` | GET_GENDER | 0/0 | — | stored gender bytes (variable, ≤ 16) | none |
| `0x22` | SET_GENDER | 0/0 | free-form bytes, ≤ 16 (`0x6C04` if longer) | — | none (only: not terminated) |
| `0x24` | GET_EC_PUB_KEY | 0/0 | — | 65-byte uncompressed secp256r1 public key (`0x6230` before INITIALIZE) | none |
| `0x25` | SIGN_AUTH | 0/0 | bridge challenge, 8–64 raw bytes (`0x6700` outside bounds) | DER ECDSA-SHA256 signature over `"IMPALA-AUTH:" ‖ accountId(16) ‖ challenge` | not terminated; provisioning gate; personalized (`0x6234`) |
| `0x2C` | INITIALIZE | 0/0 | host entropy seed (mixed into the RNG; does not determine keys) | — | one-shot: `0x6686` once initialized; not terminated |
| `0x2E` | IS_CARD_ALIVE | 0/0 | — | — (`0x6687` if terminated) | not terminated |
| `0x30` | SIGN_TRANSFER_V2 | 0/0 | 4-byte user PIN (or `0000` PIN-less) + 60-byte signable | 209 bytes: DER transfer signature (72B slot) ‖ EC pubkey (65B) ‖ issuer certificate (72B slot) | user PIN or PIN-less; not terminated; provisioning gate; personalized (`0x6234`); CLA 0x00 only (`0x6E00`) |
| `0x31` | VERIFY_TRANSFER_V2 | phase/0 | P1=0x00: 60-byte signable. P1=0x01: 209-byte tail (sig ‖ pubkey ‖ certificate) | — (P1=0x01 credits on success) | not terminated; personalized (`0x6234`); CLA 0x00 only (`0x6E00`) |
| `0x34` | GET_PERSONALIZATION | 0/0 | — | 159 bytes: state(1) ‖ flags(1) ‖ programId(16) ‖ currency(4) ‖ issuerPubKey(65, zeros if unset) ‖ certificate(72B slot) | none; CLA 0x00 only (`0x6E00`) |
| `0x35` | GET_RECEIVE_STATE | 0/0 | — | 36 bytes: lastReceiveCounter(4 BE) ‖ lastReceiveDigest(32) | none |
| `0x36` | GET_LAST_TRANSFER | 0/0 | — | 132 bytes: lastSentSignable(60) ‖ signature(72B slot); `0x6A83` when never sent | none; CLA 0x00 only (`0x6E00`) |
| `0x64` | GET_VERSION | 0/0 | — | major (2B) ‖ minor (2B) ‖ git rev count (2B) ‖ short git hash (4B) | none |

Notes:

- **INITIALIZE (0x2C) is one-shot and irreversible**: it regenerates the
  random 16-byte cardId and generates the card's secp256r1 keypair. A second
  INITIALIZE answers `0x6686`. It also regenerates the SCP03 key
  diversification value (INITIALIZE UPDATE reports `cardId[0..10)`).
- **Transfer messages are domain-tagged.** `SIGN_TRANSFER_V2` signs the
  89-byte XFER message `"IMPALA-XFER:" ‖ 0x01 ‖ programId(16) ‖ signable(60)`,
  never the bare signable; `SIGN_AUTH` signs the AUTH message. The three tags
  differ in their last four bytes. See `transfer-protocol.md` for the byte
  formats, golden vectors and the counter model. Transfer rules: the currency
  is checked on send and receive (`0x6229`); the amount must be ≥ 1 minor unit
  (`0x6239`); the receive counter must be positive, strictly greater than the
  last accepted one and within `MAX_COUNTER_JUMP` (1024) forward (`0x6233` /
  `0x623A`); the send sequence (`dateTime`) is a strictly increasing per-sender
  value, **never a timestamp** (`0x6238`), and a byte-identical re-send replays
  the cached response without a second debit.
- **Sender-key trust.** `VERIFY_TRANSFER_V2` accepts a credit only from a key
  the issuer certified for this program, bound to the signable's sender UUID
  and currency: the card verifies the 72-byte certificate slot against its own
  `issuerPubKey` over the 114-byte CERT message (`0x0022` on failure) before it
  verifies the transfer signature against the tail pubkey (`0x0023`). No PIN is
  required to receive; the trust root is the issuer key, not the holder.
- **Provisioning gate**: when the applet was installed with
  `FLAG_INSTALL_ENFORCE`, SIGN_TRANSFER_V2 and SIGN_AUTH answer `0x6985` until
  a user PIN has been provisioned (install-time PIN injection or SCP03
  PROVISION_PIN).
- **SET_FULL_NAME / SET_GENDER require no PIN** — anyone with the card can
  rewrite them. That is the current behavior of the applet, not an
  intentional guarantee; do not store anything sensitive in these fields.

### Declared but not dispatched

The following INS constants exist in `Constants.java` / `Constants.kt` but
have **no case in the applet's dispatch switch** — sending them returns
`0x6D00`. Do not implement against them:

| INS | Constant |
|---|---|
| `0x07` | INS_GET_RSA_PUB_KEY |
| `0x23` | INS_GET_CARD_NONCE |
| `0x26` | INS_SET_CARD_DATA |
| `0x2B` | INS_UPDATE_MASTER_PIN |
| `0x2D` | INS_SUICIDE |

`0x32` and `0x33` are permanently reserved (historically documented as
Set/Get Ext Pubkey; never dispatched in this repo) and must never be reused.

### Retired — dispatch removed, never reuse

These commands existed in applet 0.1 (the untagged v0 transfer envelope) and
were removed in 0.2. They now answer `0x6D00`; their INS numbers are burned
and must never be reused (a 0.1 receiver never sees a v1 message, and a 0.2
receiver refuses every v0 envelope):

| INS | Constant | Reason |
|---|---|---|
| `0x06` | INS_SIGN_TRANSFER | untagged v0 sign; replaced by SIGN_TRANSFER_V2 (0x30) |
| `0x14` | INS_VERIFY_TRANSFER | untagged v0 verify; replaced by VERIFY_TRANSFER_V2 (0x31) |

### Transfer counter

One strictly increasing counter stream per **receiving** card, allocated
off-card by the transfer coordinator; the sender persists no receive counter.
Gaps are accepted, repeats and lower values are rejected (`0x6233`), zero is
never accepted, a forward jump beyond `MAX_COUNTER_JUMP` (1024) is rejected
distinctly (`0x623A`) so a terminal knows to re-read `GET_RECEIVE_STATE`, and
the maximum is `0x7FFFFFFF`. The credit, the stored counter and the transfer
digest advance in one JavaCard transaction. See `transfer-protocol.md` for the
full model (allocation, stranded transfers, resync, replacement floor).

## SCP03 secure channel

| INS | Name | CLA | P1 / P2 | Data | Notes |
|---|---|---|---|---|---|
| `0x50` | INITIALIZE UPDATE | 0x80 | 0/0 | host challenge | returns keyDiversification = `cardId[0..10)` ‖ keyInfo ‖ card challenge ‖ cryptogram |
| `0x82` | EXTERNAL AUTHENTICATE | 0x80 or 0x84 | secLevel/0 | host cryptogram + C-MAC | `0x6300` on auth failure; C-MAC (bit 0x01) is mandatory |
| `0x70` | PROVISION_PIN | 0x84 only | 0/0 | `[pinType (0x81=master/0x82=user)][len][PIN]` | master=8 digits, user=4; all-zeros user PIN rejected (`0x6691`); a user PIN lifts the signing gate; refused over default keys under ENFORCE (`0x6236`) |
| `0x71` | APPLET_UPDATE | 0x84 only | 0/0 | `[seq (2B)][len (2B)][data]` | seq `0x0001` + 48B atomically rotates the SCP03 ENC/MAC/DEK keys; the GP default key value is refused (`0x6684`); any other (seq,len) → `0x6A86` |
| `0x72` | PERSONALIZE | 0x84 only | part/0 | P1=1 identity(40) ‖ P1=2 issuerPubKey(65) ‖ P1=3 certificate DER | C-DEC required (`0x6982`); refused over default keys (`0x6236`); commits identity+issuer key+certificate atomically; see `transfer-protocol.md` |
| `0x73` | TERMINATE | 0x84 only | 0/0 | 16-byte accountId (must match this card, else `0x6A80`) | C-DEC required (`0x6982`); refused over default keys (`0x6236`); irreversible — clears the signing key |

Default SCP03 static keys are the GP test keys `0x40..0x4F` unless overridden
by install parameters (`FLAG_INSTALL_KEYS`) or rotated by APPLET_UPDATE. A
program-bound card (install flag `0x08`, +81 bytes: programId ‖ issuerPubKey;
requires `0x02`) can never run on the default keys.

**Honesty statement.** The default-keys flag is a policy tripwire, not a
cryptographic barrier — whoever holds the current SCP03 keys can rotate them;
the only cross-card trust is the receiver's issuer key; an issuer-certified
treasury key is unbounded mint authority that the bridge must journal against
a reserve hold before signing; no on-card expiry or revocation exists in v1.

## Common status words

| SW | Meaning |
|---|---|
| `0x9000` | Success |
| `0x0022` | Certificate verification failed (VERIFY_TRANSFER_V2: the tail key is not issuer-certified for this program/sender/currency) |
| `0x0023` | Transfer signature verification failed (VERIFY_TRANSFER_V2: the tagged XFER signature does not verify under the tail key; also a v0 untagged signature) |
| `0x6224` | Insufficient funds (or balance underflow) |
| `0x6226` | Wrong signable length |
| `0x6227` | Signer initialization failed (SIGN_TRANSFER_V2 / SIGN_AUTH: the ECDSA engine refused the card key) |
| `0x6229` | Wrong currency |
| `0x6230` | Card EC key missing (SIGN_TRANSFER_V2 / SIGN_AUTH / GET_EC_PUB_KEY / PERSONALIZE before INITIALIZE) |
| `0x6231` | Wrong sender (SIGN: sender is not this card; VERIFY: sender IS this card) |
| `0x6232` | Wrong recipient (SIGN: recipient IS this card; VERIFY: recipient is not this card) |
| `0x6233` | Transfer counter invalid (VERIFY: zero, negative, or not strictly greater than the last accepted receive counter; SIGN: zero or negative counter) |
| `0x6234` | Not personalized (SIGN_AUTH / SIGN_TRANSFER_V2 / VERIFY_TRANSFER_V2 before PERSONALIZE) |
| `0x6235` | Already personalized (PERSONALIZE on a personalized card) |
| `0x6236` | Default SCP03 keys in use (PERSONALIZE / TERMINATE, or PROVISION_PIN under ENFORCE) |
| `0x6237` | PERSONALIZE part out of sequence |
| `0x6238` | Send sequence invalid (SIGN_TRANSFER_V2: dateTime not strictly increasing, or MSB set) |
| `0x6239` | Zero amount (SIGN_TRANSFER_V2 / VERIFY_TRANSFER_V2) |
| `0x623A` | Transfer counter jump too large (VERIFY: counter more than `MAX_COUNTER_JUMP` beyond the last — re-read GET_RECEIVE_STATE) |
| `0x623B` | Program already bound (PERSONALIZE part B, or part A with a different programId, on an install-bound card) |
| `0x6300` | SCP03 authentication failed |
| `0x6677` | PERSONALIZE certificate self-check failed (part C DER does not verify under the staged issuer key) |
| `0x6683` | Cryptographic exception (e.g. an invalid EC point) |
| `0x6684` | Invalid AES key (install / APPLET_UPDATE supplied the GP default key bytes) |
| `0x6686` | Already initialized |
| `0x6687` | Card terminated |
| `0x6688` | Internal null-pointer error; also the SCP03 C-MAC verification failure on a secured (CLA 0x84) command |
| `0x6689` | Internal array-bounds error |
| `0x6690` | PIN required (all-zero PIN outside PIN-less limits) |
| `0x6691` | PIN rejected (all-zeros PIN is reserved for PIN-less transfers) |
| `0x6700` | Wrong length |
| `0x6982` | Security status not satisfied (PERSONALIZE / TERMINATE without C-DEC) |
| `0x6984` | Data invalid (VERIFY_TRANSFER_V2: a credit that would overflow the 8-byte balance) |
| `0x6985` | Conditions not satisfied (master PIN not verified; provisioning gate; VERIFY_TRANSFER_V2 P1=0x01 without a staged signable) |
| `0x69C0`–`0x69C9` | PIN verification failed; low nibble = tries remaining (`0x69C0` = blocked) |
| `0x6A80` | Wrong data (malformed DER header, non-0x04 point, nil ids, bad initial counter, TERMINATE accountId mismatch, or a malformed install TLV) |
| `0x6A83` | Record not found (GET_LAST_TRANSFER before any signed transfer) |
| `0x6A86` | Incorrect P1/P2 (unknown PIN type; PERSONALIZE bad P1/P2; APPLET_UPDATE unknown (seq,len)) |
| `0x6C02` | Wrong tail length (VERIFY_TRANSFER_V2 phase 2) |
| `0x6C03` / `0x6C04` | Full name / gender too long |
| `0x6D00` | INS not supported (also: any non-SCP03 INS at CLA 0x80; the retired 0x06 / 0x14) |
| `0x6E00` | CLA not supported for this instruction (0x30 / 0x31 / 0x34 / 0x36 arriving at CLA 0x84) |

Note: wrong-PIN failures are `0x69C0`–`0x69C9`, **not** `0x63xx` — `0x6300`
is an SCP03 channel authentication failure. `0x6688` doubles as the SCP03
C-MAC failure code (a deliberate collision retained for host compatibility;
pinned by `Scp03CounterIcvTest`).

## Authentication flow (card-based login)

Bridge card login is a single-use challenge-response — there is no
password derived from the card. The bridge side is implemented in
`impala-bridge/src/handlers/card_auth.rs` (routes `/auth/card/challenge`
and `/auth/card` in `main.rs`).

1. Reader → Bridge: `POST /auth/card/challenge` with `{card_id}`.
   The bridge returns a random 32-byte challenge (64 hex chars) with a
   **60-second TTL, single use** (consumed atomically on exchange). It is
   issued unconditionally, so the response never reveals whether a card is
   registered.
2. Reader → Card: `INS_SIGN_AUTH` (0x25) with the **raw challenge bytes**
   (hex-decode the bridge's value first). The card signs
   `"IMPALA-AUTH:" ‖ accountId(16, RFC-4122 big-endian) ‖ challenge` with
   ECDSA-SHA256 (secp256r1) and returns a DER signature. A card that has not
   been personalized answers `0x6234` (its accountId is the nil UUID).
3. Reader → Bridge: `POST /auth/card` with
   `{card_id, signature: <hex DER>}`. The bridge reconstructs the same
   message from the registered card's account and verifies against the
   card's stored 65-byte uncompressed EC public key, then issues refresh +
   temporal JWTs.

Every failure mode (unknown card, expired/replayed challenge, bad
signature) returns the same generic 401 and counts toward the per-card
lockout. There is no auto-provisioning: a registered card implies an
existing account, and cards are registered via `POST /card` with their
`GET_EC_PUB_KEY` value. The bridge's separate `rsa_pubkey` requirement on
`POST /card` is an unrelated bridge gap, not addressed here.

## Writing new APDUs

If you add an INS code:

1. Declare the constant in `Constants.java` **and** SDK `Constants.kt`.
2. Implement the handler in `ImpalaApplet.java` — including a case in the
   `process()` dispatch switch (a constant without a dispatch case is dead;
   see "Declared but not dispatched").
3. Wrap it in a typed method on `ImpalaSDK.kt` (commonMain).
4. Add a unit test in `ImpalaSDKTest.kt` using `MockBIBO`.
5. Add a row to this document and bump the `claim-count` marker —
   `ApduDocDriftTest` (`sdk/src/jvmTest`) fails until this table,
   `Constants.java`, `Constants.kt` and the dispatch switch agree.
6. Add the SW to `ImpalaException.fromStatusWord` and `ExceptionMappingTest`.
7. If it changes signed bytes: add a golden test in `TransferProtocolGoldenTest`
   and `impala-bridge/src/handlers/card_auth.rs`.
8. `ApduDocTest` parses this file — keep the table shapes.

Keep INS numbers dense. Never reuse an INS even after removing a command —
historical cards in the field may still expect the old semantics.

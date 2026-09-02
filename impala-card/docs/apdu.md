# Impala APDU Command Reference

Package AID: `0102030405060708`, applet instance AID `01020304050607080102`
(defaults in `applet/build.xml`; live builds override both via
`-Papplet.aid` / `-Papplet.aid.app`). Commands are ISO 7816-4 APDUs.
`0x9000` is success.

This document is derived from the dispatch logic in
`impala-card/applet/src/jvmMain/java/com/impala/applet/ImpalaApplet.java`
(`process()`) and `Constants.java` / SDK `Constants.kt`. When in doubt, the
applet source is authoritative.

## Command classes (CLA)

The applet dispatches on CLA before INS:

- **`CLA=0x00`** — all application commands (the table below).
- **`CLA=0x80`** — GlobalPlatform SCP03 channel setup ONLY:
  `INITIALIZE UPDATE` (0x50) and `EXTERNAL AUTHENTICATE` (0x82). Every other
  INS at CLA 0x80 answers `0x6D00`.
- **`CLA=0x84`** — SCP03-secured commands: the C-MAC is verified and the
  payload unwrapped, then the INS is dispatched. `PROVISION_PIN` (0x70) and
  `APPLET_UPDATE` (0x71) are reachable **only** through this path — the plain
  CLA 0x80 dispatch for them was removed (per-command MACs are mandatory).
  Any application command may also be sent secured; its response is then
  R-MAC/R-ENC wrapped.

## Application commands (CLA 0x00)

| INS | Name | P1 / P2 | Data | Response | Auth |
|---|---|---|---|---|---|
| `0x02` | NOP | 0/0 | — | — | none |
| `0x04` | GET_BALANCE | 0/0 | — | 8-byte int64 balance (big-endian, lowest denomination) | none |
| `0x06` | SIGN_TRANSFER | 0/0 | 4-byte user PIN (or `0000` for PIN-less) + 60-byte signable | 209 bytes: DER signature (72B slot) ‖ EC pubkey (65B) ‖ zero-signature placeholder (72B slot) | user PIN, or PIN-less eligibility; not terminated; provisioning gate |
| `0x14` | VERIFY_TRANSFER | phase/0 | P1=0x00: 60-byte signable. P1=0x01: 209-byte tail (sig ‖ pubkey ‖ pubKeySig) | — (P1=0x01 credits the balance on success) | not terminated |
| `0x16` | GET_ACCOUNT_ID | 0/0 | — | 16-byte account UUID | none |
| `0x18` | VERIFY_PIN | 0/pinType | PIN digits (P2=`0x81`: 8-digit master PIN, P2=`0x82`: 4-digit user PIN) | — (`0x69C0`+tries-remaining on failure) | not terminated |
| `0x19` | UPDATE_USER_PIN | 0/0 | 4-digit new user PIN (all-zeros rejected, `0x6691`) | — | master PIN verified this session (`0x6985` otherwise); not terminated |
| `0x1E` | GET_USER_DATA | 0/0 | — | accountId (16B) ‖ cardId (16B) ‖ full name (UTF-8, variable) | none |
| `0x1F` | SET_FULL_NAME | 0/0 | UTF-8 name, ≤ 128 bytes (`0x6C03` if longer) | — | none (only: not terminated) |
| `0x20` | GET_FULL_NAME | 0/0 | — | UTF-8 name (variable) | none |
| `0x21` | GET_GENDER | 0/0 | — | stored gender bytes (variable, ≤ 16) | none |
| `0x22` | SET_GENDER | 0/0 | free-form bytes, ≤ 16 (`0x6C04` if longer) | — | none (only: not terminated) |
| `0x24` | GET_EC_PUB_KEY | 0/0 | — | 65-byte uncompressed secp256r1 public key (zeros before INITIALIZE) | none |
| `0x25` | SIGN_AUTH | 0/0 | bridge challenge, 8–64 raw bytes (`0x6700` outside bounds) | DER ECDSA-SHA256 signature over `"IMPALA-AUTH:" ‖ accountId(16) ‖ challenge` | not terminated; provisioning gate |
| `0x2C` | INITIALIZE | 0/0 | host entropy seed (mixed into the RNG; does not determine keys) | — | one-shot: `0x6686` once initialized; not terminated |
| `0x2E` | IS_CARD_ALIVE | 0/0 | — | — (`0x6687` if terminated) | not terminated |
| `0x64` | GET_VERSION | 0/0 | — | major (2B) ‖ minor (2B) ‖ git rev count (2B) ‖ short git hash | none |

Notes:

- **INITIALIZE (0x2C) is one-shot and irreversible**: it regenerates the
  random 16-byte cardId and generates the card's secp256r1 keypair. A second
  INITIALIZE answers `0x6686`. Do not send it outside the provisioning flow.
- **SIGN_TRANSFER** is not domain-tagged (unlike SIGN_AUTH) — tagging it
  would break card-to-card VERIFY_TRANSFER for already-flashed CAPs. The
  third response field is a fixed 8-byte DER zero-signature placeholder in a
  72-byte slot. PIN-less transfers: PIN field `0000`, amount ≤ 200 (lowest
  denomination), at most 4 consecutive; a `0000` PIN outside those limits
  answers `0x6690`. Sender must equal the card's accountId (`0x6231`),
  recipient must differ (`0x6232`), amount must not exceed the balance
  (`0x6224`), and the currency must match when the card has one set
  (`0x6229`).
- **Provisioning gate**: when the applet was installed with
  `FLAG_INSTALL_ENFORCE`, SIGN_TRANSFER and SIGN_AUTH answer `0x6985` until
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

> **Known gap — no personalization command.** There is currently **no
> command that sets `accountId`** (or the currency code): INS_SET_CARD_DATA
> is declared but not dispatched, and no other write path exists. A card can
> only ever report the all-zeros accountId it was installed with, so
> INS_SIGN_AUTH signs an all-zeros account id and bridge card login (which
> verifies the account UUID inside the signed message) cannot complete
> against a freshly-initialized card until a personalization command is
> added. This document describes the applet as it is; it does not invent
> that command.

## SCP03 secure channel

| INS | Name | CLA | P1 / P2 | Data | Notes |
|---|---|---|---|---|---|
| `0x50` | INITIALIZE UPDATE | 0x80 | 0/0 | host challenge | returns card challenge + cryptogram (GP SCP03) |
| `0x82` | EXTERNAL AUTHENTICATE | 0x80 or 0x84 | secLevel/0 | host cryptogram + C-MAC | `0x6300` on auth failure |
| `0x70` | PROVISION_PIN | 0x84 only | 0/0 | `[pinType (0x81=master/0x82=user)][len][PIN]` | master=8 digits, user=4; all-zeros user PIN rejected (`0x6691`); provisioning a user PIN lifts the signing gate |
| `0x71` | APPLET_UPDATE | 0x84 only | 0/0 | `[seq (2B)][len (2B)][data]` | seq `0x0001` + 48B rotates the SCP03 ENC/MAC/DEK keys |

Default SCP03 static keys are the GP test keys `0x40..0x4F` unless
overridden by install parameters (`FLAG_INSTALL_KEYS`). See `SCP03.java` and
`SCP03Channel.kt` for host-side handling.

## Common status words

| SW | Meaning |
|---|---|
| `0x9000` | Success |
| `0x6224` | Insufficient funds (or balance underflow) |
| `0x6226` | Wrong signable length |
| `0x6229` | Wrong currency |
| `0x6231` | Wrong sender (signable's sender is not this card) |
| `0x6232` | Wrong recipient |
| `0x0023` | Transfer signature verification failed |
| `0x6300` | SCP03 authentication failed |
| `0x6686` | Already initialized |
| `0x6687` | Card terminated |
| `0x6690` | PIN required (all-zero PIN outside PIN-less limits) |
| `0x6691` | PIN rejected (all-zeros PIN is reserved for PIN-less transfers) |
| `0x6700` | Wrong length |
| `0x69C0`–`0x69C9` | PIN verification failed; low nibble = tries remaining (`0x69C0` = blocked) |
| `0x6985` | Conditions not satisfied (master PIN not verified; provisioning gate) |
| `0x6A86` | Incorrect P1/P2 (unknown PIN type) |
| `0x6C02` | Wrong tail length (VERIFY_TRANSFER phase 2) |
| `0x6C03` / `0x6C04` | Full name / gender too long |
| `0x6D00` | INS not supported (also: any non-SCP03 INS at CLA 0x80) |
| `0x6688` / `0x6689` | Internal null-pointer / bounds error |

Note: wrong-PIN failures are `0x69C0`–`0x69C9`, **not** `0x63xx` — `0x6300`
is an SCP03 channel authentication failure.

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
   ECDSA-SHA256 (secp256r1) and returns a DER signature.
3. Reader → Bridge: `POST /auth/card` with
   `{card_id, signature: <hex DER>}`. The bridge reconstructs the same
   message from the registered card's account and verifies against the
   card's stored 65-byte uncompressed EC public key, then issues refresh +
   temporal JWTs.

Every failure mode (unknown card, expired/replayed challenge, bad
signature) returns the same generic 401 and counts toward the per-card
lockout. There is no auto-provisioning: a registered card implies an
existing account, and cards are registered via `POST /card` with their
`GET_EC_PUB_KEY` value.

See `impala-bridge/examples/api_examples.sh` ("Card challenge" /
"Card token exchange") for a runnable example, and
`impala-android-demo/.../LoginViewModel.kt` for the Android side.

> **Known gap (reminder):** because no personalization command sets
> `accountId` on the card, this flow cannot currently be completed
> end-to-end with a card provisioned solely through the documented APDUs —
> see "Declared but not dispatched" above.

## Writing new APDUs

If you add an INS code:

1. Declare the constant in `Constants.java` **and** SDK `Constants.kt`.
2. Implement the handler in `ImpalaApplet.java` — including a case in the
   `process()` dispatch switch (a constant without a dispatch case is dead;
   see "Declared but not dispatched").
3. Wrap it in a typed method on `ImpalaSDK.kt` (commonMain).
4. Add a unit test in `ImpalaSDKTest.kt` using `MockBIBO`.
5. Add a row to this document.

Keep INS numbers dense; reserve 0x30–0x4F for future expansion. Never reuse
an INS even after removing a command — historical cards in the field may
still expect the old semantics.

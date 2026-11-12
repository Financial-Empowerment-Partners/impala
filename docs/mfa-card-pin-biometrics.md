# Multi-factor sign-in: card PIN, phone biometrics, and the card as a factor

The contract between the card applet (0.4), the card SDK, impala-lib, the
Android demo, the bridge and the admin dashboard for everything that makes a
sign-in more than one factor. It replaces the plan in
[`sep10-card-keys.md`](sep10-card-keys.md) §8. Bytes and names here are pinned
by tests on both sides; change them on both sides or not at all.

## 1. The model in one page

A session records **how** it was authenticated. Every token and every cookie
session carries:

| Field | Meaning |
|---|---|
| `amr` | The methods the bridge itself verified for this session, sorted (§2) |
| `auth_time` | Unix seconds of the most recent verification |
| `mfr` | The account must be multi-factor to use the API (§6) |

The bridge never takes a method on a client's word. Each value of `amr` is
backed by evidence the bridge checked:

| `amr` | Factor | Evidence |
|---|---|---|
| `pwd` | knowledge | the account's password (`/token`, `/authenticate`, `/session/login`) |
| `fed` | federated | an identity provider's assertion (Google, Okta, GitHub, OIDC, LDAP) |
| `sc` | possession | a registered card's signature over a bridge challenge (`SIGN_AUTH` or `SIGN_SEP10`) |
| `pin` | knowledge | a **PIN proof** (§3.3): the card's P-256 signature under a tag the applet uses only while its user PIN is verified |
| `otp` | possession | a TOTP code, single use |
| `dev` | possession | a registered **device key**'s signature (§4) |
| `bio` | inherence | that device key is bound to the phone's biometrics, to the extent §4.3 allows the bridge to say so |
| `mfa` | (derived) | at least two different factor kinds above; never an input |

Factor kinds: knowledge (`pwd`, `pin`), federated (`fed`), possession (`sc`,
`otp`, `dev`), inherence (`bio`). `mfa` needs two different kinds, so a card
and a phone together (`sc` + `dev`) are two things you have and are **not**
multi-factor on their own; card + PIN, password + card, password + TOTP and
phone key + biometrics are.

Three ways to add a factor:

1. **In the sign-in itself.** `POST /auth/card` and `POST /auth/sep10` take
   two optional extras beside the card's signature: a PIN proof and a device
   key assertion. One tap, one request, up to `sc` + `pin` + `dev` + `bio`.
2. **Step-up.** An authenticated session presents one more factor at
   `POST /mfa/step-up` (TOTP, a card tap with or without PIN, a device key)
   and gets a new session with the union.
3. **Card policy.** A card can itself require the PIN before it signs in
   anywhere (§3.2), third-party SEP-10 servers included. That protects the
   card; the bridge still credits `pin` only on a PIN proof.

## 2. `amr` rules

- Values are the ones in the table, lowercase, sorted, no duplicates.
  Unknown values in a presented token are dropped; `mfa` is recomputed.
- A refresh rotation carries `amr` and `auth_time` forward unchanged and
  re-derives `mfr` (and the role) from the database.
- A session is multi-factor while `mfa` is in `amr` **and**
  `now - auth_time <= MFA_MAX_AGE_SECS` (default 12 h). After that it needs a
  step-up; nothing else about it changes.
- Tokens minted before this release carry no `amr`: an empty list, never
  multi-factor.

## 3. Card (applet 0.4)

### 3.1 Cardholder verification

"The user PIN is verified" means: a user PIN was **provisioned** by the
issuer (install parameters or `PROVISION_PIN` over SCP03; the factory value
`1111` never counts) and `VERIFY_PIN` (INS `0x18`, P2 `0x82`) succeeded since
the applet was selected. Deselect, reset and any failed check clear it. Five
tries; `0x69Cn` with `n` tries left, `0x69C0` when blocked.

### 3.2 Commands

| INS | Name | P1/P2 | Data | Response | Preconditions |
|---|---|---|---|---|---|
| `0x39` | GET_USER_VERIFICATION | 0/0 | none | 4 bytes: format `0x01` ‖ policy ‖ PIN tries left ‖ session | none (every state) |
| `0x3A` | SET_SIGN_IN_POLICY | P1 `0x01` require the PIN to sign in, `0x00` do not / 0 | none | none | not terminated; user PIN verified (`0x6690`; `0x6985` without a provisioned PIN); turning it off on a card installed with the policy: `0x6985` |
| `0x3B` | CHANGE_USER_PIN | 0/0 | new PIN, 4 digit values `0..9`, not `0000` | none | not terminated; user PIN verified (`0x6690` / `0x6985`); the new PIN must be verified again |
| `0x25` | SIGN_AUTH | P1 `0x00` plain, `0x01` PIN proof / 0 | challenge (8..64) | DER ECDSA signature | as before; P1 `0x01`, and P1 `0x00` on a card whose policy requires the PIN, need the user PIN verified |
| `0x38` | SIGN_SEP10 | unchanged | unchanged | unchanged | as before, plus the user PIN verified on a card whose policy requires it (every part) |

Policy byte: `0x01` the PIN is required to sign in; `0x02` that requirement
was set at install and cannot be turned off; `0x04` a user PIN is provisioned
(PIN proofs are possible). Session byte: `0x01` the user PIN is verified now.

Install parameter flag `0x10` (`FLAG_INSTALL_SIGN_IN_PIN`) sets policy bits
`0x01` and `0x02` for the life of the card.

Status words: `0x6690` the user PIN must be verified first; `0x6985` the card
has no provisioned PIN (nothing a holder could verify), or the policy is
fixed. An applet older than 0.4 answers `0x6D00` to the three new commands
and ignores P1 of `SIGN_AUTH`, so it can never produce a PIN proof.

### 3.3 PIN proof

```
"IMPALA-APIN:" (12) ‖ accountId (16) ‖ challenge (8..64)      ECDSA P-256 / SHA-256, DER
```

The same layout as the sign-in message with another tag. The applet signs it
only through `SIGN_AUTH` P1 `0x01` and only while the user PIN is verified.
The challenge is:

- at `POST /auth/card` and for a card step-up: the same bridge challenge the
  plain signature covers;
- at `POST /auth/sep10`: the 32-byte hash of the challenge transaction
  (`SHA-256(networkId ‖ 00000002 ‖ tx)`), the value the Stellar key signs.

The Stellar key is untouched: it still signs only the proof message at
personalization and challenges the card itself parsed.

The bridge credits `pin` when the proof verifies under the card's registered
P-256 key **and** the card is issuer-certified (`certified_at` set, issuer key
version not revoked): a PIN proof is a statement by the applet ("a provisioned
user PIN was verified in this session"), and only the operator's certificate
says that key lives in a genuine Impala applet. Certification also closes the
one gap the applet cannot close alone — a card still on its factory master PIN
could have had its user PIN reset through `UPDATE_USER_PIN` — because issuance
always replaces the factory master PIN before it certifies.
`MFA_CARD_PIN_TRUST=any` drops the certification condition (test rigs only). A
proof that is present and does not verify refuses the whole sign-in (401); it
is never ignored.

## 4. Device key (the phone as a factor)

### 4.1 Key

A P-256 key generated in the phone's keystore (Android Keystore, StrongBox
where the device has it), never exported. The demo app binds it to the
device's strong biometrics: usable for 30 s after a successful class 3
biometric prompt, invalidated when biometrics are re-enrolled.

P-256, not Ed25519: hardware-backed Ed25519 is not something Android devices
offer broadly, and this key signs a bridge message, not a Stellar transaction.

### 4.2 Assertion

```
"IMPALA-DKEY:" (12) ‖ 0x01 ‖ purpose (1) ‖ SHA-256(account id, UTF-8) (32) ‖ challenge (32)
ECDSA P-256 / SHA-256, DER, hex on the wire
```

| Purpose | Used at | Challenge |
|---|---|---|
| `0x01` enroll | `POST /mfa/device-keys` | a `POST /mfa/challenge` value |
| `0x02` step-up | `POST /mfa/step-up` | a `POST /mfa/challenge` value |
| `0x03` card sign-in | `POST /auth/card` | the card challenge the card signed |
| `0x04` SEP-10 sign-in | `POST /auth/sep10` | the challenge transaction hash |

### 4.3 What the bridge can say about biometrics

At enrollment the app declares `user_verification`: `biometric` or `none`.
The bridge cannot check that declaration without verifying a platform key
attestation, which it does not do (§9). So:

- `dev` is credited for any valid assertion by an active key;
- `bio` is credited only with `MFA_DEVICE_BIOMETRIC=claimed`, for keys
  declared `biometric`. The default is `off`: the phone is then one more
  possession factor and nothing else.

## 5. Bridge API

All bodies JSON. Errors use the bridge's `{error, message}` shape.

### 5.1 Sign-in extras

`POST /auth/card` — request gains optional `pin_proof` (hex DER),
`device_key_id`, `device_signature` (hex DER). `POST /auth/sep10` (JSON body
only) gains the same three. Every token response gains `amr` (array) and,
when the session must step up before it can be used, `mfa_required: true`.

### 5.2 Step-up

| Route | Auth | Body | Result |
|---|---|---|---|
| `POST /mfa/challenge` | any session, MFA not required | none | `{challenge (64 hex), expires_in}`; single use, 120 s, at most 3 outstanding |
| `POST /mfa/step-up` | any session, MFA not required | `{mfa_type, …}` | bearer: a new token pair in a **new** family (the old family is revoked); cookie: the session record is upgraded |
| `GET /mfa/status` | any session, MFA not required | | `{amr, auth_time, mfa, required, required_by_role, satisfied, max_age_secs, factors}` |

`mfa_type`: `totp` (`code`), `card` (`card_id`, `signature`, optional
`pin_proof`; the caller's own active card), `device` (`key_id`, `signature`).
SMS enrollments are not accepted: this bridge has no code sender.

Failures are a generic 401 and count toward the per (account, type, source)
lockout only when a real guess was made (a wrong TOTP code).

### 5.3 Factors

| Route | Auth | Notes |
|---|---|---|
| `GET /mfa/device-keys` | owner | public data only |
| `POST /mfa/device-keys` | owner, factor change (§6.3) | `{public_key (130 hex), label, platform, user_verification, challenge, signature}` → `{key_id}` |
| `DELETE /mfa/device-keys/{key_id}` | owner, factor change | revoke |
| `PUT /mfa/policy` | owner | `{required}`; turning it on needs a multi-factor session and signs the account out everywhere; turning it off is a factor change |
| `GET /admin/accounts/{id}/mfa` | `ReadAccounts` | factor summary, no secrets |
| `PUT /admin/accounts/{id}/mfa-policy` | admin | `{required}`: mandate or recovery |
| `DELETE /admin/accounts/{id}/mfa/device-keys/{key_id}` | admin | recovery for a lost phone |

## 6. Policy

### 6.1 Who must be multi-factor

`mfr` is stamped at issuance: the account's `mfa_required` column, or its
role being listed in `MFA_REQUIRED_ROLES` (empty by default). A session with
`mfr` that is not multi-factor gets `403 mfa_required` from every route
except the step-up routes, `GET /mfa/status`, the session's own `/session/me`
and the logout routes.

### 6.2 SEP-10 and privileged accounts

Unchanged: `POST /auth/sep10` never mints a session for an account whose role
holds a capability, whatever extras it carries. Those cards sign in at
`POST /auth/card`, where a PIN proof gives `sc` + `pin`.

### 6.3 Changing factors

When `mfr` is set, anything that adds or removes a way to authenticate
(device keys, TOTP enrollment, card registration and deletion, the Stellar
key of a card, turning the requirement off) needs a multi-factor session
whose `auth_time` is at most 15 minutes old: `403 mfa_reauth_required`
otherwise. Without `mfr`, factor changes work as before.

### 6.4 Operator settings

| Variable | Default | Meaning |
|---|---|---|
| `MFA_REQUIRED_ROLES` | empty | roles whose sessions must be multi-factor |
| `MFA_MAX_AGE_SECS` | `43200` | how long a multi-factor verification lasts |
| `MFA_CARD_PIN_TRUST` | `certified` | `certified` or `any` (§3.3) |
| `MFA_DEVICE_BIOMETRIC` | `off` | `off` or `claimed` (§4.3) |

## 7. Clients

- **SDK**: `getUserVerification`, `verifyUserPinDigits`, `signAuthChallenge(…, pinProof)`,
  `setSignInPinRequired`, `changeUserPin`, `CardError.PinRequired`,
  `DeviceKeyProtocol` (the §4.2 message).
- **impala-lib**: `CardSignIn.signIn(session, …, options)` verifies the PIN
  first when one is given, refuses before any request when the card needs one
  and none was given, and adds the extras. A wrong or blocked PIN is an
  error, never a downgrade to a PIN-less sign-in. `DeviceKeys` manages the
  keystore key.
- **Android demo**: PIN sheet before the tap, biometric prompt before arming
  the tap, "this phone as a second factor", session assurance in Settings.
- **Admin dashboard**: session assurance, step-up dialog on `mfa_required`,
  device keys, the requirement toggle, per-account MFA in Accounts.

## 8. Shared vectors

Pinned on both sides (`scripts/check-shared-vectors.sh`):

- the PIN proof tag `494d50414c412d4150494e3a` and the message layout;
- the device key message for a fixed account, purpose and challenge.

## 9. Not built

- **Platform key attestation.** Verifying Android Key Attestation (chain to
  the Google roots, revocation list, `userAuthType`, the app's signing digest)
  is what would let the bridge credit `bio` without trusting the app. Until
  then `bio` is opt-in and labelled as claimed.
- **Encrypted PIN entry.** `VERIFY_PIN` carries the PIN in the clear over NFC,
  as `SIGN_TRANSFER_V2` always has. A passive eavesdropper in radio range of a
  tap learns it.
- **On-card biometrics** (`javacardx.biometry`): a fingerprint card would
  verify the holder where the PIN is verified today, and the PIN proof would
  carry over unchanged. No such card or simulator is available here.
- **iOS**: the device key and the biometric prompt are Android only.
- **Admin dashboard MFA panels and the Android PIN-entry / step-up screens.**
  The data path and APIs are in place and unit-tested end to end; the operator
  dashboard views (session assurance, step-up, device-key list, the mandate
  toggle, per-account MFA in Accounts) and the app's PIN-entry sheet, biometric
  prompt wiring and step-up screen are not built. A card that requires a PIN
  surfaces `CardError.PinRequired` to the app, and `CardSignIn.signIn` already
  takes the PIN and device signer; the fragment that prompts and re-taps is the
  remaining UI.

## 10. Verification and QA

### 10.1 Automated coverage (what CI runs)

- **Applet 0.4** (`impala-card`, jcardsim, no hardware): `UserVerificationInteropTest`
  (PIN proof verifies host-side and only after `VERIFY_PIN`; a plain sign-in
  signature is not a PIN proof; no provisioned PIN ⇒ no proof;
  `SET_SIGN_IN_POLICY` gates sign-in and the install flag fixes it;
  `CHANGE_USER_PIN`; `GET_USER_VERIFICATION`). All three CAP variants convert.
- **SDK**: `ConstantsTest` pins the 0.4 numbers; `ApduDocDriftTest` /
  `ApduDocTest` / `ApduNamesDocTest` pin the new INS against `docs/apdu.md`.
- **impala-lib**: `CardSignInTest` (a SEP-10 sign-in with a PIN attaches a
  verifying PIN proof; with a device signer attaches a verifying device
  assertion; a legacy sign-in carries the PIN proof on the result; the domain
  tags match the bridge) and `DeviceKeyProtocol`.
- **Bridge** (`cargo test`, no DB/Redis): `mfa::` (PIN-proof vs sign-in message
  tags, device-assertion layout and purpose binding, `is_session_multi_factor`
  freshness, `account_requires_mfa`), `constants::` (`finalize_amr`, the MFA
  domain-tag hex), and the existing sign-in-order tripwires updated.
- **Android app**: `DeviceMfaTest` (the device signer produces a verifying
  assertion; purpose is bound; `forget` clears it), plus the full tnet/live
  unit suites compile against the new models and service.
- **Cross-component**: `scripts/check-shared-vectors.sh` pins the
  `IMPALA-APIN:` and `IMPALA-DKEY:` tags on both the card and the bridge side.

The **DB lane is not run here** (migration 041 is exercised only as pinned SQL
strings); QA should run `RUN_DB_TESTS=1 … cargo test --test db` and the
operator migrate against a real Postgres. **No physical card** was used;
verification is on the jcardsim simulator across JavaCard 3.0.5/3.1/3.2.

### 10.2 Manual QA checklist

1. **Migrate**: run migration 041 before rolling the binary; confirm
   `mfa_device_key` and `impala_account.mfa_required` exist.
2. **Card PIN factor**: issue a card with a provisioned user PIN, register it,
   sign in at `POST /auth/card` with a PIN proof over the challenge — expect
   the session's `amr` to carry `sc` + `pin` (and `mfa`). A wrong proof must
   fail the whole sign-in (401). A proof from a non-certified card must not be
   credited while `MFA_CARD_PIN_TRUST=certified`.
3. **Device-key factor**: enroll a key (`POST /mfa/challenge` → sign enroll →
   `POST /mfa/device-keys`), then step up (`POST /mfa/step-up` type `device`).
   Confirm `bio` appears only with `MFA_DEVICE_BIOMETRIC=claimed`.
4. **Step-up and enforcement**: set `mfa_required` on an account (or list its
   role in `MFA_REQUIRED_ROLES`); confirm a single-factor session gets
   `403 mfa_required` on a protected route but can reach `/mfa/status` and
   `/mfa/step-up`, and that a TOTP step-up clears the gate and rotates the
   token family (bearer) or upgrades the cookie session in place.
5. **SEP-10 privileged refusal** is unchanged even with extras present.
6. **No secrets**: check the event outbox rows for `mfa.*` carry only handles
   and the boolean, and that no log or response returns PIN or key bytes.

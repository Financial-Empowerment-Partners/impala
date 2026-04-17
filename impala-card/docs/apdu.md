# Impala APDU Command Reference

Applet AID: `0102030405060708`. All commands use ISO 7816-4 APDUs with
`CLA=0x80` unless noted. Response status words follow the ISO 7816-4
convention — `0x9000` is success.

This document is derived from `impala-card/applet/src/jvmMain/java/ImpalaApplet.java`.
When in doubt, the applet source is authoritative.

## Command summary

| INS | Name | CLA | P1 / P2 | Data | Response | Auth |
|---|---|---|---|---|---|---|
| `0x10` | GET_APPLET_VERSION | 0x80 | 0/0 | — | 4 bytes version | none |
| `0x1C` | SET_PIN | 0x80 | 0/0 | 8-byte new PIN | — | none (factory only) |
| `0x1D` | VERIFY_PIN | 0x80 | 0/0 | 8-byte PIN | — | — |
| `0x1E` | GET_USER_DATA | 0x80 | 0/0 | — | card_id + account_id + cardholder name | none |
| `0x1F` | SET_USER_DATA | 0x80 | 0/0 | concatenated user fields | — | PIN verified |
| `0x20` | GET_BALANCE | 0x80 | 0/0 | — | 8-byte balance (signed, big-endian) | none |
| `0x21` | CREDIT_BALANCE | 0x80 | 0/0 | 8-byte amount (signed, big-endian) | new 8-byte balance | PIN verified |
| `0x22` | DEBIT_BALANCE | 0x80 | 0/0 | 8-byte amount (signed, big-endian) | new 8-byte balance | PIN verified |
| `0x23` | GET_GENDER | 0x80 | 0/0 | — | 1 byte (0=unset, 1=male, 2=female, 3=other) | none |
| `0x24` | GET_EC_PUB_KEY | 0x80 | 0/0 | — | 65 bytes (uncompressed secp256r1 public key) | none |
| `0x25` | SIGN_AUTH | 0x80 | 0/0 | 8-byte timestamp | ECDSA-SHA256 signature (DER) | none |
| `0x26` | GET_RSA_PUB_KEY | 0x80 | 0/0 | — | DER-encoded RSA public key | none |
| `0x27` | SIGN_AUTH_RSA | 0x80 | 0/0 | 8-byte timestamp | PKCS#1 v1.5 signature over SHA-256 | none |
| `0x28` | SET_GENDER | 0x80 | 0/0 | 1 byte (1/2/3) | — | PIN verified |
| `0x29` | SET_DOB | 0x80 | 0/0 | 8-byte YYYYMMDD | — | PIN verified |
| `0x2A` | GET_DOB | 0x80 | 0/0 | — | 8-byte YYYYMMDD | none |
| `0x2B` | SET_CARDHOLDER_NAME | 0x80 | 0/0 | UTF-8 name (≤ 64 bytes) | — | PIN verified |
| `0x2C` | GET_CARDHOLDER_NAME | 0x80 | 0/0 | — | UTF-8 name | none |
| `0x2D` | SET_CARD_ID | 0x80 | 0/0 | 8-byte card ID | — | factory only |
| `0x2E` | SET_ACCOUNT_ID | 0x80 | 0/0 | 56-byte Stellar account ID | — | PIN verified |
| `0x2F` | GET_ACCOUNT_ID | 0x80 | 0/0 | — | 56-byte Stellar account ID | none |

SCP03 commands use `CLA=0x80` (plaintext) for `INITIALIZE_UPDATE` and
`CLA=0x84` (secured) for subsequent commands inside the channel. See
`SCP03Channel.kt` for host-side handling.

| INS | Name | CLA | P1 / P2 | Data | Response | Notes |
|---|---|---|---|---|---|---|
| `0x50` | INITIALIZE_UPDATE | 0x80 | 0/0 | 8-byte host challenge | 29 bytes (card challenge + cryptograms) | GP SCP03 |
| `0x82` | EXTERNAL_AUTHENTICATE | 0x84 | secLevel/0 | 16 bytes (host cryptogram + C-MAC) | — | GP SCP03 |

## Common status words

| SW | Meaning |
|---|---|
| `0x9000` | Success |
| `0x6300` | Verification failed (wrong PIN) |
| `0x6700` | Wrong length |
| `0x6982` | Security status not satisfied (PIN required) |
| `0x6A80` | Wrong data format |
| `0x6A82` | File/applet not found |
| `0x6D00` | INS not supported |
| `0x6E00` | CLA not supported |
| `0x6F00` | Generic execution error |

## Authentication flow (card-based login)

1. Reader → Card: `GET_USER_DATA` (INS 0x1E) — retrieve `account_id` + `card_id`.
2. Reader → Card: `GET_EC_PUB_KEY` (INS 0x24) — retrieve the 65-byte ECDSA public key.
3. Reader → Card: `SIGN_AUTH` (INS 0x25) with an 8-byte timestamp — receive a DER-encoded signature.
4. Reader derives password as `SHA-256(card_id).take(32)`.
5. Reader → Bridge: `POST /authenticate` with `{account_id, password}`.
6. On first login the bridge registers the user; on subsequent logins it verifies the Argon2 hash.

See `impala-android-demo/app/src/main/java/com/payala/impala/demo/ui/login/LoginViewModel.kt`
for the Android side of this flow.

## Writing new APDUs

If you add an INS code:

1. Declare the constant in `Constants.java`.
2. Implement the handler in `ImpalaApplet.java`.
3. Wrap it in a typed method on `ImpalaSDK.kt` (commonMain).
4. Add a unit test in `ImpalaSDKTest.kt` using `MockBIBO`.
5. Add a row to this document.

Keep INS numbers dense; reserve 0x30–0x4F and 0x60–0x7F for future
expansion. Never reuse an INS even after removing a command — historical
cards in the field may still expect the old semantics.

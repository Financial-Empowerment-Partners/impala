# Impala card

Offline Payala stored-value transfer between issuer-certified cards, reconciled
and settled through the bridge. Not an on-chain payment.

A card holds a balance in minor units and moves value to another card of the
same program by signing a transfer the recipient verifies offline. A **LUK**
(limited-use / issuer-certified card key) is the card's own signing key together
with the issuer certificate that binds it to an account, currency and program;
the certificate travels in the third slot of every `SIGN_TRANSFER_V2` response
and is verified on the receiving card. Value is settled and reconciled against
the bridge.

## Toolchain: JDK 17

Both Gradle modules (`:sdk`, `:applet`) pin `jvmToolchain(17)`, and **Gradle
itself must run on JDK 17** (e.g. `JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64`):
the Ant `<javacard>` task that builds the CAP runs *in the Gradle JVM*, not in
the Kotlin toolchain JVM. CI pins JDK 17 via setup-java.

Why 17 specifically (and not 21):

- the vendored `ant-javacard` v26.x (see `applet/libs/README.md`) requires
  Java 17+;
- the JavaCard 3.1.0b43 converter/verifier kit and jcardsim 3.0.6.0 are
  validated on 17, not on 21;
- AGP 9 (used by the `:sdk` Android target) requires 17+.

17 is the single version satisfying all three, so the toolchain stays on 17.

## Build and test

```bash
cd impala-card
./gradlew :sdk:jvmTest            # SDK + applet interop tests on jcardsim (no hardware)
./gradlew :applet:buildJavacard   # build the CAP file (verify=true)
```

`GET_VERSION` (10 bytes: `major2 minor2 rev2 hash4`) reports `0.2`; applet 0.2 is
the certified transfer protocol.

## Threat-scoped claim

A correctly personalized, non-compromised card atomically debits its local
balance before releasing a transfer signature; a receiving card accepts a credit
only from an issuer-certified key bound to the signable's sender, currency and
program, and rejects repeated, non-increasing or out-of-bound counters.

This holds only given, and does not itself provide:

- **issuer-key custody** — the program key is install-only on the bridge and
  never on a card/terminal;
- **terminal integrity** — live-read the recipient counter, deliver
  synchronously, never re-sign a signed transfer;
- **card anti-cloning** — a platform property of the secure element;
- **bridge reconciliation/quarantine** — see `impala-bridge/SECURITY.md`;
- **backend integrity and bridge custody**.

## Capability matrix

| Capability | Implemented | jcardsim | Physical card | Without network | Production |
|---|---|---|---|---|---|
| Card issuance / personalization | ✓ | ✓ (`PersonalizationInteropTest` P1) | no evidence in repo | ✓ | ✗ |
| Offline debit (SIGN_TRANSFER_V2) | ✓ | ✓ (`CertifiedTransferInteropTest` C1/C13) | no evidence in repo | ✓ | ✗ |
| Offline credit (VERIFY_TRANSFER_V2) | ✓ | ✓ (C1/C11/C13) | no evidence in repo | ✓ | ✗ |
| Issuer-key verification on receive | ✓ | ✓ (C2/C3/C5) | no evidence in repo | ✓ | ✗ |
| Multi-hop onward spending | ✓ | ✓ (C13) | no evidence in repo | ✓ | ✗ |
| Reconciliation / Stellar redemption | — | — | — | — | not in this repo (bridge follow-up) |

## Issuance ceremony

1. `gp --install --params 01 0B ‖ ENC‖MAC‖DEK ‖ programId‖issuerPubKey`
   (flags `0x01` ENFORCE | `0x02` KEYS | `0x08` PROGRAM; add `0x04` + a PIN block
   for factory PINs). The card is then `scp03KeysCustom`, `provisioningEnforced`
   and `programBound`. Without `0x08`, bind later with PERSONALIZE part B.
2. `INITIALIZE` (0x2C) with host entropy → card keypair + final cardId.
3. `GET_USER_DATA` → cardId; `GET_EC_PUB_KEY` → the 65-byte card key.
4. Open SCP03 with the transport keys → `APPLET_UPDATE` seq `0x0001` with per-card
   keys derived by the issuer HSM from (KMK, cardId) → reopen with the per-card
   keys (INITIALIZE UPDATE reports `cardId[0..10)` for lookup).
5. The issuer HSM signs the CERT message (`docs/transfer-protocol.md` §2).
6. `PERSONALIZE` A (accountId, currency, programId, initialReceiveCounter)[, B],
   C over the per-card channel at security level `0x33`.
7. `PROVISION_PIN` master + user (lifts ENFORCE).
8. `GET_PERSONALIZATION` read-back; register with the bridge.

The default-keys flag is a policy tripwire, not a cryptographic barrier —
whoever holds the current SCP03 keys can rotate them.

## Counter model

One strictly increasing counter stream per receiving card, allocated off-card by
the transfer coordinator (tap-present: read `GET_RECEIVE_STATE`, set
`counter = L + 1`). Gaps are accepted, repeats and lower values rejected
(`0x6233`), zero never accepted, a forward jump beyond 1024 rejected distinctly
(`0x623A`), maximum `0x7FFFFFFF`. `dateTime` is a strictly increasing per-sender
send sequence, never a timestamp. Full model, allocation and torn-delivery
decision table: `docs/transfer-protocol.md` §6.

## Lost card / replacement

The bridge revokes the pubkey/cert_id; terminals refuse to present from a
hot-listed key. A replacement uses the **same accountId**, a **new key and
certificate**, and `initialReceiveCounter ≥ the bridge's last known L`, so every
envelope the lost card accepted can never re-verify on the replacement. See
`docs/transfer-protocol.md` §6.6.

## Compatibility: applet 0.1 CAPs

Already-flashed 0.1 CAPs answer `0x6D00` to every new INS and keep the retired v0
behaviour; 0.2 receivers refuse v0 envelopes. There is no in-place upgrade:
reflash (`gp --delete/--install`) then run the ceremony.
`ImpalaSDK.requireCertifiedProtocol()` stops the SDK driving V2 flows against a
0.1 card.

## Reference

- `docs/apdu.md` — the full APDU command table and status words.
- `docs/transfer-protocol.md` — byte formats, golden vectors, lifecycle,
  personalization, the counter model, and the claims → tests table.
- `docs/IOS_NFC.md` — the iOS CoreNFC transport.

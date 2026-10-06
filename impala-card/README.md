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

Every Gradle module (`:sdk`, `:applet`, `:simulator`, `:tools:issue`) pins `jvmToolchain(17)`, and **Gradle
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
./gradlew :simulator:jvmTest      # the reusable jcardsim card + JCA test issuer
./gradlew :tools:issue:test       # issuance ceremony against a fake bridge
./gradlew :applet:buildJavacard   # build the CAP file (verify=true)
```

### Modules

| Module | What it is |
|---|---|
| `:sdk` (`com.impala:sdk`, KMP: JVM, Android, iOS) | `ImpalaSDK` (one method per INS) and, in `com.impala.sdk.flows`, the client flows every app shares: `CardIdentity` (version + personalization gates), `CardAuthFlow`, `RedemptionFlow` (compose / sign with PIN / recover the last signed tuple — never re-sign), `CreditFlow` (apply a bridge credit, report the SW), the typed `CardError`, and the one `Hex`/`UuidBytes` codec. JVM-only: `PcscBibo` (PC/SC readers via `javax.smartcardio`). Every transport passes commands through `ApduTrace.mask` before its optional `debugTrace` hook, so PIN and key bytes are never observable. |
| `:simulator` (`com.impala:simulator`, JVM, **tests and tools only**) | `SimulatorBibo` (the real applet on jcardsim; each simulated card gets its own key — jcardsim alone would give every card the same one), a JCA `TestIssuer`, `personalizedCard(...)`, and `SimulatorApduServer` (`./gradlew :simulator:serve --args="--port 9443"`: one simulated card over TCP for the Android emulator lane). impala-lib and the demo use it in their test source sets. |
| `:tools:issue` (CLI + library) | The issuance ceremony — see "Issuance tool". |
| `:applet` | The JavaCard applet (CAP via Ant). |

## Issuance tool

`tools/issue` runs the whole ceremony below against a card, idempotent per step
(an already-personalized card prints its record and exits 0; a torn
PERSONALIZE re-runs from part A), and prints a signed-off record (card id,
account UUID, program id, currency, `cert_id`, applet version, CAP sha256).

```bash
export IMPALA_ISSUE_KMK=<32 hex>             # per-card SCP03 key master key (operator secret)
export IMPALA_HOLDER_TOKEN=<bearer>          # the card holder: POST /card
export IMPALA_OPERATOR_TOKEN=<bearer>        # admin / key-custodian: the certificate
# IMPALA_USER_PIN / IMPALA_MASTER_PIN, else prompted without echo
./gradlew :tools:issue:run --args="--transport pcsc --account <holder uuid> --bridge https://bridge.example \
    --currency XLM --cap applet/build/javacard/ImpalaApplet.cap"
./gradlew :tools:issue:installDist            # standalone launcher: tools/issue/build/install/impala-issue/bin/impala-issue
```

- **Transports:** `pcsc` (a desktop reader; `--reader` filters by name),
  `tcp:HOST:PORT` (`SimulatorApduServer`), `simulator` (in-process, test only).
- **Certificates** come from the bridge (`POST /admin/cards/{card_id}/certificate`,
  `GET /card-issuer`; see `docs/runbooks/card-issuer.md`). `--test-issuer`
  instead uses a throwaway local issuer for **login-only** pilot cards: it prints
  a banner, the card is never redeemable, and it is refused against a pubnet
  bridge.
- **Per-card SCP03 keys** (open decision OD-3, recommended option): ENC/MAC/DEK =
  `AES-CMAC(KMK, cardId ‖ "IMPALA-SCP03-" ‖ label)`. The KMK never reaches the
  bridge or a phone; the tool re-derives keys on demand and stores nothing.
  Transport keys come from `IMPALA_SCP03_TRANSPORT_KEYS` (96 hex) or are the GP
  test keys for a card installed without the KEYS flag.
- **Secrets** come only from the environment or no-echo prompts; a
  token-, PIN- or KMK-looking argument is refused as usage.
- `--terminate --yes-terminate <card_id>` prints balance, receive state and the
  last signed transfer, then TERMINATEs over the per-card channel
  (`docs/transfer-protocol.md` §6.6 "recovered card").
- Exit codes: 0 done, 1 refused by the card or the bridge, 2 usage. Data on
  stdout, notices on stderr.

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
| Bridge-issued certificates (issuer key custody, certify) | ✓ (bridge 039) | ✓ (live-bridge e2e lane) | no evidence in repo | — | ✗ |
| Card login against a live bridge | ✓ | ✓ (demo `CardAuthE2ETest`) | no evidence in repo | — | ✗ |
| Reconciliation / Stellar redemption | client side only | ✓ (demo controllers, mocked bridge) | — | — | bridge `/offline/*` lane not built |

## Issuance ceremony

1. `gp --install --params 01 0B ‖ ENC‖MAC‖DEK ‖ programId‖issuerPubKey`
   (flags `0x01` ENFORCE | `0x02` KEYS | `0x08` PROGRAM; add `0x04` + a PIN block
   for factory PINs). The card is then `scp03KeysCustom`, `provisioningEnforced`
   and `programBound`. Without `0x08`, bind later with PERSONALIZE part B.
2. `INITIALIZE` (0x2C) with host entropy → card keypair + final cardId.
3. `GET_USER_DATA` → cardId; `GET_EC_PUB_KEY` → the 65-byte card key.
4. Open SCP03 with the transport keys → `APPLET_UPDATE` seq `0x0001` with per-card
   keys derived from (KMK, cardId) (the issuance tool: AES-CMAC; an issuer HSM
   in production) → reopen with the per-card keys (INITIALIZE UPDATE reports
   `cardId[0..10)` for lookup).
5. The bridge's issuer key signs the CERT message (`docs/transfer-protocol.md` §2)
   — `POST /admin/cards/{card_id}/certificate` after the holder registers the
   card (`POST /card`).
6. `PERSONALIZE` A (accountId, currency, programId, initialReceiveCounter)[, B],
   C over the per-card channel at security level `0x33`.
7. `PROVISION_PIN` master + user (lifts ENFORCE).
8. `GET_PERSONALIZATION` read-back.

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

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

Since applet 0.3 a card also holds a **Stellar key** (Ed25519) and signs in
with SEP-10, Stellar Web Authentication: see "Stellar key and SEP-10" below.
The P-256 key, `SIGN_AUTH` and the transfer protocol are unchanged.

## Toolchain: JDK 17

Every Gradle module (`:sdk`, `:applet`, `:simulator`, `:jcardsim-jc31`, `:tools:issue`) pins a Java 17 toolchain, and **Gradle
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

Moving to JDK 21 LTS is planned but not implemented: ant-javacard refuses
JDK 21 with the vendored Java Card 3.1.0 kit (it needs kit v25.0+), so the kit
upgrade comes first. See [`docs/jdk21-javacard-kit-upgrade.md`](docs/jdk21-javacard-kit-upgrade.md).

## Build and test

```bash
cd impala-card
./gradlew :applet:jvmTest         # applet unit tests: Ed25519 engines, the on-card SEP-10 validator, the simulated hardware
./gradlew :sdk:jvmTest            # SDK + applet interop tests on jcardsim (no hardware), every CAP on every card model
./gradlew :simulator:jvmTest      # the reusable jcardsim card + JCA test issuer, the TCP and vpcd card servers
./gradlew :tools:issue:test       # issuance ceremony against a fake bridge
./gradlew :applet:buildJavacard   # build the CAP file (verify=true); see "CAP variants"
./gradlew :simulator:capMatrix    # which JavaCard levels load each built CAP (after building the three variants)
./gradlew :simulator:serve --args="--platform jc32"   # one simulated card over TCP: a JavaCard 3.2 card here
```

Everything a build needs is resolved by Gradle from Maven Central (jcardsim,
ASM for the simulator layer) or vendored under `applet/libs/` (the JavaCard
kits, ant-javacard, gp.jar). There is nothing to install by hand beyond JDK 17.

### CAP variants

A CAP holds exactly one Ed25519 engine for the card's Stellar key, chosen with
`-Papplet.ed25519=`:

| Variant | Engine | Card platform | CAP |
|---|---|---|---|
| `soft` (default) | `Ed25519Soft`: Ed25519 through the card's ECDH engine, see below | JavaCard 3.0.5 | `applet/build/ImpalaApplet.cap` |
| `native` | `Ed25519Native`: the platform's EdDSA (`Signature.SIG_CIPHER_EDDSA`) | JavaCard 3.1 or later | `applet/build/ImpalaApplet-native.cap` |
| `none` | none: a legacy card (`SIGN_AUTH` only) | JavaCard 3.0.5 | `applet/build/ImpalaApplet-none.cap` |

```bash
./gradlew :applet:buildJavacard                              # soft
./gradlew :applet:buildJavacard -Papplet.ed25519=native      # JavaCard 3.1 EdDSA
./gradlew :applet:buildJavacard -Papplet.ed25519=none        # no Stellar key
./gradlew :applet:install -Papplet.ed25519=native            # the install target loads the same variant
```

The build stages the sources of the chosen variant under
`applet/build/cap-src/<variant>` (`applet/build.xml`, `stage-cap-sources`):
the engine the variant does not use is left out (`Ed25519Native` needs the
JavaCard 3.1 API, `Ed25519Soft` the 3.0.5 one) and the variant's
`Ed25519Provider` from `applet/src/cap/<variant>/` is added. All three are
converted and pass the off-card verifier in CI. The simulator is not a variant:
it holds every engine and picks one per simulated card
(`SimulatorBibo(ed25519 = "soft" | "native" | "none")`).

Any of the three installs on any card it loads on. A card whose platform turns
out to lack a primitive of its engine (no `ALG_EC_SVDP_DH_PLAIN_XY`, no custom
curve parameters, no pure Ed25519) installs and works as a legacy card: flag
`0x80` of `GET_PERSONALIZATION` is clear and `GET_STELLAR_KEY` answers `0x623C`.
Which card each variant loads on, and what it asks that card for, is in
"Platform dependencies" below.

### Modules

| Module | What it is |
|---|---|
| `:sdk` (`com.impala:sdk`, KMP: JVM, Android, iOS) | `ImpalaSDK` (one method per INS) and, in `com.impala.sdk.flows`, the client flows every app shares: `CardIdentity` (version + personalization gates), `CardAuthFlow`, `RedemptionFlow` (compose / sign with PIN / recover the last signed tuple — never re-sign), `CreditFlow` (apply a bridge credit, report the SW), the typed `CardError`, and the one `Hex`/`UuidBytes` codec. JVM-only: `PcscBibo` (PC/SC readers via `javax.smartcardio`). Every transport passes commands through `ApduTrace.mask` before its optional `debugTrace` hook, so PIN and key bytes are never observable. |
| `:simulator` (`com.impala:simulator`, JVM, **tests and tools only**) | `SimulatorBibo` (the real applet on jcardsim, as a CAP on hardware: `ed25519 =` names the CAP variant, `platform =` the simulated card, see "Simulated hardware"; each simulated card gets its own key — jcardsim alone would give every card the same one), a JCA `TestIssuer`, `personalizedCard(...)`, `SimulatorApduServer` (`./gradlew :simulator:serve --args="--port 9443 --platform jc32"`: one simulated card over TCP for the Android emulator lane), `VpcdSimulator` (`scripts/vpcd-sim.sh`: the same card over the vsmartcard protocol, so [scardutil](scardutil/README.md) can run its fleet sequences against the applet), and `CapVariant` / `CapFile` / `:simulator:capMatrix` (which JavaCard levels load each CAP). impala-lib and the demo use it in their test source sets. |
| `:tools:issue` (CLI + library) | The issuance ceremony — see "Issuance tool". |
| `:applet` | The JavaCard applet (CAP via Ant), and its JVM unit tests. |
| `:jcardsim-jc31` (JVM, **tests and tools only**) | jcardsim as simulated card hardware: the JavaCard 3.1 and 3.2 EdDSA API the native Ed25519 engine needs (backed by the JDK), and `CardPlatform`, the model of what a JavaCard 3.0.5, 3.1 or 3.2 card has and lacks. Replaces the plain jcardsim dependency everywhere; see [`jcardsim-jc31/README.md`](jcardsim-jc31/README.md). |

## Platform dependencies: JavaCard 3.0.5, 3.1 and 3.2

Three things decide whether a CAP runs on a card:

1. **The API level the CAP was converted for.** A CAP imports the platform's
   API packages at fixed versions, and a card loads it only if it has each
   package at that version or a later one.
2. **The CAP file format** the card's loader reads.
3. **The optional algorithms** the applet asks for when it is installed. The
   JavaCard API only names them; whether a card product implements them is its
   vendor's choice, so the applet finds out at install.

The build fixes the first two per variant. The third is the card's, and the
applet is written so that a missing piece costs the Stellar key and nothing
else.

### What each CAP needs from the card

|  | `soft` (default) | `none` | `native` |
|---|---|---|---|
| CAP | `ImpalaApplet.cap` | `ImpalaApplet-none.cap` | `ImpalaApplet-native.cap` |
| **Minimum platform** | **JavaCard 3.0.5** Classic | **JavaCard 3.0.5** Classic | **JavaCard 3.1** Classic |
| Converted for (`targetsdk`) | 3.0.5 | 3.0.5 | 3.1.0 |
| Imports `javacard.framework` / `javacard.security` / `javacardx.crypto` | 1.6 / 1.6 / 1.6 | 1.6 / 1.6 / 1.6 | 1.8 / 1.7 / 1.7 |
| CAP file format | 2.1 | 2.1 | 2.3 |
| Size (applet 0.3, testnet AIDs) | 22.5 KB | 18.2 KB | 19.4 KB |
| Transient memory | 1,896 bytes | 739 bytes | 1,415 bytes |
| Stellar key and SEP-10 | yes | no | yes |

No CAP imports anything else (`java.lang` 1.0 aside): not the GlobalPlatform
API (the secure channel is the applet's own SCP03), not `javacardx.apdu`
(short APDUs only, no extended length), no vendor package. The applet is
16-bit code and its CAPs do not carry the `ACC_INT` flag, so the card need not
support the optional `int` type.

The transient memory is 739 bytes for the legacy functions (560 cleared on
reset, two of them the validated flags of the PIN objects, and 179 cleared on
deselect), 676 more for the SEP-10 challenge stage, and 481 more for the
software engine's work area. The simulator books every transient allocation
of a card, and `CardHardwareInteropTest` pins these numbers.

### Algorithms asked for at install

Every variant, for the P-256 card key, transfers, `SIGN_AUTH` and the secure
channel:

| Need | JavaCard API |
|---|---|
| ECDSA over P-256 with SHA-256, the key pair generated on the card, the curve's parameters set by the applet | `Signature.ALG_ECDSA_SHA_256`, `KeyBuilder.TYPE_EC_FP_PRIVATE` / `TYPE_EC_FP_PUBLIC` at `LENGTH_EC_FP_256`, `KeyPair.genKeyPair()` |
| SHA-256 | `MessageDigest.ALG_SHA_256` |
| AES-128, CBC and ECB without padding (SCP03, AES-CMAC) | `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD`, `Cipher.ALG_AES_BLOCK_128_ECB_NOPAD`, `KeyBuilder.TYPE_AES` at `LENGTH_AES_128` |
| Random numbers | `RandomData.ALG_SECURE_RANDOM` |
| Transactions; transient arrays cleared on reset and on deselect | `JCSystem` |

None of that is newer than the JavaCard 3.0.1 API: `buildJavacardLegacy`
converts the `none` variant for 3.0.1 (see "The API levels").

The `soft` engine, in addition:

| Need | JavaCard API | Notes |
|---|---|---|
| ECDH that returns both coordinates of the result | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` | New in the 3.0.5 API (the plain ECDH of 3.0.4, `ALG_EC_SVDP_DH_PLAIN`, returns the X coordinate only). This is what puts the engine's floor at 3.0.5 |
| 256-bit prime-field EC keys on **custom domain parameters**, with key generation | `ECKey.setFieldFP` / `setA` / `setB` / `setG` / `setR` / `setK` with the Wei25519 values (cofactor 8), `KeyPair.genKeyPair()` | A card that accepts only its built-in curves, or no cofactor but 1, has no soft engine |
| SHA-512 | `MessageDigest.ALG_SHA_512` | Optional on cards |
| A 256-bit AES key object | `KeyBuilder.TYPE_AES` at `LENGTH_AES_256` | Protected storage for the nonce secret. No AES-256 cipher is used |
| A transient EC private key | `KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` | Optional. Without it the per-signature nonce lives in a persistent key object that is cleared after every use |

The `native` engine, in addition:

| Need | JavaCard API | Notes |
|---|---|---|
| Ed25519 keys | `NamedParameterSpec.ED25519`, `KeyBuilder.buildXECKey`, `XECPublicKey`, `XECPrivateKey` | New in the 3.1 API: the 3.0.5 API has none of these classes |
| Pure EdDSA | `Signature.getInstance(digest, cipher, Cipher.PAD_NULL, false)`, tried in this order: `SIG_CIPHER_EDDSA` with `MessageDigest.ALG_NULL`, `SIG_CIPHER_EDDSA` with `ALG_SHA_512`, and the JavaCard 3.2 cipher `SIG_CIPHER_EDDSA_ED25519` with `ALG_NULL` | The 3.2 API text says `ALG_NULL`; the 3.1 text left the digest constant open, and a 3.2 platform may have Ed25519 under the per-curve name only. The engine keeps the first request that passes its self-test |
| Generating an Ed25519 key pair; loading a private key | `KeyPair.genKeyPair()`, `XECPrivateKey.setEncoded` | Loading is used once, by the self-test, with an RFC 8032 test key |

Both engines test themselves before the card's key exists, with RFC 8032 test
keys: the software engine checks that the card's ECDH and its own conversion
give a known public key, the native engine that the platform verifies a known
signature and signs one that verifies.

### How a missing piece shows

| Situation | Result |
|---|---|
| The card's API is older than the CAP's (`native` on a 3.0.5 card, `soft` or `none` on a 3.0.4 card) | The card refuses to **load** the CAP. Load the variant for that platform |
| The API is there, but an algorithm of the engine is not, its self-test fails, or the card has no memory left for the challenge stage | The applet **installs as a legacy card**: flag `0x80` of `GET_PERSONALIZATION` is clear, `GET_STELLAR_KEY` answers `0x623C`, and `SIGN_AUTH` and transfers work as on applet 0.2 |
| An algorithm every variant needs is missing | The install fails |

A card that has its Stellar key says which engine made it: the first byte of
`GET_STELLAR_KEY` is `0x01` (soft) or `0x02` (native), and the Android demo's
Card Lab shows it. The dispatch sequence in [`scardutil/`](scardutil/README.md)
makes the same check on a fleet of cards: after `INITIALIZE`,
`GET_STELLAR_KEY` answers `9000` where the card OS runs the CAP's engine and
`623C` where it does not.

### The API levels

Package versions are read from the vendored kits' export files and from the
CAPs themselves.

| JavaCard Classic | `framework` / `security` / `crypto` | What the applet uses from it | In this build |
|---|---|---|---|
| 3.0.1 | 1.4 / 1.4 / 1.4 | everything but the Stellar key | `buildJavacardLegacy`: `ImpalaApplet-legacy.cap`, without a Stellar key (18,192 bytes). Converts and verifies; not built in CI and not tested on a card |
| 3.0.4 | 1.5 / 1.5 / 1.5 | nothing more | not targeted |
| 3.0.5 | 1.6 / 1.6 / 1.6 | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` | `soft` (default), `none` |
| 3.1 | 1.8 / 1.7 / 1.7 | `NamedParameterSpec`, `XECKey`, `KeyBuilder.buildXECKey`, `Signature.SIG_CIPHER_EDDSA` | `native` |
| 3.2 | 1.9 / 1.8 / 1.8 | `Signature.SIG_CIPHER_EDDSA_ED25519`, by value (see below) | no CAP of its own: the `native` CAP runs on it |

A CAP for a lower level loads on a higher one: a card's API packages are
later, compatible versions of the ones the CAP imports. So a 3.1 or 3.2 card
takes the `soft` and `none` CAPs as well, and the choice between `soft` and
`native` on such a card is a choice of engine, not of compatibility. Prefer
`native` wherever the platform has EdDSA (see "Limits of the software engine"
below).

### JavaCard 3.2

A JavaCard 3.2 card runs the existing CAPs: no CAP is built for 3.2, and none
has to be.

- **Which CAP.** By the rule above a 3.2 card loads all three. Load `native`
  if the product has EdDSA, `soft` otherwise.
- **The 3.2 way of asking for Ed25519.** The 3.2 API adds per-curve EdDSA
  ciphers (`Signature.SIG_CIPHER_EDDSA_ED25519` = 15, `_EDDSA_ED448` = 16,
  `_EDDSAPH_ED25519` = 17, `_EDDSAPH_ED448` = 18) next to the generic 3.1 one
  (`SIG_CIPHER_EDDSA` = 13, still there and not deprecated), and says both
  kinds take `MessageDigest.ALG_NULL`. A product may have Ed25519 under
  either name or both, so the native engine asks for the generic cipher first
  and for `SIG_CIPHER_EDDSA_ED25519` after it, and keeps whichever passes its
  self-test. The engine is converted against the 3.1 API, which has no such
  name; it carries the value (15). A cipher constant is only a number the
  card is handed at run time, and a card that does not know it answers
  `NO_SUCH_ALGORITHM`. That is how one `native` CAP, converted for 3.1, serves
  3.1 and 3.2 cards.
- **The source converts for 3.2 as it is.** With the vendored JavaCard 3.2
  kit (`applet/libs/sdks/jc320v24.0_kit`) as the converter, outside the build
  (2026-11-12, JDK 17, ant-javacard v26.05.15), every combination passes the
  off-card verifier:

  | Engine | Converted for | Imports | CAP format |
  |---|---|---|---|
  | `soft` | 3.0.5 | 1.6 / 1.6 / 1.6 | 2.1 |
  | `soft` | 3.2.0 | 1.9 / 1.8 / 1.8 | 2.3 |
  | `native` | 3.1.0 | 1.8 / 1.7 / 1.7 | 2.3 |
  | `native` | 3.2.0 | 1.9 / 1.8 / 1.8 | 2.3 |

  Converting *for* 3.2 changes the import versions and nothing the applet
  does, so such a CAP would load on fewer cards and gain nothing. That is why
  there is no 3.2 variant.
- **Deprecated names.** `RandomData.ALG_SECURE_RANDOM` and `generateData()`
  have been deprecated since 3.0.5, and 3.2 also deprecates
  `RandomData.getInstance(byte)`. All three are still in the 3.2 API. The
  applet keeps them because they are the only spelling present at every level
  from 3.0.1 to 3.2 (`ALG_TRNG`, `ALG_KEYGENERATION` and `nextBytes()` start at
  3.0.5, `getInstance(byte, boolean)` at 3.2). The converter's deprecation
  warnings are expected. A product that no longer implemented
  `ALG_SECURE_RANDOM` would refuse the install of every variant; none is
  known, and the simulator does not model one.

Using the 3.2 kit as the *converter* for the existing targets is a separate
question, tied to moving the build to JDK 21:
[`docs/jdk21-javacard-kit-upgrade.md`](docs/jdk21-javacard-kit-upgrade.md).

### What the build and the tests need

| Dependency | Version | Used for |
|---|---|---|
| JDK | 17 | Launches Gradle; the CAP is converted in that JVM (see "Toolchain: JDK 17") |
| ant-javacard | v26.05.15, vendored | The `<javacard>` task: compile, convert, verify off-card |
| Oracle JavaCard SDK 3.1.0 | `applet/libs/sdks/jc310b43_kit`, vendored | Converter and verifier of all three CAPs. It holds the export files for 3.0.4, 3.0.5 and 3.1.0, which is how one kit builds both levels |
| Oracle JavaCard SDK 3.0.5u4 and 3.0.3 | `jc305u4_kit`, `jc303_kit`, vendored | `buildJavacardLegacy` only (SDK 3.0.3 carries the 3.0.1 API) |
| Oracle JavaCard SDK 3.2.0 | `jc320v24.0_kit`, vendored | No build target. ant-javacard recommends kit v26.0, and JDK 21 needs v25.0 or later |
| jcardsim | 3.0.6.0, Maven Central | The JavaCard 3.0.5 simulator behind every JVM test |
| `:jcardsim-jc31` | this repository | jcardsim as simulated hardware: the JavaCard 3.1 and 3.2 EdDSA API backed by the JDK's Ed25519, so the `native` engine is run in tests and not only compiled, and the card models of "Simulated hardware" |
| GlobalPlatformPro (`gp.jar`) | v25.10.20, vendored | Loading a CAP on a physical card. Never used in CI |

### Simulated hardware

The test lanes, the fleet tool and the demo do not run the applet on "the
simulator" but on a simulated **card**: a CAP variant on a card model. A card
model (`CardPlatform` in [`jcardsim-jc31/`](jcardsim-jc31/README.md)) is a
JavaCard level plus what that card has of the optional pieces above, and the
simulated API answers the applet accordingly. The two hardware classes and
their lesser relatives:

| Card model | It is | Default CAP (`soft`) | `native` CAP |
|---|---|---|---|
| `jc305` | a JavaCard 3.0.5 card with everything the software engine needs | Stellar key, software engine | does not load |
| `jc305-no-xy`, `-fixed-curves`, `-wrong-curve-math`, `-no-sha512`, `-no-aes256`, `-small-ram`, `-tight-ram` | a JavaCard 3.0.5 card lacking one piece | legacy card | does not load |
| `jc31`, `jc31-sha512` | a JavaCard 3.1 card with EdDSA under one digest constant or the other | Stellar key, software engine | Stellar key, platform EdDSA |
| `jc32` | a JavaCard 3.2 card with EdDSA under the generic and the per-curve cipher | Stellar key, software engine | Stellar key, platform EdDSA |
| `jc32-per-curve` | a JavaCard 3.2 card with Ed25519 under the 3.2 cipher only | Stellar key, software engine | Stellar key, platform EdDSA |
| `jc32-no-eddsa`, `jc32-no-key-import` | a JavaCard 3.2 card whose EdDSA is absent, or cannot be proven by the self-test | Stellar key, software engine | legacy card |

Every cell is a test on the real applet (`CardHardwareInteropTest`). The
`none` CAP gives a legacy card wherever it is loaded (tested on a card of each
level). Where the model is chosen:

| Integration | How |
|---|---|
| Tests in any module | `SimulatorBibo(platform = CardPlatform.JC32)`, `personalizedCard(…, platform = …)`. Naming only the CAP (`ed25519 = "native"`) picks the lowest hardware that loads it; naming only the hardware picks the CAP an operator would load on it |
| A CAP on hardware that would not load it | `CapNotLoadableException`, before anything is installed, with what the CAP imports and what the card has |
| The card over TCP (issuance tool, Android emulator) | `./gradlew :simulator:serve --args="--port 9443 --platform jc32 [--ed25519 soft]"`; `--help` lists the models |
| scardutil (vpcd) | `impala.platform=jc32` in the cfg; `scardutil/impala-sim-jc305.cfg` and `impala-sim-jc32.cfg` are the two classes as fleet targets |
| The demo kit | `DEMO_CARD_PLATFORM=jc32` in `demo/.env`; its SEP-10 lanes sign in with a card of each class in every run |
| The JVM at large | `-Dimpala.platform=<model>` and `-Dimpala.ed25519=<variant>` stand in for what a caller does not name |
| The CAP files themselves | `./gradlew :simulator:capMatrix` reads the three built CAPs and checks which levels load each; CI runs it after building them |

What stands behind each level today: on `jc305` the software engine is tested
against RFC 8032 and the JDK, and each of its primitives is taken away in turn
to show the legacy card that results; on the 3.1 and 3.2 models the native
engine is tested with EdDSA under each constant, not pure in one or both
directions, without key import, or absent; all three CAPs are converted and
verified off-card in CI, and their load matrix is checked there. **No physical
card of any level has run applet 0.3.** A card model is a description of what
a platform may do, not a product: which real cards behave like which model is
not known yet, and `scardutil/` is the tool for finding out.

## Stellar key and SEP-10

The byte-level contract (card, SDK, impala-lib, bridge, Android demo) is
[`docs/sep10-card-keys.md`](../docs/sep10-card-keys.md) in the repository root;
the commands are in [`docs/apdu.md`](docs/apdu.md).

- **The key.** Generated on the card at `INITIALIZE`, never loaded and never
  read. Its public half is a Stellar account id (`G…`). **Never fund that
  address**: nothing can sign a payment from it.
- **What it signs.** `SIGN_SEP10` takes a Stellar transaction, and the card
  parses it itself (`Sep10.java`). It signs only a SEP-10 challenge for its own
  key: sequence number 0, time bounds, no memo, manage-data operations only.
  It hashes the bytes it validated; the host never supplies the hash. A
  sequence number of 0 is valid on no network, so the signature cannot move
  funds or change an account.
- **How it is bound.** At `PERSONALIZE` the card signs two fixed messages over
  its account id and card id: one with the P-256 key naming the Stellar key,
  one with the Stellar key naming the P-256 key. `GET_STELLAR_KEY` returns
  both, and the bridge verifies both before it registers the key, so an
  address cannot be registered for an account or card it does not belong to.
- **Ed25519 on JavaCard 3.0.5 (`Ed25519Soft`).** There is no EdDSA API before
  JavaCard 3.1. Curve25519 has a short-Weierstrass form, so the card's own
  ECDH engine (`ALG_EC_SVDP_DH_PLAIN_XY` with custom domain parameters)
  computes `scalar × base point`; the applet converts the result to the
  Edwards encoding (one field inversion and six multiplications modulo
  2^255 − 19) and does the arithmetic modulo the group order itself. SHA-512 is
  the card's. Signatures are standard RFC 8032 Ed25519; the nonce also mixes
  in fresh randomness, so signing the same challenge twice gives two different
  valid signatures.
- **Ed25519 on JavaCard 3.1 and 3.2 (`Ed25519Native`).** The platform's EdDSA.
  Platforms offer pure Ed25519 under the generic cipher with one of two
  message digest constants, or under the per-curve cipher JavaCard 3.2 adds,
  so the engine tries the three requests at install and keeps the first that
  verifies an RFC 8032 test vector and signs one that verifies; a platform on
  which none does gets a legacy card.
- **Limits of the software engine.** Its scalar multiplications run inside the
  card's ECDH engine, but the final `S = r + k·a` runs in applet bytecode with
  the secret scalar in transient memory. It has no secret-dependent branch or
  table index, but it does not have the side-channel and fault hardening of a
  platform's own signature primitive, and one signature costs on the order of
  a million bytecodes (seconds on a typical card; not measured on hardware).
  Use the `native` variant where the platform has EdDSA, and treat a card's
  Stellar key as a sign-in credential, never as a key that holds value.

## Fleet compatibility testing

`scardutil/` holds the dispatch test sequence, simulator cfg and fleet example
for running the CAP across physical card types (and the simulator) with
scardutil — see [`scardutil/README.md`](scardutil/README.md).

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

`GET_VERSION` (10 bytes: `major2 minor2 rev2 hash4`) reports `0.3`: applet 0.2
brought the certified transfer protocol, 0.3 adds the Stellar key.

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
| Stellar key, both Ed25519 engines (`GET_STELLAR_KEY`) | ✓ | ✓ (`StellarKeyInteropTest`, `Ed25519SoftTest`, `Ed25519NativeTest`) | no evidence in repo | ✓ | ✗ |
| SEP-10 challenge signing (`SIGN_SEP10`) and its refusals | ✓ | ✓ (`Sep10ValidatorTest`, `StellarKeyInteropTest`, `Sep10FlowTest`) | no evidence in repo | ✓ | ✗ |
| SEP-10 against an independent server | ✓ | ✓ (opt-in: impala-lib `CardSep10LiveTest` against the SDF test anchor, both engines) | no evidence in repo | — | ✗ |
| SEP-10 against the bridge's verifier | ✓ (bridge 040) | ✓ (shared vectors: `BridgeVectorTest` and bridge `sep10::card_vectors`; no live-bridge lane yet) | no evidence in repo | — | ✗ |
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

## Compatibility: applet 0.2 cards and cards without a Stellar key

A 0.2 card answers `0x6D00` to `GET_STELLAR_KEY` and `SIGN_SEP10` and does not
set flag `0x80`; a 0.3 card built as `none`, or on a platform without the
primitives, answers `0x623C`. Both sign in with `SIGN_AUTH` exactly as before:
`ImpalaSDK.getStellarKey()` returns null for either, and impala-lib's
`CardSignIn` uses the legacy challenge for them without asking the server for
SEP-10. Nothing in the transfer protocol, the certificate or the issuance
ceremony changed, and 0.2 and 0.3 cards transfer to each other. There is no
in-place upgrade from 0.2 to 0.3 (the keys are generated at `INITIALIZE`):
reflash, then run the ceremony.

## Compatibility: applet 0.1 CAPs

Already-flashed 0.1 CAPs answer `0x6D00` to every new INS and keep the retired v0
behaviour; 0.2 receivers refuse v0 envelopes. There is no in-place upgrade:
reflash (`gp --delete/--install`) then run the ceremony.
`ImpalaSDK.requireCertifiedProtocol()` stops the SDK driving V2 flows against a
0.1 card.

## Reference

- `docs/apdu.md` — the full APDU command table and status words.
- [`../docs/sep10-card-keys.md`](../docs/sep10-card-keys.md) — SEP-10 with card-held keys: the contract between card, SDK, impala-lib, bridge and app.
- [`jcardsim-jc31/README.md`](jcardsim-jc31/README.md) — the JavaCard 3.1 EdDSA layer over jcardsim used by the tests.
- `docs/transfer-protocol.md` — byte formats, golden vectors, lifecycle,
  personalization, the counter model, and the claims → tests table.
- `docs/IOS_NFC.md` — the iOS CoreNFC transport.

# Impala-lib

Android library providing NFC smartcard communication and geolocation event dispatch for the Payala-Impala payment system.

## Overview

Impala-lib bridges Android NFC and location services with the [impala-card SDK](../impala-card/sdk). It handles two NFC protocols (NDEF data tags and IsoDep smartcard contact) and geolocation broadcast events, dispatching them to registered application listeners, and owns every card byte and tag-layer fact: sessions, the read-only diagnostic inspector, and local certificate checks.

## Build

Requires Android SDK 37 (`minSdk 24`, `compileSdk 37`), a JDK 17 to launch
Gradle (set `JAVA_HOME`; newer launchers such as 26 are not supported), and the
sibling `impala-card/` checkout. Kotlin compiles on a JDK 21 toolchain
(auto-provisioned by the foojay resolver; Robolectric's SDK-36 sandbox needs
21) and emits JVM 17 bytecode.

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 17)   # macOS; or point at any JDK 17
./gradlew assembleDebug            # Build
./gradlew testDebugUnitTest        # Unit tests (JUnit 4 + Robolectric + jcardsim, host JVM)
./gradlew lintDebug                # Lint; new findings only (lint-baseline.xml holds the rest)
./gradlew connectedAndroidTest     # Instrumented tests (requires device/emulator)
```

Depends on the impala-card SDK as `com.impala:sdk`, substituted with the
sibling build's `:sdk` project via `includeBuild("../impala-card")` in
`settings.gradle.kts` (composite build — only the SDK's Android variant is
built, not its iOS/JVM targets). The Android SDK location comes from
`ANDROID_HOME` or a `local.properties` with `sdk.dir=` (gitignored) in both
this directory and `impala-card/`.

Unit tests also use `com.impala:simulator` (substituted with `:simulator`):
the real ImpalaApplet on jcardsim plus a JCA test issuer, so card flows are
tested against the applet rather than mocks. It is a test-only dependency.

## Architecture

### NFC Flows

**Reader mode (the app's card flows)** — the only path that signs or moves value:

```
CardReaderController.enableReaderMode(onTap, onResult)   (foreground activity)
  → NFC binder thread: ImpalaCardSession.open(tag, aidHex, trace, readOnly)
                       (IsoDep.connect, then SELECT applet AID — traced and guarded)
    → onTap(session)     card stays connected: read identity, fetch the bridge
                         challenge, CardAuthenticator / CardTransfers / CardInspector
  → main thread: onResult(Result<R>)   card failures arrive as CardFlowException(CardError)
```

Two optional session decorators come from the SDK (`com.impala.sdk.apdu4j`)
and are applied **before** the SELECT, so the SELECT is traced and guarded too:

- `trace: ApduExchangeHook?` receives one `ApduExchange` per command: CLA,
  INS, P1, P2, Lc, SW, response length, elapsed time, outcome (`OK`,
  `CARD_ERROR`, `TAG_LOST`, `REFUSED`, `TRANSPORT_FAILURE`) and sequence. The
  record has **no byte and no text field** (an SDK tripwire pins this), so
  PINs, challenges, signatures and credit tails never leave the transport. The
  hook runs inside `try/catch(Throwable)` and can never replace the
  transport's own exception.
- `readOnly: Boolean` wraps the transport in `ReadOnlyBibo`, which refuses
  everything except SELECT and the non-mutating Impala commands before a byte
  is sent (`CardError.ReadOnlyRefused(command)`: "Read-only session refused
  <command>. Nothing was sent to the card."). The order is
  `TracingBibo(ReadOnlyBibo(transport))`, so a refusal shows in the trace as
  `REFUSED`. A read-only session is always traced internally (its exchanges
  feed `CardInspection.exchanges`).

A SELECT that no applet answers (`6A82`, `6999`; also `6D00` anywhere) is
`CardError.AppletNotFound(sw)` and closes the transport.

**Card sign-in: SEP-10 by default, the legacy challenge as the fallback.**
`CardSignIn` is the compatibility layer between the two mechanisms a card can
sign in with, run inside `onTap` with the card connected:

```
CardSignIn(sep10Client, legacyChallenge).signIn(session)
  identity (unissued or terminated cards stop here, before any request)
  ├─ the card advertises a Stellar key (GET_PERSONALIZATION flag 0x80, applet 0.3+)
  │    GET_STELLAR_KEY → Sep10Client.prepare (stellar.toml, challenge, client checks)
  │    → SIGN_SEP10 on the card → Sep10Client.submit
  │    → CardSignInResult.Sep10(identity, stellarAddress, tokenJson)
  └─ any other card, or one of the three fallback cases
       legacyChallenge.fetch(cardId) → SIGN_AUTH
       → CardSignInResult.Legacy(identity, signatureHex, fallback)   exchange at POST /auth/card
```

The fallback has exactly three cases (`Sep10Fallback`, decided by
`CardSignIn.fallbackFor`): no SEP-10 client was configured; the server does not
offer SEP-10 (`stellar.toml` missing or without `WEB_AUTH_ENDPOINT` /
`SIGNING_KEY`, or a 404 / 503); the server answered 401 to the signed
challenge (it does not know the card's Stellar key, or, on the Impala bridge,
the account holds a privileged role, which SEP-10 never serves). Everything
else is
thrown: a 429 (`Sep10HttpException`), a transport failure, a challenge that
fails the client checks (`Sep10Exception`: wrong signing key, network, domain
or time bounds) and a challenge the card itself refuses
(`CardError.ChallengeRefused`). A failed check is never turned into a quiet
downgrade. The card signs only what its own parser accepts as a SEP-10
challenge for its key, so a hostile server cannot use this path to obtain any
other signature. The contract is
[`docs/sep10-card-keys.md`](../docs/sep10-card-keys.md).

`com.payala.impala.stellar` holds the client side: `Sep10Client`
(`prepare` / `submit`, a one-minute `stellar.toml` cache, one refetch when the
signing key appears to have rotated), `HttpSep10Transport` (https only, http
for `localhost`, `127.0.0.1` and `10.0.2.2`; no redirects; size and time
limits), `StellarToml` (a strict reader of the three keys SEP-10 needs) and
`Ed25519`, signature verification in `java.math.BigInteger` because the
platform has no Ed25519 before API 33. Nothing in the package logs.

**System dispatch (IsoDep tapped outside reader mode)** — identity only:

```
ACTION_TECH_DISCOVERED intent
  → NfcContactActivity (finishes immediately)
    → background thread: ImpalaCardSession.open(tag, aidHex = CardAppletAid.forApp(context)).identity
                         (GET_VERSION, GET_PERSONALIZATION, GET_USER_DATA, GET_EC_PUB_KEY)
    → main thread: registered CardTapListener.onCardTapped(CardTapEvent)
```

No state-changing command is ever sent from system dispatch. The AID comes
from the consuming app's manifest (see "Consumer manifest").

> **Platform note:** this IsoDep/NDEF NFC transport is **Android-only**. iOS has no native NFC transport yet — native iOS NFC is deferred. See [`docs/ios-nfc.md`](../docs/ios-nfc.md) for the rationale (Apple NFC & SE Platform constraints) and the recommended external-reader path.

**NDEF (Data Tags)** — for reading NFC data payloads:

```
ACTION_NDEF_DISCOVERED intent
  → NdefDispatchActivity
    → ImpalaNdefHandler.handle_nfc_ndef()
    → registered NdefListener callback
```

### Geolocation

```
ACTION_LOCATION_UPDATE broadcast
  → GeoUpdateReceiver
    → ImpalaGeoHandler.handle_geo_update()
    → registered GeoUpdateListener callback
```

### Key Classes

| Class | Purpose |
|-------|---------|
| `card.ImpalaCardSession` | One connected card: `sdk`, lazily read `identity` (`CardIdentity`), idempotent `close()`, plus `transport` (`CardTransportFacts`, null for `fromBibo`), `aidHex` (the AID SELECTed; null = default selection) and `isReadOnly`. `open(tag, timeoutMs, aidHex, trace, readOnly)` and `fromBibo(bibo, aidHex, trace, readOnly)` are `@JvmOverloads`. Refuses to open on the main thread. |
| `card.CardReaderController` | Reader mode (NFC-A/B, NDEF check skipped, 1 s presence check); `onTap` on the binder thread with the session open, `onResult` on the main thread. `trace: ApduExchangeHook?` (before `sessionFactory`, so positional Kotlin callers are unaffected) reaches the default factory. `debugInjectTapOrClose(session)` (emulator lane) returns false and closes the session when reader mode is off, instead of throwing like `debugInjectTap` |
| `card.CardInspector` | `inspect(session)`: a structured read for diagnostics — GET_VERSION, GET_PERSONALIZATION, GET_USER_DATA, GET_EC_PUB_KEY, IS_CARD_ALIVE, GET_RECEIVE_STATE, GET_LAST_TRANSFER, GET_BALANCE, then GET_STELLAR_KEY for a card that advertises a Stellar key, each recorded as an `InspectionStep`, so a blank or terminated card gives a partial result. Requires `session.isReadOnly` and a background thread (`IllegalStateException` otherwise); never throws for card refusals; stops after a tag loss, or when GET_VERSION fails (the answering applet is not Impala's, so later INS bytes would mean something else). Returns a `CardInspection` |
| `card.CardInspection` | Not a `data` class; `toString()` is redacted. Version line (`0.2 · r17 · g1a2b3c4d`), state and flags, program id, currency, key fingerprints, certificate length, `cert_id`, `certVerifiedByCardIssuer` (local ECDSA), receive counter and digest, the exchanges, `stellarAddress` / `stellarEngine` / `stellarBindingVerified` / `stellarProofVerified` for a card with a Stellar key, and `holderName` / `balanceMinor` / `lastTransfer` as `Masked`. Raw public key and certificate stay private behind `certificateVerifiesUnder(issuerPublicKeyHex)` |
| `card.Masked<T>` | Wraps a personal value: `toString()` is `••••`, `reveal()` returns it. The caller decides when revealing is allowed |
| `card.CardTransportFacts` | The only place tag-layer facts are read (UID, tech list, ISO 14443-4, max transceive length, extended length, timeout, historical bytes / higher-layer response, ATQA, SAK, NFC-B data). Never throws: an unreadable fact is null, 0 or false |
| `card.CardCertificates` | `verify(issuerPub65, programId, accountId, currency, cardPub65, certDer)` — the card certificate under an issuer key, with `java.security` (API 24+); malformed input is false, nothing is logged. `fingerprint(pub65)` — first 10 bytes of SHA-256 as `ab:cd:…` |
| `card.CardStepLabels` | `labelFor(exchange)`: a string id for a tap-progress label from the trace (`card_step_reading` for SELECT and every read command, `card_step_signing_login` for SIGN_AUTH and SIGN_SEP10, `card_step_signing_transfer` for SIGN_TRANSFER_V2, `card_step_applying_credit` for VERIFY_TRANSFER_V2); null otherwise (there is no VERIFY_PIN label: no flow sends it) |
| `card.CardAppletAid` | `forApp(context)`: the AID from the app's `com.payala.impala.CARD_APPLET_AID` meta-data (see "Consumer manifest") |
| `card.ImpalaLibLog` / `LibLogSink` | The library's log calls go to `android.util.Log` **and** to an optional `@Volatile` `sink` the app installs (the demo routes them into its Activity Log); a throwing sink is ignored. `LogHygieneTest` keeps secrets and personal values out of every call |
| `card.CardAuthenticator` | The card-facing steps of both sign-in mechanisms: `signChallenge(session, challengeHex)` for `POST /auth/card`; `mechanism(session)` (`CardAuthMechanism.SEP10` for a card with a Stellar key, else `LEGACY`); `stellarKey(session)` (`GET_STELLAR_KEY`, read-only, null for a card without one); `signSep10(session, cardKey, challenge)` (the signed envelope, verified under the card's key before it is returned) |
| `card.CardSignIn` / `CardSignInResult` / `Sep10Fallback` | One card sign-in for every card and server: SEP-10 when the card and the server both have it, the legacy challenge otherwise, in the same tap. See "Card sign-in" above |
| `card.CardStellarKeys` | `bindingVerifies` / `proofVerifies`: the two cross-signatures that tie a card's Stellar key to its P-256 key, account and card id, checked locally (malformed input is false, nothing is logged) |
| `stellar.Sep10Client` / `Sep10Transport` / `HttpSep10Transport` / `StellarToml` / `Ed25519` | The SEP-10 client: `stellar.toml`, challenge, client checks (`com.impala.sdk.stellar.Sep10Challenge.verify`), submit; Ed25519 verification for API 24+ |
| `card.CardTransfers` | `redeem` (zeroes the PIN `CharArray`), `recoverLastSigned`, `previousSendSequence`, `applyCredit` |
| `card.CardErrorMessages` | String resource / message for each `CardError` (`card_error_*`, overridable by the app), including `card_error_applet_not_found`, `card_error_read_only_refused` and `card_error_challenge_refused`; `message(context, error, includeStatusWord)` appends `(SW xxxx)` only when asked (the demo asks in debug builds) |
| `card.ImpalaCardTapHandler` / `CardTapListener` | Static registry for system-dispatched taps |
| `NfcContactActivity` | Transient activity for system-dispatched IsoDep taps; reads identity only |
| `NdefDispatchActivity` | Transient activity handling NDEF message discovery |
| `IsoDepBibo` | Adapter wrapping Android `IsoDep` to implement the SDK's `BIBO` interface |
| `ImpalaNdefHandler` | Static listener registry for NDEF messages |
| `ImpalaGeoHandler` | Static listener registry for geolocation updates |
| `GeoUpdateReceiver` | BroadcastReceiver for `ACTION_LOCATION_UPDATE` intents (logs that an update arrived, never the coordinates) |

### Permissions

- `android.permission.NFC` — NFC hardware access
- `android.permission.ACCESS_FINE_LOCATION` — GPS-level location
- `android.permission.ACCESS_COARSE_LOCATION` — Network-level location

NFC hardware is declared as optional (`android:required="false"`).

### Integration

Register listeners in your application before NFC/location events fire:

```java
ImpalaNdefHandler.setNdefListener(messages -> {
    // process NDEF messages
});

ImpalaGeoHandler.setGeoUpdateListener((lat, lng, accuracy, timestamp) -> {
    // process location update
});
```

Card login from a foreground activity (Kotlin):

```kotlin
val reader = CardReaderController(this, aidHex = BuildConfig.CARD_APPLET_AID.ifEmpty { null },
    trace = { exchange -> progress.onExchange(exchange) })   // optional: header-only, never bytes
reader.enableReaderMode(
    onTap = { session ->                       // binder thread, card connected
        val identity = session.identity.requirePersonalized()
        val challenge = api.cardChallenge(identity.wireCardId)   // blocking call is fine here
        identity to CardAuthenticator.signChallenge(session, challenge)
    },
    onResult = { result -> /* main thread */ }
)
```

A read-only diagnostic read (what the demo's Card Lab does):

```kotlin
val lab = CardReaderController(this, aidHex = aid, sessionFactory = { tag ->
    ImpalaCardSession.open(tag, aidHex = aid, readOnly = true)   // mutating commands are refused before the card
})
lab.enableReaderMode(onTap = { session -> CardInspector.inspect(session) }, onResult = { /* main thread */ })
```

### Consumer manifest

`NfcContactActivity` SELECTs the AID the app declares as **application-level**
meta-data whose value is a **string resource**:

```xml
<application …>
    <meta-data android:name="com.payala.impala.CARD_APPLET_AID"
               android:resource="@string/impala_card_applet_aid" />
</application>
```

Use `android:resource`, not `android:value`: AAPT2 types an all-digit AID such
as the testnet one as a float. `CardAppletAid.forApp` resolves it: an empty
string means no SELECT (the card's default-selected applet answers); 10–32 hex
digits are that AID; absent meta-data means `ImpalaCardSession.TESTNET_APPLET_AID`
(the behaviour before the meta-data existed); anything unreadable or malformed
falls back to the testnet AID with a warning. A plain-string `android:value` is
accepted for consumers that cannot declare a resource. Activity-level
meta-data is not read.

### Resources

The library ships only `values/card_strings.xml` (`card_error_*`),
`values/card_step_strings.xml` (`card_step_*`) and `xml/nfc_tech_filter.xml`,
all overridable by the app. The Android Studio template resources it used to
carry (launcher `mipmap-*`, `drawable/ic_launcher_*`, `values/{themes,colors,strings}.xml`,
`values-night/themes.xml`) are gone, and the manifest sets no icon, label or
theme: a consuming app supplies its own `app_name`, launcher icons and theme.

### Debug source set (emulator lane)

`src/debug` (never in the release AAR) holds `TcpBibo` (a `BIBO` over TCP to
impala-card's `SimulatorApduServer`) and `DebugCardTransport`: the
`debug.impala.tcp_card` system property names the endpoint, `endpointText()`,
`openConfiguredSession(trace, readOnly)`, `openSession(host, port, …)` (throws
`SimulatorUnreachableException`, an `IOException` naming `host:port`, and
closes the socket), and `probe(host, port)` / `probeConfigured()`, which send
one NOP and report a `SimProbe` of READY, BUSY (another client holds the
one-client simulator) or DOWN.

The library's contract types (`CardIdentity`, `CardError`, `RedemptionFlow`,
`CreditFlow`, `Hex`) come from the SDK's `com.impala.sdk.flows` package, so the
Android demo and JVM tools share one implementation. The demo app consumes this
module through a composite build (`includeBuild("../impala-lib")`). iOS is out
of scope here; see [`docs/ios-nfc.md`](../docs/ios-nfc.md).

# Impala-lib

Android library providing NFC smartcard communication and geolocation event dispatch for the Payala-Impala payment system.

## Overview

Impala-lib bridges Android NFC and location services with the [impala-card SDK](../impala-card/sdk). It handles two NFC protocols (NDEF data tags and IsoDep smartcard contact) and geolocation broadcast events, dispatching them to registered application listeners.

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
  → NFC binder thread: ImpalaCardSession.open(tag)  (IsoDep.connect, SELECT applet AID)
    → onTap(session)     card stays connected: read identity, fetch the bridge
                         challenge, CardAuthenticator / CardTransfers
  → main thread: onResult(Result<R>)   card failures arrive as CardFlowException(CardError)
```

**System dispatch (IsoDep tapped outside reader mode)** — identity only:

```
ACTION_TECH_DISCOVERED intent
  → NfcContactActivity (finishes immediately)
    → background thread: ImpalaCardSession.open(tag).identity
                         (GET_VERSION, GET_PERSONALIZATION, GET_USER_DATA, GET_EC_PUB_KEY)
    → main thread: registered CardTapListener.onCardTapped(CardTapEvent)
```

No state-changing command is ever sent from system dispatch.

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
| `card.ImpalaCardSession` | One connected card: `sdk`, lazily read `identity` (`CardIdentity`), idempotent `close()`. Refuses to open on the main thread. |
| `card.CardReaderController` | Reader mode (NFC-A/B, NDEF check skipped, 250 ms presence check); `onTap` on the binder thread with the session open, `onResult` on the main thread |
| `card.CardAuthenticator` | `signChallenge(session, challengeHex)` for `POST /auth/card` |
| `card.CardTransfers` | `redeem` (zeroes the PIN `CharArray`), `recoverLastSigned`, `previousSendSequence`, `applyCredit` |
| `card.CardErrorMessages` | String resource / message for each `CardError` (`card_error_*`, overridable by the app) |
| `card.ImpalaCardTapHandler` / `CardTapListener` | Static registry for system-dispatched taps |
| `NfcContactActivity` | Transient activity for system-dispatched IsoDep taps; reads identity only |
| `NdefDispatchActivity` | Transient activity handling NDEF message discovery |
| `IsoDepBibo` | Adapter wrapping Android `IsoDep` to implement the SDK's `BIBO` interface |
| `ImpalaNdefHandler` | Static listener registry for NDEF messages |
| `ImpalaGeoHandler` | Static listener registry for geolocation updates |
| `GeoUpdateReceiver` | BroadcastReceiver for `ACTION_LOCATION_UPDATE` intents |

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
val reader = CardReaderController(this)
reader.enableReaderMode(
    onTap = { session ->                       // binder thread, card connected
        val identity = session.identity.requirePersonalized()
        val challenge = api.cardChallenge(identity.wireCardId)   // blocking call is fine here
        identity to CardAuthenticator.signChallenge(session, challenge)
    },
    onResult = { result -> /* main thread */ }
)
```

The library's contract types (`CardIdentity`, `CardError`, `RedemptionFlow`,
`CreditFlow`, `Hex`) come from the SDK's `com.impala.sdk.flows` package, so the
Android demo and JVM tools share one implementation. The demo app consumes this
module through a composite build (`includeBuild("../impala-lib")`). iOS is out
of scope here; see [`docs/ios-nfc.md`](../docs/ios-nfc.md).

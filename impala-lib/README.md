# Impala-lib

Android library providing NFC smartcard communication and geolocation event dispatch for the Payala-Impala payment system.

## Overview

Impala-lib bridges Android NFC and location services with the [impala-card SDK](../impala-card/sdk). It handles two NFC protocols (NDEF data tags and IsoDep smartcard contact) and geolocation broadcast events, dispatching them to registered application listeners.

## Build

Requires Android SDK (min 30, target 34), JDK 17 (Gradle 8.14 cannot run on
newer JDKs like 26 — set `JAVA_HOME`), and the sibling `impala-card/` checkout.

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 17)   # macOS; or point at any JDK 17
./gradlew build                    # Build
./gradlew test                     # Unit tests (JUnit 4, runs on host JVM)
./gradlew connectedAndroidTest     # Instrumented tests (requires device/emulator)
```

Depends on the impala-card SDK as `com.impala:sdk`, substituted with the
sibling build's `:sdk` project via `includeBuild("../impala-card")` in
`settings.gradle.kts` (composite build — only the SDK's Android variant is
built, not its iOS/JVM targets). The Android SDK location comes from
`ANDROID_HOME` or a `local.properties` with `sdk.dir=` (gitignored) in both
this directory and `impala-card/`.

The min SDK is 30 because the impala-card SDK's Android library declares
minSdk 30; this module cannot honestly target lower.

## Architecture

### NFC Flows

**IsoDep (Smartcard Contact)** — for communicating with Impala JavaCard applets:

```
ACTION_TECH_DISCOVERED intent
  → NfcContactActivity
    → IsoDep.connect()
    → IsoDepBibo (BIBO adapter)
    → ImpalaSDK.tx(CommandAPDU)
```

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
| `NfcContactActivity` | Transient activity handling IsoDep tag discovery, creates `ImpalaSDK` session |
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

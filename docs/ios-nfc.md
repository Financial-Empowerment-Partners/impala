# iOS NFC Support — Status and Deferral

> **Status: deferred.** The impala-card SDK builds for iOS, but there is **no native iOS NFC
> transport**. Reading the Impala card on iOS is not supported in-app today. This document explains
> why (Apple's NFC platform constraints) and the recommended path forward (an external proximity
> card reader behind the existing `BIBO` interface).

## TL;DR

- The Kotlin Multiplatform SDK compiles its **logic** (APDU encoding, SCP03 secure channel,
  signature handling) to an iOS `impala-sdk` static framework. All of it lives in `commonMain`.
- What's **missing on iOS** is the *transport*: the glue that moves raw APDU bytes between the app
  and the card. Android has `IsoDepBibo` (wrapping `android.nfc.tech.IsoDep`); iOS has no
  equivalent, no `iosMain` source set, and no CoreNFC/Swift code.
- Building that transport with Apple's built-in NFC stack is gated by Apple entitlements and — for
  any Secure Element / "tap to pay"-style flow — by Apple's **NFC & SE Platform** program
  (commercial agreement, regulatory eligibility, regional limits).
- The pragmatic alternative, which **bypasses Apple's NFC stack entirely**, is an **external
  proximity smartcard reader** attached over **Lightning/USB-C (MFi)** or **Bluetooth LE**. It
  plugs into the SDK by implementing the same one-method `BIBO` interface Android uses — no changes
  to the SDK's crypto/APDU logic.

## Background: two very different iOS NFC capabilities

The Impala flow is "the phone reads a physical JavaCard and exchanges APDUs with it." On iOS, NFC
splits into two capabilities with very different gating:

| Capability | API | What it enables | Gating |
|---|---|---|---|
| **Reader mode** | CoreNFC `NFCTagReaderSession` + `NFCISO7816Tag` (iOS 13+) | The iPhone reads an external tag/card and exchanges ISO 7816-4 APDUs — **this is what Impala needs** | A standard NFC entitlement + a **paid** developer account; significant runtime constraints |
| **Card emulation / Secure Element** | NFC & SE Platform (HCE), `CardSession` | The iPhone *acts as* a contactless card / wallet credential ("payments") | Apple's **NFC & SE Platform** program: entitlement + commercial agreement + regulatory eligibility + regional availability |

The first row is technically sufficient for reading the Impala card; the second is the heavyweight
"payments" path. Both carry enough friction that native iOS NFC is deferred (see
[Why deferred](#why-ios-nfc-support-is-deferred)).

## Apple NFC & SE Platform requirements (the "payments" path)

Historically, Apple restricted NFC card emulation and Secure Element access exclusively to Apple
Pay. Apple has since opened **Host Card Emulation (HCE)-based contactless transactions** to
third-party apps via the **NFC & SE Platform**, but it is gated:

- **Entitlement.** Apps must request the **NFC & SE Platform Entitlement**
  (`com.apple.developer.nfc.hce` family). It is **not** self-serve like ordinary capabilities.
- **Commercial agreement with Apple + fees.** Developers must enter into an agreement with Apple
  and pay associated fees to obtain the entitlement.
- **Regulatory / industry eligibility.** Apple requires that the developer meet industry and
  regulatory requirements — e.g. conforming to **PCI DSS** when handling cardholder data, holding a
  license (or partnering with a licensed entity) for regulated services, holding required
  certifications, and maintaining written security/privacy policies and vulnerability-handling
  procedures.
- **Regional availability.** HCE-based transactions were first opened in the **EEA** under Apple's
  EU Digital Markets Act commitments, then expanded to a broader list of territories (Australia,
  Brazil, Canada, Japan, New Zealand, the UK, the US, and others). Several regions require
  **iOS 18.1 or later**.

This is a **business and compliance process**, not just a coding task — disproportionate for the
project's current stage, where no iOS client app exists at all.

## CoreNFC reader-mode requirements (the lighter path that still has friction)

Even the lighter "just read the card" path (`NFCTagReaderSession` returning an `NFCISO7816Tag`)
is not free:

- **Entitlement:** `com.apple.developer.nfc.readersession.formats` (the "Near Field Communication
  Tag Reading" capability).
- **Pre-declared applet AIDs:** the app must list the application identifiers it will `SELECT` in
  the `com.apple.developer.nfc.readersession.iso7816.select-identifiers` Info.plist key. For Impala
  that means declaring the applet AID `0102030405060708` (instance AID `01020304050607080102`).
- **Usage string:** an `NFCReaderUsageDescription` in Info.plist.
- **Paid Apple Developer Program membership** — NFC entitlements are not available to free accounts.
- **Runtime constraints:** sessions are **foreground-only and user-initiated**, present a **modal
  system NFC sheet**, and **time out** (~60s). There is no Android-HCE-reader-style background
  polling. Hardware support is iPhone 7 and later, with feature variation across models.

Implementing this also requires a new `iosMain` source set, a Swift ↔ Kotlin/Native interop layer,
and an iOS host app — none of which exist today.

## Why iOS NFC support is deferred

1. **No iOS client exists.** The only mobile reference app is `impala-android-demo`. There is no
   iOS app, no `iosMain` source set, and no Swift/Kotlin-Native bridge to host an NFC transport.
2. **Even reader-mode is non-trivial.** It needs entitlement provisioning, AID pre-declaration, a
   paid account, an interop layer, and an iOS app — and then must live within foreground-only,
   modal, time-limited session constraints.
3. **The Secure Element / "payments" angle is heavyweight.** Apple's NFC & SE Platform requires an
   entitlement, a commercial agreement, regulatory eligibility, and is region-limited — a
   compliance program, not a feature flag.
4. **The SDK is already cross-platform where it matters.** The APDU/SCP03/signature logic compiles
   for iOS via `commonMain`; only the transport is missing, and it can be supplied later (natively
   or via an external reader) without touching that logic.

**Decision:** keep iOS to the shared SDK logic for now and defer native iOS NFC. When an iOS client
is on the roadmap, choose between the CoreNFC reader path (accepting the entitlement/runtime
constraints) and the external-reader path below.

## Recommended path: an external proximity card reader

An **external smartcard reader** relays APDUs between the iPhone and the Impala card, **bypassing
CoreNFC and the Secure Element entirely**. This avoids every Apple NFC gate above: no NFC
entitlement, no NFC & SE Platform program, no regional restrictions, and it works on any
iPhone/iPad (and Mac). Two attachment options:

- **Lightning / USB-C MFi accessory** — a Made-for-iPhone certified reader connects to the device
  connector and communicates through Apple's **External Accessory** framework (`ExternalAccessory`,
  iAP2 protocol). Note the **Lightning → USB-C transition** (iPhone 15 and later use USB-C); the
  accessory must be MFi-certified. Example: FEITIAN **iR301** (CCID/PC-SC; newer iOS SDKs also
  integrate via **CryptoTokenKit**).
- **Bluetooth Low Energy reader** — a BLE contactless smartcard reader relays APDUs over Bluetooth.
  This is the most common approach for iOS smartcard apps that need to avoid CoreNFC's limits.
  Examples: FEITIAN **bR500** / **bR301BLE**, Twocanoes Bluetooth Smart Card Reader (CCID/PC-SC,
  contactless + contact).

**Trade-off:** external hardware adds cost and a pairing/connection UX, but removes all Apple NFC
platform gating and works uniformly across iOS devices.

## Integration point: reuse the `BIBO` transport seam

The SDK is deliberately transport-agnostic. Its single integration seam is **`BIBO`**
("Byte-In, Byte-Out") — one method that sends raw APDU bytes to a secure element and returns the
response:

```kotlin
// impala-card/sdk/src/commonMain/kotlin/com/impala/sdk/apdu4j/BIBO.kt
interface BIBO : AutoCloseable {
    @Throws(BIBOException::class)
    fun transceive(bytes: ByteArray?): ByteArray?   // payload in, response (>= 2 bytes) out
    override fun close()
}
```

`ImpalaSDK` takes a `BIBO` in its constructor and drives all card I/O through it (via `APDUBIBO`):

```kotlin
// impala-card/sdk/src/commonMain/kotlin/com/impala/sdk/ImpalaSDK.kt
class ImpalaSDK(apduChannel: BIBO, private val scp03Keys: Triple<ByteArray, ByteArray, ByteArray>? = null)
```

Android implements `BIBO` by wrapping `IsoDep`:

```java
// impala-lib/src/main/java/com/payala/impala/IsoDepBibo.java
public byte[] transceive(byte[] bytes) throws BIBOException {
    try { return isoDep.transceive(bytes); }
    catch (IOException e) { throw new BIBOException("NFC transceive failed", e); }
}
```

(See also the demo's Kotlin port,
`impala-android-demo/app/src/main/java/com/payala/impala/demo/nfc/IsoDepBibo.kt`.)

**iOS would add an `iosMain` source set with a `BIBO` implementation** — and `ImpalaSDK`,
`APDUBIBO`, SCP03, and all APDU logic are consumed **unchanged**. Two illustrative sketches:

```kotlin
// Option A — native CoreNFC (requires the reader entitlement + paid account; see constraints above)
// impala-card/sdk/src/iosMain/kotlin/com/impala/sdk/apdu4j/CoreNFCBIBO.kt  (illustrative)
class CoreNFCBIBO(private val tag: NFCISO7816TagProtocol) : BIBO {
    override fun transceive(bytes: ByteArray?): ByteArray? {
        // Wrap the raw APDU and relay to the tag, blocking until the SE responds, then
        // append SW1/SW2 to the returned data so the response is >= 2 bytes.
        // tag.sendCommand(NFCISO7816APDU(bytes!!.toNSData())) { data, sw1, sw2, _ -> ... }
        TODO("bridge CoreNFC sendCommand() to a synchronous ByteArray")
    }
    override fun close() { /* invalidate the NFCTagReaderSession */ }
}

// Option B — external MFi/BLE reader (no CoreNFC, no Apple NFC entitlement) — RECOMMENDED
// impala-card/sdk/src/iosMain/kotlin/com/impala/sdk/apdu4j/ExternalReaderBIBO.kt  (illustrative)
class ExternalReaderBIBO(private val reader: SmartcardReader /* e.g. a FEITIAN/Twocanoes SDK handle */) : BIBO {
    override fun transceive(bytes: ByteArray?): ByteArray? = reader.transmit(bytes!!)
    override fun close() { reader.disconnect() }
}
```

Either way, the rest of the stack is identical to Android:
`CommandAPDU` → `ImpalaSDK.tx()` → `APDUBIBO.transceive()` → `BIBO.transceive()` → `ResponseAPDU`.

## When to revisit

Lift the deferral when one or more of these holds:

- An **iOS client app** is on the roadmap (so there's a host for the transport and demo flows).
- A reader-hardware decision is made (an **MFi/BLE reader** is selected) — Option B can ship without
  any Apple NFC entitlement.
- The **CoreNFC reader entitlement** path is justified and a paid developer account + AID
  pre-declaration are in place — Option A.
- A genuine **Secure Element / card-emulation** requirement appears, justifying the cost and
  compliance of Apple's **NFC & SE Platform** program.

## References

- Apple — [NFC & SE Platform for Secure Contactless Transactions](https://developer.apple.com/support/nfc-se-platform/)
- Apple — [HCE-based contactless NFC transactions for apps in the EEA](https://developer.apple.com/support/hce-transactions-in-apps/)
- Apple — [`com.apple.developer.nfc.hce` entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.nfc.hce)
- Apple — [Core NFC](https://developer.apple.com/documentation/corenfc) ·
  [`NFCTagReaderSession`](https://developer.apple.com/documentation/corenfc/nfctagreadersession) ·
  [`NFCISO7816Tag`](https://developer.apple.com/documentation/corenfc/nfciso7816tag)
- Apple — [External Accessory framework](https://developer.apple.com/documentation/externalaccessory/)
- Example reader vendors — FEITIAN iOS readers (iR301, bR500/bR301BLE; CCID/PC-SC),
  Twocanoes Bluetooth Smart Card Reader

# iOS NFC (CoreNFC) integration

The Impala KMP SDK communicates with a card through the synchronous
`BIBO` interface (`transceive(ByteArray?): ByteArray?`). On iOS the transport is
[`CoreNfcBibo`](../sdk/src/iosMain/kotlin/com/impala/sdk/apdu4j/CoreNfcBibo.kt),
which wraps a connected `NFCISO7816Tag` and bridges CoreNFC's *asynchronous*
`sendCommandAPDU` to the SDK's *synchronous* `transceive` using a
`dispatch_semaphore` (with a timeout).

> Build note: the `iosMain` source set compiles only on **macOS + Xcode**; it
> cannot be built on Linux. NFC requires a **physical iPhone** (the Simulator has
> no NFC).

## Requirements

- iOS 13+ (`NFCTagReaderSession` ISO 7816 support).
- **Capability:** "Near Field Communication Tag Reading" on the app target.
- **Entitlement** `com.apple.developer.nfc.readersession.iso7816.select-identifiers`:
  an array of AIDs the app may `SELECT`. Include the Impala applet AID
  (`0102030405060708` for testnet; the live AID for production builds — see the
  applet `build.xml`). `SELECT` of an AID not listed here fails.
- **Info.plist** `NFCReaderUsageDescription`: the message shown on the scan sheet.

```xml
<!-- Info.plist -->
<key>NFCReaderUsageDescription</key>
<string>Impala uses NFC to read your card.</string>
```

## Threading contract (read this)

`CoreNfcBibo.transceive` **blocks** until CoreNFC's completion handler fires. It
**must not** run on the main thread or on the CoreNFC session/delegate queue —
either would deadlock the thread the completion handler needs. The class guards
against a main-thread call (throws `BIBOException` immediately instead of
hanging) and times out after `timeoutMs`. Always run the SDK calls on a
background queue, as the sample does.

## Recommended integration — Swift owns the session

This is the supported path: Swift drives `NFCTagReaderSession`, connects the tag,
then runs the (synchronous) SDK on a background queue.

```swift
import CoreNFC
import impala_sdk   // the KMP static framework (baseName "impala-sdk")

final class CardReader: NSObject, NFCTagReaderSessionDelegate {
    private var session: NFCTagReaderSession?

    func scan() {
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        session?.alertMessage = "Hold your Impala card near the phone"
        session?.begin()
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case let .iso7816(iso) = first else {
            session.invalidate(errorMessage: "Card is not ISO 7816 compatible")
            return
        }
        session.connect(to: first) { error in
            if let error = error {
                session.invalidate(errorMessage: error.localizedDescription)
                return
            }
            // connect()'s completion runs on the session queue — hop to a
            // background queue BEFORE the synchronous SDK calls (deadlock guard).
            DispatchQueue.global(qos: .userInitiated).async {
                let bibo = CoreNfcBibo(tag: iso, timeoutMs: 5000)
                let sdk = ImpalaSDK(apduChannel: bibo, scp03Keys: nil)
                do {
                    let version = try sdk.getImpalaAppletVersion()
                    DispatchQueue.main.async { /* update UI with version */ }
                } catch {
                    DispatchQueue.main.async { /* show error */ }
                }
                session.invalidate()   // dismiss the scan sheet
            }
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // user cancel, timeout, tag loss, etc.
    }
}
```

## Alternative — drive the session from Kotlin (experimental)

[`CoreNfcSessionDriver`](../sdk/src/iosMain/kotlin/com/impala/sdk/nfc/CoreNfcSessionDriver.kt)
runs the session entirely in Kotlin/Native and hands back a `CoreNfcBibo` on a
background queue. It is **experimental and unverified** — the exact Kotlin/Native
shapes of several CoreNFC calls vary by Xcode/Kotlin version, so compile and test
it on-device before use. Prefer the Swift path above.

## Error handling

The transport throws `BIBOException` for: NFC error from the completion handler,
malformed command APDU, timeout, and a main-thread call. `ImpalaSDK` catches
`BIBOException` and rethrows as `ImpalaException`. Status-word errors
(`ImpalaTagLostException`, etc.) are produced upstream by `ImpalaSDK` from the
returned SW, not by the transport.

## Verification (on macOS)

1. `./gradlew :sdk:jvmTest` — proves the shared `BIBO`/APDU layer is unregressed
   (runs on Linux too).
2. `./gradlew :sdk:compileKotlinIosArm64` — compile the iOS source set.
3. `./gradlew :sdk:linkDebugFrameworkIosArm64` — link the static framework and
   confirm `CoreNfcBibo` / `ImpalaSDK` are exported.
4. Embed the framework in a SwiftUI app, add the capability + entitlement +
   `NFCReaderUsageDescription`, run on a **physical iPhone**, tap an Impala card,
   call `getImpalaAppletVersion()`.
5. Negative tests: call `transceive` on the main thread (expect an immediate
   `BIBOException`, not a hang); remove the card mid-exchange (expect a
   timeout/tag-loss `BIBOException`); cancel the sheet (expect
   `didInvalidateWithError`).
```

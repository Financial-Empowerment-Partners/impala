package com.impala.sdk.nfc

import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.apdu4j.CoreNfcBibo
import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreNFC.NFCISO7816TagProtocol
import platform.CoreNFC.NFCPollingISO14443
import platform.CoreNFC.NFCTagProtocol
import platform.CoreNFC.NFCTagReaderSession
import platform.CoreNFC.NFCTagReaderSessionDelegateProtocol
import platform.Foundation.NSError
import platform.darwin.DISPATCH_QUEUE_PRIORITY_DEFAULT
import platform.darwin.NSObject
import platform.darwin.dispatch_async
import platform.darwin.dispatch_get_global_queue

/**
 * EXPERIMENTAL convenience that drives an [NFCTagReaderSession] entirely from
 * Kotlin/Native, for consumers that prefer not to write Swift. It hands a
 * connected [CoreNfcBibo] back on a **background** queue (so the caller's
 * synchronous transceive loop never runs on the CoreNFC session queue, which
 * would deadlock).
 *
 * The RECOMMENDED integration is to own the session in Swift and construct
 * [CoreNfcBibo] from the connected tag there — see `docs/IOS_NFC.md`. This driver
 * exercises several CoreNFC interop call sites whose exact Kotlin/Native binding
 * shapes vary across Xcode/Kotlin versions; it must be compiled and exercised on
 * a macOS + physical-device setup before relying on it (it cannot be built on
 * Linux). Treat it as a starting point, not a verified component.
 */
@OptIn(ExperimentalForeignApi::class)
class CoreNfcSessionDriver(
    private val alertMessage: String = "Hold your Impala card near the phone",
    private val timeoutMs: Long = CoreNfcBibo.DEFAULT_TIMEOUT_MS,
) : NSObject(), NFCTagReaderSessionDelegateProtocol {

    private var session: NFCTagReaderSession? = null
    private var onConnected: ((CoreNfcBibo) -> Unit)? = null
    private var onError: ((BIBOException) -> Unit)? = null

    /**
     * Starts a reader session. [onConnected] receives a ready [CoreNfcBibo] on a
     * background queue; [onError] receives terminal failures (no NFC, user cancel,
     * connect failure, non-ISO7816 tag, invalidation).
     */
    fun begin(onConnected: (CoreNfcBibo) -> Unit, onError: (BIBOException) -> Unit) {
        this.onConnected = onConnected
        this.onError = onError
        val s = NFCTagReaderSession(
            pollingOption = NFCPollingISO14443,
            delegate = this,
            queue = null,
        )
        if (s == null) {
            onError(BIBOException("NFC reading is not available on this device"))
            return
        }
        s.alertMessage = alertMessage
        session = s
        s.beginSession()
    }

    /** Ends the session (e.g. on a successful read or to cancel). */
    fun invalidate() {
        session?.invalidateSession()
        session = null
    }

    override fun tagReaderSessionDidBecomeActive(session: NFCTagReaderSession) {}

    @Suppress("CONFLICTING_OVERLOADS", "PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    override fun tagReaderSession(session: NFCTagReaderSession, didDetectTags: List<*>) {
        val tag = didDetectTags.firstOrNull() as? NFCTagProtocol
        if (tag == null) {
            session.invalidateSessionWithErrorMessage("No tag detected")
            return
        }
        session.connectToTag(tag) { error ->
            if (error != null) {
                session.invalidateSessionWithErrorMessage(error.localizedDescription)
                onError?.invoke(BIBOException("Failed to connect: ${error.localizedDescription}"))
                return@connectToTag
            }
            val iso = tag as? NFCISO7816TagProtocol
            if (iso == null) {
                session.invalidateSessionWithErrorMessage("Card is not ISO 7816 compatible")
                onError?.invoke(BIBOException("Tag is not ISO 7816 compatible"))
                return@connectToTag
            }
            // Hand the connected tag back on a background queue so the synchronous
            // transceive loop never runs on the CoreNFC session queue (deadlock).
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT.toLong(), 0u)) {
                onConnected?.invoke(CoreNfcBibo(iso, timeoutMs))
            }
        }
    }

    @Suppress("CONFLICTING_OVERLOADS", "PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    override fun tagReaderSession(session: NFCTagReaderSession, didInvalidateWithError: NSError) {
        onError?.invoke(
            BIBOException("NFC session invalidated: ${didInvalidateWithError.localizedDescription}")
        )
        this.session = null
    }
}

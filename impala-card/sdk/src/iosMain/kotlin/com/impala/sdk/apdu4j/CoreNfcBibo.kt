package com.impala.sdk.apdu4j

import kotlinx.cinterop.ExperimentalForeignApi
import platform.CoreNFC.NFCISO7816APDU
import platform.CoreNFC.NFCISO7816TagProtocol
import platform.Foundation.NSData
import platform.Foundation.NSThread
import platform.darwin.DISPATCH_TIME_NOW
import platform.darwin.dispatch_semaphore_create
import platform.darwin.dispatch_semaphore_signal
import platform.darwin.dispatch_semaphore_wait
import platform.darwin.dispatch_time

/**
 * [BIBO] implementation backed by an already-connected CoreNFC
 * [NFCISO7816TagProtocol] (iOS).
 *
 * The SDK's [BIBO] contract is **synchronous**, but CoreNFC's
 * `sendCommandAPDU(_:completionHandler:)` is asynchronous. This class bridges the
 * two by blocking the calling thread on a `dispatch_semaphore_t` until the
 * completion handler fires (with a timeout). Like Android's `IsoDep.transceive`,
 * a successful response is returned as `payload + [SW1, SW2]` so the SDK's
 * `ResponseAPDU` parser (which requires `size >= 2`) is satisfied.
 *
 * Threading contract (CRITICAL): [transceive] **must not** run on the main thread
 * or on the CoreNFC session/delegate queue — blocking either deadlocks the thread
 * the completion handler needs. A main-thread call throws immediately rather than
 * hanging; the timeout protects against a lost tag or stalled session. The tag
 * connection and `NFCTagReaderSession` lifecycle are owned by the caller (Swift,
 * or [com.impala.sdk.nfc.CoreNfcSessionDriver]); see `docs/IOS_NFC.md`.
 *
 * NOTE: this file targets the Apple Kotlin/Native toolchain and can only be
 * compiled/linked on macOS with Xcode; it cannot be built on Linux.
 *
 * @param tag a connected ISO 7816 NFC tag
 * @param timeoutMs per-transceive timeout in milliseconds (default 5000)
 */
@OptIn(ExperimentalForeignApi::class)
class CoreNfcBibo(
    private val tag: NFCISO7816TagProtocol,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
) : BIBO {

    private var closed = false

    @Throws(BIBOException::class)
    override fun transceive(bytes: ByteArray?): ByteArray? {
        if (closed) throw BIBOException("CoreNfcBibo is closed")
        if (NSThread.isMainThread()) {
            throw BIBOException("CoreNfcBibo.transceive must be called off the main thread")
        }
        val cmd = bytes ?: throw BIBOException("Null command APDU")
        if (cmd.isEmpty()) throw BIBOException("Empty command APDU")

        val apdu = NFCISO7816APDU(data = cmd.toNSData())
            ?: throw BIBOException("Invalid command APDU")

        val sem = dispatch_semaphore_create(0)
            ?: throw BIBOException("Failed to create semaphore")

        // Shared mutable holders: Kotlin/Native's modern memory model (2.x) allows
        // the completion closure to capture and mutate these; the semaphore
        // wait/signal pair provides the happens-before barrier.
        var outBytes: ByteArray? = null
        var outError: String? = null

        tag.sendCommandAPDU(apdu) { responseData, sw1, sw2, error ->
            if (error != null) {
                outError = error.localizedDescription
            } else {
                val payload = (responseData as NSData?)?.toByteArray() ?: ByteArray(0)
                outBytes = payload + byteArrayOf(sw1.toByte(), sw2.toByte())
            }
            dispatch_semaphore_signal(sem)
        }

        val timedOut = dispatch_semaphore_wait(
            sem,
            dispatch_time(DISPATCH_TIME_NOW, timeoutMs * 1_000_000L),
        ) != 0L
        if (timedOut) throw BIBOException("NFC transceive timed out after ${timeoutMs}ms")

        outError?.let { throw BIBOException("NFC transceive failed: $it") }
        return outBytes ?: throw BIBOException("NFC transceive returned no data")
    }

    /** Flags the bridge closed; session invalidation is owned by the caller/driver. */
    override fun close() {
        closed = true
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS: Long = 5_000L
    }
}

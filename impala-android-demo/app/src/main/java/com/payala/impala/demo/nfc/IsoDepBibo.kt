package com.payala.impala.demo.nfc

import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import java.io.IOException

/**
 * [BIBO] implementation backed by an Android [IsoDep] NFC tag connection.
 *
 * Allows [ImpalaCardReader] to transceive APDUs over NFC to an Impala
 * JavaCard applet. The caller is responsible for calling [IsoDep.connect]
 * before constructing this adapter and [close] when finished.
 *
 * The transceive timeout is set in the constructor (default 5 s). Tag-loss
 * (card removed mid-exchange) is surfaced distinctly from other I/O errors so
 * callers can prompt a re-tap, and oversized APDUs are rejected up front.
 *
 * Ported from `com.payala.impala.IsoDepBibo` (impala-lib).
 */
class IsoDepBibo(
    private val isoDep: IsoDep,
    timeoutMs: Int = DEFAULT_TIMEOUT_MS,
) : BIBO {

    init {
        isoDep.timeout = timeoutMs
    }

    @Throws(BIBOException::class)
    override fun transceive(bytes: ByteArray?): ByteArray? {
        if (bytes != null) {
            val max = isoDep.maxTransceiveLength
            if (max > 0 && bytes.size > max) {
                throw BIBOException(
                    "APDU length ${bytes.size} exceeds IsoDep max transceive length $max " +
                        "(extendedApduSupported=${isoDep.isExtendedLengthApduSupported})"
                )
            }
        }
        return try {
            isoDep.transceive(bytes)
        } catch (e: TagLostException) {
            throw BIBOException("NFC tag lost (card removed during transceive)", e)
        } catch (e: IOException) {
            throw BIBOException("NFC transceive failed", e)
        }
    }

    override fun close() {
        try {
            isoDep.close()
        } catch (_: IOException) { }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 5000
    }
}

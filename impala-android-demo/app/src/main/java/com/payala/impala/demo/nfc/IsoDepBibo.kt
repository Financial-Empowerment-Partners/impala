package com.payala.impala.demo.nfc

import android.nfc.tech.IsoDep
import java.io.IOException

/**
 * [BIBO] implementation backed by an Android [IsoDep] NFC tag connection.
 *
 * Allows [ImpalaCardReader] to transceive APDUs over NFC to an Impala
 * JavaCard applet. The caller is responsible for calling [IsoDep.connect]
 * before constructing this adapter and [close] when finished.
 *
 * Ported from `com.payala.impala.IsoDepBibo` (impala-lib).
 */
class IsoDepBibo(private val isoDep: IsoDep) : BIBO {

    @Throws(BIBOException::class)
    override fun transceive(bytes: ByteArray?): ByteArray? {
        try {
            return isoDep.transceive(bytes)
        } catch (e: IOException) {
            throw BIBOException("NFC transceive failed", e)
        }
    }

    override fun close() {
        try {
            isoDep.close()
        } catch (_: IOException) { }
    }
}

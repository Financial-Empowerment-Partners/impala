package com.payala.impala.demo.nfc

/**
 * Extension on top of [BIBO] that allows transmitting [CommandAPDU]s and
 * receiving [ResponseAPDU]s. Drop-in replacement for code that uses
 * `javax.smartcardio` APDU classes.
 *
 * Ported from `com.impala.sdk.apdu4j.APDUBIBO`.
 */
class APDUBIBO(private val bibo: BIBO) : BIBO {

    @Throws(BIBOException::class)
    fun transmit(command: CommandAPDU): ResponseAPDU {
        val resp = transceive(command.bytes) ?: byteArrayOf()
        return ResponseAPDU(resp)
    }

    @Throws(BIBOException::class)
    fun transceive(command: CommandAPDU): ByteArray? {
        if (command.bytes.isEmpty()) {
            throw IllegalStateException()
        }
        return bibo.transceive(command.bytes)
    }

    override fun transceive(bytes: ByteArray?): ByteArray? {
        return bibo.transceive(bytes)
    }

    override fun close() {
        bibo.close()
    }
}

package com.payala.impala.demo.nfc

/**
 * Byte-level I/O interface for transceiving raw bytes to a secure element.
 *
 * Comparable to `IsoDep.transceive()` (Android), `SCardTransmit()` (PC/SC),
 * `CardChannel.transmit()` (javax.smartcardio).
 *
 * Ported from `com.impala.sdk.apdu4j.BIBO`.
 */
interface BIBO : AutoCloseable {
    /**
     * Transceives bytes to a secure element, synchronously.
     *
     * @param bytes payload to send
     * @return the bytes returned from the SE (size should always be >= 2)
     * @throws BIBOException when transceive fails
     */
    @Throws(BIBOException::class)
    fun transceive(bytes: ByteArray?): ByteArray?

    override fun close()
}

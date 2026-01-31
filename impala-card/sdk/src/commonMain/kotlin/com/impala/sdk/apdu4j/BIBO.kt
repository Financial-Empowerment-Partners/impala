package com.impala.sdk.apdu4j

interface BIBO : AutoCloseable {
    /**
     * Transceives a bunch of bytes to a secure element, synchronously.
     *
     *
     * Comparable to:
     *
     *
     * IsoDep.transceive() in Android
     * SCardTransmit() in PC/SC
     * CardChannel.transmit(ByteBuffer, ByteBuffer) in javax.smartcardio
     * Channel.transmit() in OpenMobileAPI
     *
     * @param bytes payload
     * @return the bytes returned from the SE. The size should always be &gt;= 2 bytes
     * @throws BIBOException when transceive fails
     */
    @Throws(BIBOException::class)
    fun transceive(bytes: ByteArray?): ByteArray?

    override fun close()
}

package com.impala.sdk.apdu4j

// Extension on top of BIBO, not unline CardChannel, which allows
// to transmit APDU-s back and forth over BIBO. Drop-in replacement for
// code that currently uses javax.smartcardio *APDU, with a new import for *APDU
class APDUBIBO(bibo: BIBO) : BIBO {
    val bibo: BIBO = bibo

    @Throws(BIBOException::class)
    fun transmit(command: CommandAPDU): ResponseAPDU {
        var resp = transceive(command.bytes) ?: byteArrayOf()
        return ResponseAPDU(resp)
    }

//    @Throws(BIBOException::class)
//    fun transceive(bytes: ByteArray): ByteArray? {
//        return bibo.transceive(bytes)
//    }

    @Throws(BIBOException::class)
    fun transceive(command: CommandAPDU): ByteArray? {
        if(command.bytes.isEmpty()){
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

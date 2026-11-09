package com.impala.sdk.apdu4j

/**
 * Thrown by [ReadOnlyBibo] instead of forwarding a command outside the
 * read-only allow-list. It is a [BIBOException], so `ImpalaSDK.tx` keeps it as
 * the cause and `CardError.from` maps it to `CardError.ReadOnlyRefused`.
 *
 * [cla] and [ins] are -1 when the command was too short to carry them.
 */
open class ReadOnlyViolationException(val cla: Int, val ins: Int) :
    BIBOException("read-only session refused " + (if (ins < 0) "a malformed command" else ApduNames.ins(cla, ins)))

/**
 * A [BIBO] that forwards only SELECT and [ApduNames.READ_ONLY_INS] at CLA 0x00
 * and refuses everything else **before** the inner transport sees a byte:
 * every mutating, PIN, signing, secure-channel (CLA 0x80/0x84) or unknown
 * command, and any command too short to carry a header (fail closed).
 */
class ReadOnlyBibo(private val inner: BIBO) : BIBO {
    override fun transceive(bytes: ByteArray?): ByteArray? {
        if (bytes == null || bytes.size < 4) {
            throw ReadOnlyViolationException(
                bytes?.getOrNull(0)?.let { it.toInt() and 0xFF } ?: -1,
                bytes?.getOrNull(1)?.let { it.toInt() and 0xFF } ?: -1
            )
        }
        val cla = bytes[0].toInt() and 0xFF
        val ins = bytes[1].toInt() and 0xFF
        if (!ApduNames.isReadOnly(cla, ins)) throw ReadOnlyViolationException(cla, ins)
        return inner.transceive(bytes)
    }

    override fun close() = inner.close()
}

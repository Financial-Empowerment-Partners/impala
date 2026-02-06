package com.payala.impala.demo.nfc

/**
 * Represents an ISO 7816-4 Response APDU received from a smartcard.
 *
 * The raw bytes are structured as: `[data...] [SW1] [SW2]`, where `SW1` and
 * `SW2` form the 2-byte status word. A response must contain at least the
 * status word (2 bytes); the data portion may be empty.
 *
 * Ported from `com.impala.sdk.apdu4j.ResponseAPDU`.
 *
 * @param apdu raw response bytes (must be at least 2 bytes)
 * @throws IllegalArgumentException if [apdu] is shorter than 2 bytes
 */
class ResponseAPDU(private val apdu: ByteArray) {

    init {
        if (apdu.size < 2) {
            throw IllegalArgumentException("APDU must be at least 2 bytes!")
        }
    }

    /** Status byte 1 (the second-to-last byte), as an unsigned int (0x00-0xFF). */
    val sW1: Int
        get() = apdu[apdu.size - 2].toInt() and 0xff

    /** Status byte 2 (the last byte), as an unsigned int (0x00-0xFF). */
    val sW2: Int
        get() = apdu[apdu.size - 1].toInt() and 0xff

    /** Combined 2-byte status word: `(SW1 shl 8) or SW2`. 0x9000 = success. */
    val sw: Int
        get() = (sW1 shl 8) or this.sW2

    /** Response data payload (everything except the trailing 2-byte status word). */
    val data: ByteArray
        get() = apdu.copyOf(apdu.size - 2)

    /** Complete raw response bytes including the status word. */
    val bytes: ByteArray
        get() = apdu.copyOf()

    /** The 2-byte status word as a ByteArray: `[SW1, SW2]`. */
    val sWBytes: ByteArray
        get() = apdu.copyOfRange(apdu.size - 2, apdu.size)
}

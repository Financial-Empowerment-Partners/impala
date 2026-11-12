package com.impala.sdk.stellar

/**
 * Stellar account ids (SEP-23 strkey, `G…`) and nothing else: the 56-character
 * RFC 4648 base32 (uppercase, no padding) of `0x30 ‖ ed25519 public key(32) ‖
 * CRC16-XModem(first 33 bytes), little-endian`.
 *
 * Decoding is strict: exact length, uppercase alphabet only, version byte
 * `0x30` (so muxed `M…`, seeds `S…` and every other strkey kind are refused),
 * valid checksum, and canonical trailing bits (vacuous at 56 characters, which
 * carry exactly 35 bytes, but enforced by the decoder regardless).
 */
object StrKey {
    private const val VERSION_ACCOUNT_ID = 6 shl 3 // 0x30, 'G'
    private const val ACCOUNT_ID_LENGTH = 56
    private const val PAYLOAD_LENGTH = 35
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** The `G…` address of a 32-byte Ed25519 public key. */
    fun encodeAccountId(publicKey: ByteArray): String {
        require(publicKey.size == 32) { "an account id public key is 32 bytes, got ${publicKey.size}" }
        val payload = ByteArray(PAYLOAD_LENGTH)
        payload[0] = VERSION_ACCOUNT_ID.toByte()
        publicKey.copyInto(payload, 1)
        val crc = crc16XModem(payload, 0, 33)
        payload[33] = (crc and 0xFF).toByte()
        payload[34] = (crc ushr 8).toByte()
        return base32Encode(payload)
    }

    /** The 32-byte public key of [address]; [IllegalArgumentException] when it is not a valid account id. */
    fun decodeAccountId(address: String): ByteArray {
        require(address.length == ACCOUNT_ID_LENGTH) { "an account id is $ACCOUNT_ID_LENGTH characters, got ${address.length}" }
        val payload = base32Decode(address)
        require(payload.size == PAYLOAD_LENGTH) { "an account id decodes to $PAYLOAD_LENGTH bytes" }
        require(payload[0] == VERSION_ACCOUNT_ID.toByte()) { "not an account id (version byte)" }
        val crc = crc16XModem(payload, 0, 33)
        val stored = (payload[33].toInt() and 0xFF) or ((payload[34].toInt() and 0xFF) shl 8)
        require(crc == stored) { "account id checksum mismatch" }
        return payload.copyOfRange(1, 33)
    }

    fun isValidAccountId(address: String): Boolean = try {
        decodeAccountId(address)
        true
    } catch (_: IllegalArgumentException) {
        false
    }

    /** CRC-16/XMODEM: polynomial 0x1021, initial value 0, no reflection, no final XOR. */
    internal fun crc16XModem(data: ByteArray, from: Int, to: Int): Int {
        var crc = 0
        for (i in from until to) {
            crc = crc xor ((data[i].toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if (crc and 0x8000 != 0) (crc shl 1) xor 0x1021 else crc shl 1
                crc = crc and 0xFFFF
            }
        }
        return crc
    }

    internal fun base32Encode(data: ByteArray): String {
        val out = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                out.append(ALPHABET[(buffer ushr (bits - 5)) and 0x1F])
                bits -= 5
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) out.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return out.toString()
    }

    /**
     * Strict RFC 4648 base32 without padding: uppercase alphabet only, a length
     * that a whole number of bytes can produce, and zero trailing bits.
     */
    internal fun base32Decode(text: String): ByteArray {
        require(text.length * 5 % 8 < 5) { "base32 length ${text.length} is not a whole number of bytes" }
        val out = ByteArray(text.length * 5 / 8)
        var buffer = 0
        var bits = 0
        var n = 0
        for (c in text) {
            val v = ALPHABET.indexOf(c)
            require(v >= 0) { "not an uppercase base32 character: '$c'" }
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                out[n++] = (buffer ushr (bits - 8)).toByte()
                bits -= 8
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        require(buffer == 0) { "non-canonical base32 trailing bits" }
        return out
    }
}

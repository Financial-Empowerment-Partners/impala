package com.impala.sdk.flows

/**
 * The one hex codec for card flows: lowercase, no separators, strict on decode
 * (even length, hex digits only, optional exact byte length). Wire forms the
 * bridge pins — `card_id`, `ec_pubkey`, signatures, challenges — all go
 * through here so no caller re-implements it.
 */
object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            out.append(DIGITS[v ushr 4]).append(DIGITS[v and 0x0F])
        }
        return out.toString()
    }

    /**
     * Decodes [hex] (either case). Throws [IllegalArgumentException] on odd
     * length, a non-hex character, or a byte length other than [expectedBytes].
     */
    fun decode(hex: String, expectedBytes: Int? = null): ByteArray {
        require(hex.length % 2 == 0) { "hex string has odd length ${hex.length}" }
        if (expectedBytes != null) {
            require(hex.length == expectedBytes * 2) { "expected ${expectedBytes * 2} hex chars, got ${hex.length}" }
        }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = nibble(hex[2 * i])
            val lo = nibble(hex[2 * i + 1])
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun nibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("not a hex digit: '$c'")
    }
}

/** RFC-4122 UUID <-> 16 big-endian bytes, without a platform UUID type. */
object UuidBytes {
    /** Parses a dashed (8-4-4-4-12) or bare 32-hex UUID, either case. */
    fun parse(uuid: String): ByteArray {
        val bare = when (uuid.length) {
            36 -> {
                require(uuid[8] == '-' && uuid[13] == '-' && uuid[18] == '-' && uuid[23] == '-') { "malformed UUID: $uuid" }
                uuid.replace("-", "")
            }
            32 -> uuid
            else -> throw IllegalArgumentException("malformed UUID (length ${uuid.length})")
        }
        return Hex.decode(bare, 16)
    }

    /** Lowercase dashed form. */
    fun format(bytes: ByteArray): String {
        require(bytes.size == 16) { "UUID must be 16 bytes" }
        val h = Hex.encode(bytes)
        return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
    }

    /** True when [a] and [b] (dashed or 32-hex, any case) denote the same UUID. */
    fun same(a: String, b: String): Boolean =
        runCatching { parse(a).contentEquals(parse(b)) }.getOrDefault(false)
}

package com.impala.sdk.stellar

/** A structural XDR failure: short data, a bad length, non-zero padding or trailing bytes. */
internal class XdrException(message: String) : Exception(message)

/**
 * Strict RFC 4506 reader over a byte array: big-endian, every variable-length
 * item bounded by its declared maximum, padding checked to be zero, and
 * [requireEnd] for an exact end of data. [position] is the offset into the
 * original array, so callers can slice the exact bytes they parsed.
 */
internal class XdrReader(private val data: ByteArray) {
    var position: Int = 0
        private set

    val remaining: Int get() = data.size - position

    private fun need(n: Int) {
        if (n < 0 || n > remaining) throw XdrException("truncated: need $n bytes at offset $position, have $remaining")
    }

    /** An unsigned 32-bit integer, as a non-negative Long. */
    fun uint32(): Long {
        need(4)
        var v = 0L
        repeat(4) { v = (v shl 8) or (data[position++].toLong() and 0xFF) }
        return v
    }

    /** A signed 32-bit integer (enum tags, union discriminants). */
    fun int32(): Int = uint32().toInt()

    /** A signed 64-bit integer. */
    fun int64(): Long {
        need(8)
        var v = 0L
        repeat(8) { v = (v shl 8) or (data[position++].toLong() and 0xFF) }
        return v
    }

    /** Fixed-length opaque of [n] bytes, followed by zero padding to a multiple of 4. */
    fun fixedOpaque(n: Int): ByteArray {
        need(n)
        val out = data.copyOfRange(position, position + n)
        position += n
        padding(n)
        return out
    }

    /** Variable-length opaque `opaque<max>`: a uint32 length (at most [max]), the bytes and zero padding. */
    fun varOpaque(max: Int): ByteArray {
        val len = uint32()
        if (len > max) throw XdrException("opaque length $len exceeds maximum $max at offset ${position - 4}")
        return fixedOpaque(len.toInt())
    }

    /** `string<max>`, as raw bytes (Stellar strings are not required to be UTF-8). */
    fun string(max: Int): ByteArray = varOpaque(max)

    /** An XDR optional (`T*`): true when present. Any discriminant other than 0 or 1 is malformed. */
    fun optional(): Boolean = when (val flag = uint32()) {
        0L -> false
        1L -> true
        else -> throw XdrException("optional flag $flag at offset ${position - 4}")
    }

    /** A variable-length array count `T<max>`. */
    fun count(max: Int): Int {
        val n = uint32()
        if (n > max) throw XdrException("array count $n exceeds maximum $max at offset ${position - 4}")
        return n.toInt()
    }

    fun requireEnd() {
        if (remaining != 0) throw XdrException("$remaining trailing bytes at offset $position")
    }

    private fun padding(n: Int) {
        val pad = (4 - n % 4) % 4
        need(pad)
        repeat(pad) {
            if (data[position] != 0.toByte()) throw XdrException("non-zero padding at offset $position")
            position++
        }
    }
}

/** Minimal XDR writer for the few items the SDK appends (no re-encoding of anything it parsed). */
internal class XdrWriter {
    private var buf = ByteArray(64)
    private var size = 0

    private fun ensure(n: Int) {
        if (size + n > buf.size) buf = buf.copyOf(maxOf(buf.size * 2, size + n))
    }

    fun uint32(v: Long): XdrWriter {
        require(v in 0..0xFFFF_FFFFL) { "uint32 out of range: $v" }
        ensure(4)
        for (shift in intArrayOf(24, 16, 8, 0)) buf[size++] = (v ushr shift).toByte()
        return this
    }

    fun int64(v: Long): XdrWriter {
        ensure(8)
        for (i in 7 downTo 0) buf[size++] = (v ushr (8 * i)).toByte()
        return this
    }

    fun raw(bytes: ByteArray): XdrWriter {
        ensure(bytes.size)
        bytes.copyInto(buf, size)
        size += bytes.size
        return this
    }

    fun fixedOpaque(bytes: ByteArray): XdrWriter {
        raw(bytes)
        val pad = (4 - bytes.size % 4) % 4
        ensure(pad)
        repeat(pad) { buf[size++] = 0 }
        return this
    }

    fun varOpaque(bytes: ByteArray): XdrWriter = uint32(bytes.size.toLong()).fixedOpaque(bytes)

    fun toByteArray(): ByteArray = buf.copyOf(size)
}

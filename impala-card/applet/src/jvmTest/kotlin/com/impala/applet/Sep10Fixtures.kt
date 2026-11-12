package com.impala.applet

import java.nio.ByteBuffer

/**
 * Hand-built Stellar `Transaction` XDR for the SEP-10 tests, with every field
 * of the grammar in docs/sep10-card-keys.md (section 3.3) open to mutation.
 */
internal object Sep10Xdr {
    fun u32(v: Long): ByteArray = ByteBuffer.allocate(4).putInt(v.toInt()).array()
    fun u32(v: Int): ByteArray = u32(v.toLong())
    fun u64(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()
    fun padded(b: ByteArray): ByteArray = b + ByteArray((4 - b.size % 4) % 4)

    const val MANAGE_DATA = 10

    /** One operation. `source == null` leaves the optional source account out. */
    fun op(
        source: ByteArray?,
        name: ByteArray,
        value: ByteArray?,
        type: Int = MANAGE_DATA,
        sourceKeyType: Int = 0,
        namePadding: ByteArray? = null,
        valueFlag: Int? = null,
        valuePadding: ByteArray? = null,
        nameLength: Long? = null,
        valueLength: Long? = null
    ): ByteArray {
        val src = if (source == null) u32(0) else u32(1) + u32(sourceKeyType) + source
        val n = u32(nameLength ?: name.size.toLong()) + name + (namePadding ?: ByteArray((4 - name.size % 4) % 4))
        val v = when {
            value == null -> u32(valueFlag ?: 0)
            else -> u32(valueFlag ?: 1) + u32(valueLength ?: value.size.toLong()) + value +
                (valuePadding ?: ByteArray((4 - value.size % 4) % 4))
        }
        return src + u32(type) + n + v
    }

    fun op(source: ByteArray?, name: String, value: ByteArray?): ByteArray = op(source, name.toByteArray(), value)

    fun tx(
        source: ByteArray,
        ops: List<ByteArray>,
        fee: Long = 100,
        sequence: Long = 0,
        condType: Int = 1,
        minTime: Long = 1_700_000_000,
        maxTime: Long = 1_700_000_900,
        memo: ByteArray = u32(0),
        ext: ByteArray = u32(0),
        sourceKeyType: Int = 0,
        opCount: Long? = null,
        timeBounds: ByteArray? = null
    ): ByteArray =
        u32(sourceKeyType) + source + u32(fee) + u64(sequence) + u32(condType) +
            (timeBounds ?: (u64(minTime) + u64(maxTime))) + memo +
            u32(opCount ?: ops.size.toLong()) + ops.fold(ByteArray(0)) { a, b -> a + b } + ext

    /** The challenge a SEP-10 server issues: the auth entry, then `web_auth_domain`. */
    fun challenge(
        cardKey: ByteArray,
        serverKey: ByteArray,
        homeDomain: String = "bridge.example.org",
        nonce: ByteArray = ByteArray(64) { ('A'.code + it % 26).toByte() },
        extraOps: List<ByteArray> = emptyList()
    ): ByteArray = tx(
        serverKey,
        listOf(
            op(cardKey, "$homeDomain auth", nonce),
            op(serverKey, "web_auth_domain", homeDomain.toByteArray())
        ) + extraOps
    )
}

/**
 * An independent reading of the same grammar, written the obvious way with a
 * [ByteBuffer] and exceptions. `null` means accepted; otherwise the status
 * word the card must answer. The on-card parser has to agree with it on every
 * input the tests can invent.
 */
internal object Sep10Reference {
    const val MALFORMED = 0x6240
    const val SEQUENCE_NOT_ZERO = 0x6241
    const val NOT_MANAGE_DATA = 0x6242
    const val WRONG_ACCOUNT = 0x6243
    const val NOT_AUTH_CHALLENGE = 0x6244
    const val NO_TIME_BOUNDS = 0x6245

    private class Refused(val sw: Int) : Exception()

    fun verdict(tx: ByteArray, cardKey: ByteArray): Int? = try {
        parse(ByteBuffer.wrap(tx), cardKey)
        null
    } catch (e: Refused) {
        e.sw
    }

    private fun ByteBuffer.need(n: Int) {
        if (remaining() < n) throw Refused(MALFORMED)
    }

    private fun ByteBuffer.int32(): Long {
        need(4)
        return int.toLong() and 0xFFFFFFFFL
    }

    private fun ByteBuffer.bytes(n: Int): ByteArray {
        need(n)
        return ByteArray(n).also { get(it) }
    }

    private fun ByteBuffer.opaque(max: Int, min: Int): ByteArray {
        val len = int32()
        if (len < min || len > max) throw Refused(MALFORMED)
        val body = bytes(len.toInt())
        if (bytes((4 - len.toInt() % 4) % 4).any { it != 0.toByte() }) throw Refused(MALFORMED)
        return body
    }

    private fun parse(b: ByteBuffer, cardKey: ByteArray) {
        b.need(36)
        if (b.int32() != 0L) throw Refused(MALFORMED)
        if (b.bytes(32).contentEquals(cardKey)) throw Refused(WRONG_ACCOUNT)
        b.int32() // fee
        b.need(8)
        if (b.long != 0L) throw Refused(SEQUENCE_NOT_ZERO)
        b.need(4)
        if (b.int32() != 1L) throw Refused(NO_TIME_BOUNDS)
        b.need(16)
        b.long // minTime
        if (b.long == 0L) throw Refused(NO_TIME_BOUNDS)
        if (b.int32() != 0L) throw Refused(MALFORMED)
        val count = b.int32()
        if (count < 1 || count > 5) throw Refused(NOT_MANAGE_DATA)
        for (i in 0 until count.toInt()) {
            b.need(40)
            if (b.int32() != 1L) throw Refused(MALFORMED)
            if (b.int32() != 0L) throw Refused(MALFORMED)
            val source = b.bytes(32)
            if (b.int32() != 10L) throw Refused(NOT_MANAGE_DATA)
            val name = b.opaque(64, 1)
            val value: ByteArray? = when (b.int32()) {
                0L -> null
                1L -> b.opaque(64, 0)
                else -> throw Refused(MALFORMED)
            }
            val mine = source.contentEquals(cardKey)
            if (i == 0) {
                if (!mine) throw Refused(WRONG_ACCOUNT)
                val auth = name.size >= 6 && String(name.copyOfRange(name.size - 5, name.size), Charsets.ISO_8859_1) == " auth"
                if (!auth || value == null || value.isEmpty()) throw Refused(NOT_AUTH_CHALLENGE)
            } else if (mine) {
                throw Refused(WRONG_ACCOUNT)
            }
        }
        if (b.int32() != 0L) throw Refused(MALFORMED)
        if (b.hasRemaining()) throw Refused(MALFORMED)
    }
}

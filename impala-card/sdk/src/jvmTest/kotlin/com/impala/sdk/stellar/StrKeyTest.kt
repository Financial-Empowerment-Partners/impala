package com.impala.sdk.stellar

import com.impala.sdk.flows.Hex
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StrKeyTest {
    /** SEP-23 test vector: a valid account id and its key. */
    private val sep23 = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
    private val sep23Key = "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"

    /**
     * Independent reference: the address as one 280-bit big-endian number
     * (56 × 5 bits = 35 bytes exactly), and a table-driven CRC-16/XMODEM.
     */
    private fun referenceDecode(address: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var n = BigInteger.ZERO
        for (c in address) n = n.shiftLeft(5).or(BigInteger.valueOf(alphabet.indexOf(c).toLong().also { check(it >= 0) }))
        val raw = n.toByteArray().let { if (it.size > 35) it.copyOfRange(it.size - 35, it.size) else ByteArray(35 - it.size) + it }
        return raw
    }

    private val crcTable = IntArray(256) { i ->
        var c = i shl 8
        repeat(8) { c = if (c and 0x8000 != 0) (c shl 1) xor 0x1021 else c shl 1 }
        c and 0xFFFF
    }

    private fun referenceCrc(data: ByteArray): Int =
        data.fold(0) { crc, b -> ((crc shl 8) xor crcTable[((crc ushr 8) xor (b.toInt() and 0xFF)) and 0xFF]) and 0xFFFF }

    private fun referenceEncode(version: Int, body: ByteArray): String {
        val payload = byteArrayOf(version.toByte()) + body
        val crc = referenceCrc(payload)
        val all = payload + byteArrayOf((crc and 0xFF).toByte(), (crc ushr 8).toByte())
        check(all.size * 8 % 5 == 0)
        val n = BigInteger(1, all)
        val chars = all.size * 8 / 5
        return (0 until chars).joinToString("") { i -> "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[n.shiftRight(5 * (chars - 1 - i)).toInt() and 0x1F].toString() }
    }

    @Test
    fun `the reference CRC is CRC-16 XMODEM (check value 0x31C3)`() {
        assertEquals(0x31C3, referenceCrc("123456789".toByteArray()))
        assertEquals(0x31C3, StrKey.crc16XModem("123456789".toByteArray(), 0, 9))
    }

    @Test
    fun `the SEP-23 vector decodes to its key, by the SDK and by the independent reference`() {
        assertContentEquals(Hex.decode(sep23Key), StrKey.decodeAccountId(sep23))
        val ref = referenceDecode(sep23)
        assertEquals(0x30, ref[0].toInt())
        assertEquals(sep23Key, Hex.encode(ref.copyOfRange(1, 33)))
        val crc = referenceCrc(ref.copyOfRange(0, 33))
        assertEquals(crc, (ref[33].toInt() and 0xFF) or ((ref[34].toInt() and 0xFF) shl 8))
        assertEquals(sep23, StrKey.encodeAccountId(Hex.decode(sep23Key)))
        assertEquals(sep23, referenceEncode(0x30, Hex.decode(sep23Key)))
        assertTrue(StrKey.isValidAccountId(sep23))
    }

    @Test
    fun `known addresses - the zero key and the SDF reference anchor signing key`() {
        assertEquals("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", StrKey.encodeAccountId(ByteArray(32)))
        // testanchor.stellar.org SIGNING_KEY and the source key of a challenge it issued (see Sep10ChallengeTest)
        assertEquals(
            "8eb38c2e51b49b31300cd725f6e6f35df24ae8d4c10566e2bdae1ed91abfadad",
            Hex.encode(StrKey.decodeAccountId("GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR"))
        )
    }

    @Test
    fun `random keys round-trip and agree with the reference encoder`() {
        val rnd = java.security.SecureRandom()
        repeat(500) {
            val key = ByteArray(32).also(rnd::nextBytes)
            val g = StrKey.encodeAccountId(key)
            assertEquals(56, g.length)
            assertEquals('G', g[0])
            assertEquals(referenceEncode(0x30, key), g)
            assertContentEquals(key, StrKey.decodeAccountId(g))
        }
    }

    @Test
    fun `rejections - length, version byte, checksum, alphabet, case, padding`() {
        val bad = mapOf(
            "55 characters" to sep23.dropLast(1),
            "57 characters" to sep23 + "A",
            "empty" to "",
            "lowercase" to sep23.lowercase(),
            "one lowercase character" to sep23.substring(0, 10) + sep23[10].lowercaseChar() + sep23.substring(11),
            "digit 1" to sep23.substring(0, 5) + "1" + sep23.substring(6),
            "digit 0" to sep23.substring(0, 5) + "0" + sep23.substring(6),
            "digit 8" to sep23.substring(0, 5) + "8" + sep23.substring(6),
            "padding" to sep23.dropLast(1) + "=",
            "space" to " " + sep23.drop(1),
            "bad checksum" to sep23.dropLast(1) + (if (sep23.last() == 'A') 'B' else 'A'),
            "one flipped data character" to sep23.substring(0, 20) + (if (sep23[20] == 'A') 'B' else 'A') + sep23.substring(21),
            "seed version (S...)" to referenceEncode(18 shl 3, ByteArray(32) { 7 }),
            "pre-auth tx version (T...)" to referenceEncode(19 shl 3, ByteArray(32) { 7 }),
            "hash-x version (X...)" to referenceEncode(23 shl 3, ByteArray(32) { 7 }),
            "muxed version, 56 chars" to referenceEncode(12 shl 3, ByteArray(32) { 7 }),
            "muxed-account length (69 chars)" to "M" + sep23.drop(1) + "A".repeat(13),
        )
        for ((name, address) in bad) {
            assertFailsWith<IllegalArgumentException>(name) { StrKey.decodeAccountId(address) }
            assertFalse(StrKey.isValidAccountId(address), name)
        }
        assertEquals('S', bad.getValue("seed version (S...)")[0])
        assertFailsWith<IllegalArgumentException> { StrKey.encodeAccountId(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { StrKey.encodeAccountId(ByteArray(33)) }
    }

    @Test
    fun `the base32 decoder refuses non-canonical trailing bits and impossible lengths`() {
        // 2 characters = 10 bits = 1 byte + 2 trailing bits, which must be zero
        assertContentEquals(byteArrayOf(0), StrKey.base32Decode("AA"))
        assertFailsWith<IllegalArgumentException> { StrKey.base32Decode("AB") }
        assertFailsWith<IllegalArgumentException> { StrKey.base32Decode("AD") }
        // lengths 1, 3 and 6 (mod 8) cannot come from whole bytes
        for (n in listOf(1, 3, 6, 9)) assertFailsWith<IllegalArgumentException>("length $n") { StrKey.base32Decode("A".repeat(n)) }
        for (len in 0..40) {
            val data = ByteArray(len) { (it * 37 + 11).toByte() }
            assertContentEquals(data, StrKey.base32Decode(StrKey.base32Encode(data)))
        }
    }
}

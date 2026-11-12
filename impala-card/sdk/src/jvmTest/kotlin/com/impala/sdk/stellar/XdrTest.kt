package com.impala.sdk.stellar

import com.impala.sdk.flows.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class XdrTest {
    @Test
    fun `integers are big-endian, uint32 is unsigned`() {
        val r = XdrReader(Hex.decode("ffffffff" + "80000000" + "0102030405060708"))
        assertEquals(0xFFFF_FFFFL, r.uint32())
        assertEquals(Int.MIN_VALUE, r.int32())
        assertEquals(0x0102030405060708L, r.int64())
        r.requireEnd()
    }

    @Test
    fun `opaque and string padding must be zero and present`() {
        assertContentEquals(byteArrayOf(1, 2, 3), XdrReader(Hex.decode("00000003" + "01020300")).varOpaque(4))
        assertFailsWith<XdrException> { XdrReader(Hex.decode("00000003" + "01020301")).varOpaque(4) }
        assertFailsWith<XdrException> { XdrReader(Hex.decode("00000003" + "010203")).varOpaque(4) }
        assertContentEquals(ByteArray(0), XdrReader(Hex.decode("00000000")).varOpaque(4))
        assertContentEquals(byteArrayOf(9, 9, 9, 9), XdrReader(Hex.decode("00000004" + "09090909")).string(4))
    }

    @Test
    fun `lengths and counts are bounded, truncation and trailing bytes fail`() {
        assertFailsWith<XdrException> { XdrReader(Hex.decode("00000005" + "0102030405000000")).varOpaque(4) }
        assertFailsWith<XdrException> { XdrReader(Hex.decode("ffffffff")).varOpaque(64) }
        assertFailsWith<XdrException> { XdrReader(Hex.decode("00000015")).count(20) }
        assertEquals(20, XdrReader(Hex.decode("00000014")).count(20))
        assertFailsWith<XdrException> { XdrReader(Hex.decode("000000")).uint32() }
        assertFailsWith<XdrException> { XdrReader(Hex.decode("00000000000000")).int64() }
        assertFailsWith<XdrException> { XdrReader(Hex.decode("0000000000")).also { it.uint32() }.requireEnd() }
    }

    @Test
    fun `optional flags are 0 or 1 only`() {
        assertFalse(XdrReader(Hex.decode("00000000")).optional())
        assertTrue(XdrReader(Hex.decode("00000001")).optional())
        assertFailsWith<XdrException> { XdrReader(Hex.decode("00000002")).optional() }
        assertFailsWith<XdrException> { XdrReader(Hex.decode("01000001")).optional() }
    }

    @Test
    fun `the writer pads and frames like the reader expects`() {
        val bytes = XdrWriter().uint32(7).int64(-2).varOpaque(byteArrayOf(1, 2, 3, 4, 5)).fixedOpaque(byteArrayOf(9)).toByteArray()
        assertEquals("00000007" + "fffffffffffffffe" + "00000005" + "0102030405000000" + "09000000", Hex.encode(bytes))
        val r = XdrReader(bytes)
        assertEquals(7, r.uint32())
        assertEquals(-2, r.int64())
        assertContentEquals(byteArrayOf(1, 2, 3, 4, 5), r.varOpaque(64))
        assertContentEquals(byteArrayOf(9), r.fixedOpaque(1))
        r.requireEnd()
        assertFailsWith<IllegalArgumentException> { XdrWriter().uint32(-1) }
        assertFailsWith<IllegalArgumentException> { XdrWriter().uint32(0x1_0000_0000L) }
    }
}

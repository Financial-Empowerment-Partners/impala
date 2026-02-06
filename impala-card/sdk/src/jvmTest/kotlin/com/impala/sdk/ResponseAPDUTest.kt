package com.impala.sdk

import com.impala.sdk.apdu4j.ResponseAPDU
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Unit tests for ResponseAPDU parsing and property accessors.
 *
 * Covers status word extraction, data payload separation, edge cases
 * around minimal APDUs, and common ISO 7816-4 status word values.
 */
class ResponseAPDUTest {

    @Test
    fun `success status word 0x9000`() {
        val resp = ResponseAPDU(byteArrayOf(0x90.toByte(), 0x00))
        assertEquals(0x9000, resp.sw)
        assertEquals(0x90, resp.sW1)
        assertEquals(0x00, resp.sW2)
    }

    @Test
    fun `data payload extraction`() {
        val raw = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0x90.toByte(), 0x00)
        val resp = ResponseAPDU(raw)
        assertEquals(3, resp.data.size)
        assertContentEquals(byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte()), resp.data)
    }

    @Test
    fun `empty data with status word only`() {
        val resp = ResponseAPDU(byteArrayOf(0x69.toByte(), 0x82.toByte()))
        assertEquals(0, resp.data.size)
        assertEquals(0x6982, resp.sw)
    }

    @Test
    fun `bytes returns complete APDU`() {
        val raw = byteArrayOf(0x01, 0x02, 0x90.toByte(), 0x00)
        val resp = ResponseAPDU(raw)
        assertContentEquals(raw, resp.bytes)
    }

    @Test
    fun `sWBytes returns last two bytes`() {
        val raw = byteArrayOf(0x01, 0x02, 0x03, 0x61.toByte(), 0x10)
        val resp = ResponseAPDU(raw)
        assertContentEquals(byteArrayOf(0x61.toByte(), 0x10), resp.sWBytes)
    }

    @Test
    fun `rejects APDU shorter than 2 bytes`() {
        assertFailsWith<IllegalArgumentException> {
            ResponseAPDU(byteArrayOf(0x90.toByte()))
        }
    }

    @Test
    fun `rejects empty APDU`() {
        assertFailsWith<IllegalArgumentException> {
            ResponseAPDU(byteArrayOf())
        }
    }

    @Test
    fun `common error status words`() {
        // File not found
        assertEquals(0x6A82, ResponseAPDU(byteArrayOf(0x6A.toByte(), 0x82.toByte())).sw)
        // Wrong length
        assertEquals(0x6700, ResponseAPDU(byteArrayOf(0x67.toByte(), 0x00)).sw)
        // Conditions not satisfied
        assertEquals(0x6985, ResponseAPDU(byteArrayOf(0x69.toByte(), 0x85.toByte())).sw)
        // Wrong P1/P2
        assertEquals(0x6B00, ResponseAPDU(byteArrayOf(0x6B.toByte(), 0x00)).sw)
        // INS not supported
        assertEquals(0x6D00, ResponseAPDU(byteArrayOf(0x6D.toByte(), 0x00)).sw)
        // CLA not supported
        assertEquals(0x6E00, ResponseAPDU(byteArrayOf(0x6E.toByte(), 0x00)).sw)
    }

    @Test
    fun `large data payload`() {
        // 256 bytes of data + SW
        val data = ByteArray(256) { it.toByte() }
        val apdu = data + byteArrayOf(0x90.toByte(), 0x00)
        val resp = ResponseAPDU(apdu)
        assertEquals(256, resp.data.size)
        assertEquals(0x9000, resp.sw)
        assertContentEquals(data, resp.data)
    }

    @Test
    fun `data is a copy not a reference`() {
        val raw = byteArrayOf(0x01, 0x02, 0x90.toByte(), 0x00)
        val resp = ResponseAPDU(raw)
        val data1 = resp.data
        val data2 = resp.data
        // Should be equal but not the same array instance
        assertContentEquals(data1, data2)
        data1[0] = 0xFF.toByte()
        // Modifying the copy should not affect subsequent calls
        assertEquals(0x01, resp.data[0])
    }

    @Test
    fun `SW1 and SW2 are unsigned`() {
        // 0xFF bytes should be 255, not -1
        val resp = ResponseAPDU(byteArrayOf(0xFF.toByte(), 0xFF.toByte()))
        assertEquals(0xFF, resp.sW1)
        assertEquals(0xFF, resp.sW2)
        assertEquals(0xFFFF, resp.sw)
    }
}

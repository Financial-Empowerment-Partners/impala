package com.impala.sdk

import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.ResponseAPDU
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertFailsWith

/**
 * Unit tests for CommandAPDU and ResponseAPDU encoding/decoding.
 *
 * These tests verify ISO/IEC 7816-4 APDU serialization without requiring
 * a JavaCard simulator — they exercise the pure-Kotlin APDU layer.
 */
class CommandAPDUTest {

    @Test
    fun `Case 1 APDU - no data, no response expected`() {
        // CLA=0x00 INS=0xA4 P1=0x04 P2=0x00
        val cmd = CommandAPDU(0x00, 0xA4, 0x04, 0x00)
        assertEquals(0x00, cmd.cLA)
        assertEquals(0xA4, cmd.iNS)
        assertEquals(0x04, cmd.p1)
        assertEquals(0x00, cmd.p2)
        assertEquals(0, cmd.nc)
    }

    @Test
    fun `Case 2 APDU - no data, response expected`() {
        // CLA=0x00 INS=0xCA P1=0x00 P2=0x00 Ne=256
        val cmd = CommandAPDU(0x00, 0xCA, 0x00, 0x00, ne = 256)
        assertEquals(0xCA, cmd.iNS)
        assertEquals(256, cmd.ne)
        assertEquals(0, cmd.nc)
    }

    @Test
    fun `Case 3 APDU - data, no response expected`() {
        val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val cmd = CommandAPDU(0x00, 0xDA, 0x00, 0x00, data)
        assertEquals(4, cmd.nc)
        assertEquals(data.toList(), cmd.data.toList())
    }

    @Test
    fun `Case 4 APDU - data and response expected`() {
        val data = byteArrayOf(0xAA.toByte(), 0xBB.toByte())
        val cmd = CommandAPDU(0x00, 0xDA, 0x01, 0x02, data, 0, data.size, 128)
        assertEquals(2, cmd.nc)
        assertEquals(128, cmd.ne)
        assertEquals(data.toList(), cmd.data.toList())
    }

    @Test
    fun `CommandAPDU round-trip via bytes`() {
        val data = byteArrayOf(0x10, 0x20, 0x30)
        val original = CommandAPDU(0x80, 0x50, 0x00, 0x00, data)
        val bytes = original.bytes
        val restored = CommandAPDU(bytes)

        assertEquals(original.cLA, restored.cLA)
        assertEquals(original.iNS, restored.iNS)
        assertEquals(original.p1, restored.p1)
        assertEquals(original.p2, restored.p2)
        assertEquals(original.data.toList(), restored.data.toList())
    }

    @Test
    fun `CommandAPDU equality`() {
        val a = CommandAPDU(0x00, 0xA4, 0x04, 0x00)
        val b = CommandAPDU(0x00, 0xA4, 0x04, 0x00)
        val c = CommandAPDU(0x00, 0xA4, 0x04, 0x01)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, c)
    }

    @Test
    fun `ResponseAPDU parses status word`() {
        // SW=0x9000 (success), no data
        val resp = ResponseAPDU(byteArrayOf(0x90.toByte(), 0x00))
        assertEquals(0x9000, resp.sw)
        assertEquals(0x90, resp.sW1)
        assertEquals(0x00, resp.sW2)
        assertEquals(0, resp.data.size)
    }

    @Test
    fun `ResponseAPDU parses data and status word`() {
        // 3 bytes data + SW=0x9000
        val raw = byteArrayOf(0x01, 0x02, 0x03, 0x90.toByte(), 0x00)
        val resp = ResponseAPDU(raw)
        assertEquals(0x9000, resp.sw)
        assertEquals(3, resp.data.size)
        assertEquals(listOf<Byte>(0x01, 0x02, 0x03), resp.data.toList())
    }

    @Test
    fun `ResponseAPDU rejects bytes shorter than 2`() {
        assertFailsWith<IllegalArgumentException> {
            ResponseAPDU(byteArrayOf(0x90.toByte()))
        }
    }

    @Test
    fun `ResponseAPDU error status words`() {
        // SW=0x6982 (security status not satisfied)
        val resp = ResponseAPDU(byteArrayOf(0x69.toByte(), 0x82.toByte()))
        assertEquals(0x6982, resp.sw)
        assertEquals(0x69, resp.sW1)
        assertEquals(0x82, resp.sW2)
    }
}

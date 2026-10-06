package com.impala.sdk.apdu4j

import kotlin.test.Test
import kotlin.test.assertContentEquals

class ApduTraceTest {
    @Test
    fun `sign transfer v2 masks only the leading PIN`() {
        val cmd = byteArrayOf(0x00, 0x30, 0x00, 0x00, 64) + byteArrayOf(1, 2, 3, 4) + ByteArray(60) { 7 }
        val masked = ApduTrace.mask(cmd)
        assertContentEquals(ByteArray(4) { 0x2A }, masked.copyOfRange(5, 9))
        assertContentEquals(cmd.copyOfRange(9, cmd.size), masked.copyOfRange(9, masked.size))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), cmd.copyOfRange(5, 9)) // input untouched
    }

    @Test
    fun `pin and key commands are fully masked at any CLA`() {
        for (ins in listOf(0x18, 0x19, 0x2B, 0x70, 0x71)) {
            val cmd = byteArrayOf(0x84.toByte(), ins.toByte(), 0x00, 0x00, 3, 9, 9, 9)
            assertContentEquals(byteArrayOf(0x84.toByte(), ins.toByte(), 0x00, 0x00, 3, 0x2A, 0x2A, 0x2A), ApduTrace.mask(cmd))
        }
    }

    @Test
    fun `non secret commands pass through`() {
        val cmd = byteArrayOf(0x00, 0x25, 0x00, 0x00, 2, 5, 6)
        assertContentEquals(cmd, ApduTrace.mask(cmd))
        assertContentEquals(byteArrayOf(0x00, 0x64, 0x00, 0x00), ApduTrace.mask(byteArrayOf(0x00, 0x64, 0x00, 0x00)))
    }
}

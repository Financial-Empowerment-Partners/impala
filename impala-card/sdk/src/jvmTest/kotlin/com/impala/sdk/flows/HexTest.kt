package com.impala.sdk.flows

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HexTest {
    @Test
    fun `encode is lowercase without separators and decode is strict`() {
        assertEquals("00ff10ab", Hex.encode(byteArrayOf(0, -1, 16, 0xAB.toByte())))
        assertContentEquals(byteArrayOf(0, -1, 16, 0xAB.toByte()), Hex.decode("00FF10ab"))
        assertFailsWith<IllegalArgumentException> { Hex.decode("abc") }
        assertFailsWith<IllegalArgumentException> { Hex.decode("zz") }
        assertFailsWith<IllegalArgumentException> { Hex.decode("00", expectedBytes = 2) }
    }

    @Test
    fun `uuid wire forms`() {
        val bytes = UuidBytes.parse("00112233-4455-6677-8899-AABBCCDDEEFF")
        assertEquals("00112233-4455-6677-8899-aabbccddeeff", UuidBytes.format(bytes))
        assertEquals("00112233445566778899aabbccddeeff", Hex.encode(bytes))
        assertTrue(UuidBytes.same("00112233445566778899aabbccddeeff", "00112233-4455-6677-8899-aabbccddeeff"))
        assertFalse(UuidBytes.same("not-a-uuid", "00112233-4455-6677-8899-aabbccddeeff"))
        assertFailsWith<IllegalArgumentException> { UuidBytes.parse("0011223344556677-8899-aabbccddeeff00") }
    }
}

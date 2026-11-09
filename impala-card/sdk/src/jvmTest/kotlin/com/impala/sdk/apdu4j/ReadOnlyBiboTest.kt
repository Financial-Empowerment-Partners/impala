package com.impala.sdk.apdu4j

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.flows.CardAuthFlow
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import java.nio.ByteBuffer
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ReadOnlyBiboTest {
    private class CountingBibo : BIBO {
        var calls = 0
        override fun transceive(bytes: ByteArray?): ByteArray? { calls++; return byteArrayOf(0x90.toByte(), 0x00) }
        override fun close() {}
    }

    private fun cmd(cla: Int, ins: Int, data: Int = 0): ByteArray =
        byteArrayOf(cla.toByte(), ins.toByte(), 0, 0) + (if (data > 0) byteArrayOf(data.toByte()) + ByteArray(data) else ByteArray(0))

    @Test
    fun `mutating, PIN and signing instructions are refused with zero inner calls`() {
        for (ins in listOf(0x18, 0x19, 0x1F, 0x22, 0x25, 0x2C, 0x30, 0x31)) {
            val inner = CountingBibo()
            val e = assertFailsWith<ReadOnlyViolationException> { ReadOnlyBibo(inner).transceive(cmd(0x00, ins, 4)) }
            assertEquals(0x00, e.cla)
            assertEquals(ins, e.ins)
            assertEquals(0, inner.calls, "INS 0x%02X reached the transport".format(ins))
            assertTrue(e.message!!.startsWith("read-only session refused "), e.message)
        }
    }

    @Test
    fun `every CLA 0x80 or 0x84 command is refused, including secured reads`() {
        for (cla in listOf(0x80, 0x84)) for (ins in listOf(0x50, 0x82, 0x70, 0x71, 0x72, 0x73, 0x04, 0x64, 0xA4)) {
            val inner = CountingBibo()
            assertFailsWith<ReadOnlyViolationException> { ReadOnlyBibo(inner).transceive(cmd(cla, ins)) }
            assertEquals(0, inner.calls)
        }
    }

    @Test
    fun `unknown instructions and malformed commands are refused (fail closed)`() {
        val inner = CountingBibo()
        for (bytes in listOf(cmd(0x00, 0x99), cmd(0x00, 0x06), cmd(0x00, 0xC0), byteArrayOf(0x00, 0x04), null)) {
            assertFailsWith<ReadOnlyViolationException> { ReadOnlyBibo(inner).transceive(bytes) }
        }
        assertEquals(0, inner.calls)
        val malformed = assertFailsWith<ReadOnlyViolationException> { ReadOnlyBibo(inner).transceive(null) }
        assertEquals("a malformed command", assertIs<CardError.ReadOnlyRefused>(CardError.from(malformed)).command)
    }

    @Test
    fun `SELECT and the read-only allow-list are forwarded`() {
        val inner = CountingBibo()
        val bibo = ReadOnlyBibo(inner)
        bibo.transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x02, 0x01, 0x02))
        for (ins in ApduNames.READ_ONLY_INS) bibo.transceive(cmd(0x00, ins))
        assertEquals(1 + ApduNames.READ_ONLY_INS.size, inner.calls)
    }

    @Test
    fun `SIGN_AUTH over a read-only jcardsim session is CardFlowException ReadOnlyRefused SIGN_AUTH`() {
        val u = UUID.randomUUID()
        val account = ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()
        val card = personalizedCard(TestIssuer(), account)
        val seen = mutableListOf<ApduExchange>()
        val sdk = ImpalaSDK(TracingBibo(ReadOnlyBibo(card.bibo), { seen += it }), null)

        // Identity reads pass the guard...
        val identity = CardIdentity.read(sdk)
        assertTrue(identity.isPersonalized)
        var signs = 0
        card.bibo.debugTrace = { c, _ -> if ((c[1].toInt() and 0xFF) == 0x25) signs++ }

        // ...the signing oracle does not.
        val e = assertFailsWith<CardFlowException> { CardAuthFlow.sign(sdk, "ab".repeat(32)) }
        val refused = assertIs<CardError.ReadOnlyRefused>(e.error)
        assertEquals("SIGN_AUTH", refused.command)
        assertEquals("card_error_read_only_refused", refused.userMessageKey)
        assertEquals(0, signs)
        assertEquals(ApduExchange.Outcome.REFUSED, seen.last().outcome)
        assertEquals("SIGN_AUTH", seen.last().insName)
        assertTrue(seen.dropLast(1).all { it.outcome == ApduExchange.Outcome.OK })
    }
}

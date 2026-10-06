package com.impala.sdk.apdu4j

import java.nio.ByteBuffer
import javax.smartcardio.ATR
import javax.smartcardio.Card
import javax.smartcardio.CardChannel
import javax.smartcardio.CardException
import javax.smartcardio.CardTerminal
import javax.smartcardio.CommandAPDU
import javax.smartcardio.ResponseAPDU
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PcscBiboTest {
    private class FakeChannel(val card: FakeCard, val reply: (ByteArray) -> ByteArray) : CardChannel() {
        val sent = mutableListOf<ByteArray>()
        override fun getCard(): Card = card
        override fun getChannelNumber(): Int = 0
        override fun transmit(command: CommandAPDU): ResponseAPDU {
            sent += command.bytes
            return ResponseAPDU(reply(command.bytes))
        }
        override fun transmit(command: ByteBuffer, response: ByteBuffer): Int = throw UnsupportedOperationException()
        override fun close() {}
    }

    private class FakeCard(reply: (ByteArray) -> ByteArray) : Card() {
        val channel = FakeChannel(this, reply)
        var disconnects = 0
        var lastReset: Boolean? = null
        override fun getATR(): ATR = ATR(byteArrayOf(0x3B, 0x00))
        override fun getProtocol(): String = "T=1"
        override fun getBasicChannel(): CardChannel = channel
        override fun openLogicalChannel(): CardChannel = throw UnsupportedOperationException()
        override fun beginExclusive() {}
        override fun endExclusive() {}
        override fun transmitControlCommand(controlCode: Int, command: ByteArray?): ByteArray = ByteArray(0)
        override fun disconnect(reset: Boolean) { disconnects++; lastReset = reset }
    }

    private class FakeTerminal(val nm: String, val card: FakeCard?) : CardTerminal() {
        var connects = 0
        override fun getName(): String = nm
        override fun connect(protocol: String): Card { connects++; return card ?: throw CardException("no card") }
        override fun isCardPresent(): Boolean = card != null
        override fun waitForCardPresent(timeout: Long): Boolean = card != null
        override fun waitForCardAbsent(timeout: Long): Boolean = card == null
    }

    private val ok = byteArrayOf(0x90.toByte(), 0x00)

    @Test
    fun `refuses commands over 255 data bytes before touching the terminal`() {
        val terminal = FakeTerminal("Reader", FakeCard { ok })
        val bibo = PcscBibo(null, PcscBibo.DEFAULT_APPLET_AID, null) { listOf(terminal) }
        val oversized = byteArrayOf(0x00, 0x31, 0x01, 0x00, 0xFF.toByte()) + ByteArray(256)
        assertFailsWith<BIBOException> { bibo.transceive(oversized) }
        val extended = byteArrayOf(0x00, 0x31, 0x01, 0x00, 0x00, 0x01, 0x00) + ByteArray(256)
        assertFailsWith<BIBOException> { bibo.transceive(extended) }
        assertEquals(0, terminal.connects)
    }

    @Test
    fun `maps CardException to BIBOException and closes the channel`() {
        var calls = 0
        val card = FakeCard { if (calls++ == 0) ok else throw CardException("tag gone") }
        val bibo = PcscBibo(null, PcscBibo.DEFAULT_APPLET_AID, null) { listOf(FakeTerminal("Reader", card)) }.connect()
        val e = assertFailsWith<BIBOException> { bibo.transceive(byteArrayOf(0x00, 0x64, 0x00, 0x00)) }
        assertTrue(e.cause is CardException)
        assertEquals(1, card.disconnects)
        assertEquals(false, card.lastReset)
        assertFailsWith<BIBOException> { bibo.transceive(byteArrayOf(0x00, 0x64, 0x00, 0x00)) }
    }

    @Test
    fun `connect selects the applet instance AID on the filtered terminal`() {
        val wanted = FakeCard { ok }
        val other = FakeTerminal("Other Reader", FakeCard { ok })
        val bibo = PcscBibo("acs", PcscBibo.DEFAULT_APPLET_AID, null) { listOf(other, FakeTerminal("ACS ACR1252", wanted)) }.connect()
        assertEquals("ACS ACR1252", bibo.terminalName)
        assertEquals(0, other.connects)
        assertContentEquals(
            byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2),
            wanted.channel.sent.single()
        )
        bibo.close()
        bibo.close()
        assertEquals(1, wanted.disconnects)
    }

    @Test
    fun `failed SELECT is a BIBOException and disconnects`() {
        val card = FakeCard { byteArrayOf(0x6A, 0x82.toByte()) }
        val bibo = PcscBibo(null, PcscBibo.DEFAULT_APPLET_AID, null) { listOf(FakeTerminal("Reader", card)) }
        val e = assertFailsWith<BIBOException> { bibo.connect() }
        assertTrue(e.message!!.contains("6A82"))
        assertEquals(1, card.disconnects)
    }

    @Test
    fun `trace hook receives masked PIN bytes`() {
        val seen = mutableListOf<ByteArray>()
        val bibo = PcscBibo(null, PcscBibo.DEFAULT_APPLET_AID, { c, _ -> seen += c }) {
            listOf(FakeTerminal("Reader", FakeCard { ok }))
        }.connect()
        bibo.transceive(byteArrayOf(0x00, 0x18, 0x00, 0x82.toByte(), 0x04, 1, 2, 3, 4))
        assertContentEquals(byteArrayOf(0x00, 0x18, 0x00, 0x82.toByte(), 0x04, 0x2A, 0x2A, 0x2A, 0x2A), seen.last())
    }
}

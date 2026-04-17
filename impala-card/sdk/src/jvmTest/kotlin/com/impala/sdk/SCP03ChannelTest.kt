package com.impala.sdk

import com.impala.sdk.apdu4j.APDUBIBO
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.scp03.SCP03Channel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Defensive unit tests for [SCP03Channel].
 *
 * The full happy-path mutual-auth flow requires a real card (valid card
 * cryptogram), so these tests focus on the defensive branches that guard
 * against protocol violations and misuse. Cryptographic correctness of the
 * session-key derivation and C-MAC computation is exercised by AESCMACTest
 * and by the card-side integration tests.
 */
class SCP03ChannelTest {

    private val staticENC = ByteArray(16) { 0x40.toByte() }
    private val staticMAC = ByteArray(16) { 0x41.toByte() }
    private val staticDEK = ByteArray(16) { 0x42.toByte() }

    private fun newChannel(mock: MockBIBO): SCP03Channel {
        return SCP03Channel(APDUBIBO(mock), staticENC, staticMAC, staticDEK)
    }

    @Test
    fun `new channel is not open`() {
        val channel = newChannel(MockBIBO())
        assertFalse(channel.isChannelOpen(), "channel must start closed")
    }

    @Test
    fun `secureTransmit on unopened channel throws`() {
        val channel = newChannel(MockBIBO())
        assertFailsWith<ImpalaException> {
            channel.secureTransmit(CommandAPDU(0x80, 0x10, 0x00, 0x00, byteArrayOf()))
        }
    }

    @Test
    fun `openSecureChannel throws when card returns non-9000 status word on INITIALIZE UPDATE`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6A82) // File not found / applet rejected
        val channel = newChannel(mock)

        val ex = assertFailsWith<ImpalaException> { channel.openSecureChannel() }
        assertTrue(
            ex.message?.contains("INITIALIZE UPDATE") == true,
            "error must identify the failing step, got: ${ex.message}"
        )
        assertFalse(channel.isChannelOpen(), "channel must remain closed after failed open")
    }

    @Test
    fun `openSecureChannel throws on malformed INITIALIZE UPDATE response length`() {
        val mock = MockBIBO()
        // Respond with 10 bytes of data + 9000, but SCP03 expects exactly 29 data bytes.
        mock.respondWith(ByteArray(10) { 0x00 })
        val channel = newChannel(mock)

        val ex = assertFailsWith<ImpalaException> { channel.openSecureChannel() }
        assertTrue(
            ex.message?.contains("unexpected response length") == true,
            "error must describe the length mismatch, got: ${ex.message}"
        )
    }

    @Test
    fun `openSecureChannel throws when card cryptogram does not verify`() {
        val mock = MockBIBO()
        // Well-formed 29-byte response with zeroed challenge+cryptogram. The
        // computed cryptogram will not match these zero bytes, so verification
        // must reject.
        mock.respondWith(ByteArray(29) { 0x00 })
        val channel = newChannel(mock)

        val ex = assertFailsWith<ImpalaException> { channel.openSecureChannel() }
        assertTrue(
            ex.message?.contains("cryptogram") == true,
            "error must mention cryptogram verification, got: ${ex.message}"
        )
        assertFalse(channel.isChannelOpen(), "channel must remain closed after bad cryptogram")
    }

    @Test
    fun `closeSecureChannel leaves channel marked closed`() {
        val channel = newChannel(MockBIBO())
        channel.closeSecureChannel()
        assertFalse(channel.isChannelOpen())
    }

    @Test
    fun `INITIALIZE UPDATE is the first APDU transmitted during open`() {
        val mock = MockBIBO()
        // Use a response guaranteed to fail cryptogram verification, so we
        // can observe the INITIALIZE UPDATE command without dealing with
        // EXTERNAL AUTHENTICATE. This test asserts ordering, not crypto.
        mock.respondWith(ByteArray(29) { 0x00 })
        val channel = newChannel(mock)

        runCatching { channel.openSecureChannel() } // expected to fail on cryptogram

        assertTrue(mock.sentCommands.isNotEmpty(), "at least one APDU must be sent")
        val first = mock.sentCommands.first()
        // GP INITIALIZE UPDATE: CLA=0x80, INS=0x50
        assertEquals(0x80, first.cLA, "first command CLA must be GP (0x80)")
        assertEquals(0x50, first.iNS, "first command INS must be INITIALIZE UPDATE (0x50)")
    }
}

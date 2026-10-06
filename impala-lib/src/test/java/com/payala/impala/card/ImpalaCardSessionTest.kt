package com.payala.impala.card

import android.nfc.Tag
import com.impala.sdk.flows.UuidBytes
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.mock
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ImpalaCardSessionTest {
    @Test
    fun `open on the main thread is refused`() {
        val e = assertThrows(IllegalStateException::class.java) { ImpalaCardSession.open(mock(Tag::class.java)) }
        assertTrue(e.message!!.contains("main thread"))
    }

    @Test
    fun `identity is read from a jcardsim-backed BIBO and exposes the 32-hex wire card id`() {
        val account = uuidBytes()
        val card = personalizedCard(TestIssuer(), account)
        val session = ImpalaCardSession.fromBibo(card.bibo)
        val identity = offMain { session.identity }
        assertEquals(UuidBytes.format(account), identity.accountUuid)
        assertEquals(32, identity.wireCardId.length)
        assertTrue(identity.wireCardId.matches(Regex("[0-9a-f]{32}")))
        assertEquals(identity.cardUuid.replace("-", ""), identity.wireCardId)
        assertEquals(130, identity.pubKeyHex.length)
        assertTrue(identity.isPersonalized)
        assertEquals("0.2", identity.versionString)
    }

    @Test
    fun `identity read on the main thread is refused`() {
        val session = ImpalaCardSession.fromBibo(personalizedCard(TestIssuer(), uuidBytes()).bibo)
        assertThrows(IllegalStateException::class.java) { session.identity }
    }

    @Test
    fun `close is idempotent and closes the BIBO once`() {
        val bibo = ScriptedBibo(emptyMap())
        val session = ImpalaCardSession.fromBibo(bibo)
        session.close()
        session.close()
        session.use { }
        assertEquals(1, bibo.closes)
        assertTrue(session.isClosed)
    }

    @Test
    fun `SELECT is sent when an AID is given and a refusal closes the transport`() {
        val ok = ScriptedBibo(mapOf(0xA4 to SW_OK))
        ImpalaCardSession.fromBibo(ok, ImpalaCardSession.TESTNET_APPLET_AID)
        assertEquals("00a404000a01020304050607080102", ok.sent.single().joinToString("") { "%02x".format(it) })

        val refused = ScriptedBibo(mapOf(0xA4 to byteArrayOf(0x6A, 0x82.toByte())))
        assertThrows(com.impala.sdk.flows.CardFlowException::class.java) {
            ImpalaCardSession.fromBibo(refused, ImpalaCardSession.TESTNET_APPLET_AID)
        }
        assertEquals(1, refused.closes)
    }
}

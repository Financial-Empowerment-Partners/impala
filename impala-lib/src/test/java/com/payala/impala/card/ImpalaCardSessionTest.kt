package com.payala.impala.card

import android.nfc.Tag
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduExchangeHook
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.UuidBytes
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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
        assertEquals("0.4", identity.versionString)
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

    @Test
    fun `a 6A82 or 6999 SELECT is AppletNotFound and closes the transport`() {
        for (sw in listOf(0x6A82, 0x6999)) {
            val refused = ScriptedBibo(mapOf(0xA4 to byteArrayOf((sw shr 8).toByte(), sw.toByte())))
            val e = assertThrows(CardFlowException::class.java) {
                ImpalaCardSession.fromBibo(refused, ImpalaCardSession.TESTNET_APPLET_AID)
            }
            assertTrue(e.error is CardError.AppletNotFound)
            assertEquals(sw, e.error.statusWord)
            assertEquals("card_error_applet_not_found", e.error.userMessageKey)
            assertEquals(1, refused.closes)
        }
    }

    @Test
    fun `the trace sees the SELECT and every later command, header only`() {
        val seen = mutableListOf<ApduExchange>()
        val bibo = ScriptedBibo(mapOf(0xA4 to SW_OK, 0x64 to versionAnswer(0, 2)))
        val session = ImpalaCardSession.fromBibo(bibo, ImpalaCardSession.TESTNET_APPLET_AID, trace = { seen += it })
        offMain { session.sdk.getImpalaAppletVersion() }
        assertEquals(listOf("SELECT", "GET_VERSION"), seen.map { it.insName })
        assertEquals(10, seen[0].lc)
        assertEquals(ApduExchange.Outcome.OK, seen[0].outcome)
        assertEquals(10, seen[1].responseLength)
        assertEquals(ImpalaCardSession.TESTNET_APPLET_AID, session.aidHex)
        assertFalse(session.isReadOnly)
        assertNull(session.transport)
    }

    @Test
    fun `a throwing trace hook never breaks the session`() {
        val bibo = ScriptedBibo(mapOf(0xA4 to SW_OK, 0x64 to versionAnswer(0, 2)))
        val session = ImpalaCardSession.fromBibo(bibo, ImpalaCardSession.TESTNET_APPLET_AID, trace = ApduExchangeHook { throw IllegalStateException("bad hook") })
        assertEquals(2, offMain { session.sdk.getImpalaAppletVersion() }.minor.toInt())
    }

    @Test
    fun `a read-only session refuses SIGN_AUTH with zero bytes sent and says so`() {
        val bibo = ScriptedBibo(mapOf(0x25 to SW_OK))
        val seen = mutableListOf<ApduExchange>()
        val session = ImpalaCardSession.fromBibo(bibo, trace = { seen += it }, readOnly = true)
        assertTrue(session.isReadOnly)
        val e = assertThrows(CardFlowException::class.java) {
            offMain { CardAuthenticator.signChallenge(session, "ab".repeat(32)) }
        }
        val refused = e.error as CardError.ReadOnlyRefused
        assertEquals("SIGN_AUTH", refused.command)
        assertTrue(bibo.sent.isEmpty())
        assertEquals(ApduExchange.Outcome.REFUSED, seen.single().outcome)
    }

    @Test
    fun `a read-only session over jcardsim reads the identity and selects nothing it should not`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val ins = mutableListOf<Int>()
        card.bibo.debugTrace = { cmd, _ -> ins += cmd[1].toInt() and 0xFF }
        val session = ImpalaCardSession.fromBibo(card.bibo, readOnly = true)
        assertTrue(offMain { session.identity }.isPersonalized)
        assertEquals(setOf(0x64, 0x1E, 0x24, 0x34), ins.toSet())
        val (_, recorded) = session.recordingExchanges { offMain { session.sdk.getBalance() } }
        assertEquals(listOf("GET_BALANCE"), recorded.map { it.insName })
    }
}

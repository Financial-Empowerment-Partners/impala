package com.payala.impala.card

import com.impala.sdk.flows.CardAuthFlow
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.RedemptionFlow
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.TestIssuer
import com.impala.simulator.fund
import com.impala.simulator.personalizedCard
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CardTransfersTest {
    @Test
    fun `redeem zeroes the PIN array after signing`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, uuidBytes(), userPin = "2468")
        fund(card, issuer.externalSender(uuidBytes()), 500, 1)
        val session = ImpalaCardSession.fromBibo(card.bibo)
        val pin = "2468".toCharArray()
        val tuple = offMain {
            val signable = RedemptionFlow.compose(session.identity, uuidBytes(), 100u, 5, 1)
            CardTransfers.redeem(session, pin, signable)
        }
        assertArrayEquals(CharArray(4), pin)
        assertEquals(120, tuple.signableHex.length)
        assertEquals(400L, card.sdk.getBalance())

        val bad = "0001".toCharArray()
        assertThrows(CardFlowException::class.java) {
            offMain { CardTransfers.redeem(session, bad, RedemptionFlow.compose(session.identity, uuidBytes(), 1u, 9, 1, 5)) }
        }
        assertArrayEquals(CharArray(4), bad)
    }

    @Test
    fun `0_1 applet (GET_VERSION 0_1 stub) yields WrongProtocolVersion before SIGN_TRANSFER_V2 is sent`() {
        val bibo = ScriptedBibo(mapOf(0x64 to versionAnswer(0, 1)))
        val session = ImpalaCardSession.fromBibo(bibo)
        val signable = Signable(1, uuidBytes(), uuidBytes(), TransferProtocol.CURRENCY_XLM, 1, 0, 1)
        val pin = "1234".toCharArray()
        val e = assertThrows(CardFlowException::class.java) { offMain { CardTransfers.redeem(session, pin, signable) } }
        assertEquals("0.1", (e.error as CardError.WrongProtocolVersion).found)
        assertTrue(bibo.sent.none { (it[1].toInt() and 0xFF) == 0x30 })
        assertArrayEquals(CharArray(4), pin)
    }

    @Test
    fun `transfer helpers refuse the main thread`() {
        val session = ImpalaCardSession.fromBibo(ScriptedBibo(emptyMap()))
        assertThrows(IllegalStateException::class.java) { CardTransfers.recoverLastSigned(session) }
        assertThrows(IllegalStateException::class.java) { CardTransfers.applyCredit(session, ByteArray(60), ByteArray(209)) }
        assertThrows(IllegalStateException::class.java) { CardAuthenticator.signChallenge(session, "00".repeat(32)) }
    }
}

@RunWith(RobolectricTestRunner::class)
class CardAuthenticatorTest {
    @Test
    fun `challenge outside 8 to 64 bytes is refused before any APDU`() {
        val bibo = ScriptedBibo(emptyMap())
        val session = ImpalaCardSession.fromBibo(bibo)
        for (hex in listOf("00".repeat(CardAuthFlow.MIN_CHALLENGE_BYTES - 1), "00".repeat(CardAuthFlow.MAX_CHALLENGE_BYTES + 1))) {
            val e = assertThrows(CardFlowException::class.java) { offMain { CardAuthenticator.signChallenge(session, hex) } }
            assertTrue(e.error is CardError.InvalidRequest)
        }
        assertEquals(0, bibo.sent.size)
    }
}

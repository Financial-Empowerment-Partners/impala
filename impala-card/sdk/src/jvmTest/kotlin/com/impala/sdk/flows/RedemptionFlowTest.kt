package com.impala.sdk.flows

import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.Jca
import com.impala.simulator.PersonalizedCard
import com.impala.simulator.TestIssuer
import com.impala.simulator.fund
import com.impala.simulator.personalizedCard
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RedemptionFlowTest {
    private fun fundedCard(issuer: TestIssuer, account: ByteArray, amount: Long): PersonalizedCard {
        val card = personalizedCard(issuer, account, TransferProtocol.CURRENCY_USDC, userPin = "1234")
        fund(card, issuer.externalSender(uuidBytes()), amount, sendSequence = 1)
        return card
    }

    @Test
    fun `composed signable reproduces the golden XFER message and transfer_id when signed on jcardsim`() {
        val issuer = TestIssuer(GOLDEN_PROGRAM)
        val card = fundedCard(issuer, GOLDEN_SENDER, 5000)
        val identity = CardIdentity.read(card.sdk)
        val prev = RedemptionFlow.previousSendSequence(card.sdk)
        assertEquals(0L, prev)
        val signable = RedemptionFlow.compose(identity, GOLDEN_RECIPIENT, 1000u, sendSequence = 1, counter = 1, previousSendSequence = prev)
        val tuple = RedemptionFlow.sign(card.sdk, identity, "1234".toCharArray(), signable)

        val xfer = TransferProtocol.xferMessage(GOLDEN_PROGRAM, Hex.decode(tuple.signableHex))
        assertEquals(
            "494d50414c412d584645523a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000100112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110055534443000003e8000000000000000000000001",
            Hex.encode(xfer)
        )
        assertEquals("6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9", tuple.transferIdHex(GOLDEN_PROGRAM))
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), xfer, Hex.decode(tuple.signatureDerHex)))
        assertEquals(Hex.encode(card.cert), tuple.cardCertHex)
        assertEquals(4000L, card.sdk.getBalance())
    }

    @Test
    fun `wrong PIN maps to WrongPin with tries remaining and never debits`() {
        val issuer = TestIssuer()
        val card = fundedCard(issuer, uuidBytes(), 500)
        val identity = CardIdentity.read(card.sdk)
        val signable = RedemptionFlow.compose(identity, uuidBytes(), 100u, 10, 1)
        val e = assertFailsWith<CardFlowException> { RedemptionFlow.sign(card.sdk, identity, "9999".toCharArray(), signable) }
        val err = assertIs<CardError.WrongPin>(e.error)
        assertEquals(4, err.triesLeft)
        assertEquals(500L, card.sdk.getBalance())
        assertNull(RedemptionFlow.recoverLastSigned(card.sdk, identity))
    }

    @Test
    fun `recoverLastSigned returns the identical tuple after a simulated torn response and the card does not debit twice`() {
        val issuer = TestIssuer()
        val card = fundedCard(issuer, uuidBytes(), 500)
        val identity = CardIdentity.read(card.sdk)
        val signable = RedemptionFlow.compose(identity, uuidBytes(), 200u, 10, 1)
        val signed = RedemptionFlow.sign(card.sdk, identity, "1234".toCharArray(), signable)
        // The response "was lost": the host recovers from the card instead of re-signing.
        val recovered = RedemptionFlow.recoverLastSigned(card.sdk, identity)
        assertEquals(signed, recovered)
        // Re-sending the byte-identical signable replays the cached response.
        val replayed = RedemptionFlow.sign(card.sdk, identity, "1234".toCharArray(), signable)
        assertEquals(signed, replayed)
        assertEquals(300L, card.sdk.getBalance())
        assertEquals(10L, RedemptionFlow.previousSendSequence(card.sdk))
    }

    @Test
    fun `compose refuses zero amount, non-positive counter, stale send sequence and self recipient`() {
        val account = uuidBytes()
        val card = personalizedCard(TestIssuer(), account)
        val identity = CardIdentity.read(card.sdk)
        val other = uuidBytes()
        fun refused(block: () -> Unit) = assertIs<CardError.InvalidRequest>(assertFailsWith<CardFlowException>(block = block).error)
        refused { RedemptionFlow.compose(identity, other, 0u, 5, 1) }
        refused { RedemptionFlow.compose(identity, other, 1u, 5, 0) }
        refused { RedemptionFlow.compose(identity, other, 1u, 5, -3) }
        refused { RedemptionFlow.compose(identity, other, 1u, 5, 1, previousSendSequence = 5) }
        refused { RedemptionFlow.compose(identity, other, 1u, -1, 1) }
        refused { RedemptionFlow.compose(identity, account.copyOf(), 1u, 5, 1) }
        val ok = RedemptionFlow.compose(identity, other, UInt.MAX_VALUE, 6, 1, previousSendSequence = 5)
        assertEquals(0xFFFF_FFFFL, ok.amount)
    }

    @Test
    fun `pin of wrong shape is refused before any APDU`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val identity = CardIdentity.read(card.sdk)
        val signable = RedemptionFlow.compose(identity, uuidBytes(), 1u, 1, 1)
        for (pin in listOf("123", "12a4", "12345")) {
            val e = assertFailsWith<CardFlowException> { RedemptionFlow.sign(card.sdk, identity, pin.toCharArray(), signable) }
            assertIs<CardError.InvalidRequest>(e.error)
        }
    }
}

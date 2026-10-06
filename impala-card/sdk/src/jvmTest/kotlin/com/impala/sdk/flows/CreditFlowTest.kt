package com.impala.sdk.flows

import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class CreditFlowTest {
    @Test
    fun `bridge-style credit tail is applied and the receive counter advances, a replayed tail answers 6233 and is reported as an ack status word, not thrown`() {
        val issuer = TestIssuer()
        val account = uuidBytes()
        val card = personalizedCard(issuer, account, TransferProtocol.CURRENCY_XLM)
        val redemptionUuid = uuidBytes()
        val treasury = issuer.externalSender(redemptionUuid, TransferProtocol.CURRENCY_XLM)
        val counter = TransferProtocol.nextReceiveCounter(card.sdk.getReceiveState().counter)
        val signable = Signable(1, redemptionUuid, account, TransferProtocol.CURRENCY_XLM, 100_000, 0, counter).encode()
        val tail = treasury.envelope(signable).tail209()

        assertEquals("9000", CreditFlow.apply(card.sdk, signable, tail))
        assertEquals(counter, card.sdk.getReceiveState().counter)
        assertEquals(100_000L, card.sdk.getBalance())

        assertEquals("6233", CreditFlow.apply(card.sdk, signable, tail))
        assertEquals(100_000L, card.sdk.getBalance())
    }

    @Test
    fun `malformed tail is refused before the card`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val e = assertFailsWith<CardFlowException> { CreditFlow.apply(card.sdk, ByteArray(60), ByteArray(208)) }
        assertIs<CardError.InvalidRequest>(e.error)
    }
}

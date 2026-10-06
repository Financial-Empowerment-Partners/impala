package com.payala.impala.demo

import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferProtocol
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.model.FundingInstructions
import com.payala.impala.demo.model.IssuanceAckRequest
import com.payala.impala.demo.model.IssuanceCreditResponse
import com.payala.impala.demo.model.IssuanceResponse
import com.payala.impala.demo.model.SignSubmitRequest
import com.payala.impala.demo.model.SignSubmitResponse
import com.payala.impala.demo.transfer.IssuanceController
import com.payala.impala.demo.transfer.IssuanceController.TornVerdict
import com.payala.impala.demo.transfer.IssuanceRefused
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verifyBlocking
import org.robolectric.RobolectricTestRunner
import retrofit2.Response

/** Bridge → card load (C-6): funding contract, credit application on jcardsim, torn-apply decisions. */
@RunWith(RobolectricTestRunner::class)
class IssuanceViewModelTest {
    private val funding = FundingInstructions(
        destination = "GRESERVE7ADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        asset = "XLM", amount = "0.0100000", memo = "ISABCDEFGHJKMNPQRSTVWXYZ01", idempotency_key = "ISABCDEFGHJKMNPQRSTVWXYZ01"
    )

    private fun created(world: TransferWorld) = IssuanceResponse("iss-1", funding.memo, "awaiting_funds", funding)

    /** A bridge-style credit for the world's card: sender = redemption uuid, recipient = card account. */
    private fun credit(world: TransferWorld, amount: Long = 100_000, counter: Int? = null): IssuanceCreditResponse {
        val c = counter ?: (world.card.sdk.getReceiveState().counter + 1)
        val signable = Signable(world.sendSequence++, UuidBytes.parse(world.redemptionUuid), UuidBytes.parse(world.account), TransferProtocol.CURRENCY_XLM, amount, 0, c).encode()
        val env = world.treasury.envelope(signable)
        return IssuanceCreditResponse("iss-1", "issued", c, 1, Hex.encode(signable), Hex.encode(env.signature),
            Hex.encode(world.treasury.pub65), Hex.encode(world.treasury.cert), Hex.encode(env.tail209()))
    }

    private fun api(world: TransferWorld, credit: IssuanceCreditResponse? = null, sign: Response<SignSubmitResponse> =
        Response.success(200, SignSubmitResponse(true, "settled", status = "settled", intent_id = "int-1"))): BridgeApiService = mock {
        onBlocking { createIssuance(any()) } doReturn Response.success(created(world))
        onBlocking { signAndSubmit(any()) } doReturn sign
        onBlocking { issuance(any()) } doReturn IssuanceResponse("iss-1", funding.memo, "funded")
        if (credit != null) onBlocking { issuanceCredit(any()) } doReturn Response.success(credit)
        onBlocking { ackIssuance(any(), any()) } doReturn Response.success(IssuanceResponse("iss-1", funding.memo, "acked"))
    }

    @Test
    fun `funding request uses the bridge-provided destination, amount, memo and idempotency key verbatim`() = runTest {
        val world = TransferWorld(balance = 0)
        val store = freshStore()
        val api = api(world)
        val c = IssuanceController(api, store)
        c.create(world.account, world.cardId, 100_000, 0)
        val funded = c.fund(world.account, "iss-1")
        assertEquals("settled", funded.fundingStatus)
        val captor = argumentCaptor<SignSubmitRequest>()
        verifyBlocking(api) { signAndSubmit(captor.capture()) }
        assertEquals(SignSubmitRequest(world.account, funding.destination, funding.amount, funding.memo, funding.idempotency_key), captor.firstValue)
    }

    @Test
    fun `ambiguous sign outcome never sends a second sign request with a different key`() = runTest {
        val world = TransferWorld(balance = 0)
        val store = freshStore()
        val api = api(world, sign = Response.success(202, SignSubmitResponse(false, "outcome unknown", status = "ambiguous", intent_id = "int-1")))
        val c = IssuanceController(api, store)
        c.create(world.account, world.cardId, 100_000, 0)
        assertEquals("ambiguous", c.fund(world.account, "iss-1").fundingStatus)
        val e = assertThrows(IssuanceRefused::class.java) { runBlocking { c.fund(world.account, "iss-1", newAttemptAfterRejection = true) } }
        assertEquals("not_rejected", e.code)
        c.fund(world.account, "iss-1") // a replay is allowed — with the same key
        val captor = argumentCaptor<SignSubmitRequest>()
        verifyBlocking(api, times(2)) { signAndSubmit(captor.capture()) }
        assertTrue(captor.allValues.all { it.idempotency_key == funding.idempotency_key })
    }

    @Test
    fun `credit applied on jcardsim advances GET_RECEIVE_STATE and acks 9000`() = runTest {
        val world = TransferWorld(balance = 0)
        val store = freshStore()
        val creditResponse = credit(world)
        val api = api(world, creditResponse)
        val c = IssuanceController(api, store)
        val observed = offMain { c.observeReceiveCounter(ImpalaCardSession.fromBibo(world.card.bibo)) }
        c.create(world.account, world.cardId, 100_000, observed)
        c.fund(world.account, "iss-1")
        assertEquals("funded", c.awaitFunded("iss-1", intervalMs = 1).state)
        c.fetchCredit("iss-1")
        val applied = offMain { c.applyOnCard(ImpalaCardSession.fromBibo(world.card.bibo), "iss-1") }
        assertEquals("9000", applied.ackStatusWord)
        assertEquals(creditResponse.counter, world.card.sdk.getReceiveState().counter)
        assertEquals(100_000L, world.card.sdk.getBalance())
        c.ack("iss-1")
        verifyBlocking(api) { ackIssuance(eq("iss-1"), eq(IssuanceAckRequest(true, "9000"))) }
    }

    @Test
    fun `credit refused by the card is acked with applied=false and the status word`() = runTest {
        val world = TransferWorld(balance = 0)
        val store = freshStore()
        // A credit for the wrong currency: the card answers 6229.
        val wrong = run {
            val c = world.card.sdk.getReceiveState().counter + 1
            val usdc = world.issuer.externalSender(UuidBytes.parse(world.redemptionUuid), TransferProtocol.CURRENCY_USDC)
            val s = Signable(9, UuidBytes.parse(world.redemptionUuid), UuidBytes.parse(world.account), TransferProtocol.CURRENCY_USDC, 5, 0, c).encode()
            val env = usdc.envelope(s)
            IssuanceCreditResponse("iss-1", "issued", c, 1, Hex.encode(s), Hex.encode(env.signature), Hex.encode(usdc.pub65), Hex.encode(usdc.cert), Hex.encode(env.tail209()))
        }
        val api = api(world, wrong)
        val c = IssuanceController(api, store)
        c.create(world.account, world.cardId, 5, 0)
        c.fetchCredit("iss-1")
        val refused = offMain { c.applyOnCard(ImpalaCardSession.fromBibo(world.card.bibo), "iss-1") }
        assertEquals("6229", refused.ackStatusWord)
        assertEquals("card_refused", refused.state)
        c.ack("iss-1")
        verifyBlocking(api) { ackIssuance(eq("iss-1"), eq(IssuanceAckRequest(false, "6229"))) }
        assertEquals(0L, world.card.sdk.getBalance())
    }

    @Test
    fun `torn apply - digest equal means already applied, counter behind means re-present, counter ahead with different digest is an exception, never auto-credit`() = runTest {
        val c = IssuanceController(mock(), freshStore())
        assertEquals(TornVerdict.ALREADY_APPLIED, c.tornVerdict(5, "ab".repeat(32), 5, "AB".repeat(32)))
        assertEquals(TornVerdict.PRESENT, c.tornVerdict(4, "00".repeat(32), 5, "ab".repeat(32)))
        assertEquals(TornVerdict.EXCEPTION, c.tornVerdict(5, "00".repeat(32), 5, "ab".repeat(32)))
        assertEquals(TornVerdict.EXCEPTION, c.tornVerdict(9, "00".repeat(32), 5, "ab".repeat(32)))

        // On the card: re-presenting an applied credit does not send VERIFY_TRANSFER_V2 again.
        val world = TransferWorld(balance = 0)
        val store = freshStore()
        val api = api(world, credit(world))
        val ic = IssuanceController(api, store)
        ic.create(world.account, world.cardId, 100_000, 0)
        ic.fetchCredit("iss-1")
        offMain { ic.applyOnCard(ImpalaCardSession.fromBibo(world.card.bibo), "iss-1") }
        val verifies = world.verifyTransferCount()
        val again = offMain { ic.applyOnCard(ImpalaCardSession.fromBibo(world.card.bibo), "iss-1") }
        assertEquals("9000", again.ackStatusWord)
        assertEquals(verifies, world.verifyTransferCount())
        assertEquals(100_000L, world.card.sdk.getBalance())

        // Another credit took the counter: exception, nothing applied, no ack.
        val world2 = TransferWorld(balance = 0)
        val store2 = freshStore()
        val stale = credit(world2) // counter 1
        com.impala.simulator.fund(world2.card, world2.treasury, 7, world2.sendSequence++) // someone else's credit uses counter 1
        val ic2 = IssuanceController(api(world2, stale), store2)
        ic2.create(world2.account, world2.cardId, 100_000, 0)
        ic2.fetchCredit("iss-1")
        val ex = offMain { ic2.applyOnCard(ImpalaCardSession.fromBibo(world2.card.bibo), "iss-1") }
        assertEquals(IssuanceController.EXCEPTION_SW, ex.ackStatusWord)
        assertEquals(7L, world2.card.sdk.getBalance())
        assertEquals("exception_needs_operator", assertThrows(IssuanceRefused::class.java) { runBlocking { ic2.ack("iss-1") } }.code)
    }
}

package com.payala.impala.demo

import com.google.gson.Gson
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.Signable
import com.impala.simulator.Jca
import com.impala.sdk.models.TransferProtocol
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.model.RedemptionRequest
import com.payala.impala.demo.model.RedemptionResponse
import com.payala.impala.demo.model.RedemptionStatusResponse
import com.payala.impala.demo.transfer.Money
import com.payala.impala.demo.transfer.PendingRedemption
import com.payala.impala.demo.transfer.RedemptionController
import com.payala.impala.demo.transfer.RedemptionRefused
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.doSuspendableAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verifyBlocking
import org.robolectric.RobolectricTestRunner
import retrofit2.Response
import java.io.IOException

/**
 * Card → bridge redemption (C-5) against the real applet on jcardsim and a
 * mocked bridge: compose rules, never-re-sign, replay handling, frozen and
 * refusal paths.
 */
@RunWith(RobolectricTestRunner::class)
class RedemptionViewModelTest {
    private val now = 1_800_000_000_000L

    private fun api(world: TransferWorld, lastRedeemed: Int = 0, configured: Boolean = true, certified: Boolean = true): BridgeApiService = mock {
        onBlocking { cardIssuer() } doReturn world.issuerResponse(configured)
        onBlocking { offlineCard(any()) } doReturn world.offlineCard(certified, lastRedeemed)
        onBlocking { createRedemption(any()) } doReturn Response.success(202, RedemptionResponse("r-1", "ORABCDEFGH", "accepted", 40_000, 400_000_000, "XLM"))
        onBlocking { redemptionStatus(any()) } doReturn RedemptionStatusResponse(state = "paid", btxid = "b-1")
    }

    private fun sign(world: TransferWorld, controller: RedemptionController, prepared: RedemptionController.Prepared, amount: Long = 40_000, pin: String = "2468") =
        offMain { controller.signOnCard(ImpalaCardSession.fromBibo(world.card.bibo), prepared, world.storedCard(), amount, pin.toCharArray()) }

    @Test
    fun `composes the signable with recipient = redemption uuid, counter = last + 1 and a send sequence greater than the previous`() = runTest {
        val world = TransferWorld()
        val store = freshStore()
        val controller = RedemptionController(api(world, lastRedeemed = 7), store) { now }
        val signed = sign(world, controller, controller.prepare(world.cardId))
        val s = Signable.decode(Hex.decode(signed.signableHex))
        assertArrayEquals(UuidBytes.parse(world.redemptionUuid), s.recipient)
        assertArrayEquals(UuidBytes.parse(world.account), s.sender)
        assertArrayEquals(TransferProtocol.CURRENCY_XLM, s.currency)
        assertEquals(8, s.counter)
        assertEquals(40_000L, s.amount)
        assertEquals(now, s.dateTime) // max(previous + 1, now) with previous = 0
        // The tuple verifies over the 89-byte XFER message under the card key.
        val xfer = TransferProtocol.xferMessage(world.issuer.programId, Hex.decode(signed.tuple!!.signableHex))
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(world.card.pub65), xfer, Hex.decode(signed.tuple!!.signatureDerHex)))
        assertEquals(60_000L, world.card.sdk.getBalance())

        // A second redemption (clock went backwards) still advances the sequence.
        store.archiveRedemption(world.cardId)
        val back = RedemptionController(api(world, lastRedeemed = 8), store) { 5 }
        val second = sign(world, back, back.prepare(world.cardId), amount = 1)
        assertEquals(now + 1, Signable.decode(Hex.decode(second.signableHex)).dateTime)
        assertEquals(9, Signable.decode(Hex.decode(second.signableHex)).counter)
    }

    @Test
    fun `amount parsing accepts digits only, refuses zero, refuses above u32 and never uses floating point`() {
        assertEquals(1L, Money.parseCardAmount("1"))
        assertEquals(4_294_967_295L, Money.parseCardAmount("4294967295"))
        for (bad in listOf("0", "", " ", "-1", "+5", "1.5", "1e3", "4294967296", "99999999999", "1,000", "١٢")) {
            assertNull(bad, Money.parseCardAmount(bad))
        }
        assertEquals("0.0040000", Money.format(40_000, 7))
        assertEquals("12.0000000", Money.format(120_000_000, 7))
        assertEquals("5", Money.format(5, 0))
    }

    @Test
    fun `persists the tuple before POST and re-posts identical bytes on network failure`() = runTest {
        val world = TransferWorld()
        val store = freshStore()
        var calls = 0
        val api = api(world).also { m ->
            org.mockito.kotlin.whenever(runBlocking { m.createRedemption(any()) }).doSuspendableAnswer {
                if (calls++ == 0) throw IOException("connection reset")
                Response.success(202, RedemptionResponse("r-9", "ORZZ", "accepted"))
            }
        }
        val controller = RedemptionController(api, store) { now }
        val signed = sign(world, controller, controller.prepare(world.cardId))
        assertEquals(PendingRedemption.STATE_SIGNED, store.redemption(world.cardId)!!.state)
        assertEquals(signed.tuple, store.redemption(world.cardId)!!.tuple)

        assertThrows(IOException::class.java) { runBlocking { controller.submit(world.account, world.cardId) } }
        // Same slot, still signed, nothing re-signed.
        assertEquals(signed.tuple, store.redemption(world.cardId)!!.tuple)
        val after = controller.submit(world.account, world.cardId)
        assertEquals("r-9", after.redemptionId)

        val captor = argumentCaptor<RedemptionRequest>()
        verifyBlocking(api, times(2)) { createRedemption(captor.capture()) }
        assertEquals(captor.firstValue, captor.secondValue)
        assertEquals(Gson().toJson(captor.firstValue), Gson().toJson(captor.secondValue))
        assertEquals(signed.tuple!!.cardCertHex, captor.firstValue.card_cert_hex)
        assertEquals(1, world.signTransferCount())
    }

    @Test
    fun `202 replay and 409 counter_consumed are treated as already-submitted, not as errors to re-sign`() = runTest {
        for (case in listOf("replay", "counter_consumed")) {
            val world = TransferWorld()
            val store = freshStore()
            val api = api(world).also { m ->
                val resp: Response<RedemptionResponse> = if (case == "replay") Response.success(202, RedemptionResponse("r-old", null, "paying"))
                else Response.error(409, """{"error":{"code":"counter_consumed","message":"counter already used"}}""".toResponseBody("application/json".toMediaType()))
                org.mockito.kotlin.whenever(runBlocking { m.createRedemption(any()) }).doReturn(resp)
            }
            val controller = RedemptionController(api, store) { now }
            sign(world, controller, controller.prepare(world.cardId))
            val r = controller.submit(world.account, world.cardId)
            if (case == "replay") {
                assertEquals("r-old", r.redemptionId)
                assertEquals("paying", r.state)
            } else {
                assertEquals(PendingRedemption.STATE_SUBMITTED, r.state)
                assertTrue(r.isTerminal)
            }
            assertEquals(1, world.signTransferCount())
        }
    }

    @Test
    fun `frozen state is shown as ambiguous and blocks a new redemption from the same card until resolved`() = runTest {
        val world = TransferWorld()
        val store = freshStore()
        val api = api(world).also { m ->
            org.mockito.kotlin.whenever(runBlocking { m.redemptionStatus(any()) }).doReturn(RedemptionStatusResponse(state = "frozen"))
        }
        val controller = RedemptionController(api, store) { now }
        sign(world, controller, controller.prepare(world.cardId))
        controller.submit(world.account, world.cardId)
        val tracked = controller.track(world.cardId, intervalMs = 1, maxMs = 3)
        assertTrue(tracked.isFrozen)
        val e = assertThrows(RedemptionRefused::class.java) { runBlocking { controller.prepare(world.cardId) } }
        assertEquals(RedemptionRefused.Refusal.FROZEN_PENDING, e.refusal)
    }

    @Test
    fun `recoverLastSigned offers resume when a signed transfer has no stored redemption id`() = runTest {
        val world = TransferWorld()
        val store = freshStore()
        val controller = RedemptionController(api(world), store) { now }
        val signed = sign(world, controller, controller.prepare(world.cardId))
        // The app "died" after the card signed but before the tuple was persisted.
        store.saveRedemption(signed.copy(tuple = null, state = PendingRedemption.STATE_SIGNING))
        assertTrue(controller.needsRecovery(world.cardId))
        val recovered = offMain { controller.recoverOnCard(ImpalaCardSession.fromBibo(world.card.bibo), world.cardId) }
        assertEquals(signed.tuple, recovered!!.tuple)
        assertEquals(1, world.signTransferCount())
        assertEquals(60_000L, world.card.sdk.getBalance())
        assertEquals("r-1", controller.submit(world.account, world.cardId).redemptionId)

        // A slot the card never signed is dropped (nothing was debited).
        val other = TransferWorld()
        store.saveRedemption(PendingRedemption(other.cardId, "00".repeat(60)))
        assertNull(offMain { controller.recoverOnCard(ImpalaCardSession.fromBibo(other.card.bibo), other.cardId) })
        assertNull(store.redemption(other.cardId))
    }

    @Test
    fun `refuses when card-issuer is unconfigured or the card is not certified`() = runTest {
        val world = TransferWorld()
        val e1 = assertThrows(RedemptionRefused::class.java) {
            runBlocking { RedemptionController(api(world, configured = false), freshStore()).prepare(world.cardId) }
        }
        assertEquals(RedemptionRefused.Refusal.ISSUER_UNCONFIGURED, e1.refusal)
        val e2 = assertThrows(RedemptionRefused::class.java) {
            runBlocking { RedemptionController(api(world, certified = false), freshStore()).prepare(world.cardId) }
        }
        assertEquals(RedemptionRefused.Refusal.CARD_NOT_CERTIFIED, e2.refusal)
    }

    @Test
    fun `wrong PIN yields WrongPin and leaves only an unsigned slot`() = runTest {
        val world = TransferWorld()
        val store = freshStore()
        val api = api(world)
        val controller = RedemptionController(api, store) { now }
        val prepared = controller.prepare(world.cardId)
        val e = assertThrows(CardFlowException::class.java) { sign(world, controller, prepared, pin = "1357") }
        assertEquals(4, (e.error as CardError.WrongPin).triesLeft)
        assertEquals(100_000L, world.card.sdk.getBalance())
        verifyBlocking(api, never()) { createRedemption(any()) }
        // The unsigned slot is resolved on the next tap: the card never signed it.
        assertNull(offMain { controller.recoverOnCard(ImpalaCardSession.fromBibo(world.card.bibo), world.cardId) })
    }

    @Test
    fun `PIN 0000 and bad amounts are refused before the card`() = runTest {
        val world = TransferWorld()
        val controller = RedemptionController(api(world), freshStore()) { now }
        val prepared = controller.prepare(world.cardId)
        val pin = "0000".toCharArray()
        val e = assertThrows(RedemptionRefused::class.java) {
            offMain { controller.signOnCard(ImpalaCardSession.fromBibo(world.card.bibo), prepared, world.storedCard(), 5, pin) }
        }
        assertEquals(RedemptionRefused.Refusal.PIN_LESS_REFUSED, e.refusal)
        assertArrayEquals(CharArray(4), pin)
        assertEquals(RedemptionRefused.Refusal.AMOUNT_INVALID, assertThrows(RedemptionRefused::class.java) { sign(world, controller, prepared, amount = 0) }.refusal)
        assertEquals(0, world.signTransferCount())
    }
}

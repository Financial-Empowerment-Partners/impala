package com.payala.impala.demo.transfer

import com.impala.sdk.flows.RedemptionTuple
import com.payala.impala.demo.R
import com.payala.impala.demo.ui.transfer.TransferPresentation
import com.payala.impala.demo.ui.transfer.TransferPresentation.RowAction
import com.payala.impala.demo.ui.transfer.TransferPresentation.SubmitOutcome
import com.payala.impala.demo.ui.transfer.TransferPresentation.Tone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Transfers row table (design F8): label, tone, action and persistent banner per raw state. */
class TransferPresentationTest {

    private val cardId = "00112233445566778899aabbccddeeff"
    private val tuple = RedemptionTuple("ab".repeat(60), "30".repeat(36), "04" + "11".repeat(64), "30".repeat(36))

    private fun redemption(state: String, tuple: RedemptionTuple? = this.tuple, id: String? = "red-1", reason: String? = null, amount: Long = 12_500) =
        PendingRedemption(cardId, "ab", tuple, id, state, reason, null, amount, 1_000)

    private fun credit(
        state: String = "awaiting_funds",
        funding: String = "none",
        signable: String? = null,
        sw: String? = null,
        amount: Long = 10_000_000
    ) = PendingCredit("iss-1", cardId, amount, issuanceRef = "ref-1", fundingStatus = funding, state = state, signableHex = signable, ackStatusWord = sw, createdAt = 2_000)

    private data class Expect(val label: Int, val tone: Tone, val action: RowAction, val banner: Int?)

    private fun TransferPresentation.TransferRow.expect() = Expect(label, tone, action, banner?.textRes)

    @Test
    fun `redemption table`() {
        val table = mapOf(
            redemption("signing", tuple = null, id = null) to Expect(R.string.transfer_label_signing, Tone.PENDING, RowAction.NONE, null),
            redemption("signed", id = null) to Expect(R.string.transfer_label_ready_to_send, Tone.PENDING, RowAction.SEND, null),
            redemption("submitted", id = null) to Expect(R.string.transfer_label_sent, Tone.PENDING, RowAction.NONE, null),
            redemption("accepted") to Expect(R.string.transfer_label_sent, Tone.PENDING, RowAction.NONE, null),
            redemption("paying") to Expect(R.string.transfer_label_sent, Tone.PENDING, RowAction.NONE, null),
            redemption("paid") to Expect(R.string.transfer_label_paid, Tone.SUCCESS, RowAction.NONE, null),
            redemption("failed") to Expect(R.string.transfer_label_failed, Tone.NEUTRAL, RowAction.NONE, null),
            redemption("cancelled") to Expect(R.string.transfer_label_cancelled, Tone.NEUTRAL, RowAction.NONE, null),
            redemption("refused", reason = "bad_cert") to Expect(R.string.transfer_label_held, Tone.DANGER, RowAction.DETAILS, R.string.transfer_refused_needs_operator),
            redemption("frozen") to Expect(R.string.transfer_label_outcome_unknown, Tone.WARNING, RowAction.DETAILS, R.string.transfer_frozen)
        )
        table.forEach { (r, expected) -> assertEquals(r.state, expected, TransferPresentation.redemption(r).expect()) }
    }

    @Test
    fun `a signed slot without a tuple never offers Send`() {
        val row = TransferPresentation.redemption(redemption("signed", tuple = null, id = null))
        assertEquals(RowAction.NONE, row.action)
    }

    @Test
    fun `persistent banners carry their arguments and tones`() {
        val refused = TransferPresentation.redemption(redemption("refused", reason = "bad_cert")).banner!!
        assertEquals("bad_cert", refused.arg)
        assertEquals(Tone.DANGER, refused.tone)
        val frozen = TransferPresentation.redemption(redemption("frozen")).banner!!
        assertEquals(Tone.WARNING, frozen.tone)
        val cardRefused = TransferPresentation.credit(credit(state = "card_refused", sw = "6A80")).banner!!
        assertEquals(R.string.transfer_card_refused_credit, cardRefused.textRes)
        assertEquals("6A80", cardRefused.arg)
        assertEquals(Tone.DANGER, cardRefused.tone)
    }

    @Test
    fun `unknown redemption states are shown raw, with details`() {
        val row = TransferPresentation.redemption(redemption("teleported"))
        assertEquals(R.string.transfer_label_other, row.label)
        assertEquals("teleported", row.labelArg)
        assertEquals(RowAction.DETAILS, row.action)
    }

    @Test
    fun `credit table`() {
        val table = mapOf(
            credit(funding = "none") to Expect(R.string.transfer_label_needs_funding, Tone.WARNING, RowAction.FUND, null),
            credit(funding = "rejected") to Expect(R.string.transfer_label_needs_funding, Tone.WARNING, RowAction.FUND, null),
            credit(funding = "submitted") to Expect(R.string.transfer_label_funding, Tone.PENDING, RowAction.NONE, null),
            credit(funding = "ambiguous") to Expect(R.string.transfer_label_funding_unknown, Tone.WARNING, RowAction.DETAILS, R.string.transfer_fund_ambiguous),
            credit(funding = "settled") to Expect(R.string.transfer_label_waiting_bridge, Tone.PENDING, RowAction.NONE, null),
            credit(state = "funded", funding = "settled", signable = "aa") to Expect(R.string.transfer_label_ready_to_apply, Tone.PENDING, RowAction.APPLY, null),
            credit(state = "issued", funding = "settled", signable = "aa") to Expect(R.string.transfer_label_ready_to_apply, Tone.PENDING, RowAction.APPLY, null),
            credit(state = "funded", funding = "settled") to Expect(R.string.transfer_label_funded, Tone.PENDING, RowAction.NONE, null),
            credit(state = "applied", funding = "settled", signable = "aa", sw = "9000") to Expect(R.string.transfer_label_loaded, Tone.SUCCESS, RowAction.NONE, null),
            credit(state = "acked", funding = "settled", signable = "aa", sw = "9000") to Expect(R.string.transfer_label_loaded, Tone.SUCCESS, RowAction.NONE, null),
            credit(state = "card_refused", funding = "settled", signable = "aa", sw = "6A80") to Expect(R.string.transfer_label_card_refused, Tone.DANGER, RowAction.DETAILS, R.string.transfer_card_refused_credit),
            credit(state = "exception", funding = "settled", signable = "aa", sw = IssuanceController.EXCEPTION_SW) to Expect(R.string.transfer_label_needs_operator, Tone.DANGER, RowAction.DETAILS, R.string.transfer_credit_exception),
            credit(state = "expired") to Expect(R.string.transfer_label_expired, Tone.NEUTRAL, RowAction.NONE, null),
            credit(state = "reversed") to Expect(R.string.transfer_label_reversed, Tone.NEUTRAL, RowAction.NONE, null)
        )
        table.forEach { (c, expected) -> assertEquals("${c.state}/${c.fundingStatus}/${c.ackStatusWord}", expected, TransferPresentation.credit(c).expect()) }
    }

    @Test
    fun `an applied credit that the card refused or that hit an exception never offers Apply again`() {
        for (sw in listOf("6A80", IssuanceController.EXCEPTION_SW)) {
            val row = TransferPresentation.credit(credit(state = "issued", funding = "settled", signable = "aa", sw = sw))
            assertEquals(RowAction.DETAILS, row.action)
            assertEquals(Tone.DANGER, row.tone)
        }
    }

    @Test
    fun `amounts are signed integer minor units at scale 7`() {
        val r = TransferPresentation.redemption(redemption("paid", amount = 12_500))
        assertEquals("-0.0012500", r.amountText)
        assertTrue(r.negative)
        val c = TransferPresentation.credit(credit(amount = 10_000_000))
        assertEquals("+1.0000000", c.amountText)
        assertEquals("+429.4967295", TransferPresentation.credit(credit(amount = Money.MAX_CARD_AMOUNT)).amountText)
        assertEquals("-0.0000001", TransferPresentation.redemption(redemption("paid", amount = 1)).amountText)
        assertEquals("scale 0", "-12500", TransferPresentation.redemption(redemption("paid", amount = 12_500), scale = 0).amountText)
    }

    @Test
    fun `rows name the card by its last four and keep stable keys`() {
        val r = TransferPresentation.redemption(redemption("paid"))
        assertEquals("eeff", r.cardLast4)
        assertEquals("r:red-1", r.key)
        assertEquals("c:iss-1", TransferPresentation.credit(credit()).key)
        assertEquals("r:$cardId:1000", TransferPresentation.redemption(redemption("signing", tuple = null, id = null)).key)
    }

    @Test
    fun `submit outcome drives the sheet's real outcome`() {
        assertNull(TransferPresentation.submitOutcome(null))
        assertNull("not answered yet", TransferPresentation.submitOutcome(redemption("signed", id = null)))
        assertEquals(SubmitOutcome.ACCEPTED, TransferPresentation.submitOutcome(redemption("accepted")))
        assertEquals(SubmitOutcome.ACCEPTED, TransferPresentation.submitOutcome(redemption("submitted", id = null)))
        assertEquals(SubmitOutcome.REFUSED, TransferPresentation.submitOutcome(redemption("refused", id = null, reason = "x")))
        assertEquals(SubmitOutcome.AMBIGUOUS, TransferPresentation.submitOutcome(redemption("frozen")))
    }
}

package com.payala.impala.demo.ui.transfer

import androidx.annotation.StringRes
import com.payala.impala.demo.R
import com.payala.impala.demo.transfer.IssuanceController
import com.payala.impala.demo.transfer.Money
import com.payala.impala.demo.transfer.PendingCredit
import com.payala.impala.demo.transfer.PendingRedemption

/**
 * How a pending or finished card transfer reads on the Transfers list (pure;
 * TransferPresentationTest pins the table). A NoFloatingPointMoneyTest root:
 * integer minor units only, formatted with [Money.format].
 *
 * Ambiguous and stranded outcomes carry a **persistent** in-row banner
 * (frozen payout, ambiguous funding, refused tuple, credit exception or
 * card refusal) instead of a Snackbar that disappears; none of them offers
 * anything that could repeat a debit or a credit.
 */
object TransferPresentation {

    enum class Tone { PENDING, SUCCESS, WARNING, DANGER, NEUTRAL }

    enum class RowAction { NONE, SEND, FUND, APPLY, DETAILS }

    enum class Kind { REDEEM, LOAD }

    class Banner(@StringRes val textRes: Int, val arg: String?, val tone: Tone)

    class TransferRow(
        /** Redemption id, issuance reference or a local key: stable for list diffing. */
        val key: String,
        val kind: Kind,
        val cardId: String,
        val cardLast4: String,
        /** Signed amount at [scale]: "-…" for a redemption (card debit), "+…" for a load (card credit). */
        val amountText: String,
        val negative: Boolean,
        @StringRes val label: Int,
        /** Argument for [label] when it takes one ([R.string.transfer_label_other]). */
        val labelArg: String?,
        val tone: Tone,
        val action: RowAction,
        val banner: Banner?,
        val createdAt: Long
    )

    /** The card amount scale (XLM cards: 7). */
    const val DEFAULT_SCALE = 7

    fun redemption(r: PendingRedemption, scale: Int = DEFAULT_SCALE): TransferRow {
        val (label, tone, action) = when (r.state) {
            PendingRedemption.STATE_SIGNING -> Triple(R.string.transfer_label_signing, Tone.PENDING, RowAction.NONE)
            PendingRedemption.STATE_SIGNED ->
                if (r.tuple != null) Triple(R.string.transfer_label_ready_to_send, Tone.PENDING, RowAction.SEND)
                else Triple(R.string.transfer_label_signing, Tone.PENDING, RowAction.NONE)
            PendingRedemption.STATE_SUBMITTED, "accepted", "paying" -> Triple(R.string.transfer_label_sent, Tone.PENDING, RowAction.NONE)
            "paid" -> Triple(R.string.transfer_label_paid, Tone.SUCCESS, RowAction.NONE)
            "failed" -> Triple(R.string.transfer_label_failed, Tone.NEUTRAL, RowAction.NONE)
            "cancelled" -> Triple(R.string.transfer_label_cancelled, Tone.NEUTRAL, RowAction.NONE)
            PendingRedemption.STATE_REFUSED -> Triple(R.string.transfer_label_held, Tone.DANGER, RowAction.DETAILS)
            "frozen" -> Triple(R.string.transfer_label_outcome_unknown, Tone.WARNING, RowAction.DETAILS)
            else -> Triple(R.string.transfer_label_other, Tone.NEUTRAL, RowAction.DETAILS)
        }
        val banner = when {
            r.isFrozen -> Banner(R.string.transfer_frozen, null, Tone.WARNING)
            r.state == PendingRedemption.STATE_REFUSED -> Banner(R.string.transfer_refused_needs_operator, r.reason ?: "", Tone.DANGER)
            else -> null
        }
        return TransferRow(
            key = "r:" + (r.redemptionId ?: (r.cardId + ":" + r.createdAt)),
            kind = Kind.REDEEM,
            cardId = r.cardId,
            cardLast4 = r.cardId.takeLast(LAST) ,
            amountText = "-" + Money.format(r.amount, scale),
            negative = true,
            label = label,
            labelArg = if (label == R.string.transfer_label_other) r.state else null,
            tone = tone,
            action = action,
            banner = banner,
            createdAt = r.createdAt
        )
    }

    fun credit(c: PendingCredit, scale: Int = DEFAULT_SCALE): TransferRow {
        val sw = c.ackStatusWord
        val (label, tone, action) = when {
            c.state == "exception" || sw == IssuanceController.EXCEPTION_SW ->
                Triple(R.string.transfer_label_needs_operator, Tone.DANGER, RowAction.DETAILS)
            c.state == "card_refused" || (sw != null && sw != SW_OK) ->
                Triple(R.string.transfer_label_card_refused, Tone.DANGER, RowAction.DETAILS)
            sw == SW_OK || c.state == "applied" || c.state == "acked" ->
                Triple(R.string.transfer_label_loaded, Tone.SUCCESS, RowAction.NONE)
            c.fundingStatus == "ambiguous" ->
                Triple(R.string.transfer_label_funding_unknown, Tone.WARNING, RowAction.DETAILS)
            c.state == "awaiting_funds" && c.fundingStatus in FUNDABLE ->
                Triple(R.string.transfer_label_needs_funding, Tone.WARNING, RowAction.FUND)
            c.fundingStatus == "submitted" ->
                Triple(R.string.transfer_label_funding, Tone.PENDING, RowAction.NONE)
            c.state == "awaiting_funds" ->
                Triple(R.string.transfer_label_waiting_bridge, Tone.PENDING, RowAction.NONE)
            c.state in READY && c.signableHex != null ->
                Triple(R.string.transfer_label_ready_to_apply, Tone.PENDING, RowAction.APPLY)
            c.state in READY -> Triple(R.string.transfer_label_funded, Tone.PENDING, RowAction.NONE)
            c.state == "expired" -> Triple(R.string.transfer_label_expired, Tone.NEUTRAL, RowAction.NONE)
            c.state == "reversed" -> Triple(R.string.transfer_label_reversed, Tone.NEUTRAL, RowAction.NONE)
            else -> Triple(R.string.transfer_label_other, Tone.NEUTRAL, RowAction.DETAILS)
        }
        val banner = when (label) {
            R.string.transfer_label_needs_operator -> Banner(R.string.transfer_credit_exception, null, Tone.DANGER)
            R.string.transfer_label_card_refused -> Banner(R.string.transfer_card_refused_credit, sw ?: "", Tone.DANGER)
            R.string.transfer_label_funding_unknown -> Banner(R.string.transfer_fund_ambiguous, null, Tone.WARNING)
            else -> null
        }
        return TransferRow(
            key = "c:" + c.issuanceId,
            kind = Kind.LOAD,
            cardId = c.cardId,
            cardLast4 = c.cardId.takeLast(LAST),
            amountText = "+" + Money.format(c.cardAmount, scale),
            negative = false,
            label = label,
            labelArg = if (label == R.string.transfer_label_other) c.state else null,
            tone = tone,
            action = action,
            banner = banner,
            createdAt = c.createdAt
        )
    }

    /** Where a just-signed redemption stands after its submit, for the tap sheet's real outcome. */
    enum class SubmitOutcome { ACCEPTED, REFUSED, AMBIGUOUS }

    /**
     * Null while the submit has not answered yet (no bridge id, not
     * terminal). [r] is the card's current redemption (open slot, or the
     * newest archived one).
     */
    fun submitOutcome(r: PendingRedemption?): SubmitOutcome? = when {
        r == null -> null
        r.state == PendingRedemption.STATE_REFUSED -> SubmitOutcome.REFUSED
        r.isFrozen -> SubmitOutcome.AMBIGUOUS
        r.redemptionId != null || r.isTerminal -> SubmitOutcome.ACCEPTED
        else -> null
    }

    private const val LAST = 4
    private const val SW_OK = "9000"
    private val FUNDABLE = setOf("none", "rejected")
    private val READY = setOf("funded", "issued")
}

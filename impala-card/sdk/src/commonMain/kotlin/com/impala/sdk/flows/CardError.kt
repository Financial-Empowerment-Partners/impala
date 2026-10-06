package com.impala.sdk.flows

import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.apdu4j.BIBOTagLostException
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaPinException

/**
 * Typed card-flow failure. Every case has a stable [userMessageKey] so Android
 * (string resources) and JVM callers render the same text; [statusWord] is the
 * card's SW when the failure came from the card (for debug display and for the
 * bridge's opaque `ack_status_word`).
 */
sealed class CardError(val userMessageKey: String, val statusWord: Int? = null) {
    object NotPersonalized : CardError("card_error_not_personalized", 0x6234)
    object ProvisioningRequired : CardError("card_error_provisioning_required", 0x6985)
    object Terminated : CardError("card_error_terminated", 0x6687)
    class WrongPin(val triesLeft: Int) : CardError("card_error_wrong_pin", 0x69C0 or triesLeft)
    object PinBlocked : CardError("card_error_pin_blocked", 0x69C0)
    object InsufficientFunds : CardError("card_error_insufficient_funds", 0x6224)
    object CounterInvalid : CardError("card_error_counter_invalid", 0x6233)
    object CounterJump : CardError("card_error_counter_jump", 0x623A)
    object SendSequenceInvalid : CardError("card_error_send_sequence_invalid", 0x6238)
    class WrongProtocolVersion(val found: String) : CardError("card_error_wrong_protocol_version")
    object TagLost : CardError("card_error_tag_lost")
    /** A request the flow refuses before any card command (zero amount, self recipient, …). */
    class InvalidRequest(val reason: String) : CardError("card_error_invalid_request")
    /** Any other card status word, or a transport failure when [sw] is null. */
    class Other(val sw: Int?) : CardError("card_error_other", sw)

    /** The SW as 4 uppercase hex digits, or null. */
    val statusWordHex: String? get() = statusWord?.let { it.toString(16).uppercase().padStart(4, '0') }

    override fun toString(): String = this::class.simpleName + (statusWordHex?.let { "(SW=$it)" } ?: "")

    companion object {
        /** Every [userMessageKey] a caller must be able to render. */
        val ALL_MESSAGE_KEYS: List<String> = listOf(
            "card_error_not_personalized", "card_error_provisioning_required", "card_error_terminated",
            "card_error_wrong_pin", "card_error_pin_blocked", "card_error_insufficient_funds",
            "card_error_counter_invalid", "card_error_counter_jump", "card_error_send_sequence_invalid",
            "card_error_wrong_protocol_version", "card_error_tag_lost", "card_error_invalid_request",
            "card_error_other"
        )

        /** Maps a card status word to its case. */
        fun fromStatusWord(sw: Int): CardError = when (sw) {
            0x6234 -> NotPersonalized
            0x6985 -> ProvisioningRequired
            0x6687 -> Terminated
            0x69C0 -> PinBlocked
            in 0x69C1..0x69C9 -> WrongPin(sw and 0x0F)
            0x6224 -> InsufficientFunds
            0x6233 -> CounterInvalid
            0x623A -> CounterJump
            0x6238 -> SendSequenceInvalid
            0x6D00 -> WrongProtocolVersion("unknown (INS not supported)")
            else -> Other(sw)
        }

        /**
         * Maps anything a card flow can throw. Walks the cause chain so a
         * tag loss wrapped by `ImpalaSDK.tx` is still [TagLost].
         */
        fun from(t: Throwable): CardError {
            if (t is CardFlowException) return t.error
            var c: Throwable? = t
            while (c != null) {
                if (c is BIBOTagLostException) return TagLost
                c = c.cause
            }
            if (t is ImpalaPinException) return if (t.triesRemaining == 0) PinBlocked else WrongPin(t.triesRemaining)
            if (t is ImpalaException) t.statusWord?.let { return fromStatusWord(it) }
            if (t is IllegalArgumentException) return InvalidRequest(t.message ?: "invalid request")
            if (t is BIBOException) return Other(null)
            return Other(null)
        }
    }
}

/** Thrown by every card flow; carries the typed [error]. */
class CardFlowException(val error: CardError, cause: Throwable? = null) :
    RuntimeException(error.toString(), cause)

/** Runs [block], converting any failure into a [CardFlowException]. */
internal inline fun <T> cardFlow(block: () -> T): T =
    try {
        block()
    } catch (e: CardFlowException) {
        throw e
    } catch (e: Exception) {
        throw CardFlowException(CardError.from(e), e)
    }

package com.payala.impala.card

import android.content.Context
import com.impala.sdk.flows.CardError
import com.payala.impala.R

/** Renders a [CardError] with the library's string resources (English; apps may override them). */
object CardErrorMessages {
    /** The string resource for each [CardError.userMessageKey]. */
    @JvmStatic
    fun resId(key: String): Int = when (key) {
        "card_error_not_personalized" -> R.string.card_error_not_personalized
        "card_error_provisioning_required" -> R.string.card_error_provisioning_required
        "card_error_terminated" -> R.string.card_error_terminated
        "card_error_wrong_pin" -> R.string.card_error_wrong_pin
        "card_error_pin_blocked" -> R.string.card_error_pin_blocked
        "card_error_insufficient_funds" -> R.string.card_error_insufficient_funds
        "card_error_counter_invalid" -> R.string.card_error_counter_invalid
        "card_error_counter_jump" -> R.string.card_error_counter_jump
        "card_error_send_sequence_invalid" -> R.string.card_error_send_sequence_invalid
        "card_error_wrong_protocol_version" -> R.string.card_error_wrong_protocol_version
        "card_error_tag_lost" -> R.string.card_error_tag_lost
        "card_error_invalid_request" -> R.string.card_error_invalid_request
        else -> R.string.card_error_other
    }

    /**
     * The user-facing message. With [includeStatusWord] (debug builds only)
     * the raw SW is appended for diagnosis.
     */
    @JvmStatic
    @JvmOverloads
    fun message(context: Context, error: CardError, includeStatusWord: Boolean = false): String {
        val base = when (error) {
            is CardError.WrongPin -> context.getString(resId(error.userMessageKey), error.triesLeft)
            is CardError.WrongProtocolVersion -> context.getString(resId(error.userMessageKey), error.found)
            is CardError.InvalidRequest -> context.getString(resId(error.userMessageKey), error.reason)
            else -> context.getString(resId(error.userMessageKey))
        }
        val sw = error.statusWordHex
        return if (includeStatusWord && sw != null) "$base (SW $sw)" else base
    }
}

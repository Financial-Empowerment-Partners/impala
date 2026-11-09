package com.payala.impala.demo.ui.tap

import android.content.Context
import com.impala.sdk.flows.CardFlowException
import com.payala.impala.card.CardErrorMessages
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.card.DebugCards

/** The device cannot take a card tap right now; delivered to a request instead of waiting forever. */
class CardReaderUnavailableException(val readerDisabled: Boolean) :
    IllegalStateException(if (readerDisabled) "NFC is disabled" else "NFC is not available")

/**
 * The request was dropped before any card was tapped (the user cancelled, or
 * its screen went away). Delivered so the requester can release what it holds
 * (a PIN buffer); never shown as a failure.
 */
class TapCancelledException : IllegalStateException("card tap cancelled")

/** The simulated tap could not be started (reader mode off, or no simulated card configured). */
class SimulatedTapNotStartedException(message: String) : IllegalStateException(message)

/** How a tap failure reads on the sheet: message, SW (debug builds only) and whether NFC is off. */
class TapFailureText(val message: CharSequence, val swHex: String?, val readerDisabled: Boolean)

/**
 * Renders a tap failure for the sheet. A simulated-card failure uses the
 * debug transport's own text (release builds never produce one); card
 * refusals use the lib's card error strings, with the status word split out
 * (debug builds only); anything else shows its message.
 */
object TapFailures {
    fun describe(context: Context, e: Throwable): TapFailureText {
        DebugCards.describeFailure(e)?.let { return TapFailureText(it, null, false) }
        return when (e) {
            is CardReaderUnavailableException -> TapFailureText(
                context.getString(if (e.readerDisabled) R.string.nfc_disabled else R.string.nfc_not_available), null, e.readerDisabled
            )
            is SimulatedTapNotStartedException -> TapFailureText(context.getString(R.string.tap_reader_off), null, false)
            is CardFlowException -> TapFailureText(
                CardErrorMessages.message(context, e.error, includeStatusWord = false),
                if (BuildConfig.DEBUG) e.error.statusWordHex else null,
                false
            )
            else -> TapFailureText(e.message?.takeIf { it.isNotBlank() } ?: context.getString(R.string.tap_failed_unknown), null, false)
        }
    }
}

package com.payala.impala.demo.ui.tap

import androidx.annotation.StringRes
import com.payala.impala.demo.card.TapStep

/**
 * What the tap sheet shows. Produced only by [TapStateMachine]; plain
 * classes (not data classes) so every transition is a new identity and no
 * state ever renders anything but labels, ids and messages.
 */
sealed interface TapUiState {

    /** No sheet. */
    object Hidden : TapUiState

    /** Armed: waiting for the card. [endpoint] is the simulated card's `host:port` (debug builds only). */
    class Waiting(
        val prompt: TapPrompt,
        val simulated: Boolean,
        val endpoint: String?
    ) : TapUiState {
        /** The user may always back out before a card is in the field. */
        val cancelable: Boolean get() = true
    }

    /**
     * The card is in the field ([finishing] false: [labelRes] comes from the
     * card step labels or [TapStep.CONTACTING_BRIDGE]) or the card half is
     * over and the app waits for the bridge follow-up ([finishing] true).
     *
     * [cancelable]: only while waiting on the bridge inside a non-money tap.
     * [slow]: the 8 s watchdog fired ("Still working…"). [closable]: the 20 s
     * watchdog fired; closing hides the sheet and never cancels anything.
     * [simulated]: the tap is the debug build's simulated card (no radio, so
     * nothing to hold still), carried over from [Waiting].
     */
    class Busy(
        val prompt: TapPrompt,
        @StringRes val labelRes: Int,
        val cancelable: Boolean,
        val closable: Boolean,
        val slow: Boolean,
        val finishing: Boolean = false,
        val step: TapStep? = null,
        val simulated: Boolean = false
    ) : TapUiState

    /** The real outcome is known and it succeeded ([summaryRes]). */
    class Done(
        val prompt: TapPrompt,
        @StringRes val summaryRes: Int
    ) : TapUiState

    /**
     * The tap or its follow-up failed. [warning] marks an ambiguous outcome
     * ("Outcome unknown — do not repeat": Close only). [swHex] is shown in
     * debug builds only (the caller passes null in release).
     */
    class Failed(
        val prompt: TapPrompt,
        val message: CharSequence,
        val swHex: String?,
        val warning: Boolean,
        val actions: List<TapAction>
    ) : TapUiState
}

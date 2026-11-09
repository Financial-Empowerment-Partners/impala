package com.payala.impala.demo.ui.tap

import androidx.annotation.StringRes
import com.payala.impala.demo.card.TapStep

/** Inputs to [TapStateMachine.reduce]. Label ids are passed in, so the reducer stays pure. */
sealed interface TapEvent {
    /** A host asked for a tap (always resets, from any state). */
    class Arm(val prompt: TapPrompt, val simulated: Boolean, val endpoint: String?) : TapEvent

    /** `onTap` started running with the card connected. */
    class TapStarted(@StringRes val labelRes: Int) : TapEvent

    /** One traced card exchange; [labelRes] is the step label, or null to keep the current one. */
    class Exchange(@StringRes val labelRes: Int?) : TapEvent

    /** A non-card step reported from inside `onTap` (TapProgress). */
    class Step(val step: TapStep, @StringRes val labelRes: Int) : TapEvent

    /** The card half is over; the app now waits for the bridge follow-up. */
    class Finishing(@StringRes val labelRes: Int) : TapEvent

    /** A bridge follow-up with no tap before it (e.g. "Register anyway?" confirmed): shows the sheet in Finishing. */
    class FollowUp(val prompt: TapPrompt, @StringRes val labelRes: Int) : TapEvent

    /** The real outcome is known and it succeeded. */
    class Succeeded(@StringRes val summaryRes: Int) : TapEvent

    /**
     * The tap or its follow-up failed. [warning]: the outcome is ambiguous.
     * [hasRecovery]: a recovery slot exists (money prompts offer Resume).
     * [readerDisabled]: NFC is off (offer the NFC settings).
     */
    class Failed(
        val message: CharSequence,
        val swHex: String?,
        val warning: Boolean,
        val hasRecovery: Boolean,
        val readerDisabled: Boolean = false
    ) : TapEvent

    /** Watchdog: [elapsedMs] since Busy began. */
    class Tick(val elapsedMs: Long) : TapEvent

    /** The user cancelled (button, back or swipe). Honoured only where [TapStateMachine.canCancel]. */
    object Cancel : TapEvent

    /** The user closed a finished sheet, or a Busy sheet after the 20 s watchdog. Never cancels anything. */
    object Close : TapEvent

    /** The host dropped a request that was still waiting for a card (e.g. its screen went away). */
    object Drop : TapEvent

    /**
     * The host hands the follow-up to something else (a "Register anyway?"
     * dialog, or its screen is gone). Hides the sheet from any state; it
     * cancels nothing, and later outcomes are reported elsewhere.
     */
    object Hide : TapEvent
}

/**
 * The tap sheet's rules, as a pure reducer (TapStateMachineTest pins them):
 *
 * 1. Cancel is allowed while Waiting, and while Busy only when the tap is
 *    waiting on the bridge ([TapStep.CONTACTING_BRIDGE]) in a non-money
 *    prompt; never while a card command is in flight, never while finishing.
 * 2. Watchdog: [SLOW_MS] after Busy began the sheet says "Still working…";
 *    after [CLOSE_MS] it may be closed. Closing never cancels anything.
 * 3. Money prompts ([TapPrompt.moneyMoving]) never offer [TapAction.TRY_AGAIN]:
 *    [TapAction.RESUME] when a recovery slot exists, plus Close.
 * 4. An ambiguous outcome ([TapEvent.Failed.warning]) offers Close only.
 * 5. NFC off offers [TapAction.OPEN_NFC_SETTINGS] plus Close.
 * 6. Done only follows [TapEvent.Succeeded], i.e. the real outcome.
 * 7. Events that arrive after the sheet is gone (a late result after Close or
 *    Cancel) change nothing; only [TapEvent.Arm] and [TapEvent.FollowUp]
 *    start a sheet.
 */
object TapStateMachine {
    const val SLOW_MS = 8_000L
    const val CLOSE_MS = 20_000L

    fun reduce(state: TapUiState, event: TapEvent): TapUiState = when (event) {
        is TapEvent.Arm -> TapUiState.Waiting(event.prompt, event.simulated, event.endpoint)

        is TapEvent.TapStarted -> when (state) {
            is TapUiState.Waiting -> busy(state.prompt, event.labelRes, simulated = state.simulated)
            else -> state // a Busy tap already moved on its first exchange
        }

        is TapEvent.Exchange -> when (state) {
            is TapUiState.Waiting -> busy(state.prompt, event.labelRes ?: return state, simulated = state.simulated)
            is TapUiState.Busy ->
                if (state.finishing) state
                else busy(state.prompt, event.labelRes ?: state.labelRes, state.slow, state.closable, step = null, simulated = state.simulated)
            else -> state
        }

        is TapEvent.Step -> when (state) {
            is TapUiState.Waiting -> busy(state.prompt, event.labelRes, step = event.step, simulated = state.simulated)
            is TapUiState.Busy ->
                if (state.finishing) state
                else busy(state.prompt, event.labelRes, state.slow, state.closable, step = event.step, simulated = state.simulated)
            else -> state
        }

        is TapEvent.Finishing -> when (state) {
            is TapUiState.Waiting -> busy(state.prompt, event.labelRes, finishing = true, simulated = state.simulated)
            is TapUiState.Busy -> busy(state.prompt, event.labelRes, state.slow, state.closable, finishing = true, simulated = state.simulated)
            else -> state
        }

        is TapEvent.FollowUp -> busy(event.prompt, event.labelRes, finishing = true)

        is TapEvent.Succeeded -> when (state) {
            is TapUiState.Busy -> TapUiState.Done(state.prompt, event.summaryRes)
            else -> state
        }

        is TapEvent.Failed -> when (state) {
            is TapUiState.Waiting -> failed(state.prompt, event)
            is TapUiState.Busy -> failed(state.prompt, event)
            else -> state
        }

        is TapEvent.Tick -> when (state) {
            is TapUiState.Busy -> {
                val slow = state.slow || event.elapsedMs >= SLOW_MS
                val closable = state.closable || event.elapsedMs >= CLOSE_MS
                if (slow == state.slow && closable == state.closable) state
                else busy(state.prompt, state.labelRes, slow, closable, state.finishing, state.step, state.simulated)
            }
            else -> state
        }

        TapEvent.Cancel -> if (canCancel(state)) TapUiState.Hidden else state

        TapEvent.Close -> when (state) {
            is TapUiState.Done, is TapUiState.Failed -> TapUiState.Hidden
            is TapUiState.Busy -> if (state.closable) TapUiState.Hidden else state
            else -> state
        }

        TapEvent.Drop -> if (state is TapUiState.Waiting) TapUiState.Hidden else state

        TapEvent.Hide -> TapUiState.Hidden
    }

    /** Rule 1. */
    fun canCancel(state: TapUiState): Boolean = when (state) {
        is TapUiState.Waiting -> true
        is TapUiState.Busy -> state.cancelable
        else -> false
    }

    /** Whether the user may dismiss the sheet now (back, swipe, outside touch). */
    fun canDismiss(state: TapUiState): Boolean = when (state) {
        is TapUiState.Waiting, is TapUiState.Done, is TapUiState.Failed -> true
        is TapUiState.Busy -> state.cancelable || state.closable
        TapUiState.Hidden -> true
    }

    /** Rules 3 to 5: what a failure of [prompt] offers. */
    fun actionsFor(prompt: TapPrompt, warning: Boolean, hasRecovery: Boolean, readerDisabled: Boolean): List<TapAction> =
        when {
            warning -> listOf(TapAction.CLOSE)
            readerDisabled -> listOf(TapAction.OPEN_NFC_SETTINGS, TapAction.CLOSE)
            prompt.moneyMoving -> if (hasRecovery) listOf(TapAction.RESUME, TapAction.CLOSE) else listOf(TapAction.CLOSE)
            else -> listOf(TapAction.TRY_AGAIN, TapAction.CLOSE)
        }

    private fun failed(prompt: TapPrompt, e: TapEvent.Failed) = TapUiState.Failed(
        prompt, e.message, e.swHex, e.warning, actionsFor(prompt, e.warning, e.hasRecovery, e.readerDisabled)
    )

    private fun busy(
        prompt: TapPrompt,
        labelRes: Int,
        slow: Boolean = false,
        closable: Boolean = false,
        finishing: Boolean = false,
        step: TapStep? = null,
        simulated: Boolean = false
    ) = TapUiState.Busy(
        prompt = prompt,
        labelRes = labelRes,
        cancelable = !finishing && step == TapStep.CONTACTING_BRIDGE && !prompt.moneyMoving,
        closable = closable,
        slow = slow,
        finishing = finishing,
        step = if (finishing) null else step,
        simulated = simulated
    )
}

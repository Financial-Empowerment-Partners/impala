package com.payala.impala.demo.ui.tap

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.annotation.StringRes
import androidx.annotation.VisibleForTesting
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.impala.sdk.apdu4j.ApduExchange
import com.payala.impala.card.CardStepLabels
import com.payala.impala.demo.R
import com.payala.impala.demo.card.TapStep
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Activity-scoped owner of one tap at a time: the pending request (for hosts
 * that hand one over with [offer] / [take]) and the sheet state, reduced by
 * [TapStateMachine] on the main thread only.
 *
 * Threading: [onExchange], [onStep] and [runTap] are called on the card I/O
 * thread (NFC binder or `impala-card-debug-tap`); they only post to main.
 * Everything else is main-thread. Exchanges and steps of a tap that started
 * before the current [arm] (an abandoned tap still finishing in the
 * background) are dropped, so they can never move a newer sheet.
 *
 * The hooks ([onCancel], [onRetry], [onResume], [onOpenNfcSettings]) are set
 * by the host activity in `onCreate` (and by a fragment for its own Resume)
 * and cleared in `onDestroy`, so the view model never outlives a reference
 * to a destroyed screen for long.
 */
class TapViewModel : ViewModel() {

    private val _state = MutableLiveData<TapUiState>(TapUiState.Hidden)
    val state: LiveData<TapUiState> = _state

    /** The current state (main thread). */
    val current: TapUiState get() = _state.value ?: TapUiState.Hidden

    /** True while a sheet is up (anything but [TapUiState.Hidden]). */
    val isActive: Boolean get() = current !is TapUiState.Hidden

    /** Runs when the user cancels a Waiting tap or a tap waiting on the bridge. */
    var onCancel: (() -> Unit)? = null

    /** Runs for [TapAction.TRY_AGAIN]. */
    var onRetry: (() -> Unit)? = null

    /** Runs for [TapAction.RESUME] (routes into the existing recovery paths only). */
    var onResume: (() -> Unit)? = null

    /** Runs for [TapAction.OPEN_NFC_SETTINGS]. */
    var onOpenNfcSettings: (() -> Unit)? = null

    enum class Haptic { DETECTED, SUCCESS, FAILURE }

    private var pendingHaptic: Haptic? = null

    /** Wall-clock source for the watchdog (elapsed realtime). */
    @VisibleForTesting
    internal var clock: () -> Long = SystemClock::elapsedRealtime

    private val main = Handler(Looper.getMainLooper())
    private val armGeneration = AtomicInteger(0)
    private val runGeneration = ThreadLocal<Int?>()
    private var busySince = 0L
    private val watchdog = Runnable { tick() }

    /** A request a host parked for the next tap; consumed exactly once with [take]. */
    private val pending = AtomicReference<Any?>(null)

    fun offer(request: Any) = pending.set(request)

    /** Takes the parked request, or null (any thread; the race between two takers is won once). */
    fun take(): Any? = pending.getAndSet(null)

    /** Removes [request] only if it is still the parked one; true when it was. */
    fun withdraw(request: Any): Boolean = pending.compareAndSet(request, null)

    /** The parked request without taking it (for labelling the trace ring). */
    fun peek(): Any? = pending.get()

    // ── Host calls (main thread) ────────────────────────────────────────

    /** Shows the sheet waiting for a card for [prompt]. */
    fun arm(prompt: TapPrompt, simulated: Boolean, endpoint: String?) {
        armGeneration.incrementAndGet()
        apply(TapEvent.Arm(prompt, simulated, endpoint))
    }

    /** The card half is over; the sheet waits for the bridge follow-up ([label]). */
    fun finishing(@StringRes label: Int) = apply(TapEvent.Finishing(label))

    /** Shows the sheet in Finishing for a follow-up that had no tap before it. */
    fun followUp(prompt: TapPrompt, @StringRes label: Int) {
        armGeneration.incrementAndGet()
        apply(TapEvent.FollowUp(prompt, label))
    }

    /** The real outcome succeeded. */
    fun succeeded(@StringRes summary: Int) = apply(TapEvent.Succeeded(summary))

    /** The tap or its follow-up failed. Pass [swHex] only in debug builds. */
    fun failed(
        message: CharSequence,
        swHex: String?,
        warning: Boolean,
        hasRecovery: Boolean,
        readerDisabled: Boolean = false
    ) = apply(TapEvent.Failed(message, swHex, warning, hasRecovery, readerDisabled))

    /** User cancel (button, back, swipe); runs [onCancel] when it was allowed. */
    fun cancel() {
        if (!TapStateMachine.canCancel(current)) return
        apply(TapEvent.Cancel)
        onCancel?.invoke()
    }

    /** The host dropped a request still waiting for a card: a Waiting sheet goes away. */
    fun dropWaiting() = apply(TapEvent.Drop)

    /** The host hides the sheet (the follow-up continues elsewhere); cancels nothing. */
    fun hide() = apply(TapEvent.Hide)

    /** The user dismissed the sheet (back, swipe, Close). */
    fun dismissed() {
        val s = current
        when {
            TapStateMachine.canCancel(s) -> cancel()
            else -> apply(TapEvent.Close)
        }
    }

    /** A Failed sheet's button. */
    fun perform(action: TapAction) {
        when (action) {
            TapAction.CLOSE -> apply(TapEvent.Close)
            TapAction.TRY_AGAIN -> {
                // The retry re-arms (Failed -> Waiting on the same sheet); without one, just close.
                val retry = onRetry
                if (retry == null) apply(TapEvent.Close) else retry()
            }
            TapAction.RESUME -> {
                val resume = onResume
                apply(TapEvent.Close)
                resume?.invoke()
            }
            TapAction.OPEN_NFC_SETTINGS -> {
                apply(TapEvent.Close)
                onOpenNfcSettings?.invoke()
            }
        }
    }

    /** The haptic owed by the last transition, once. */
    fun consumeHaptic(): Haptic? = pendingHaptic.also { pendingHaptic = null }

    // ── Card I/O thread ─────────────────────────────────────────────────

    /**
     * Wraps one `onTap`: the sheet goes Busy, and exchanges and steps reported
     * from this thread while [block] runs are tagged with the current arm, so
     * they are dropped if the user re-arms before this tap finishes.
     */
    fun <T> runTap(block: () -> T): T {
        val generation = armGeneration.get()
        runGeneration.set(generation)
        post(generation, TapEvent.TapStarted(com.payala.impala.R.string.card_step_reading))
        try {
            return block()
        } finally {
            runGeneration.remove()
        }
    }

    /** The trace hook: one header-only exchange (never bytes). */
    fun onExchange(e: ApduExchange) {
        post(runGeneration.get(), TapEvent.Exchange(CardStepLabels.labelFor(e)))
    }

    /** A TapProgress sink. */
    fun onStep(s: TapStep) {
        val label = when (s) {
            TapStep.CONTACTING_BRIDGE -> R.string.tap_step_contacting_bridge
        }
        post(runGeneration.get(), TapEvent.Step(s, label))
    }

    // ── Internals ───────────────────────────────────────────────────────

    /** [generation] null: not tagged (e.g. the SELECT before `onTap`); applies to the current arm. */
    private fun post(generation: Int?, event: TapEvent) {
        val run = Runnable { if (generation == null || generation == armGeneration.get()) apply(event) }
        if (Looper.myLooper() == Looper.getMainLooper()) run.run() else main.post(run)
    }

    private fun apply(event: TapEvent) {
        val before = current
        val after = TapStateMachine.reduce(before, event)
        if (after === before) return
        if (after is TapUiState.Busy && before !is TapUiState.Busy) {
            busySince = clock()
            main.removeCallbacks(watchdog)
            main.postDelayed(watchdog, TapStateMachine.SLOW_MS)
        }
        if (after !is TapUiState.Busy) main.removeCallbacks(watchdog)
        // A Waiting sheet that ends without a card taking its request (a host failure or
        // follow-up, then Close) releases the parked request: it never runs later with no
        // sheet up, and a redeem's PIN is zeroed (the host's onCancel delivers TapCancelledException).
        val release = before is TapUiState.Waiting && after !is TapUiState.Waiting && event !is TapEvent.Cancel &&
            event !is TapEvent.TapStarted && event !is TapEvent.Exchange && event !is TapEvent.Step
        pendingHaptic = when {
            after is TapUiState.Busy && before is TapUiState.Waiting -> Haptic.DETECTED
            after is TapUiState.Done -> Haptic.SUCCESS
            after is TapUiState.Failed -> Haptic.FAILURE
            else -> pendingHaptic
        }
        _state.value = after
        if (release) onCancel?.invoke()
    }

    /** Watchdog tick (main): applies the elapsed time and schedules the next threshold. */
    @VisibleForTesting
    internal fun tick() {
        if (current !is TapUiState.Busy) return
        val elapsed = clock() - busySince
        apply(TapEvent.Tick(elapsed))
        val busy = current as? TapUiState.Busy ?: return
        if (!busy.closable) {
            val next = if (elapsed < TapStateMachine.SLOW_MS) TapStateMachine.SLOW_MS else TapStateMachine.CLOSE_MS
            main.postDelayed(watchdog, (next - elapsed).coerceAtLeast(MIN_TICK_MS))
        }
    }

    override fun onCleared() {
        main.removeCallbacks(watchdog)
        pending.set(null)
        onCancel = null; onRetry = null; onResume = null; onOpenNfcSettings = null
    }

    private companion object {
        const val MIN_TICK_MS = 100L
    }
}

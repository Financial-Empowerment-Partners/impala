package com.payala.impala.demo.ui.tap

import android.animation.Animator
import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.DialogInterface
import android.graphics.drawable.Animatable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.FragmentActivity
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.transition.TransitionManager
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.color.MaterialColors
import com.google.android.material.transition.MaterialFadeThrough
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.SheetCardTapBinding
import com.payala.impala.demo.ui.common.Haptics
import com.payala.impala.demo.ui.common.enableSheetEdgeToEdge
import com.payala.impala.demo.ui.common.padForSystemBars

/**
 * The one tap-to-card sheet (Waiting → Busy → Done | Failed), a thin view
 * over the host activity's [TapViewModel]. It never decides anything: every
 * transition comes from [TapStateMachine]; buttons call the view model.
 *
 * Lifecycle: hosts show it through [sync], which only shows it while the
 * host is at least STARTED (and is called again from the state observer,
 * which LiveData delivers on `onStart`). On re-creation it rebinds to the
 * surviving view model (configuration change), or dismisses itself when the
 * view model is [TapUiState.Hidden] (process death: the request is gone with
 * the process). Done dismisses itself shortly after the real outcome.
 */
class CardTapSheet : BottomSheetDialogFragment() {

    private val tap: TapViewModel by activityViewModels()
    private var _binding: SheetCardTapBinding? = null
    private val ripple = ArrayList<Animator>()
    private val handler = Handler(Looper.getMainLooper())
    private val autoDismiss = Runnable { if (tap.current is TapUiState.Done) tap.dismissed() }
    private var lastRendered: TapUiState? = null

    /** Set once this sheet asked to be dismissed; a newer state then belongs to a new sheet. */
    private var dismissing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null && tap.current is TapUiState.Hidden) {
            dismissing = true
            dismissAllowingStateLoss()
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        val b = SheetCardTapBinding.inflate(inflater, container, false)
        _binding = b
        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val b = _binding ?: return
        b.buttonRow.padForSystemBars(bottom = true)
        tap.state.observe(viewLifecycleOwner) { state -> render(state) }
    }

    override fun onStart() {
        super.onStart()
        enableSheetEdgeToEdge()
        (dialog as? BottomSheetDialog)?.behavior?.apply {
            skipCollapsed = true
            state = BottomSheetBehavior.STATE_EXPANDED
        }
    }

    /** Back, swipe or outside touch (only possible when [TapStateMachine.canDismiss]). */
    override fun onCancel(dialog: DialogInterface) {
        super.onCancel(dialog)
        tap.dismissed()
    }

    override fun onDestroyView() {
        handler.removeCallbacks(autoDismiss)
        stopRipple()
        _binding = null
        lastRendered = null
        super.onDestroyView()
    }

    private fun render(state: TapUiState) {
        val b = _binding ?: return
        if (dismissing) return
        if (state is TapUiState.Hidden) {
            dismissing = true
            if (isAdded) dismissAllowingStateLoss()
            return
        }
        val previous = lastRendered
        lastRendered = state
        if (previous != null && previous::class != state::class && animationsEnabled()) {
            TransitionManager.beginDelayedTransition(b.sheetContent, MaterialFadeThrough())
        }
        isCancelable = TapStateMachine.canDismiss(state)
        when (state) {
            is TapUiState.Waiting -> renderWaiting(b, state)
            is TapUiState.Busy -> renderBusy(b, state)
            is TapUiState.Done -> renderDone(b, state)
            is TapUiState.Failed -> renderFailed(b, state)
            TapUiState.Hidden -> Unit
        }
        when (tap.consumeHaptic()) {
            TapViewModel.Haptic.DETECTED -> Haptics.cardDetected(b.root)
            TapViewModel.Haptic.SUCCESS -> Haptics.success(b.root)
            TapViewModel.Haptic.FAILURE -> Haptics.failure(b.root)
            null -> Unit
        }
    }

    private fun renderWaiting(b: SheetCardTapBinding, s: TapUiState.Waiting) {
        showGlyph(b, glyph = true)
        b.tvMessage.visibility = View.VISIBLE
        startRipple(b)
        b.tvTitle.text = title(s.prompt)
        b.tvMessage.text = waitingHint(s.prompt)
        b.tvDetail.visibility = if (s.simulated) View.VISIBLE else View.GONE
        if (s.simulated) {
            b.tvDetail.text = s.endpoint?.let { getString(R.string.tap_hint_simulated, it) }
                ?: getString(R.string.tap_hint_simulated_no_endpoint)
        }
        b.chipSw.visibility = View.GONE
        buttons(b, primary = null, secondary = R.string.tap_action_cancel) { tap.cancel() }
    }

    private fun renderBusy(b: SheetCardTapBinding, s: TapUiState.Busy) {
        stopRipple()
        b.tvMessage.visibility = View.VISIBLE
        showGlyph(b, glyph = true, progress = true)
        if (!animationsEnabled() && b.progress.isIndeterminate) {
            // Static frame: a closed ring around the glyph (an indeterminate arc frozen mid-spin reads as an arrow).
            b.progress.visibility = View.INVISIBLE
            b.progress.isIndeterminate = false
            b.progress.setProgressCompat(PROGRESS_FULL, false)
            b.progress.visibility = View.VISIBLE
        }
        b.tvTitle.text = title(s.prompt)
        b.tvMessage.text = getString(s.labelRes)
        val detail = when {
            s.closable -> getString(R.string.tap_closable)
            s.slow -> getString(R.string.tap_slow)
            // A simulated card has no radio: there is nothing to hold still.
            !s.finishing && s.step == null && s.simulated -> getString(R.string.tap_hint_simulated_busy)
            !s.finishing && s.step == null -> getString(R.string.tap_hint_keep_still)
            else -> null
        }
        b.tvDetail.visibility = if (detail == null) View.GONE else View.VISIBLE
        b.tvDetail.text = detail
        b.chipSw.visibility = View.GONE
        when {
            s.cancelable -> buttons(b, primary = null, secondary = R.string.tap_action_cancel) { tap.cancel() }
            s.closable -> buttons(b, primary = null, secondary = R.string.tap_action_close) { tap.dismissed() }
            else -> buttons(b, primary = null, secondary = null) {}
        }
    }

    private fun renderDone(b: SheetCardTapBinding, s: TapUiState.Done) {
        stopRipple()
        showGlyph(b, done = true)
        if (animationsEnabled()) {
            b.ivDone.setImageResource(R.drawable.avd_check)
            (b.ivDone.drawable as? Animatable)?.start()
        } else {
            // Static end frame.
            b.ivDone.setImageResource(R.drawable.ic_check_circle)
            b.ivDone.imageTintList = android.content.res.ColorStateList.valueOf(
                MaterialColors.getColor(b.ivDone, R.attr.colorStatusSuccess)
            )
        }
        b.tvTitle.text = getString(s.summaryRes)
        // The outcome's next step, not the prompt again ("Card registered / Register a card").
        val detail = TapCopy.doneDetail(s.summaryRes)
        b.tvMessage.visibility = if (detail == null) View.GONE else View.VISIBLE
        b.tvMessage.text = detail?.let { getString(it) }
        b.tvDetail.visibility = View.GONE
        b.chipSw.visibility = View.GONE
        buttons(b, primary = null, secondary = R.string.tap_action_done) { tap.dismissed() }
        handler.removeCallbacks(autoDismiss)
        handler.postDelayed(autoDismiss, DONE_DISMISS_MS)
    }

    private fun renderFailed(b: SheetCardTapBinding, s: TapUiState.Failed) {
        stopRipple()
        b.tvMessage.visibility = View.VISIBLE
        showGlyph(b, failed = true)
        b.ivFailed.setImageResource(if (s.warning) R.drawable.ic_warning else R.drawable.ic_error)
        b.ivFailed.imageTintList = android.content.res.ColorStateList.valueOf(
            MaterialColors.getColor(b.ivFailed, if (s.warning) R.attr.colorStatusWarning else androidx.appcompat.R.attr.colorError)
        )
        b.tvTitle.text = TapCopy.failedTitle(resources, s.prompt, s.warning)
        b.tvMessage.text = s.message
        // An ambiguous outcome's title is the fixed warning; the flow it belongs to goes underneath.
        b.tvDetail.visibility = if (s.warning) View.VISIBLE else View.GONE
        b.tvDetail.text = if (s.warning) title(s.prompt) else null
        b.chipSw.visibility = if (s.swHex != null) View.VISIBLE else View.GONE
        b.chipSw.text = s.swHex?.let { getString(R.string.tap_sw, it) }
        val primary = s.actions.firstOrNull { it != TapAction.CLOSE }
        b.btnPrimary.visibility = if (primary != null) View.VISIBLE else View.GONE
        if (primary != null) {
            b.btnPrimary.text = getString(
                when (primary) {
                    TapAction.TRY_AGAIN -> R.string.tap_action_try_again
                    TapAction.RESUME -> R.string.tap_action_resume
                    TapAction.OPEN_NFC_SETTINGS -> R.string.tap_action_open_nfc_settings
                    TapAction.CLOSE -> R.string.tap_action_close
                }
            )
            b.btnPrimary.setOnClickListener { tap.perform(primary) }
        }
        b.btnSecondary.visibility = if (TapAction.CLOSE in s.actions) View.VISIBLE else View.GONE
        b.btnSecondary.setText(R.string.tap_action_close)
        b.btnSecondary.setOnClickListener { tap.perform(TapAction.CLOSE) }
    }

    private fun buttons(b: SheetCardTapBinding, primary: Int?, secondary: Int?, onSecondary: () -> Unit) {
        b.btnPrimary.visibility = if (primary == null) View.GONE else View.VISIBLE
        if (primary != null) b.btnPrimary.setText(primary)
        b.btnSecondary.visibility = if (secondary == null) View.INVISIBLE else View.VISIBLE
        if (secondary != null) b.btnSecondary.setText(secondary)
        b.btnSecondary.setOnClickListener { onSecondary() }
    }

    private fun showGlyph(
        b: SheetCardTapBinding,
        glyph: Boolean = false,
        progress: Boolean = false,
        done: Boolean = false,
        failed: Boolean = false
    ) {
        b.ivGlyph.visibility = if (glyph) View.VISIBLE else View.GONE
        b.progress.visibility = if (progress) View.VISIBLE else View.GONE
        b.ivDone.visibility = if (done) View.VISIBLE else View.GONE
        b.ivFailed.visibility = if (failed) View.VISIBLE else View.GONE
        if (!glyph || progress) listOf(b.ring1, b.ring2, b.ring3).forEach { it.alpha = 0f }
    }

    private fun title(p: TapPrompt): String = when (p) {
        TapPrompt.Register -> getString(R.string.tap_title_register)
        TapPrompt.SignIn -> getString(R.string.tap_title_sign_in)
        is TapPrompt.Read -> p.cardSuffix?.let { getString(R.string.tap_title_read_card, it) } ?: getString(R.string.tap_title_read)
        is TapPrompt.Sign -> getString(R.string.tap_title_sign, p.cardSuffix)
        is TapPrompt.Apply -> getString(R.string.tap_title_apply, p.cardSuffix)
    }

    private fun waitingHint(p: TapPrompt): String {
        val suffix = when (p) {
            is TapPrompt.Read -> p.cardSuffix
            is TapPrompt.Sign -> p.cardSuffix
            is TapPrompt.Apply -> p.cardSuffix
            else -> null
        }
        return suffix?.let { getString(R.string.tap_hint_waiting_card, it) } ?: getString(R.string.nfc_tap_prompt)
    }

    // ── Waiting ripple: three rings, scale 1 → 2.2 and alpha 0.35 → 0 over 1600 ms, staggered 400 ms ──

    private fun startRipple(b: SheetCardTapBinding) {
        if (ripple.isNotEmpty()) return
        val rings = listOf(b.ring1, b.ring2, b.ring3)
        if (!animationsEnabled()) {
            // Static frame: one faint ring around the glyph.
            rings.forEach { it.alpha = 0f }
            b.ring1.scaleX = RING_STATIC_SCALE; b.ring1.scaleY = RING_STATIC_SCALE; b.ring1.alpha = RING_ALPHA
            return
        }
        rings.forEachIndexed { i, ring ->
            val sx = ObjectAnimator.ofFloat(ring, View.SCALE_X, 1f, RING_MAX_SCALE)
            val sy = ObjectAnimator.ofFloat(ring, View.SCALE_Y, 1f, RING_MAX_SCALE)
            val a = ObjectAnimator.ofFloat(ring, View.ALPHA, RING_ALPHA, 0f)
            listOf(sx, sy, a).forEach {
                it.repeatCount = ValueAnimator.INFINITE
                it.repeatMode = ValueAnimator.RESTART
            }
            val set = AnimatorSet().apply {
                playTogether(sx, sy, a)
                duration = RING_PERIOD_MS
                startDelay = i * RING_STAGGER_MS
            }
            set.start()
            ripple += set
        }
    }

    private fun stopRipple() {
        ripple.forEach { it.cancel() }
        ripple.clear()
    }

    private fun animationsEnabled(): Boolean {
        val ctx = context ?: return false
        val scale = Settings.Global.getFloat(ctx.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
        return scale > 0f
    }

    companion object {
        const val TAG = "CardTapSheet"
        private const val DONE_DISMISS_MS = 1_200L
        private const val RING_PERIOD_MS = 1_600L
        private const val RING_STAGGER_MS = 400L
        private const val RING_MAX_SCALE = 2.2f
        private const val RING_STATIC_SCALE = 1.6f
        private const val RING_ALPHA = 0.35f
        private const val PROGRESS_FULL = 100

        /**
         * Shows the sheet for [tap]'s current state when it is not Hidden and
         * not already shown, only while [host] is at least STARTED (otherwise
         * the host's state observer calls this again from `onStart`).
         */
        fun sync(host: FragmentActivity, tap: TapViewModel) {
            if (tap.current is TapUiState.Hidden) return
            if (!host.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
            val fm = host.supportFragmentManager
            if (fm.isStateSaved) return
            val shown = fm.findFragmentByTag(TAG) as? CardTapSheet
            if (shown != null && !shown.dismissing && !shown.isRemoving) return
            CardTapSheet().show(fm, TAG)
        }
    }
}

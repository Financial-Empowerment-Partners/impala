package com.payala.impala.demo.ui.common

import android.os.Build
import android.view.HapticFeedbackConstants
import android.view.View

/**
 * Tap-to-card haptics. View haptics only: no VIBRATE permission, and never
 * FLAG_IGNORE_GLOBAL_SETTING, so the user's system haptics setting always wins.
 */
object Haptics {
    /** The first card exchange of a tap: the card was detected. */
    fun cardDetected(v: View) {
        v.performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK)
    }

    /** The tap's real outcome is known and it succeeded. */
    fun success(v: View) {
        v.performHapticFeedback(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.CONFIRM
            else HapticFeedbackConstants.VIRTUAL_KEY
        )
    }

    /** The tap failed (or its outcome is unknown). */
    fun failure(v: View) {
        v.performHapticFeedback(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.REJECT
            else HapticFeedbackConstants.LONG_PRESS
        )
    }
}

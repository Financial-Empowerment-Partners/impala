package com.payala.impala.demo.ui.tap

import android.content.res.Resources
import androidx.annotation.StringRes
import com.payala.impala.demo.R

/**
 * Sheet copy that depends on the outcome rather than on the prompt alone:
 * the line under a Done title (what happens next, never the prompt again),
 * and the Failed title, which keeps the flow's context ("Couldn't register
 * the card") instead of a generic "That didn't work".
 */
object TapCopy {

    /** The Done sheet's outcome line for [summaryRes], or null for none. */
    @StringRes
    fun doneDetail(@StringRes summaryRes: Int): Int? = when (summaryRes) {
        R.string.tap_done_registered -> R.string.tap_done_detail_registered
        R.string.tap_done_signed_in -> R.string.tap_done_detail_signed_in
        R.string.tap_done_sent, R.string.tap_done_load_created -> R.string.tap_done_detail_transfers
        R.string.tap_done_loaded -> R.string.tap_done_detail_loaded
        R.string.tap_done_nothing_signed -> R.string.tap_done_detail_nothing_signed
        else -> null
    }

    /** The Failed sheet's title for [prompt]. An ambiguous outcome keeps "Outcome unknown — do not repeat". */
    fun failedTitle(res: Resources, prompt: TapPrompt, warning: Boolean): String {
        if (warning) return res.getString(R.string.tap_failed_warning_title)
        return when (prompt) {
            TapPrompt.Register -> res.getString(R.string.tap_failed_title_register)
            TapPrompt.SignIn -> res.getString(R.string.tap_failed_title_sign_in)
            is TapPrompt.Read -> prompt.cardSuffix?.let { res.getString(R.string.tap_failed_title_read_card, it) }
                ?: res.getString(R.string.tap_failed_title_read)
            is TapPrompt.Sign -> res.getString(R.string.tap_failed_title_sign, prompt.cardSuffix)
            is TapPrompt.Apply -> res.getString(R.string.tap_failed_title_apply, prompt.cardSuffix)
        }
    }
}

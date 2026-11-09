package com.payala.impala.demo.ui.lab

import android.content.Context
import android.content.Intent
import com.payala.impala.demo.ui.nfc.NfcDebugActivity

/**
 * The one way into the Card Lab (`ui.nfc.NfcDebugActivity`, whose class name
 * is kept for the manifest, the menu and the scenario-07 hooks). Callers start
 * the returned intent; the Lab reads [EXTRA_TAB] and [EXTRA_CARD_ID].
 */
object LabIntents {
    const val EXTRA_TAB = "com.payala.impala.demo.lab.TAB"
    const val EXTRA_CARD_ID = "com.payala.impala.demo.lab.CARD_ID"

    const val TAB_INSPECTOR = "inspector"
    const val TAB_DOCTOR = "doctor"
    const val TAB_TRACE = "trace"
    const val TAB_DEVICE = "device"

    /** All tabs, in display order. */
    val TABS: List<String> = listOf(TAB_INSPECTOR, TAB_DOCTOR, TAB_TRACE, TAB_DEVICE)

    /**
     * An intent opening the Lab on [tab] (unknown values fall back to the
     * inspector), optionally focused on [cardId] (a card id, never PII).
     */
    fun open(ctx: Context, tab: String = TAB_INSPECTOR, cardId: String? = null): Intent =
        Intent(ctx, NfcDebugActivity::class.java)
            .putExtra(EXTRA_TAB, if (tab in TABS) tab else TAB_INSPECTOR)
            .apply { if (cardId != null) putExtra(EXTRA_CARD_ID, cardId) }
}

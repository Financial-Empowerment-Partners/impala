package com.payala.impala.card

import androidx.annotation.StringRes
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduNames
import com.payala.impala.R

/**
 * What the card is doing, for a progress label, from a traced exchange: reads
 * (SELECT and every read-only command) are "Reading card"; SIGN_AUTH and
 * SIGN_SEP10 (both sign a login), SIGN_TRANSFER_V2 and VERIFY_TRANSFER_V2
 * have their own labels. There is no
 * label for VERIFY_PIN: no app flow sends it (the PIN rides inside
 * SIGN_TRANSFER_V2). Anything else is null (keep the current label).
 */
object CardStepLabels {
    private const val SIGN_AUTH = 0x25
    private const val SIGN_SEP10 = 0x38
    private const val SIGN_TRANSFER_V2 = 0x30
    private const val VERIFY_TRANSFER_V2 = 0x31

    @JvmStatic
    @StringRes
    fun labelFor(exchange: ApduExchange): Int? {
        if (exchange.cla != 0x00) return null
        return when (exchange.ins) {
            SIGN_AUTH, SIGN_SEP10 -> R.string.card_step_signing_login
            SIGN_TRANSFER_V2 -> R.string.card_step_signing_transfer
            VERIFY_TRANSFER_V2 -> R.string.card_step_applying_credit
            ApduNames.SELECT_INS, in ApduNames.READ_ONLY_INS -> R.string.card_step_reading
            else -> null
        }
    }
}

package com.payala.impala.card

import com.impala.sdk.flows.CreditFlow
import com.impala.sdk.flows.RedemptionFlow
import com.impala.sdk.flows.RedemptionTuple
import com.impala.sdk.models.Signable

/**
 * Card transfer helpers for Android callers: thin, main-thread-refusing
 * wrappers over the SDK flows. Never log what passes through here.
 */
object CardTransfers {
    /**
     * Signs [signable] with the user PIN (SIGN_TRANSFER_V2). [pinDigits] is
     * zeroed before returning, whether signing succeeded or not. The version
     * and personalization gates run first (via the session identity).
     */
    @JvmStatic
    fun redeem(session: ImpalaCardSession, pinDigits: CharArray, signable: Signable): RedemptionTuple {
        try {
            requireBackgroundThread("Signing a transfer")
            val identity = session.identity.requirePersonalized()
            return RedemptionFlow.sign(session.sdk, identity, pinDigits, signable)
        } finally {
            pinDigits.fill('\u0000')
        }
    }

    /** Rebuilds the card's last signed tuple (never re-sign), or null when it never signed. */
    @JvmStatic
    fun recoverLastSigned(session: ImpalaCardSession): RedemptionTuple? {
        requireBackgroundThread("Reading the last transfer")
        return RedemptionFlow.recoverLastSigned(session.sdk, session.identity.requirePersonalized())
    }

    /** The card's previous send sequence (GET_LAST_TRANSFER), 0 when it never signed. */
    @JvmStatic
    fun previousSendSequence(session: ImpalaCardSession): Long {
        requireBackgroundThread("Reading the last transfer")
        return RedemptionFlow.previousSendSequence(session.sdk)
    }

    /**
     * Applies a bridge-signed credit (VERIFY_TRANSFER_V2) and returns the ack
     * status word: "9000" when applied, the card's SW otherwise.
     */
    @JvmStatic
    fun applyCredit(session: ImpalaCardSession, signable: ByteArray, tail209: ByteArray): String {
        requireBackgroundThread("Applying a credit")
        session.identity.requirePersonalized()
        return CreditFlow.apply(session.sdk, signable, tail209)
    }
}

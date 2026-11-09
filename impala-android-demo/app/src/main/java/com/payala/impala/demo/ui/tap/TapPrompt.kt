package com.payala.impala.demo.ui.tap

/**
 * Why the app is asking for a card tap. The prompt decides the sheet's copy
 * and, through [moneyMoving], what a failure may offer: a prompt that moves
 * money (signing a redemption, applying a credit) never offers "Try again"
 * (a second attempt could sign or apply twice); it offers Resume, which only
 * routes into the existing recovery paths, when a recovery slot exists.
 *
 * Card suffixes are the last four hex digits of a card id: an identifier,
 * never PII.
 */
sealed class TapPrompt(val moneyMoving: Boolean) {
    /** Cards: read a card's identity to register it with the bridge. */
    object Register : TapPrompt(moneyMoving = false)

    /** Login: the card signs the bridge's login challenge. */
    object SignIn : TapPrompt(moneyMoving = false)

    /** A read-only tap (receive counter for a load, recovering a signed tuple). */
    class Read(val cardSuffix: String?) : TapPrompt(moneyMoving = false)

    /** Redeem: the card verifies the PIN and signs a debit. */
    class Sign(val cardSuffix: String) : TapPrompt(moneyMoving = true)

    /** Load: the card applies a bridge-signed credit. */
    class Apply(val cardSuffix: String) : TapPrompt(moneyMoving = true)

    /** Short stable name for logs and the trace ring (no identifiers). */
    val logName: String
        get() = when (this) {
            Register -> "register"
            SignIn -> "sign-in"
            is Read -> "read"
            is Sign -> "sign"
            is Apply -> "apply"
        }

    companion object {
        /** The last four characters of [cardId] (the sheet and rows name cards as ····abcd). */
        fun suffixOf(cardId: String): String = cardId.takeLast(4)
    }
}

/** What a Failed sheet can offer. */
enum class TapAction { TRY_AGAIN, RESUME, OPEN_NFC_SETTINGS, CLOSE }

package com.payala.impala.demo.ui.fragments

import androidx.annotation.StringRes
import com.payala.impala.demo.R
import com.payala.impala.demo.auth.TokenManager

/**
 * What Settings says about how the session was signed in, from the stored
 * auth provider and, for a card, the mechanism the card used. Pure: the
 * strings are resources, the inputs come from [TokenManager].
 */
object SignInSummary {
    /**
     * The label for [provider] (`password`, `google`, `github`, `okta`, `card`),
     * or null for a provider this build has no label for (the caller shows it
     * as stored). A card names its mechanism when it is known.
     */
    @StringRes
    fun methodRes(provider: String?, cardSignIn: String?): Int? = when (provider) {
        "password" -> R.string.settings_sign_in_password
        "google" -> R.string.settings_sign_in_google
        "github" -> R.string.settings_sign_in_github
        "okta" -> R.string.settings_sign_in_okta
        "card" -> when (cardSignIn) {
            TokenManager.CARD_SIGN_IN_SEP10 -> R.string.settings_sign_in_card_sep10
            TokenManager.CARD_SIGN_IN_LEGACY -> R.string.settings_sign_in_card_legacy
            else -> R.string.settings_sign_in_card
        }
        else -> null
    }

    /** The card's Stellar address is shown only for the session it signed in with SEP-10. */
    fun showsStellarAddress(provider: String?, cardSignIn: String?): Boolean =
        provider == "card" && cardSignIn == TokenManager.CARD_SIGN_IN_SEP10
}

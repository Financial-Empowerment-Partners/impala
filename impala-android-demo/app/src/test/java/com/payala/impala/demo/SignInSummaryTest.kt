package com.payala.impala.demo

import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.ui.fragments.SignInSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** What Settings says about how the session was signed in: a card names its mechanism. */
class SignInSummaryTest {
    @Test
    fun `a card session names SEP-10 or the card challenge, and plain Card when the mechanism is unknown`() {
        assertEquals(R.string.settings_sign_in_card_sep10, SignInSummary.methodRes("card", TokenManager.CARD_SIGN_IN_SEP10))
        assertEquals(R.string.settings_sign_in_card_legacy, SignInSummary.methodRes("card", TokenManager.CARD_SIGN_IN_LEGACY))
        // A session stored by a build that did not record the mechanism.
        assertEquals(R.string.settings_sign_in_card, SignInSummary.methodRes("card", null))
        assertEquals(R.string.settings_sign_in_card, SignInSummary.methodRes("card", "something-new"))
    }

    @Test
    fun `the other providers have their labels and an unknown one has none`() {
        assertEquals(R.string.settings_sign_in_password, SignInSummary.methodRes("password", null))
        assertEquals(R.string.settings_sign_in_google, SignInSummary.methodRes("google", null))
        assertEquals(R.string.settings_sign_in_github, SignInSummary.methodRes("github", null))
        assertEquals(R.string.settings_sign_in_okta, SignInSummary.methodRes("okta", null))
        // A card mechanism left over in storage never relabels another provider's session.
        assertEquals(R.string.settings_sign_in_password, SignInSummary.methodRes("password", TokenManager.CARD_SIGN_IN_SEP10))
        assertNull(SignInSummary.methodRes("saml", null))
        assertNull(SignInSummary.methodRes(null, null))
    }

    @Test
    fun `the card's Stellar address is shown only for a card session that used SEP-10`() {
        assertTrue(SignInSummary.showsStellarAddress("card", TokenManager.CARD_SIGN_IN_SEP10))
        assertFalse(SignInSummary.showsStellarAddress("card", TokenManager.CARD_SIGN_IN_LEGACY))
        assertFalse(SignInSummary.showsStellarAddress("card", null))
        assertFalse(SignInSummary.showsStellarAddress("password", TokenManager.CARD_SIGN_IN_SEP10))
        assertFalse(SignInSummary.showsStellarAddress(null, null))
    }
}

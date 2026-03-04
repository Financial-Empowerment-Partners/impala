package com.payala.impala.demo.auth

import android.app.Activity
import android.os.Bundle

/**
 * Transparent activity that handles the `impala://okta-callback` deep link.
 *
 * Declared in the manifest with `android:launchMode="singleTask"` and an
 * intent-filter for the `impala` scheme / `okta-callback` host. When Okta
 * redirects the browser after OAuth authorization, this activity extracts the
 * `code` query parameter and passes it to [OktaAuthHelper.pendingCallback].
 *
 * Finishes immediately so the user returns to [LoginActivity].
 */
class OktaRedirectActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uri = intent?.data
        val state = uri?.getQueryParameter("state")
        val expectedState = OktaAuthHelper.pendingState

        if (state == null || state != expectedState) {
            OktaAuthHelper.pendingCallback?.invoke(
                OktaSignInResult.Error("Invalid state parameter")
            )
        } else {
            val code = uri?.getQueryParameter("code")

            if (code != null) {
                OktaAuthHelper.pendingCallback?.invoke(OktaSignInResult.CodeReceived(code))
            } else {
                val error = uri?.getQueryParameter("error_description")
                    ?: uri?.getQueryParameter("error")
                    ?: "No authorization code received"
                OktaAuthHelper.pendingCallback?.invoke(OktaSignInResult.Error(error))
            }
        }

        OktaAuthHelper.pendingCallback = null
        OktaAuthHelper.pendingCodeVerifier = null
        OktaAuthHelper.pendingState = null

        finish()
    }
}

package com.payala.impala.demo.auth

import android.app.Activity
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import com.payala.impala.demo.BuildConfig
import java.util.UUID

/** Result of the first phase of GitHub OAuth (authorization code retrieval). */
sealed class GitHubSignInResult {
    /** The user authorized the app; [code] is the OAuth authorization code. */
    data class CodeReceived(val code: String) : GitHubSignInResult()
    /** Authorization failed or was denied. */
    data class Error(val message: String) : GitHubSignInResult()
}

/**
 * Handles the client half of the GitHub OAuth 2.0 authorization-code flow.
 *
 * **Flow overview:**
 * 1. [startSignIn] opens a Custom Chrome Tab pointing at GitHub's authorize URL.
 * 2. After the user authorizes, GitHub redirects to `impala://github-callback?code=...`.
 * 3. [GitHubRedirectActivity] catches the deep link and invokes [pendingCallback].
 * 4. The caller forwards the code to the bridge (`POST /auth/github
 *    {code, redirect_uri}`), which performs the code→token exchange server-side
 *    — the GitHub client secret lives only on the bridge, never in the APK.
 *
 * @param activity the host Activity used to launch the Custom Chrome Tab
 */
class GitHubAuthHelper(private val activity: Activity) {

    companion object {
        private const val GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"

        var pendingCallback: ((GitHubSignInResult) -> Unit)? = null

        /**
         * CSRF `state` for the in-flight authorization request. The redirect
         * activity is exported (BROWSABLE deep link), so any app can deliver a
         * callback — [GitHubRedirectActivity] must reject callbacks whose
         * `state` does not match this value (as [OktaRedirectActivity] does).
         */
        var pendingState: String? = null
    }

    /** Opens a Custom Chrome Tab for GitHub authorization. Results arrive via [pendingCallback]. */
    fun startSignIn(callback: (GitHubSignInResult) -> Unit) {
        val state = UUID.randomUUID().toString()

        val url = Uri.parse(GITHUB_AUTH_URL).buildUpon()
            .appendQueryParameter("client_id", BuildConfig.GITHUB_CLIENT_ID)
            .appendQueryParameter("redirect_uri", BuildConfig.GITHUB_REDIRECT_URI)
            .appendQueryParameter("scope", "user:email")
            .appendQueryParameter("state", state)
            .build()

        pendingCallback = callback
        pendingState = state

        val customTabsIntent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
        customTabsIntent.launchUrl(activity, url)
    }
}

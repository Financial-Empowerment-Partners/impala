package com.payala.impala.demo.auth

import android.app.Activity
import android.os.Bundle

/**
 * Transparent activity that handles the `impala://github-callback` deep link.
 *
 * Declared in the manifest with `android:launchMode="singleTask"` and an
 * intent-filter for the `impala` scheme / `github-callback` host. When GitHub
 * redirects the browser after OAuth authorization, this activity extracts the
 * `code` query parameter and passes it to [GitHubAuthHelper.pendingCallback].
 *
 * Finishes immediately so the user returns to [LoginActivity].
 */
class GitHubRedirectActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uri = intent?.data
        val code = uri?.getQueryParameter("code")

        if (code != null) {
            GitHubAuthHelper.pendingCallback?.invoke(GitHubSignInResult.CodeReceived(code))
        } else {
            val error = uri?.getQueryParameter("error") ?: "No authorization code received"
            GitHubAuthHelper.pendingCallback?.invoke(GitHubSignInResult.Error(error))
        }
        GitHubAuthHelper.pendingCallback = null

        finish()
    }
}

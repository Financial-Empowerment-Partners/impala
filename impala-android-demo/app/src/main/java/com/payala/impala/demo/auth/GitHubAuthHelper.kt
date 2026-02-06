package com.payala.impala.demo.auth

import android.app.Activity
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.payala.impala.demo.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.UUID

/** Result of the first phase of GitHub OAuth (authorization code retrieval). */
sealed class GitHubSignInResult {
    /** The user authorized the app; [code] is the OAuth authorization code. */
    data class CodeReceived(val code: String) : GitHubSignInResult()
    /** Authorization failed or was denied. */
    data class Error(val message: String) : GitHubSignInResult()
}

/** GitHub's OAuth token-exchange response. */
data class GitHubTokenResponse(
    @SerializedName("access_token") val accessToken: String?,
    @SerializedName("token_type") val tokenType: String?,
    val scope: String?,
    val error: String?,
    @SerializedName("error_description") val errorDescription: String?
)

/** Subset of the GitHub `/user` API response. */
data class GitHubUser(
    val login: String,
    val email: String?,
    val name: String?
)

/**
 * Handles the GitHub OAuth 2.0 authorization-code flow.
 *
 * **Flow overview:**
 * 1. [startSignIn] opens a Custom Chrome Tab pointing at GitHub's authorize URL.
 * 2. After the user authorizes, GitHub redirects to `impala://github-callback?code=...`.
 * 3. [GitHubRedirectActivity] catches the deep link and invokes [pendingCallback].
 * 4. The caller then uses [exchangeCodeForUser] to trade the code for an access
 *    token and fetch the GitHub user profile.
 *
 * @param activity the host Activity used to launch the Custom Chrome Tab
 */
class GitHubAuthHelper(private val activity: Activity) {

    companion object {
        private const val GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
        private const val GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
        private const val GITHUB_USER_URL = "https://api.github.com/user"

        var pendingCallback: ((GitHubSignInResult) -> Unit)? = null
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

        val customTabsIntent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
        customTabsIntent.launchUrl(activity, url)
    }

    /**
     * Exchanges an OAuth authorization [code] for an access token, then fetches
     * the authenticated GitHub user profile.
     *
     * @return the [GitHubUser] on success, or `null` if any HTTP call fails
     */
    suspend fun exchangeCodeForUser(code: String): GitHubUser? = withContext(Dispatchers.IO) {
        val client = OkHttpClient()
        val gson = Gson()

        // Exchange code for access token
        val tokenRequest = Request.Builder()
            .url(GITHUB_TOKEN_URL)
            .post(
                FormBody.Builder()
                    .add("client_id", BuildConfig.GITHUB_CLIENT_ID)
                    .add("client_secret", BuildConfig.GITHUB_CLIENT_SECRET)
                    .add("code", code)
                    .add("redirect_uri", BuildConfig.GITHUB_REDIRECT_URI)
                    .build()
            )
            .header("Accept", "application/json")
            .build()

        val tokenResponse = client.newCall(tokenRequest).execute()
        if (!tokenResponse.isSuccessful) return@withContext null

        val tokenBody = tokenResponse.body?.string() ?: return@withContext null
        val token = gson.fromJson(tokenBody, GitHubTokenResponse::class.java)
        if (token.accessToken == null) return@withContext null

        // Fetch user info
        val userRequest = Request.Builder()
            .url(GITHUB_USER_URL)
            .header("Authorization", "token ${token.accessToken}")
            .header("Accept", "application/json")
            .build()

        val userResponse = client.newCall(userRequest).execute()
        if (!userResponse.isSuccessful) return@withContext null

        val userBody = userResponse.body?.string() ?: return@withContext null
        gson.fromJson(userBody, GitHubUser::class.java)
    }
}

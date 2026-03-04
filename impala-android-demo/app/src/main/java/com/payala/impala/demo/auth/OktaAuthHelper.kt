package com.payala.impala.demo.auth

import android.app.Activity
import android.net.Uri
import android.util.Base64
import androidx.browser.customtabs.CustomTabsIntent
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.payala.impala.demo.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

/** Result of the Okta OAuth authorization code retrieval. */
sealed class OktaSignInResult {
    /** The user authorized the app; [code] is the OAuth authorization code. */
    data class CodeReceived(val code: String) : OktaSignInResult()
    /** Authorization failed or was denied. */
    data class Error(val message: String) : OktaSignInResult()
}

/** Okta's OAuth token-exchange response. */
data class OktaTokenResponse(
    @SerializedName("access_token") val accessToken: String?,
    @SerializedName("token_type") val tokenType: String?,
    @SerializedName("expires_in") val expiresIn: Int?,
    @SerializedName("id_token") val idToken: String?,
    val scope: String?,
    val error: String?,
    @SerializedName("error_description") val errorDescription: String?
)

/**
 * Handles the Okta OAuth 2.0 Authorization Code + PKCE flow.
 *
 * **Flow overview:**
 * 1. [startSignIn] generates a PKCE code verifier/challenge, then opens a Custom
 *    Chrome Tab pointing at the Okta authorize endpoint.
 * 2. After the user authorizes, Okta redirects to `impala://okta-callback?code=...`.
 * 3. [OktaRedirectActivity] catches the deep link and invokes [pendingCallback].
 * 4. The caller then uses [exchangeCodeForToken] to trade the code for an access token.
 *
 * @param activity the host Activity used to launch the Custom Chrome Tab
 */
class OktaAuthHelper(private val activity: Activity) {

    companion object {
        var pendingCallback: ((OktaSignInResult) -> Unit)? = null
        var pendingCodeVerifier: String? = null
        var pendingState: String? = null

        private val httpClient = OkHttpClient.Builder()
            .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .build()
    }

    /**
     * Opens a Custom Chrome Tab for Okta authorization using PKCE.
     * Results arrive via [pendingCallback].
     */
    fun startSignIn(
        issuerUrl: String,
        clientId: String,
        callback: (OktaSignInResult) -> Unit
    ) {
        val state = UUID.randomUUID().toString()
        val codeVerifier = generateCodeVerifier()
        val codeChallenge = generateCodeChallenge(codeVerifier)

        pendingCodeVerifier = codeVerifier
        pendingCallback = callback
        pendingState = state

        val authorizeUrl = Uri.parse("${issuerUrl.trimEnd('/')}/v1/authorize").buildUpon()
            .appendQueryParameter("client_id", clientId)
            .appendQueryParameter("redirect_uri", BuildConfig.OKTA_REDIRECT_URI)
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("scope", "openid profile email")
            .appendQueryParameter("state", state)
            .appendQueryParameter("code_challenge", codeChallenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()

        val customTabsIntent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
        customTabsIntent.launchUrl(activity, authorizeUrl)
    }

    /**
     * Exchanges an OAuth authorization [code] for an access token using PKCE.
     *
     * @param code the authorization code from the redirect
     * @param codeVerifier the PKCE code verifier generated during [startSignIn]
     * @return the access token on success, or null if the exchange fails
     */
    suspend fun exchangeCodeForToken(
        issuerUrl: String,
        clientId: String,
        code: String,
        codeVerifier: String
    ): String? = withContext(Dispatchers.IO) {
        val gson = Gson()

        val tokenUrl = "${issuerUrl.trimEnd('/')}/v1/token"

        val tokenRequest = Request.Builder()
            .url(tokenUrl)
            .post(
                FormBody.Builder()
                    .add("grant_type", "authorization_code")
                    .add("client_id", clientId)
                    .add("code", code)
                    .add("redirect_uri", BuildConfig.OKTA_REDIRECT_URI)
                    .add("code_verifier", codeVerifier)
                    .build()
            )
            .header("Accept", "application/json")
            .build()

        val tokenResponse = httpClient.newCall(tokenRequest).execute()
        if (!tokenResponse.isSuccessful) return@withContext null

        val tokenBody = tokenResponse.body?.string() ?: return@withContext null
        val token = gson.fromJson(tokenBody, OktaTokenResponse::class.java)
        token.accessToken
    }

    /** Generate a cryptographically random PKCE code verifier (43-128 chars, URL-safe). */
    private fun generateCodeVerifier(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    /** Generate a PKCE code challenge from a code verifier using SHA-256. */
    private fun generateCodeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}

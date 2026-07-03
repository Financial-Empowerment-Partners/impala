package com.payala.impala.demo.ui.login

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.NfcCardResult
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.AuthenticateRequest
import com.payala.impala.demo.model.CardAuthRequest
import com.payala.impala.demo.model.CardChallengeRequest
import com.payala.impala.demo.model.GitHubTokenExchangeRequest
import com.payala.impala.demo.model.GoogleTokenExchangeRequest
import com.payala.impala.demo.model.OktaTokenExchangeRequest
import com.payala.impala.demo.model.TokenRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import retrofit2.HttpException
import java.io.IOException

/**
 * ViewModel managing the authentication state for [LoginActivity].
 *
 * Supports five sign-in methods, all converging on the bridge's two-token
 * JWT model (14-day refresh token, 1-hour temporal token):
 * - **Password** – `/authenticate` then `POST /token {username, password}`.
 * - **Google** – Credential Manager ID token exchanged at `POST /auth/google`.
 * - **GitHub** – OAuth authorization code exchanged at `POST /auth/github`
 *   (the bridge performs the code→token exchange server-side).
 * - **Okta** – access token exchanged at `POST /auth/okta`.
 * - **Card** – NFC challenge-response: `POST /auth/card/challenge`, signed
 *   on-card (ECDSA-SHA256 over the `"IMPALA-AUTH:"`-prefixed message), then
 *   exchanged at `POST /auth/card`.
 *
 * Every method finishes via [completeTokenFlow]: save the refresh token, then
 * `POST /token {refresh_token}` for the temporal token. Each login coroutine
 * runs under a shared [LOGIN_TIMEOUT_MS] timeout.
 */
class LoginViewModel : ViewModel() {

    private val _loginState = MutableLiveData<LoginState>(LoginState.Idle)
    /** Observable authentication state. UI observes this to show loading/error/success. */
    val loginState: LiveData<LoginState> = _loginState

    companion object {
        /** Upper bound for a whole login flow (all bridge round-trips). */
        const val LOGIN_TIMEOUT_MS = 15_000L
    }

    /** Classifies login errors for UI mapping to appropriate user-facing messages. */
    enum class ErrorType {
        NETWORK, AUTH_FAILED, TOKEN_FAILED, SERVER_ERROR, VALIDATION, TIMEOUT, UNKNOWN
    }

    /** Represents the current state of the login flow. */
    sealed class LoginState {
        data object Idle : LoginState()
        data object Loading : LoginState()
        data class Success(val accountId: String) : LoginState()
        data class Error(val message: String, val errorType: ErrorType = ErrorType.UNKNOWN) : LoginState()
    }

    /** Input validation errors returned before making network calls. */
    sealed class ValidationError(val message: String) {
        class EmptyUsername : ValidationError("Username is required")
        class EmptyPassword : ValidationError("Password is required")
        class PasswordTooShort : ValidationError("Password must be at least 8 characters")
        class InvalidToken : ValidationError("Authentication token is missing")
    }

    /** Validates username/password input before a password login attempt. */
    fun validatePasswordLogin(username: String, password: String): ValidationError? {
        if (username.isBlank()) return ValidationError.EmptyUsername()
        if (password.isEmpty()) return ValidationError.EmptyPassword()
        if (password.length < 8) return ValidationError.PasswordTooShort()
        return null
    }

    /** Validates that an OAuth token is present before an OAuth login attempt. */
    fun validateOAuthLogin(token: String?): ValidationError? {
        if (token.isNullOrBlank()) return ValidationError.InvalidToken()
        return null
    }

    /** Maps an exception to the appropriate [ErrorType]. */
    private fun classifyError(e: Exception): ErrorType {
        return when (e) {
            is IOException -> ErrorType.NETWORK
            is HttpException -> when (e.code()) {
                401, 403 -> ErrorType.AUTH_FAILED
                in 500..599 -> ErrorType.SERVER_ERROR
                else -> ErrorType.UNKNOWN
            }
            else -> ErrorType.UNKNOWN
        }
    }

    /** Authenticate with a direct account ID and password. */
    fun loginWithPassword(
        api: BridgeApiService,
        tokenManager: TokenManager,
        accountId: String,
        password: String
    ) {
        val validationError = validatePasswordLogin(accountId, password)
        if (validationError != null) {
            _loginState.value = LoginState.Error(validationError.message, ErrorType.VALIDATION)
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            runLogin("password", "Network error") {
                AppLogger.i("Auth", "Password login attempt for: $accountId")
                val authResponse = api.authenticate(AuthenticateRequest(accountId, password))
                if (!authResponse.success) {
                    AppLogger.w("Auth", "Password login failed: ${authResponse.message}")
                    _loginState.value = LoginState.Error(authResponse.message, ErrorType.AUTH_FAILED)
                    return@runLogin
                }

                AppLogger.d("Auth", "Requesting refresh token for: $accountId")
                val tokenResponse = api.token(TokenRequest(username = accountId, password = password))
                if (!tokenResponse.success || tokenResponse.refresh_token == null) {
                    AppLogger.w("Auth", "Token request failed: ${tokenResponse.message}")
                    _loginState.value = LoginState.Error(tokenResponse.message, ErrorType.TOKEN_FAILED)
                    return@runLogin
                }

                completeTokenFlow(api, tokenManager, tokenResponse.refresh_token, accountId, "password")
            }
        }
    }

    /**
     * Authenticate via Google. Exchanges the Credential Manager [idToken] with
     * the bridge via `POST /auth/google` — no password derivation.
     */
    fun loginWithGoogle(
        api: BridgeApiService,
        tokenManager: TokenManager,
        email: String,
        idToken: String,
        displayName: String?
    ) {
        val validationError = validateOAuthLogin(idToken)
        if (validationError != null) {
            _loginState.value = LoginState.Error(validationError.message, ErrorType.VALIDATION)
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            runLogin("google", "Google login failed") {
                AppLogger.i("Auth", "Google login attempt for: $email")
                val exchangeResponse = api.googleTokenExchange(GoogleTokenExchangeRequest(idToken))
                if (!exchangeResponse.success || exchangeResponse.refresh_token == null) {
                    AppLogger.w("Auth", "Google token exchange failed: ${exchangeResponse.message}")
                    _loginState.value = LoginState.Error(exchangeResponse.message, ErrorType.AUTH_FAILED)
                    return@runLogin
                }

                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                val accountId = accountIdFromRefreshToken(
                    exchangeResponse.refresh_token, email.lowercase()
                )
                completeTokenFlow(api, tokenManager, exchangeResponse.refresh_token, accountId, "google")
            }
        }
    }

    /**
     * Authenticate via GitHub. Sends the OAuth authorization [code] to the
     * bridge via `POST /auth/github {code, redirect_uri}`; the bridge performs
     * the code→token exchange server-side (the GitHub client secret never
     * ships in the APK) and returns the profile's `login`/`display_name`
     * alongside the JWT tokens.
     */
    fun loginWithGitHub(
        api: BridgeApiService,
        tokenManager: TokenManager,
        code: String
    ) {
        val validationError = validateOAuthLogin(code)
        if (validationError != null) {
            _loginState.value = LoginState.Error(validationError.message, ErrorType.VALIDATION)
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            runLogin("github", "GitHub login failed") {
                AppLogger.i("Auth", "GitHub login attempt (authorization code)")
                val exchangeResponse = api.gitHubTokenExchange(
                    GitHubTokenExchangeRequest(
                        code = code,
                        redirect_uri = BuildConfig.GITHUB_REDIRECT_URI
                    )
                )
                if (!exchangeResponse.success || exchangeResponse.refresh_token == null) {
                    AppLogger.w("Auth", "GitHub token exchange failed: ${exchangeResponse.message}")
                    _loginState.value = LoginState.Error(exchangeResponse.message, ErrorType.AUTH_FAILED)
                    return@runLogin
                }

                // display_name (GitHub profile name) may be unset; login is
                // always present in the bridge's response on success.
                val displayName = exchangeResponse.display_name ?: exchangeResponse.login
                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                val accountId = accountIdFromRefreshToken(exchangeResponse.refresh_token, "github")
                completeTokenFlow(api, tokenManager, exchangeResponse.refresh_token, accountId, "github")
            }
        }
    }

    /**
     * Requests a single-use card-auth challenge from the bridge and hex-decodes
     * it to the raw bytes the card signs. Invoked from the NFC reader-mode
     * callback **while the card is still connected**, so the challenge can be
     * signed on-card within its 60-second TTL.
     *
     * @return the raw challenge bytes (32 for the bridge's 64-hex challenge)
     * @throws IllegalStateException if the bridge refuses to issue a challenge
     * @throws IllegalArgumentException if the challenge is not valid hex
     */
    suspend fun fetchCardChallenge(api: BridgeApiService, cardId: String): ByteArray {
        AppLogger.d("Auth", "Requesting card-auth challenge")
        val response = api.cardChallenge(CardChallengeRequest(cardId))
        val challengeHex = response.challenge
        if (!response.success || challengeHex.isNullOrEmpty()) {
            throw IllegalStateException("Bridge did not issue a card challenge")
        }
        return decodeHex(challengeHex)
    }

    /**
     * Authenticate via NFC smartcard challenge-response.
     *
     * The challenge was fetched ([fetchCardChallenge]) and signed on-card while
     * the card was connected; here the DER signature is hex-encoded and
     * exchanged at `POST /auth/card` for local JWT tokens. The card must
     * already be registered with the bridge (Cards screen) — there is no
     * auto-provisioning on this path.
     */
    fun loginWithCard(
        api: BridgeApiService,
        tokenManager: TokenManager,
        cardResult: NfcCardResult.Success
    ) {
        val signature = cardResult.authSignature
        if (signature == null || signature.isEmpty()) {
            _loginState.value = LoginState.Error(
                "Card did not sign the authentication challenge", ErrorType.VALIDATION
            )
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            runLogin("card", "Card login failed") {
                val user = cardResult.user
                AppLogger.i("Auth", "Card login attempt for card: ${user.cardId}")
                val signatureHex = signature.joinToString("") { "%02x".format(it) }

                val exchangeResponse = api.cardTokenExchange(
                    CardAuthRequest(card_id = user.wireCardId, signature = signatureHex)
                )
                if (!exchangeResponse.success || exchangeResponse.refresh_token == null) {
                    AppLogger.w("Auth", "Card token exchange failed: ${exchangeResponse.message}")
                    _loginState.value = LoginState.Error(exchangeResponse.message, ErrorType.AUTH_FAILED)
                    return@runLogin
                }

                tokenManager.saveDisplayName(user.fullName)

                val accountId = accountIdFromRefreshToken(
                    exchangeResponse.refresh_token, user.accountId
                )
                completeTokenFlow(api, tokenManager, exchangeResponse.refresh_token, accountId, "card")
            }
        }
    }

    /**
     * Authenticate via Okta. Exchanges the Okta access token with the bridge
     * via the dedicated `POST /auth/sso/okta` endpoint (no password derivation).
     */
    fun loginWithOkta(
        api: BridgeApiService,
        tokenManager: TokenManager,
        oktaAccessToken: String,
        displayName: String?
    ) {
        val validationError = validateOAuthLogin(oktaAccessToken)
        if (validationError != null) {
            _loginState.value = LoginState.Error(validationError.message, ErrorType.VALIDATION)
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            runLogin("okta", "Okta login failed") {
                AppLogger.i("Auth", "Okta login attempt")
                val exchangeResponse = api.oktaTokenExchange(
                    OktaTokenExchangeRequest(oktaAccessToken)
                )
                if (!exchangeResponse.success || exchangeResponse.refresh_token == null) {
                    AppLogger.w("Auth", "Okta token exchange failed: ${exchangeResponse.message}")
                    _loginState.value = LoginState.Error(exchangeResponse.message, ErrorType.AUTH_FAILED)
                    return@runLogin
                }

                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                val accountId = accountIdFromRefreshToken(exchangeResponse.refresh_token, "okta-user")
                completeTokenFlow(api, tokenManager, exchangeResponse.refresh_token, accountId, "okta")
            }
        }
    }

    /**
     * Shared login-coroutine wrapper: runs [block] under the [LOGIN_TIMEOUT_MS]
     * timeout, mapping a timeout to [ErrorType.TIMEOUT] and any thrown
     * exception to a classified [LoginState.Error].
     */
    private suspend fun runLogin(provider: String, fallbackMessage: String, block: suspend () -> Unit) {
        val completed = withTimeoutOrNull(LOGIN_TIMEOUT_MS) {
            try {
                block()
            } catch (e: CancellationException) {
                // Let withTimeoutOrNull (and scope cancellation) see this.
                throw e
            } catch (e: Exception) {
                AppLogger.e("Auth", "$provider login error: ${e.message}")
                _loginState.value = LoginState.Error(e.message ?: fallbackMessage, classifyError(e))
            }
        }
        if (completed == null) {
            AppLogger.w("Auth", "$provider login timed out after ${LOGIN_TIMEOUT_MS / 1000}s")
            _loginState.value = LoginState.Error("Login timed out", ErrorType.TIMEOUT)
        }
    }

    /**
     * Completes every login flow's shared tail:
     * 1. persist the refresh token + session metadata,
     * 2. exchange it for a 1-hour temporal token (`POST /token {refresh_token}`).
     *
     * A failed temporal exchange is non-fatal — the auth interceptor simply
     * sends the next request unauthenticated and the caller can re-refresh.
     */
    private suspend fun completeTokenFlow(
        api: BridgeApiService,
        tokenManager: TokenManager,
        refreshToken: String,
        accountId: String,
        provider: String
    ) {
        tokenManager.saveRefreshToken(refreshToken)
        tokenManager.saveAccountId(accountId)
        tokenManager.saveAuthProvider(provider)
        AppLogger.i("Auth", "Refresh token acquired")

        val temporalResponse = api.token(TokenRequest(refresh_token = refreshToken))
        if (temporalResponse.success) {
            // Strict refresh rotation: the bridge may rotate the refresh token
            // on every /token call and revokes the presented one, so the
            // rotated token from the response MUST be persisted — keeping the
            // old token would strand the session at the next refresh.
            // NOTE: ALL future `/token {refresh_token}` call sites must
            // likewise persist the rotated token (use saveTokenPair).
            tokenManager.saveTokenPair(
                temporalResponse.refresh_token,
                temporalResponse.temporal_token
            )
            if (temporalResponse.temporal_token != null) {
                AppLogger.i("Auth", "Temporal token acquired")
            }
        }

        AppLogger.i("Auth", "Login successful via $provider for: $accountId")
        _loginState.value = LoginState.Success(accountId)
    }

    /**
     * Extracts the bridge-assigned account ID from the refresh token's JWT
     * `sub` claim, falling back to [fallback] if the token is unparseable.
     */
    private fun accountIdFromRefreshToken(refreshToken: String, fallback: String): String {
        val payload = refreshToken.split(".").getOrNull(1) ?: return fallback
        return try {
            val decoded = android.util.Base64.decode(payload, android.util.Base64.URL_SAFE)
            val json = org.json.JSONObject(String(decoded))
            json.optString("sub", fallback).ifEmpty { fallback }
        } catch (_: Exception) {
            fallback
        }
    }

    /** Decodes a hex string (e.g. the bridge's 64-hex challenge) to raw bytes. */
    private fun decodeHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Malformed hex challenge (odd length)" }
        return ByteArray(hex.length / 2) { i ->
            val hi = Character.digit(hex[2 * i], 16)
            val lo = Character.digit(hex[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "Malformed hex challenge (invalid character)" }
            ((hi shl 4) or lo).toByte()
        }
    }
}

package com.payala.impala.demo.ui.login

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.NfcCardResult
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.AuthenticateRequest
import com.payala.impala.demo.model.CreateAccountRequest
import com.payala.impala.demo.model.CreateCardRequest
import com.payala.impala.demo.model.TokenRequest
import kotlinx.coroutines.launch
import retrofit2.HttpException
import java.io.IOException
import java.security.MessageDigest

/**
 * ViewModel managing the authentication state for [LoginActivity].
 *
 * Supports three sign-in methods:
 * - **Password** – direct username/password against the bridge.
 * - **Google** – Credential Manager ID token, converted to a derived password.
 * - **GitHub** – OAuth authorization code flow, converted to a derived password.
 *
 * All three methods converge on the same bridge token flow:
 * `/authenticate` -> `/token` (refresh) -> `/token` (temporal).
 *
 * OAuth password derivation uses `SHA-256(providerToken).take(32)`. This is a
 * demo shortcut; production would use dedicated OAuth bridge endpoints.
 */
class LoginViewModel : ViewModel() {

    private val _loginState = MutableLiveData<LoginState>(LoginState.Idle)
    /** Observable authentication state. UI observes this to show loading/error/success. */
    val loginState: LiveData<LoginState> = _loginState

    /** Classifies login errors for UI mapping to appropriate user-facing messages. */
    enum class ErrorType {
        NETWORK, AUTH_FAILED, TOKEN_FAILED, SERVER_ERROR, VALIDATION, UNKNOWN
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
            try {
                AppLogger.i("Auth", "Password login attempt for: $accountId")
                val authResponse = api.authenticate(AuthenticateRequest(accountId, password))
                if (!authResponse.success) {
                    AppLogger.w("Auth", "Password login failed: ${authResponse.message}")
                    _loginState.value = LoginState.Error(authResponse.message, ErrorType.AUTH_FAILED)
                    return@launch
                }

                completeTokenFlow(api, tokenManager, accountId, password, "password")
            } catch (e: Exception) {
                AppLogger.e("Auth", "Password login error: ${e.message}")
                _loginState.value = LoginState.Error(e.message ?: "Network error", classifyError(e))
            }
        }
    }

    /** Authenticate via Google. Derives a password from the Google [idToken]. */
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
            try {
                AppLogger.i("Auth", "Google login attempt for: $email")
                val derivedPassword = derivePassword(idToken)

                // Ensure account exists (create if needed)
                ensureAccountExists(api, email, displayName ?: email)

                val authResponse = api.authenticate(AuthenticateRequest(email, derivedPassword))
                if (!authResponse.success) {
                    AppLogger.w("Auth", "Google login failed: ${authResponse.message}")
                    _loginState.value = LoginState.Error(authResponse.message, ErrorType.AUTH_FAILED)
                    return@launch
                }

                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                completeTokenFlow(api, tokenManager, email, derivedPassword, "google")
            } catch (e: Exception) {
                AppLogger.e("Auth", "Google login error: ${e.message}")
                _loginState.value = LoginState.Error(e.message ?: "Google login failed", classifyError(e))
            }
        }
    }

    /** Authenticate via GitHub. Derives a password from the GitHub [accessToken]. */
    fun loginWithGitHub(
        api: BridgeApiService,
        tokenManager: TokenManager,
        login: String,
        accessToken: String,
        displayName: String?
    ) {
        val validationError = validateOAuthLogin(accessToken)
        if (validationError != null) {
            _loginState.value = LoginState.Error(validationError.message, ErrorType.VALIDATION)
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            try {
                AppLogger.i("Auth", "GitHub login attempt for: $login")
                val derivedPassword = derivePassword(accessToken)

                ensureAccountExists(api, login, displayName ?: login)

                val authResponse = api.authenticate(AuthenticateRequest(login, derivedPassword))
                if (!authResponse.success) {
                    AppLogger.w("Auth", "GitHub login failed: ${authResponse.message}")
                    _loginState.value = LoginState.Error(authResponse.message, ErrorType.AUTH_FAILED)
                    return@launch
                }

                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                completeTokenFlow(api, tokenManager, login, derivedPassword, "github")
            } catch (e: Exception) {
                AppLogger.e("Auth", "GitHub login error: ${e.message}")
                _loginState.value = LoginState.Error(e.message ?: "GitHub login failed", classifyError(e))
            }
        }
    }

    /**
     * Authenticate via NFC smartcard. Derives a deterministic password from
     * the card's UUID and registers the card's public keys with the bridge.
     */
    fun loginWithCard(
        api: BridgeApiService,
        tokenManager: TokenManager,
        cardResult: NfcCardResult.Success
    ) {
        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            try {
                val user = cardResult.user
                AppLogger.i("Auth", "Card login attempt for: ${user.accountId} (card: ${user.cardId})")
                val derivedPassword = derivePassword(user.cardId)

                ensureAccountExists(api, user.accountId, user.fullName)

                val authResponse = api.authenticate(
                    AuthenticateRequest(user.accountId, derivedPassword)
                )
                if (!authResponse.success) {
                    AppLogger.w("Auth", "Card login failed: ${authResponse.message}")
                    _loginState.value = LoginState.Error(authResponse.message, ErrorType.AUTH_FAILED)
                    return@launch
                }

                tokenManager.saveDisplayName(user.fullName)

                // Register card public keys with bridge (best-effort)
                try {
                    val ecHex = cardResult.ecPubKey.joinToString("") { "%02x".format(it) }
                    val rsaHex = cardResult.rsaPubKey.joinToString("") { "%02x".format(it) }
                    api.createCard(
                        CreateCardRequest(
                            account_id = user.accountId,
                            card_id = user.cardId,
                            ec_pubkey = ecHex,
                            rsa_pubkey = rsaHex
                        )
                    )
                    AppLogger.i("Auth", "Card registered with bridge")
                } catch (_: Exception) { /* card may already be registered */ }

                completeTokenFlow(api, tokenManager, user.accountId, derivedPassword, "card")
            } catch (e: Exception) {
                AppLogger.e("Auth", "Card login error: ${e.message}")
                _loginState.value = LoginState.Error(e.message ?: "Card login failed", classifyError(e))
            }
        }
    }

    /**
     * Completes the two-step token exchange:
     * 1. username/password -> refresh_token (30-day)
     * 2. refresh_token -> temporal_token (1-hour)
     */
    private suspend fun completeTokenFlow(
        api: BridgeApiService,
        tokenManager: TokenManager,
        accountId: String,
        password: String,
        provider: String
    ) {
        // Get refresh token
        AppLogger.d("Auth", "Requesting refresh token for: $accountId")
        val tokenResponse = api.token(TokenRequest(username = accountId, password = password))
        if (!tokenResponse.success || tokenResponse.refresh_token == null) {
            AppLogger.w("Auth", "Token request failed: ${tokenResponse.message}")
            _loginState.value = LoginState.Error(tokenResponse.message, ErrorType.TOKEN_FAILED)
            return
        }

        tokenManager.saveRefreshToken(tokenResponse.refresh_token)
        tokenManager.saveAccountId(accountId)
        tokenManager.saveAuthProvider(provider)
        AppLogger.i("Auth", "Refresh token acquired")

        // Get temporal token
        val temporalResponse = api.token(TokenRequest(refresh_token = tokenResponse.refresh_token))
        if (temporalResponse.success && temporalResponse.temporal_token != null) {
            tokenManager.saveTemporalToken(temporalResponse.temporal_token)
            AppLogger.i("Auth", "Temporal token acquired")
        }

        AppLogger.i("Auth", "Login successful via $provider for: $accountId")
        _loginState.value = LoginState.Success(accountId)
    }

    /** Creates a placeholder account for OAuth users if one doesn't already exist. */
    private suspend fun ensureAccountExists(
        api: BridgeApiService,
        accountId: String,
        displayName: String
    ) {
        // Generate a placeholder Stellar account ID for OAuth users
        val placeholderStellarId = "G" + accountId.hashCode().toUInt().toString().padStart(55, '0').take(55)
        val nameParts = displayName.split(" ", limit = 2)

        try {
            api.createAccount(
                CreateAccountRequest(
                    stellar_account_id = placeholderStellarId,
                    payala_account_id = accountId,
                    first_name = nameParts.getOrElse(0) { accountId },
                    last_name = nameParts.getOrElse(1) { "" }
                )
            )
        } catch (_: Exception) {
            // Account may already exist -- that's fine
        }
    }

    /** Derives a deterministic 32-char hex password from an OAuth token via SHA-256. */
    private fun derivePassword(token: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(token.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }.take(32)
    }
}

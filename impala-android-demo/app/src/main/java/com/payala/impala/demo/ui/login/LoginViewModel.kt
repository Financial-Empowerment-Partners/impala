package com.payala.impala.demo.ui.login

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.model.AuthenticateRequest
import com.payala.impala.demo.model.CreateAccountRequest
import com.payala.impala.demo.model.TokenRequest
import kotlinx.coroutines.launch
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

    /** Represents the current state of the login flow. */
    sealed class LoginState {
        data object Idle : LoginState()
        data object Loading : LoginState()
        data class Success(val accountId: String) : LoginState()
        data class Error(val message: String) : LoginState()
    }

    /** Authenticate with a direct account ID and password. */
    fun loginWithPassword(
        api: BridgeApiService,
        tokenManager: TokenManager,
        accountId: String,
        password: String
    ) {
        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            try {
                val authResponse = api.authenticate(AuthenticateRequest(accountId, password))
                if (!authResponse.success) {
                    _loginState.value = LoginState.Error(authResponse.message)
                    return@launch
                }

                completeTokenFlow(api, tokenManager, accountId, password, "password")
            } catch (e: Exception) {
                _loginState.value = LoginState.Error(e.message ?: "Network error")
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
        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            try {
                val derivedPassword = derivePassword(idToken)

                // Ensure account exists (create if needed)
                ensureAccountExists(api, email, displayName ?: email)

                val authResponse = api.authenticate(AuthenticateRequest(email, derivedPassword))
                if (!authResponse.success) {
                    _loginState.value = LoginState.Error(authResponse.message)
                    return@launch
                }

                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                completeTokenFlow(api, tokenManager, email, derivedPassword, "google")
            } catch (e: Exception) {
                _loginState.value = LoginState.Error(e.message ?: "Google login failed")
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
        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            try {
                val derivedPassword = derivePassword(accessToken)

                ensureAccountExists(api, login, displayName ?: login)

                val authResponse = api.authenticate(AuthenticateRequest(login, derivedPassword))
                if (!authResponse.success) {
                    _loginState.value = LoginState.Error(authResponse.message)
                    return@launch
                }

                if (displayName != null) {
                    tokenManager.saveDisplayName(displayName)
                }

                completeTokenFlow(api, tokenManager, login, derivedPassword, "github")
            } catch (e: Exception) {
                _loginState.value = LoginState.Error(e.message ?: "GitHub login failed")
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
        val tokenResponse = api.token(TokenRequest(username = accountId, password = password))
        if (!tokenResponse.success || tokenResponse.refresh_token == null) {
            _loginState.value = LoginState.Error(tokenResponse.message)
            return
        }

        tokenManager.saveRefreshToken(tokenResponse.refresh_token)
        tokenManager.saveAccountId(accountId)
        tokenManager.saveAuthProvider(provider)

        // Get temporal token
        val temporalResponse = api.token(TokenRequest(refresh_token = tokenResponse.refresh_token))
        if (temporalResponse.success && temporalResponse.temporal_token != null) {
            tokenManager.saveTemporalToken(temporalResponse.temporal_token)
        }

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

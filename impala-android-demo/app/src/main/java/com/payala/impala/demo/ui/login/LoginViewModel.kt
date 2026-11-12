package com.payala.impala.demo.ui.login

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.api.BridgeApiService
import com.impala.sdk.flows.CardAuthFlow
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.Hex
import com.impala.sdk.models.StellarCardKey
import com.impala.sdk.stellar.Sep10Exception
import com.payala.impala.card.CardStellarKeys
import com.payala.impala.card.CardSignIn
import com.payala.impala.card.CardSignInResult
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.card.Sep10Fallback
import com.payala.impala.demo.auth.CardSep10
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.card.TapProgress
import com.payala.impala.demo.card.TapStep
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.AuthenticateRequest
import com.payala.impala.demo.model.CardAuthRequest
import com.payala.impala.demo.model.CardChallengeRequest
import com.payala.impala.demo.model.SetCardStellarKeyRequest
import com.payala.impala.demo.model.GitHubTokenExchangeRequest
import com.payala.impala.demo.model.GoogleTokenExchangeRequest
import com.payala.impala.demo.model.OktaTokenExchangeRequest
import com.payala.impala.demo.model.TokenRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import com.payala.impala.stellar.Sep10Client
import com.payala.impala.stellar.Sep10ClientException
import com.payala.impala.stellar.Sep10HttpException
import retrofit2.HttpException
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * What a card tap produced for login.
 *
 * A card with a Stellar key signs in with SEP-10 inside the tap (the signed
 * challenge is posted while the card is still in the field, so the legacy
 * challenge can follow in the same tap when the server turns it down):
 * [sep10TokenJson] is then the bridge's `POST /auth/sep10` answer and
 * [signatureHex] is empty. Any other tap carries the card's DER signature
 * (lowercase hex) over the legacy bridge challenge, to exchange at
 * `POST /auth/card`; [sep10Fallback] says why a card that has a Stellar key
 * was signed in that way.
 */
data class CardLoginTap(
    val identity: CardIdentity,
    val signatureHex: String,
    val sep10TokenJson: String? = null,
    val sep10Fallback: Sep10Fallback? = null,
    /** The card's Stellar key when a fallback tap read it (public values); see [LoginViewModel.loginWithCard]. */
    val stellarKey: StellarCardKey? = null
)

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
 * - **Card** – NFC challenge-response. A card with a Stellar key uses SEP-10
 *   (`GET /auth/sep10`, the challenge transaction signed on-card with
 *   `SIGN_SEP10`, `POST /auth/sep10`). Any other card, and any server that
 *   does not offer SEP-10 or does not know the card's Stellar key, uses the
 *   legacy pair: `POST /auth/card/challenge`, signed on-card (ECDSA-SHA256
 *   over the `"IMPALA-AUTH:"`-prefixed message), then `POST /auth/card`.
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

        /** How long a finished card login waits for the optional Stellar key registration. */
        const val STELLAR_KEY_REGISTRATION_TIMEOUT_MS = 4_000L
    }

    /** Classifies login errors for UI mapping to appropriate user-facing messages. */
    enum class ErrorType {
        NETWORK, AUTH_FAILED, TOKEN_FAILED, SERVER_ERROR, VALIDATION, TIMEOUT, UNKNOWN,
        /** The card refused or could not be read; see [LoginState.Error.cardError]. */
        CARD,
        /** `POST /auth/card` answered the generic 401 (unregistered card, bad or expired challenge). */
        CARD_REJECTED,
        /** HTTP 429: per-card / per-source budget or the 15-minute lockout. */
        LOCKED_OUT
    }

    /** Represents the current state of the login flow. */
    sealed class LoginState {
        data object Idle : LoginState()
        data object Loading : LoginState()
        data class Success(val accountId: String) : LoginState()
        data class Error(
            val message: String,
            val errorType: ErrorType = ErrorType.UNKNOWN,
            val cardError: CardError? = null
        ) : LoginState()
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
    private fun classifyError(e: Exception, provider: String? = null): ErrorType {
        return when (e) {
            // An HTTP answer of the SEP-10 exchange (an IOException subclass: test it first).
            is Sep10HttpException -> when (e.status) {
                401 -> ErrorType.CARD_REJECTED
                429 -> ErrorType.LOCKED_OUT
                in 500..599 -> ErrorType.SERVER_ERROR
                else -> ErrorType.UNKNOWN
            }
            // The server's SEP-10 challenge or stellar.toml failed a client check.
            is Sep10Exception, is Sep10ClientException -> ErrorType.SERVER_ERROR
            is IOException -> ErrorType.NETWORK
            is HttpException -> when (e.code()) {
                401 -> if (provider == "card") ErrorType.CARD_REJECTED else ErrorType.AUTH_FAILED
                403 -> ErrorType.AUTH_FAILED
                429 -> if (provider == "card") ErrorType.LOCKED_OUT else ErrorType.UNKNOWN
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
                AppLogger.i("Auth", "Password login attempt")
                val authResponse = api.authenticate(AuthenticateRequest(accountId, password))
                if (!authResponse.success) {
                    AppLogger.w("Auth", "Password login failed: ${authResponse.message}")
                    _loginState.value = LoginState.Error(authResponse.message, ErrorType.AUTH_FAILED)
                    return@runLogin
                }

                AppLogger.d("Auth", "Requesting refresh token")
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
                // Provider only: the e-mail address is PII and never enters the log.
                AppLogger.i("Auth", "Google login attempt")
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

    /** Set while a card login (tap through token exchange) is running; a second tap is ignored. */
    private val cardLoginInFlight = AtomicBoolean(false)

    /** Claims the single card-login slot; false while another card login is in flight. */
    fun tryBeginCardLogin(): Boolean = cardLoginInFlight.compareAndSet(false, true)

    private fun endCardLogin() = cardLoginInFlight.set(false)

    /**
     * The user cancelled a card login whose card half had not finished (the
     * tap sheet's Cancel while the bridge is being contacted). Releases the
     * card-login slot so a new tap can start, without touching [loginState];
     * the abandoned tap's late result is ignored by the caller.
     */
    fun cardTapAbandoned() {
        if (cardLoginInFlight.getAndSet(false)) AppLogger.i("Auth", "Card login abandoned by the user")
    }

    /**
     * Requests a single-use card-auth challenge from the bridge and returns it
     * as validated hex (8..64 bytes; the bridge issues 32). Invoked from the
     * reader-mode `onTap` **while the card is still connected**, so the
     * challenge is signed within its 60-second TTL.
     *
     * @throws IllegalStateException if the bridge refuses to issue a challenge
     * @throws IllegalArgumentException if the challenge is not valid hex of a signable length
     */
    suspend fun fetchCardChallenge(api: BridgeApiService, wireCardId: String): String {
        AppLogger.d("Auth", "Requesting card-auth challenge")
        val response = api.cardChallenge(CardChallengeRequest(wireCardId))
        val challengeHex = response.challenge
        if (!response.success || challengeHex.isNullOrEmpty()) {
            throw IllegalStateException("Bridge did not issue a card challenge")
        }
        val bytes = Hex.decode(challengeHex)
        require(bytes.size in CardAuthFlow.MIN_CHALLENGE_BYTES..CardAuthFlow.MAX_CHALLENGE_BYTES) {
            "Challenge must be ${CardAuthFlow.MIN_CHALLENGE_BYTES}..${CardAuthFlow.MAX_CHALLENGE_BYTES} bytes"
        }
        return challengeHex.lowercase()
    }

    /**
     * The card half of card login, run in reader mode's `onTap` (NFC binder
     * thread, card connected): read the identity — the applet-version and
     * personalization gates run here, so an unissued card fails **before** a
     * challenge is requested and never spends the card's challenge budget —
     * then sign in with the mechanism the card and the server share
     * (impala-lib's [CardSignIn]):
     *
     * - a card with a Stellar key and a server that offers SEP-10: the whole
     *   SEP-10 exchange, here, with the card in the field;
     * - any other card, no [sep10] client for this build, a server without
     *   SEP-10 or one that does not know the card's Stellar key (401): the
     *   legacy challenge, fetched (bounded by [LOGIN_TIMEOUT_MS], so a slow
     *   network aborts before signing) and signed in the same tap.
     *
     * A lockout (429), a transport failure and a SEP-10 challenge that fails
     * verification are errors, never a reason to fall back.
     *
     * @param sep10 the SEP-10 client of this build, or null (legacy only)
     * @throws CardFlowException for any card refusal (typed [CardError])
     * @throws HttpException / IOException from the bridge requests
     * @throws Sep10Exception when the server's challenge fails the client checks
     */
    fun signInWithCardTap(
        session: ImpalaCardSession,
        api: BridgeApiService,
        sep10: Sep10Client? = null
    ): CardLoginTap {
        val signIn = CardSignIn(sep10) { wireCardId ->
            runBlocking { withTimeout(LOGIN_TIMEOUT_MS) { fetchCardChallenge(api, wireCardId) } }
        }
        val result = signIn.signIn(session) { step ->
            when (step) {
                CardSignIn.Step.CONTACTING_SERVER, CardSignIn.Step.SUBMITTING, CardSignIn.Step.FALLING_BACK ->
                    TapProgress.report(TapStep.CONTACTING_BRIDGE)
                // The card steps show through the traced exchanges (CardStepLabels).
                CardSignIn.Step.READING_CARD, CardSignIn.Step.SIGNING -> Unit
            }
        }
        return when (result) {
            is CardSignInResult.Sep10 -> {
                AppLogger.i("Auth", "Card signed a SEP-10 challenge")
                CardLoginTap(result.identity, "", sep10TokenJson = result.tokenJson)
            }
            is CardSignInResult.Legacy -> {
                result.fallback?.let { AppLogger.i("Auth", "Card login used the legacy challenge (SEP-10: $it)") }
                CardLoginTap(result.identity, result.signatureHex, sep10Fallback = result.fallback, stellarKey = result.stellarKey)
            }
        }
    }

    /** A card tap failed before the exchange; releases the in-flight slot and shows why. */
    fun cardTapFailed(e: Throwable) {
        endCardLogin()
        _loginState.value = when (e) {
            is CardFlowException -> {
                AppLogger.w("Auth", "Card login refused by the card: ${e.error}")
                LoginState.Error(e.error.userMessageKey, ErrorType.CARD, e.error)
            }
            is TimeoutCancellationException -> LoginState.Error("Login timed out", ErrorType.TIMEOUT)
            is Sep10Exception, is Sep10ClientException -> {
                // Never the exception text: it can quote the server's answer.
                AppLogger.w("Auth", "The server's SEP-10 challenge was not accepted: ${e.javaClass.simpleName}")
                LoginState.Error("The server's sign-in challenge could not be verified", ErrorType.SERVER_ERROR)
            }
            is Sep10HttpException -> {
                AppLogger.w("Auth", "SEP-10 card login refused by the server: HTTP ${e.status}")
                LoginState.Error("Card login failed (HTTP ${e.status})", classifyError(e, "card"))
            }
            is Exception -> {
                AppLogger.w("Auth", "Card login failed before the exchange: ${e.javaClass.simpleName}")
                LoginState.Error(e.message ?: "Card login failed", classifyError(e, "card"))
            }
            else -> LoginState.Error("Card login failed", ErrorType.UNKNOWN)
        }
    }

    /**
     * Authenticate via NFC smartcard challenge-response: exchanges the
     * on-card signature at `POST /auth/card` for local JWT tokens, or, when
     * the tap already completed SEP-10, takes the tokens `POST /auth/sep10`
     * returned. The card must already be registered with the bridge (Cards
     * screen) — there is no auto-provisioning on either path. The stored auth
     * provider is `card` for both. Releases the in-flight slot when done.
     *
     * One repair is made on the way: when SEP-10 was refused because the
     * bridge does not know the card's Stellar key ([Sep10Fallback.NOT_REGISTERED])
     * and the legacy login then succeeds, the key the tap read is registered
     * (`PUT /card/stellar-key`) before the login completes, so the card's next
     * login uses SEP-10. The bridge verifies the card's own signatures over
     * the key; a failure of this step is logged and changes nothing.
     */
    fun loginWithCard(
        api: BridgeApiService,
        tokenManager: TokenManager,
        tap: CardLoginTap
    ) {
        if (tap.sep10TokenJson == null && tap.signatureHex.isEmpty()) {
            endCardLogin()
            _loginState.value = LoginState.Error(
                "Card did not sign the authentication challenge", ErrorType.VALIDATION
            )
            return
        }

        viewModelScope.launch {
            _loginState.value = LoginState.Loading
            try {
                runLogin("card", "Card login failed") {
                    val identity = tap.identity
                    AppLogger.i("Auth", "Card login attempt for card: ${identity.wireCardId}")

                    val exchangeResponse = if (tap.sep10TokenJson != null) {
                        CardSep10.parseTokens(tap.sep10TokenJson) ?: run {
                            AppLogger.w("Auth", "The SEP-10 token response was not readable")
                            _loginState.value = LoginState.Error("Card login failed", ErrorType.TOKEN_FAILED)
                            return@runLogin
                        }
                    } else {
                        api.cardTokenExchange(
                            CardAuthRequest(card_id = identity.wireCardId, signature = tap.signatureHex)
                        )
                    }
                    @Suppress("SENSELESS_COMPARISON") // Gson can leave a non-null field null
                    if (!exchangeResponse.success || exchangeResponse.refresh_token == null) {
                        AppLogger.w("Auth", "Card token exchange failed: ${exchangeResponse.message}")
                        _loginState.value = LoginState.Error(
                            exchangeResponse.message ?: "Card login failed", ErrorType.CARD_REJECTED
                        )
                        return@runLogin
                    }

                    if (identity.fullName.isNotBlank()) tokenManager.saveDisplayName(identity.fullName)
                    tokenManager.saveCardId(identity.wireCardId)
                    tokenManager.saveCardAccountId(identity.accountUuid)

                    val accountId = accountIdFromRefreshToken(
                        exchangeResponse.refresh_token, identity.accountUuid
                    )
                    completeTokenFlow(api, tokenManager, exchangeResponse.refresh_token, accountId, "card") {
                        registerStellarKeyAfterFallback(api, tap)
                    }
                }
            } finally {
                endCardLogin()
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
                _loginState.value = LoginState.Error(e.message ?: fallbackMessage, classifyError(e, provider))
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
        provider: String,
        beforeSuccess: (suspend () -> Unit)? = null
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

        // Best-effort follow-up with the new session (it handles its own failures).
        beforeSuccess?.invoke()

        // No account id here: for OAuth providers it can fall back to an e-mail address.
        AppLogger.i("Auth", "Login successful via $provider")
        _loginState.value = LoginState.Success(accountId)
    }

    /**
     * After a legacy card login that was a [Sep10Fallback.NOT_REGISTERED]
     * fallback: registers the card's Stellar key with the bridge, under the
     * session the card just opened. Sent only when both of the card's
     * cross-signatures verify here; bounded by [STELLAR_KEY_REGISTRATION_TIMEOUT_MS];
     * never fails the login.
     */
    private suspend fun registerStellarKeyAfterFallback(api: BridgeApiService, tap: CardLoginTap) {
        if (tap.sep10Fallback != Sep10Fallback.NOT_REGISTERED) return
        val key = tap.stellarKey ?: return
        val identity = tap.identity
        val binding = key.bindingSignature
        val proof = key.proofSignature
        if (binding == null || proof == null ||
            !CardStellarKeys.bindingVerifies(identity.pubKey, identity.accountId, identity.cardId, key) ||
            !CardStellarKeys.proofVerifies(identity.pubKey, identity.accountId, identity.cardId, key)
        ) {
            AppLogger.w("Auth", "The card's Stellar key signatures do not verify; not registering it")
            return
        }
        try {
            val response = withTimeoutOrNull(STELLAR_KEY_REGISTRATION_TIMEOUT_MS) {
                api.setCardStellarKey(
                    SetCardStellarKeyRequest(identity.wireCardId, key.address, Hex.encode(binding), Hex.encode(proof))
                )
            }
            when {
                response == null -> AppLogger.w("Auth", "Registering the card's Stellar key timed out; it will be tried again at the next card login")
                response.success -> AppLogger.i("Auth", "The card's Stellar key is registered; its next login uses SEP-10")
                else -> AppLogger.w("Auth", "The bridge did not register the card's Stellar key")
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            AppLogger.w("Auth", "The bridge refused the card's Stellar key: HTTP ${e.code()}")
        } catch (e: Exception) {
            AppLogger.w("Auth", "Registering the card's Stellar key failed: ${e.javaClass.simpleName}")
        }
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
}

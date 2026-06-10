package com.payala.impala.demo

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.NfcCardResult
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.model.AuthenticateResponse
import com.payala.impala.demo.model.CardAuthRequest
import com.payala.impala.demo.model.CardChallengeResponse
import com.payala.impala.demo.model.TokenRequest
import com.payala.impala.demo.model.TokenResponse
import com.payala.impala.demo.nfc.CardUser
import com.payala.impala.demo.ui.login.LoginViewModel
import com.payala.impala.demo.ui.login.LoginViewModel.ErrorType
import com.payala.impala.demo.ui.login.LoginViewModel.LoginState
import com.payala.impala.demo.ui.login.LoginViewModel.ValidationError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.doSuspendableAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import retrofit2.HttpException
import retrofit2.Response

/**
 * Unit tests for [LoginViewModel].
 *
 * The bridge API is mocked per the card-auth HTTP contract:
 * `POST /auth/google {id_token}`, `POST /auth/github {code, redirect_uri}`
 * (server-side code exchange), `POST /auth/card/challenge {card_id}` ->
 * `{success, challenge, expires_in}`, `POST /auth/card {card_id, signature}`
 * -> TokenResponse — all sharing the `TokenResponse {success, message,
 * refresh_token, temporal_token}` shape.
 *
 * [Dispatchers.Main] is replaced with a [StandardTestDispatcher] so the
 * 15-second login timeout runs on virtual time.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LoginViewModelTest {

    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private lateinit var viewModel: LoginViewModel
    private lateinit var tokenManager: TokenManager

    @Before
    fun setUp() {
        Dispatchers.setMain(StandardTestDispatcher())
        viewModel = LoginViewModel()
        tokenManager = mock()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    // ── Input validation ────────────────────────────────────────────────

    @Test
    fun `initial state is Idle`() {
        val state = viewModel.loginState.value
        assertTrue(state is LoginState.Idle)
    }

    @Test
    fun `validatePasswordLogin with empty username returns EmptyUsername`() {
        val error = viewModel.validatePasswordLogin("", "password123")
        assertTrue(error is ValidationError.EmptyUsername)
    }

    @Test
    fun `validatePasswordLogin with blank username returns EmptyUsername`() {
        val error = viewModel.validatePasswordLogin("   ", "password123")
        assertTrue(error is ValidationError.EmptyUsername)
    }

    @Test
    fun `validatePasswordLogin with empty password returns EmptyPassword`() {
        val error = viewModel.validatePasswordLogin("user1", "")
        assertTrue(error is ValidationError.EmptyPassword)
    }

    @Test
    fun `validatePasswordLogin with short password returns PasswordTooShort`() {
        val error = viewModel.validatePasswordLogin("user1", "short")
        assertTrue(error is ValidationError.PasswordTooShort)
    }

    @Test
    fun `validatePasswordLogin with 7 char password returns PasswordTooShort`() {
        val error = viewModel.validatePasswordLogin("user1", "1234567")
        assertTrue(error is ValidationError.PasswordTooShort)
    }

    @Test
    fun `validatePasswordLogin with valid input returns null`() {
        val error = viewModel.validatePasswordLogin("user1", "password123")
        assertNull(error)
    }

    @Test
    fun `validatePasswordLogin with exactly 8 char password returns null`() {
        val error = viewModel.validatePasswordLogin("user1", "12345678")
        assertNull(error)
    }

    @Test
    fun `validateOAuthLogin with null token returns InvalidToken`() {
        val error = viewModel.validateOAuthLogin(null)
        assertTrue(error is ValidationError.InvalidToken)
    }

    @Test
    fun `validateOAuthLogin with blank token returns InvalidToken`() {
        val error = viewModel.validateOAuthLogin("  ")
        assertTrue(error is ValidationError.InvalidToken)
    }

    @Test
    fun `validateOAuthLogin with empty token returns InvalidToken`() {
        val error = viewModel.validateOAuthLogin("")
        assertTrue(error is ValidationError.InvalidToken)
    }

    @Test
    fun `validateOAuthLogin with valid token returns null`() {
        val error = viewModel.validateOAuthLogin("valid-oauth-token")
        assertNull(error)
    }

    @Test
    fun `loginWithPassword with empty username emits validation error`() {
        viewModel.loginWithPassword(createUnreachableApi(), tokenManager, "", "password123")
        assertValidationError()
    }

    @Test
    fun `loginWithPassword with short password emits validation error`() {
        viewModel.loginWithPassword(createUnreachableApi(), tokenManager, "user1", "short")
        assertValidationError()
    }

    @Test
    fun `loginWithGoogle with empty token emits validation error`() {
        viewModel.loginWithGoogle(
            createUnreachableApi(), tokenManager, "user@example.com", "", "User"
        )
        assertValidationError()
    }

    @Test
    fun `loginWithGitHub with blank code emits validation error`() {
        viewModel.loginWithGitHub(createUnreachableApi(), tokenManager, "  ")
        assertValidationError()
    }

    @Test
    fun `loginWithOkta with blank token emits validation error`() {
        viewModel.loginWithOkta(createUnreachableApi(), tokenManager, "", null)
        assertValidationError()
    }

    @Test
    fun `loginWithCard without an auth signature emits validation error`() {
        viewModel.loginWithCard(createUnreachableApi(), tokenManager, cardResult(signature = null))
        assertValidationError()
    }

    @Test
    fun `loginWithCard with an empty auth signature emits validation error`() {
        viewModel.loginWithCard(
            createUnreachableApi(), tokenManager, cardResult(signature = byteArrayOf())
        )
        assertValidationError()
    }

    // ── Password flow ───────────────────────────────────────────────────

    @Test
    fun `loginWithPassword success completes the two-step token flow`() = runTest {
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doReturn AuthenticateResponse(true, "ok", "verified")
            on { token(any()) } doSuspendableAnswer { invocation ->
                val request = invocation.getArgument<TokenRequest>(0)
                if (request.refresh_token != null) {
                    TokenResponse(true, "ok", temporal_token = TEMPORAL_TOKEN)
                } else {
                    TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
                }
            }
        }

        viewModel.loginWithPassword(api, tokenManager, "user1", "password123")
        advanceUntilIdle()

        val state = viewModel.loginState.value
        assertTrue("expected Success, got $state", state is LoginState.Success)
        assertEquals("user1", (state as LoginState.Success).accountId)
        verify(tokenManager).saveRefreshToken(REFRESH_TOKEN)
        verify(tokenManager).saveTokenPair(null, TEMPORAL_TOKEN, 3600L)
        verify(tokenManager).saveAccountId("user1")
        verify(tokenManager).saveAuthProvider("password")
    }

    @Test
    fun `loginWithPassword with rejected credentials emits AUTH_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doReturn
                AuthenticateResponse(false, "Invalid credentials", "verified")
        }

        viewModel.loginWithPassword(api, tokenManager, "user1", "password123")
        advanceUntilIdle()

        assertErrorType(ErrorType.AUTH_FAILED)
        verify(api, never()).token(any())
    }

    @Test
    fun `loginWithPassword with failed token request emits TOKEN_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doReturn AuthenticateResponse(true, "ok", "verified")
            on { token(any()) } doReturn TokenResponse(false, "rate limited")
        }

        viewModel.loginWithPassword(api, tokenManager, "user1", "password123")
        advanceUntilIdle()

        assertErrorType(ErrorType.TOKEN_FAILED)
    }

    @Test
    fun `loginWithPassword still succeeds when the temporal exchange soft-fails`() = runTest {
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doReturn AuthenticateResponse(true, "ok", "verified")
            on { token(any()) } doSuspendableAnswer { invocation ->
                val request = invocation.getArgument<TokenRequest>(0)
                if (request.refresh_token != null) {
                    TokenResponse(false, "redis unavailable")
                } else {
                    TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
                }
            }
        }

        viewModel.loginWithPassword(api, tokenManager, "user1", "password123")
        advanceUntilIdle()

        assertTrue(viewModel.loginState.value is LoginState.Success)
        verify(tokenManager).saveRefreshToken(REFRESH_TOKEN)
        verify(tokenManager, never()).saveTokenPair(anyOrNull(), anyOrNull(), any())
    }

    @Test
    fun `loginWithPassword maps a 5xx to SERVER_ERROR`() = runTest {
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doSuspendableAnswer { throw httpException(503) }
        }

        viewModel.loginWithPassword(api, tokenManager, "user1", "password123")
        advanceUntilIdle()

        assertErrorType(ErrorType.SERVER_ERROR)
    }

    @Test
    fun `loginWithPassword emits TIMEOUT when the bridge hangs`() = runTest {
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doSuspendableAnswer { awaitCancellation() }
        }

        viewModel.loginWithPassword(api, tokenManager, "user1", "password123")
        advanceUntilIdle()

        assertErrorType(ErrorType.TIMEOUT)
    }

    // ── Google flow ─────────────────────────────────────────────────────

    @Test
    fun `loginWithGoogle success exchanges the id token and saves tokens`() = runTest {
        val api = exchangeApi {
            on { googleTokenExchange(any()) } doReturn
                TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
        }

        viewModel.loginWithGoogle(api, tokenManager, "User@Example.com", "google-id-token", "User")
        advanceUntilIdle()

        val state = viewModel.loginState.value
        assertTrue("expected Success, got $state", state is LoginState.Success)
        // REFRESH_TOKEN has no JWT payload, so the account ID falls back to
        // the lowercased e-mail (mirroring the bridge's verified-email rule).
        assertEquals("user@example.com", (state as LoginState.Success).accountId)
        verify(tokenManager).saveRefreshToken(REFRESH_TOKEN)
        verify(tokenManager).saveTokenPair(null, TEMPORAL_TOKEN, 3600L)
        verify(tokenManager).saveAuthProvider("google")
        verify(tokenManager).saveDisplayName("User")
    }

    @Test
    fun `loginWithGoogle with refused exchange emits AUTH_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { googleTokenExchange(any()) } doReturn TokenResponse(false, "invalid id_token")
        }

        viewModel.loginWithGoogle(api, tokenManager, "user@example.com", "bad-token", null)
        advanceUntilIdle()

        assertErrorType(ErrorType.AUTH_FAILED)
        verify(api, never()).token(any())
    }

    @Test
    fun `loginWithGoogle with 401 emits AUTH_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { googleTokenExchange(any()) } doSuspendableAnswer { throw httpException(401) }
        }

        viewModel.loginWithGoogle(api, tokenManager, "user@example.com", "bad-token", null)
        advanceUntilIdle()

        assertErrorType(ErrorType.AUTH_FAILED)
    }

    @Test
    fun `loginWithGoogle emits TIMEOUT when the exchange hangs`() = runTest {
        val api = mock<BridgeApiService> {
            on { googleTokenExchange(any()) } doSuspendableAnswer { awaitCancellation() }
        }

        viewModel.loginWithGoogle(api, tokenManager, "user@example.com", "google-id-token", null)
        advanceUntilIdle()

        assertErrorType(ErrorType.TIMEOUT)
    }

    // ── GitHub flow ─────────────────────────────────────────────────────

    @Test
    fun `loginWithGitHub success sends the code for server-side exchange`() = runTest {
        val api = exchangeApi {
            on { gitHubTokenExchange(any()) } doReturn
                TokenResponse(
                    true, "ok", refresh_token = REFRESH_TOKEN,
                    login = "ghuser", display_name = "GH User"
                )
        }

        viewModel.loginWithGitHub(api, tokenManager, "gh-auth-code")
        advanceUntilIdle()

        val state = viewModel.loginState.value
        assertTrue("expected Success, got $state", state is LoginState.Success)
        // REFRESH_TOKEN has no JWT payload, so the account ID falls back to
        // the provider fallback "github" (the `sub` claim is authoritative).
        assertEquals("github", (state as LoginState.Success).accountId)

        val captor = argumentCaptor<com.payala.impala.demo.model.GitHubTokenExchangeRequest>()
        verify(api).gitHubTokenExchange(captor.capture())
        assertEquals("gh-auth-code", captor.firstValue.code)
        assertEquals(BuildConfig.GITHUB_REDIRECT_URI, captor.firstValue.redirect_uri)
        // The legacy on-device shape must not be sent: no access token exists
        // client-side any more (the bridge holds the client secret).
        assertNull(captor.firstValue.access_token)
        verify(tokenManager).saveAuthProvider("github")
        verify(tokenManager).saveDisplayName("GH User")
    }

    @Test
    fun `loginWithGitHub falls back to the login for the display name`() = runTest {
        val api = exchangeApi {
            on { gitHubTokenExchange(any()) } doReturn
                TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN, login = "ghuser")
        }

        viewModel.loginWithGitHub(api, tokenManager, "gh-auth-code")
        advanceUntilIdle()

        assertTrue(viewModel.loginState.value is LoginState.Success)
        verify(tokenManager).saveDisplayName("ghuser")
    }

    @Test
    fun `loginWithGitHub with refused exchange emits AUTH_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { gitHubTokenExchange(any()) } doReturn TokenResponse(false, "invalid code")
        }

        viewModel.loginWithGitHub(api, tokenManager, "bad-code")
        advanceUntilIdle()

        assertErrorType(ErrorType.AUTH_FAILED)
        verify(api, never()).token(any())
    }

    @Test
    fun `loginWithGitHub emits TIMEOUT when the exchange hangs`() = runTest {
        val api = mock<BridgeApiService> {
            on { gitHubTokenExchange(any()) } doSuspendableAnswer { awaitCancellation() }
        }

        viewModel.loginWithGitHub(api, tokenManager, "gh-auth-code")
        advanceUntilIdle()

        assertErrorType(ErrorType.TIMEOUT)
    }

    // ── Refresh-token rotation ──────────────────────────────────────────
    // Under the bridge's strict rotation, `POST /token {refresh_token}` may
    // return a rotated refresh token that must replace the stored one. These
    // tests use a real TokenManager over in-memory prefs (injectable-prefs
    // pattern) to assert what actually gets persisted.

    @Test
    fun `completeTokenFlow persists the rotated refresh token when present`() = runTest {
        val manager = TokenManager(FakePrefs())
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doReturn AuthenticateResponse(true, "ok", "verified")
            on { token(any()) } doSuspendableAnswer { invocation ->
                val request = invocation.getArgument<TokenRequest>(0)
                if (request.refresh_token != null) {
                    TokenResponse(
                        true, "ok",
                        refresh_token = ROTATED_REFRESH_TOKEN,
                        temporal_token = TEMPORAL_TOKEN
                    )
                } else {
                    TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
                }
            }
        }

        viewModel.loginWithPassword(api, manager, "user1", "password123")
        advanceUntilIdle()

        assertTrue(viewModel.loginState.value is LoginState.Success)
        assertEquals(ROTATED_REFRESH_TOKEN, manager.getRefreshToken())
        assertEquals(TEMPORAL_TOKEN, manager.getTemporalToken())
    }

    @Test
    fun `completeTokenFlow keeps the original refresh token when none is rotated`() = runTest {
        val manager = TokenManager(FakePrefs())
        val api = mock<BridgeApiService> {
            on { authenticate(any()) } doReturn AuthenticateResponse(true, "ok", "verified")
            on { token(any()) } doSuspendableAnswer { invocation ->
                val request = invocation.getArgument<TokenRequest>(0)
                if (request.refresh_token != null) {
                    TokenResponse(true, "ok", temporal_token = TEMPORAL_TOKEN)
                } else {
                    TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
                }
            }
        }

        viewModel.loginWithPassword(api, manager, "user1", "password123")
        advanceUntilIdle()

        assertTrue(viewModel.loginState.value is LoginState.Success)
        assertEquals(REFRESH_TOKEN, manager.getRefreshToken())
        assertEquals(TEMPORAL_TOKEN, manager.getTemporalToken())
    }

    // ── Okta flow ───────────────────────────────────────────────────────

    @Test
    fun `loginWithOkta success uses the shared token flow`() = runTest {
        val api = exchangeApi {
            on { oktaTokenExchange(any()) } doReturn
                TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
        }

        viewModel.loginWithOkta(api, tokenManager, "okta-access-token", "Okta User")
        advanceUntilIdle()

        val state = viewModel.loginState.value
        assertTrue("expected Success, got $state", state is LoginState.Success)
        assertEquals("okta-user", (state as LoginState.Success).accountId)
        verify(tokenManager).saveRefreshToken(REFRESH_TOKEN)
        verify(tokenManager).saveTokenPair(null, TEMPORAL_TOKEN, 3600L)
        verify(tokenManager).saveAuthProvider("okta")
    }

    @Test
    fun `loginWithOkta with refused exchange emits AUTH_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { oktaTokenExchange(any()) } doReturn TokenResponse(false, "invalid okta_token")
        }

        viewModel.loginWithOkta(api, tokenManager, "bad-token", null)
        advanceUntilIdle()

        assertErrorType(ErrorType.AUTH_FAILED)
    }

    @Test
    fun `loginWithOkta emits TIMEOUT when the exchange hangs`() = runTest {
        val api = mock<BridgeApiService> {
            on { oktaTokenExchange(any()) } doSuspendableAnswer { awaitCancellation() }
        }

        viewModel.loginWithOkta(api, tokenManager, "okta-access-token", null)
        advanceUntilIdle()

        assertErrorType(ErrorType.TIMEOUT)
    }

    // ── Card flow ───────────────────────────────────────────────────────

    @Test
    fun `loginWithCard success posts the hex DER signature to the exchange`() = runTest {
        val api = exchangeApi {
            on { cardTokenExchange(any()) } doReturn
                TokenResponse(true, "ok", refresh_token = REFRESH_TOKEN)
        }

        viewModel.loginWithCard(
            api, tokenManager, cardResult(signature = byteArrayOf(0x30, 0x44, 0x02, 0x20, 0x7f))
        )
        advanceUntilIdle()

        val state = viewModel.loginState.value
        assertTrue("expected Success, got $state", state is LoginState.Success)
        assertEquals(CARD_ACCOUNT_ID, (state as LoginState.Success).accountId)

        val captor = argumentCaptor<CardAuthRequest>()
        verify(api).cardTokenExchange(captor.capture())
        // Wire format is the dash-stripped 32-hex form (bridge validate_card_id).
        assertEquals(CARD_ID_WIRE, captor.firstValue.card_id)
        assertEquals("304402207f", captor.firstValue.signature)
        verify(tokenManager).saveRefreshToken(REFRESH_TOKEN)
        verify(tokenManager).saveTokenPair(null, TEMPORAL_TOKEN, 3600L)
        verify(tokenManager).saveAuthProvider("card")
        verify(tokenManager).saveDisplayName("Card Holder")
    }

    @Test
    fun `loginWithCard with refused exchange emits AUTH_FAILED`() = runTest {
        val api = mock<BridgeApiService> {
            on { cardTokenExchange(any()) } doReturn TokenResponse(false, "invalid signature")
        }

        viewModel.loginWithCard(api, tokenManager, cardResult())
        advanceUntilIdle()

        assertErrorType(ErrorType.AUTH_FAILED)
        verify(api, never()).token(any())
    }

    @Test
    fun `loginWithCard emits TIMEOUT when the exchange hangs`() = runTest {
        val api = mock<BridgeApiService> {
            on { cardTokenExchange(any()) } doSuspendableAnswer { awaitCancellation() }
        }

        viewModel.loginWithCard(api, tokenManager, cardResult())
        advanceUntilIdle()

        assertErrorType(ErrorType.TIMEOUT)
    }

    // ── Card challenge fetch ────────────────────────────────────────────

    @Test
    fun `fetchCardChallenge decodes the bridge's 64-hex challenge`() = runTest {
        val challengeHex = "00112233445566778899aabbccddeeff" +
            "00112233445566778899aabbccddeeff"
        val api = mock<BridgeApiService> {
            on { cardChallenge(any()) } doReturn
                CardChallengeResponse(true, challengeHex, 60)
        }

        val challenge = viewModel.fetchCardChallenge(api, CARD_ID)

        assertEquals(32, challenge.size)
        assertEquals(0x00.toByte(), challenge[0])
        assertEquals(0x11.toByte(), challenge[1])
        assertEquals(0xff.toByte(), challenge[15])
        assertEquals(0xff.toByte(), challenge[31])
    }

    @Test
    fun `fetchCardChallenge throws when the bridge refuses`() {
        val api = mock<BridgeApiService> {
            on { cardChallenge(any()) } doReturn CardChallengeResponse(false)
        }

        assertThrows(IllegalStateException::class.java) {
            runBlocking { viewModel.fetchCardChallenge(api, CARD_ID) }
        }
    }

    @Test
    fun `fetchCardChallenge throws on a malformed hex challenge`() {
        val api = mock<BridgeApiService> {
            on { cardChallenge(any()) } doReturn
                CardChallengeResponse(true, "zz".repeat(32), 60)
        }

        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { viewModel.fetchCardChallenge(api, CARD_ID) }
        }
    }

    @Test
    fun `fetchCardChallenge throws on an odd-length hex challenge`() {
        val api = mock<BridgeApiService> {
            on { cardChallenge(any()) } doReturn CardChallengeResponse(true, "abc", 60)
        }

        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { viewModel.fetchCardChallenge(api, CARD_ID) }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private companion object {
        // No JWT payload section, so account-ID extraction falls back to the
        // per-provider fallback deterministically in unit tests.
        const val REFRESH_TOKEN = "refresh-token"
        const val ROTATED_REFRESH_TOKEN = "rotated-refresh-token"
        const val TEMPORAL_TOKEN = "temporal-token"
        const val CARD_ACCOUNT_ID = "0f0e0d0c-0b0a-0908-0706-050403020100"
        const val CARD_ID = "00112233-4455-6677-8899-aabbccddeeff"
        const val CARD_ID_WIRE = "00112233445566778899aabbccddeeff"
    }

    /** Builds a [NfcCardResult.Success] as produced by the login reader-mode path. */
    private fun cardResult(
        signature: ByteArray? = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
    ): NfcCardResult.Success {
        return NfcCardResult.Success(
            user = CardUser(CARD_ACCOUNT_ID, CARD_ID, "Card Holder"),
            ecPubKey = ByteArray(65),
            rsaPubKey = byteArrayOf(),
            authSignature = signature
        )
    }

    /**
     * Mocks [BridgeApiService] with a `POST /token {refresh_token}` stub for
     * the shared temporal-token step, plus the [stubbing] for the
     * provider-specific exchange endpoint.
     */
    private fun exchangeApi(
        stubbing: org.mockito.kotlin.KStubbing<BridgeApiService>.() -> Unit
    ): BridgeApiService {
        return mock {
            on { token(any()) } doSuspendableAnswer { invocation ->
                val request = invocation.getArgument<TokenRequest>(0)
                assertNotNull("temporal exchange must send refresh_token", request.refresh_token)
                TokenResponse(true, "ok", temporal_token = TEMPORAL_TOKEN)
            }
            stubbing()
        }
    }

    /** Builds a [HttpException] with the given [code], as Retrofit throws for non-2xx. */
    private fun httpException(code: Int): HttpException {
        val body = """{"success":false,"message":"error"}"""
            .toResponseBody("application/json".toMediaType())
        return HttpException(Response.error<TokenResponse>(code, body))
    }

    private fun assertValidationError() {
        val state = viewModel.loginState.value
        assertTrue("expected Error, got $state", state is LoginState.Error)
        assertEquals(ErrorType.VALIDATION, (state as LoginState.Error).errorType)
    }

    private fun assertErrorType(expected: ErrorType) {
        val state = viewModel.loginState.value
        assertTrue("expected Error, got $state", state is LoginState.Error)
        assertEquals(expected, (state as LoginState.Error).errorType)
    }

    /**
     * Creates a proxy-based mock of [BridgeApiService] that throws
     * [UnsupportedOperationException] for any call. Used in validation tests
     * where the API must never be reached.
     */
    private fun createUnreachableApi(): BridgeApiService {
        @Suppress("UNCHECKED_CAST")
        return java.lang.reflect.Proxy.newProxyInstance(
            BridgeApiService::class.java.classLoader,
            arrayOf(BridgeApiService::class.java)
        ) { _, method, _ ->
            throw UnsupportedOperationException("${method.name} should not be called during validation tests")
        } as BridgeApiService
    }

    /**
     * Minimal in-memory [android.content.SharedPreferences] so the rotation
     * tests can exercise a real [TokenManager] (injectable-prefs pattern)
     * without Robolectric.
     */
    private class FakePrefs : android.content.SharedPreferences {
        private val map = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = map.toMutableMap()
        override fun getString(key: String, defValue: String?): String? =
            map[key] as? String ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
            map[key] as? MutableSet<String> ?: defValues
        override fun getInt(key: String, defValue: Int): Int = map[key] as? Int ?: defValue
        override fun getLong(key: String, defValue: Long): Long = map[key] as? Long ?: defValue
        override fun getFloat(key: String, defValue: Float): Float = map[key] as? Float ?: defValue
        override fun getBoolean(key: String, defValue: Boolean): Boolean =
            map[key] as? Boolean ?: defValue
        override fun contains(key: String): Boolean = map.containsKey(key)
        override fun edit(): android.content.SharedPreferences.Editor = FakeEditor()
        override fun registerOnSharedPreferenceChangeListener(
            listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?
        ) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(
            listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?
        ) = Unit

        private inner class FakeEditor : android.content.SharedPreferences.Editor {
            private val pending = mutableMapOf<String, Any?>()
            private var clearFirst = false

            override fun putString(key: String, value: String?) = apply { pending[key] = value }
            override fun putStringSet(key: String, values: MutableSet<String>?) =
                apply { pending[key] = values }
            override fun putInt(key: String, value: Int) = apply { pending[key] = value }
            override fun putLong(key: String, value: Long) = apply { pending[key] = value }
            override fun putFloat(key: String, value: Float) = apply { pending[key] = value }
            override fun putBoolean(key: String, value: Boolean) = apply { pending[key] = value }
            override fun remove(key: String) = apply { pending[key] = null }
            override fun clear() = apply { clearFirst = true }

            override fun commit(): Boolean {
                applyPending()
                return true
            }

            override fun apply() = applyPending()

            private fun applyPending() {
                if (clearFirst) map.clear()
                for ((key, value) in pending) {
                    if (value == null) map.remove(key) else map[key] = value
                }
            }
        }
    }
}

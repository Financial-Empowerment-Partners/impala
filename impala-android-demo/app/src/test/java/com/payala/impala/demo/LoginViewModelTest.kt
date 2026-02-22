package com.payala.impala.demo

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.payala.impala.demo.ui.login.LoginViewModel
import com.payala.impala.demo.ui.login.LoginViewModel.ErrorType
import com.payala.impala.demo.ui.login.LoginViewModel.LoginState
import com.payala.impala.demo.ui.login.LoginViewModel.ValidationError
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class LoginViewModelTest {

    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private lateinit var viewModel: LoginViewModel

    @Before
    fun setUp() {
        viewModel = LoginViewModel()
    }

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
        viewModel.loginWithPassword(
            api = createMockApi(),
            tokenManager = createMockTokenManager(),
            accountId = "",
            password = "password123"
        )

        val state = viewModel.loginState.value
        assertTrue(state is LoginState.Error)
        assertEquals(ErrorType.VALIDATION, (state as LoginState.Error).errorType)
    }

    @Test
    fun `loginWithPassword with short password emits validation error`() {
        viewModel.loginWithPassword(
            api = createMockApi(),
            tokenManager = createMockTokenManager(),
            accountId = "user1",
            password = "short"
        )

        val state = viewModel.loginState.value
        assertTrue(state is LoginState.Error)
        assertEquals(ErrorType.VALIDATION, (state as LoginState.Error).errorType)
    }

    @Test
    fun `loginWithGoogle with null token emits validation error`() {
        viewModel.loginWithGoogle(
            api = createMockApi(),
            tokenManager = createMockTokenManager(),
            email = "user@example.com",
            idToken = "",
            displayName = "User"
        )

        val state = viewModel.loginState.value
        assertTrue(state is LoginState.Error)
        assertEquals(ErrorType.VALIDATION, (state as LoginState.Error).errorType)
    }

    @Test
    fun `loginWithGitHub with blank token emits validation error`() {
        viewModel.loginWithGitHub(
            api = createMockApi(),
            tokenManager = createMockTokenManager(),
            login = "ghuser",
            accessToken = "  ",
            displayName = "GH User"
        )

        val state = viewModel.loginState.value
        assertTrue(state is LoginState.Error)
        assertEquals(ErrorType.VALIDATION, (state as LoginState.Error).errorType)
    }

    /**
     * Creates a proxy-based mock of [com.payala.impala.demo.api.BridgeApiService]
     * that throws [UnsupportedOperationException] for any call. Used in validation
     * tests where the API should never be reached.
     */
    private fun createMockApi(): com.payala.impala.demo.api.BridgeApiService {
        @Suppress("UNCHECKED_CAST")
        return java.lang.reflect.Proxy.newProxyInstance(
            com.payala.impala.demo.api.BridgeApiService::class.java.classLoader,
            arrayOf(com.payala.impala.demo.api.BridgeApiService::class.java)
        ) { _, method, _ ->
            throw UnsupportedOperationException("${method.name} should not be called during validation tests")
        } as com.payala.impala.demo.api.BridgeApiService
    }

    /**
     * Creates a minimal [com.payala.impala.demo.auth.TokenManager] mock.
     * Not used directly in validation tests but required as a parameter.
     */
    private fun createMockTokenManager(): com.payala.impala.demo.auth.TokenManager {
        return org.mockito.Mockito.mock(com.payala.impala.demo.auth.TokenManager::class.java)
    }
}

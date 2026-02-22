package com.payala.impala.demo

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.auth.TokenManager
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class TokenManagerTest {

    private lateinit var tokenManager: TokenManager

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        tokenManager = TokenManager(context)
        tokenManager.clearAll()
    }

    @Test
    fun `save and retrieve refresh token`() {
        assertNull(tokenManager.getRefreshToken())
        tokenManager.saveRefreshToken("test-refresh-token")
        assertEquals("test-refresh-token", tokenManager.getRefreshToken())
    }

    @Test
    fun `save and retrieve temporal token`() {
        assertNull(tokenManager.getTemporalToken())
        tokenManager.saveTemporalToken("test-temporal-token", expiresInSeconds = 3600)
        assertEquals("test-temporal-token", tokenManager.getTemporalToken())
    }

    @Test
    fun `temporal token returns null when expired`() {
        tokenManager.saveTemporalToken("expired-token", expiresInSeconds = 0)
        assertNull(tokenManager.getTemporalToken())
    }

    @Test
    fun `isTemporalTokenExpired returns true when no token stored`() {
        assertTrue(tokenManager.isTemporalTokenExpired())
    }

    @Test
    fun `isTemporalTokenExpired returns false for valid token`() {
        tokenManager.saveTemporalToken("valid-token", expiresInSeconds = 3600)
        assertFalse(tokenManager.isTemporalTokenExpired())
    }

    @Test
    fun `clearAll removes all stored data`() {
        tokenManager.saveRefreshToken("refresh")
        tokenManager.saveTemporalToken("temporal")
        tokenManager.saveAccountId("user1")
        tokenManager.saveAuthProvider("password")
        tokenManager.saveDisplayName("Test User")

        tokenManager.clearAll()

        assertNull(tokenManager.getRefreshToken())
        assertNull(tokenManager.getTemporalToken())
        assertNull(tokenManager.getAccountId())
        assertNull(tokenManager.getAuthProvider())
        assertNull(tokenManager.getDisplayName())
    }

    @Test
    fun `hasValidSession returns false when no tokens stored`() {
        assertFalse(tokenManager.hasValidSession())
    }

    @Test
    fun `hasValidSession returns true when refresh token stored`() {
        tokenManager.saveRefreshToken("some-token")
        assertTrue(tokenManager.hasValidSession())
    }

    @Test
    fun `save and retrieve account id`() {
        assertNull(tokenManager.getAccountId())
        tokenManager.saveAccountId("test-account")
        assertEquals("test-account", tokenManager.getAccountId())
    }

    @Test
    fun `save and retrieve auth provider`() {
        assertNull(tokenManager.getAuthProvider())
        tokenManager.saveAuthProvider("google")
        assertEquals("google", tokenManager.getAuthProvider())
    }

    @Test
    fun `save and retrieve display name`() {
        assertNull(tokenManager.getDisplayName())
        tokenManager.saveDisplayName("John Doe")
        assertEquals("John Doe", tokenManager.getDisplayName())
    }
}

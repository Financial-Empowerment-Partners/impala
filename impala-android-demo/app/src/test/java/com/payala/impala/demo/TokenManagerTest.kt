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
@Config(sdk = [24, 36], manifest = Config.NONE)
class TokenManagerTest {

    private lateinit var prefs: android.content.SharedPreferences
    private lateinit var tokenManager: TokenManager

    @Before
    fun setUp() {
        // Inject a plain SharedPreferences: EncryptedSharedPreferences needs the
        // AndroidKeyStore, which Robolectric does not provide.
        val context = ApplicationProvider.getApplicationContext<Context>()
        prefs = context.getSharedPreferences("impala_test_prefs", Context.MODE_PRIVATE)
        tokenManager = TokenManager(prefs)
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

    // ── Expiry skew (fake clock) ────────────────────────────────────────
    // isTemporalTokenExpired() reports expiry 5 minutes early (clock-skew
    // safety margin) while getTemporalToken() keeps the hard expiry, so a
    // token inside the skew window is "expired" for refresh purposes but
    // still usable for requests.

    @Test
    fun `token with 4 minutes remaining is expired-for-refresh but still usable`() {
        var now = 0L
        val manager = TokenManager(prefs) { now }
        manager.saveTemporalToken("skew-token", expiresInSeconds = 3600)

        now = 3600_000L - 4 * 60 * 1000L // 4 minutes before hard expiry

        assertTrue(manager.isTemporalTokenExpired())
        assertEquals("skew-token", manager.getTemporalToken())
    }

    @Test
    fun `token with 6 minutes remaining is not expired`() {
        var now = 0L
        val manager = TokenManager(prefs) { now }
        manager.saveTemporalToken("skew-token", expiresInSeconds = 3600)

        now = 3600_000L - 6 * 60 * 1000L // 6 minutes before hard expiry

        assertFalse(manager.isTemporalTokenExpired())
        assertEquals("skew-token", manager.getTemporalToken())
    }

    @Test
    fun `token past its hard expiry is expired and unusable`() {
        var now = 0L
        val manager = TokenManager(prefs) { now }
        manager.saveTemporalToken("skew-token", expiresInSeconds = 3600)

        now = 3600_000L // exactly at hard expiry

        assertTrue(manager.isTemporalTokenExpired())
        assertNull(manager.getTemporalToken())
    }

    // ── saveTokenPair (strict refresh rotation) ─────────────────────────

    @Test
    fun `saveTokenPair persists both tokens when present`() {
        tokenManager.saveRefreshToken("old-refresh")
        tokenManager.saveTokenPair("rotated-refresh", "new-temporal")

        assertEquals("rotated-refresh", tokenManager.getRefreshToken())
        assertEquals("new-temporal", tokenManager.getTemporalToken())
    }

    @Test
    fun `saveTokenPair keeps the stored refresh token when no rotation happened`() {
        tokenManager.saveRefreshToken("old-refresh")
        tokenManager.saveTokenPair(null, "new-temporal")

        assertEquals("old-refresh", tokenManager.getRefreshToken())
        assertEquals("new-temporal", tokenManager.getTemporalToken())
    }

    @Test
    fun `saveTokenPair keeps the stored temporal token when the new one is null`() {
        tokenManager.saveTemporalToken("old-temporal", expiresInSeconds = 3600)
        tokenManager.saveTokenPair("rotated-refresh", null)

        assertEquals("rotated-refresh", tokenManager.getRefreshToken())
        assertEquals("old-temporal", tokenManager.getTemporalToken())
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

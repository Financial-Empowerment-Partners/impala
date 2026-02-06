package com.payala.impala.demo.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys

/**
 * Secure token storage backed by [EncryptedSharedPreferences].
 *
 * Manages the two-tier JWT lifecycle used by impala-bridge:
 * - **Refresh token** – valid for 30 days, obtained via username/password login.
 * - **Temporal token** – valid for 1 hour, obtained by presenting the refresh token.
 *
 * Also stores auxiliary session data: account ID, auth provider name, and
 * display name (for OAuth users).
 *
 * Encryption uses AES-256-SIV for keys and AES-256-GCM for values, backed by
 * the Android Keystore master key.
 *
 * @param context Application context used to open EncryptedSharedPreferences
 */
class TokenManager(context: Context) {

    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        "impala_secure_prefs",
        masterKeyAlias,
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_TEMPORAL_TOKEN = "temporal_token"
        private const val KEY_TEMPORAL_EXPIRY = "temporal_token_expiry"
        private const val KEY_ACCOUNT_ID = "account_id"
        private const val KEY_AUTH_PROVIDER = "auth_provider"
        private const val KEY_DISPLAY_NAME = "display_name"
    }

    fun saveRefreshToken(token: String) {
        prefs.edit().putString(KEY_REFRESH_TOKEN, token).apply()
    }

    fun getRefreshToken(): String? = prefs.getString(KEY_REFRESH_TOKEN, null)

    /**
     * Stores the temporal token and records its expiry time.
     * @param expiresInSeconds token lifetime (default 3600 = 1 hour)
     */
    fun saveTemporalToken(token: String, expiresInSeconds: Long = 3600) {
        val expiry = System.currentTimeMillis() + (expiresInSeconds * 1000)
        prefs.edit()
            .putString(KEY_TEMPORAL_TOKEN, token)
            .putLong(KEY_TEMPORAL_EXPIRY, expiry)
            .apply()
    }

    /** Returns the temporal token if it has not yet expired, or `null` otherwise. */
    fun getTemporalToken(): String? {
        val token = prefs.getString(KEY_TEMPORAL_TOKEN, null) ?: return null
        val expiry = prefs.getLong(KEY_TEMPORAL_EXPIRY, 0)
        if (System.currentTimeMillis() >= expiry) {
            return null
        }
        return token
    }

    fun isTemporalTokenExpired(): Boolean {
        val expiry = prefs.getLong(KEY_TEMPORAL_EXPIRY, 0)
        return System.currentTimeMillis() >= expiry
    }

    fun saveAccountId(accountId: String) {
        prefs.edit().putString(KEY_ACCOUNT_ID, accountId).apply()
    }

    fun getAccountId(): String? = prefs.getString(KEY_ACCOUNT_ID, null)

    fun saveAuthProvider(provider: String) {
        prefs.edit().putString(KEY_AUTH_PROVIDER, provider).apply()
    }

    fun getAuthProvider(): String? = prefs.getString(KEY_AUTH_PROVIDER, null)

    fun saveDisplayName(name: String) {
        prefs.edit().putString(KEY_DISPLAY_NAME, name).apply()
    }

    fun getDisplayName(): String? = prefs.getString(KEY_DISPLAY_NAME, null)

    /** Removes all stored tokens and session data (used on logout). */
    fun clearAll() {
        prefs.edit().clear().apply()
    }

    /** Returns `true` if a refresh token is stored (session may still be valid). */
    fun hasValidSession(): Boolean {
        return getRefreshToken() != null
    }
}

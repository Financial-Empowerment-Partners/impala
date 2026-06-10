package com.payala.impala.demo.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Secure token storage backed by [EncryptedSharedPreferences].
 *
 * Manages the two-tier JWT lifecycle used by impala-bridge:
 * - **Refresh token** – valid for 14 days, obtained via username/password login.
 * - **Temporal token** – valid for 1 hour, obtained by presenting the refresh token.
 *
 * Also stores auxiliary session data: account ID, auth provider name, and
 * display name (for OAuth users).
 *
 * Encryption uses AES-256-SIV for keys and AES-256-GCM for values, backed by
 * the Android Keystore master key.
 *
 * The primary [SharedPreferences] is injectable (internal) so unit tests can
 * supply a plain in-memory store — `EncryptedSharedPreferences` requires the
 * AndroidKeyStore, which is unavailable under Robolectric. Production code uses
 * the public [Context] constructor, which always opens the encrypted store.
 * The [clock] is likewise injectable so expiry logic is testable with a fake
 * clock; production uses [System.currentTimeMillis].
 */
class TokenManager internal constructor(
    private val prefs: SharedPreferences,
    private val clock: () -> Long = System::currentTimeMillis
) {

    /** @param context Application context used to open [EncryptedSharedPreferences]. */
    constructor(context: Context) : this(createEncryptedPrefs(context))

    companion object {
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_TEMPORAL_TOKEN = "temporal_token"
        private const val KEY_TEMPORAL_EXPIRY = "temporal_token_expiry"
        private const val KEY_ACCOUNT_ID = "account_id"
        private const val KEY_AUTH_PROVIDER = "auth_provider"
        private const val KEY_DISPLAY_NAME = "display_name"

        /**
         * Safety margin for [isTemporalTokenExpired]: report the token as
         * expired 5 minutes early so callers refresh before client/server
         * clock skew or in-flight latency can produce a 401.
         */
        private const val EXPIRY_SKEW_MS = 5 * 60 * 1000L

        private fun createEncryptedPrefs(context: Context): SharedPreferences {
            // security-crypto 1.1.0 stable: MasterKeys was deprecated in favor of
            // MasterKey.Builder. The builder's default alias equals the old
            // MasterKeys default and the prefs file name is unchanged, so tokens
            // stored under 1.1.0-alpha06 remain decryptable after this migration.
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            return EncryptedSharedPreferences.create(
                context,
                "impala_secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }
    }

    fun saveRefreshToken(token: String) {
        prefs.edit().putString(KEY_REFRESH_TOKEN, token).apply()
    }

    fun getRefreshToken(): String? = prefs.getString(KEY_REFRESH_TOKEN, null)

    /**
     * Atomically persists the tokens returned by a `POST /token` response in a
     * single prefs edit. Null values are skipped (the stored value is kept):
     * under the bridge's strict refresh-token rotation a temporal-token
     * response may also carry a rotated refresh token, and persisting it in
     * the same commit as the temporal token guarantees the pair can't be torn
     * by a crash between two separate writes.
     *
     * @param refreshToken rotated refresh token, or `null` to keep the current one
     * @param temporalToken new temporal token, or `null` to keep the current one
     * @param expiresInSeconds temporal-token lifetime (default 3600 = 1 hour)
     */
    fun saveTokenPair(refreshToken: String?, temporalToken: String?, expiresInSeconds: Long = 3600) {
        val editor = prefs.edit()
        if (refreshToken != null) {
            editor.putString(KEY_REFRESH_TOKEN, refreshToken)
        }
        if (temporalToken != null) {
            editor.putString(KEY_TEMPORAL_TOKEN, temporalToken)
            editor.putLong(KEY_TEMPORAL_EXPIRY, clock() + (expiresInSeconds * 1000))
        }
        editor.apply()
    }

    /**
     * Stores the temporal token and records its expiry time.
     * @param expiresInSeconds token lifetime (default 3600 = 1 hour)
     */
    fun saveTemporalToken(token: String, expiresInSeconds: Long = 3600) {
        val expiry = clock() + (expiresInSeconds * 1000)
        prefs.edit()
            .putString(KEY_TEMPORAL_TOKEN, token)
            .putLong(KEY_TEMPORAL_EXPIRY, expiry)
            .apply()
    }

    /**
     * Returns the temporal token if it has not passed its **hard** expiry, or
     * `null` otherwise. Deliberately ignores [EXPIRY_SKEW_MS]: a token inside
     * the skew window is still valid server-side and remains usable while the
     * early refresh signalled by [isTemporalTokenExpired] happens — returning
     * `null` here would cause gratuitous unauthenticated requests.
     */
    fun getTemporalToken(): String? {
        val token = prefs.getString(KEY_TEMPORAL_TOKEN, null) ?: return null
        val expiry = prefs.getLong(KEY_TEMPORAL_EXPIRY, 0)
        if (clock() >= expiry) {
            return null
        }
        return token
    }

    /**
     * Returns `true` when the temporal token should be refreshed: within
     * [EXPIRY_SKEW_MS] (5 minutes) of — or past — its recorded expiry. This
     * signals "refresh now" early to cover client/server clock skew and
     * in-flight request latency; the token itself stays usable until the hard
     * expiry (see [getTemporalToken]).
     */
    fun isTemporalTokenExpired(): Boolean {
        val expiry = prefs.getLong(KEY_TEMPORAL_EXPIRY, 0)
        return clock() >= expiry - EXPIRY_SKEW_MS
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

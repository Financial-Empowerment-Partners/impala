package com.payala.impala.demo.api

import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.TokenResponse

/**
 * Exchanges the stored 14-day refresh token for a fresh 1-hour temporal token
 * via `POST /token`, and persists the (possibly rotated) pair.
 *
 * This is the single place that performs a mid-session refresh, shared by the
 * proactive path ([AuthInterceptor], which refreshes before a request when the
 * temporal token is at/near expiry) and the reactive path ([TokenAuthenticator],
 * which refreshes after the bridge returns 401). Without it, the temporal token
 * acquired at login is never renewed and every session breaks silently ~1 hour
 * after sign-in.
 *
 * The actual network call is injected as [refresh] so the endpoint wiring lives
 * in [ApiClient] and this class stays trivially unit-testable.
 *
 * @param refresh performs the `POST /token` exchange for a refresh token, or
 *   returns `null` on failure (it must not throw for ordinary HTTP errors).
 */
class TokenRefresher(
    private val tokenManager: TokenManager,
    private val refresh: (refreshToken: String) -> TokenResponse?
) {

    /**
     * Refreshes the temporal token and returns the current valid one, or `null`
     * if no refresh token is stored or the exchange failed (the caller should
     * then proceed unauthenticated / surface re-login).
     *
     * `@Synchronized` collapses a burst of concurrent 401s (or expired-token
     * requests) into a single refresh: a caller passes the temporal token it
     * last saw as [seenTemporalToken]; if another thread already rotated the
     * stored token while this call waited on the lock, the newer token is
     * returned without a second network round-trip.
     */
    @Synchronized
    fun refreshTemporalToken(seenTemporalToken: String?): String? {
        val current = tokenManager.getTemporalToken()
        if (current != null && current != seenTemporalToken) {
            // Another thread refreshed while we were blocked on the lock.
            return current
        }

        val refreshToken = tokenManager.getRefreshToken() ?: return null

        val response = try {
            refresh(refreshToken)
        } catch (e: Exception) {
            AppLogger.w("Auth", "Temporal token refresh threw: ${e.message}")
            null
        }

        if (response != null && response.success && response.temporal_token != null) {
            // Strict refresh-token rotation: the bridge may rotate the refresh
            // token on every /token call and revoke the presented one, so the
            // rotated token (if any) MUST be persisted alongside the temporal
            // token in the same commit (see LoginViewModel.completeTokenFlow).
            tokenManager.saveTokenPair(response.refresh_token, response.temporal_token)
            AppLogger.i("Auth", "Temporal token refreshed")
            return response.temporal_token
        }

        AppLogger.w("Auth", "Temporal token refresh failed; session may require re-login")
        return null
    }
}

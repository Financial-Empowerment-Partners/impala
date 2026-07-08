package com.payala.impala.demo.api

import com.payala.impala.demo.auth.TokenManager
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/**
 * OkHttp [Authenticator] that transparently recovers from an expired temporal
 * token: when the bridge answers a request with 401, it exchanges the stored
 * refresh token for a new temporal token (via [TokenRefresher]) and retries the
 * original request once with the fresh credential.
 *
 * This is the reactive safety net that keeps a session alive past the 1-hour
 * temporal-token lifetime; [AuthInterceptor] additionally refreshes proactively
 * so most requests never see the 401 at all.
 *
 * Refresh is skipped for the token-issuing endpoints themselves (`/authenticate`,
 * `/token`, `auth/…`) so a 401 from those can never spiral into a refresh loop,
 * and a request is retried at most once (guarded via the prior-response chain).
 */
class TokenAuthenticator(
    private val tokenManager: TokenManager,
    private val tokenRefresher: TokenRefresher
) : Authenticator {

    override fun authenticate(route: Route?, response: Response): Request? {
        val path = response.request.url.encodedPath
        if (path.endsWith("/authenticate") || path.endsWith("/token") || path.contains("/auth/")) {
            return null
        }

        // Give up after a single retry to avoid an infinite 401 loop when the
        // refresh token is itself invalid/revoked.
        if (priorResponseCount(response) >= 2) {
            return null
        }

        val seenToken = response.request.header("Authorization")
            ?.removePrefix("Bearer ")
        val newToken = tokenRefresher.refreshTemporalToken(seenToken) ?: return null

        return response.request.newBuilder()
            .header("Authorization", "Bearer $newToken")
            .build()
    }

    /** Number of responses in the chain (initial + each authenticated retry). */
    private fun priorResponseCount(response: Response): Int {
        var count = 1
        var prior = response.priorResponse
        while (prior != null) {
            count++
            prior = prior.priorResponse
        }
        return count
    }
}

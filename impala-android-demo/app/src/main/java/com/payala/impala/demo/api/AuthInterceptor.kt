package com.payala.impala.demo.api

import com.payala.impala.demo.auth.TokenManager
import okhttp3.Interceptor
import okhttp3.Response

/**
 * OkHttp interceptor that attaches the JWT temporal token to outgoing requests.
 *
 * Requests to `/authenticate`, `/token`, and the `auth/` token-exchange
 * endpoints (Okta, Google, GitHub, card challenge-response) are excluded
 * because those endpoints are used to *obtain* tokens in the first place. If
 * no temporal token is stored (or it has expired), the request proceeds
 * without an `Authorization` header.
 *
 * When a [TokenRefresher] is supplied, the interceptor also refreshes
 * proactively: if the temporal token is within its expiry-skew window (see
 * [TokenManager.isTemporalTokenExpired]) and a refresh token is stored, it
 * exchanges for a fresh temporal token *before* sending, so the request carries
 * a valid credential instead of racing a 401. [TokenAuthenticator] remains the
 * reactive fallback for any 401 that still slips through.
 */
class AuthInterceptor(
    private val tokenManager: TokenManager,
    private val tokenRefresher: TokenRefresher? = null
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val path = request.url.encodedPath

        // Do not attach tokens to auth endpoints
        if (path.endsWith("/authenticate") || path.endsWith("/token") || path.contains("/auth/")) {
            return chain.proceed(request)
        }

        // Proactively renew a temporal token that is at/near its expiry so this
        // request is authenticated on the first try rather than after a 401.
        if (tokenRefresher != null &&
            tokenManager.getRefreshToken() != null &&
            tokenManager.isTemporalTokenExpired()
        ) {
            tokenRefresher.refreshTemporalToken(tokenManager.getTemporalToken())
        }

        val temporalToken = tokenManager.getTemporalToken()
        if (temporalToken != null) {
            val authedRequest = request.newBuilder()
                .header("Authorization", "Bearer $temporalToken")
                .build()
            return chain.proceed(authedRequest)
        }

        return chain.proceed(request)
    }
}

package com.payala.impala.demo.api

import com.payala.impala.demo.auth.TokenManager
import okhttp3.Interceptor
import okhttp3.Response

/**
 * OkHttp interceptor that attaches the JWT temporal token to outgoing requests.
 *
 * Requests to `/authenticate` and `/token` are excluded because those endpoints
 * are used to *obtain* tokens in the first place. If no temporal token is stored
 * (or it has expired), the request proceeds without an `Authorization` header.
 */
class AuthInterceptor(private val tokenManager: TokenManager) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val path = request.url.encodedPath

        // Do not attach tokens to auth endpoints
        if (path.endsWith("/authenticate") || path.endsWith("/token")) {
            return chain.proceed(request)
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

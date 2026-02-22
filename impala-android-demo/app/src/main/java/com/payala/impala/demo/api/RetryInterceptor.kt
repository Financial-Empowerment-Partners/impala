package com.payala.impala.demo.api

import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException

/**
 * OkHttp interceptor that retries failed GET requests with exponential backoff.
 *
 * Only retries on:
 * - [IOException] (network failures, timeouts)
 * - HTTP 5xx responses for GET requests (server errors)
 *
 * Non-GET requests are never retried to avoid duplicate side effects.
 *
 * @param maxRetries Maximum number of retry attempts (default 3)
 * @param initialDelayMs Delay before the first retry in milliseconds (default 1000)
 */
class RetryInterceptor(
    private val maxRetries: Int = 3,
    private val initialDelayMs: Long = 1000
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        var lastException: IOException? = null
        var lastResponse: Response? = null

        for (attempt in 0..maxRetries) {
            if (attempt > 0) {
                val delay = initialDelayMs * (1L shl (attempt - 1))
                Thread.sleep(delay)
                lastResponse?.close()
            }

            try {
                val response = chain.proceed(chain.request())
                if (response.isSuccessful || response.code < 500) {
                    return response
                }
                if (chain.request().method != "GET") {
                    return response
                }
                lastResponse = response
            } catch (e: IOException) {
                lastException = e
                if (attempt == maxRetries) {
                    throw e
                }
            }
        }

        throw lastException ?: IOException("Retry failed")
    }
}

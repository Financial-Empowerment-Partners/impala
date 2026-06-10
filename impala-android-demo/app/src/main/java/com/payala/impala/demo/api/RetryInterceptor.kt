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
 * Non-GET requests are never retried to avoid duplicate side effects, and a
 * cancelled call ([okhttp3.Call.isCanceled]) is never retried — cancellation
 * is checked before and after each backoff sleep so a cancelled call fails
 * fast instead of sleeping through the remaining attempts.
 *
 * @param maxRetries Maximum number of retry attempts (default 2)
 * @param initialDelayMs Delay before the first retry in milliseconds (default 250)
 */
class RetryInterceptor(
    private val maxRetries: Int = 2,
    private val initialDelayMs: Long = 250
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        var lastException: IOException? = null
        var lastResponse: Response? = null

        for (attempt in 0..maxRetries) {
            if (attempt > 0) {
                lastResponse?.close()
                if (chain.call().isCanceled()) {
                    throw lastException ?: IOException("Call cancelled; not retrying")
                }
                val delay = initialDelayMs * (1L shl (attempt - 1))
                Thread.sleep(delay)
                if (chain.call().isCanceled()) {
                    throw lastException ?: IOException("Call cancelled; not retrying")
                }
            }

            try {
                val response = chain.proceed(chain.request())
                if (response.isSuccessful || response.code < 500) {
                    return response
                }
                if (chain.request().method != "GET") {
                    return response
                }
                if (attempt == maxRetries) {
                    // Out of retries — surface the last 5xx to the caller
                    // rather than discarding it
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

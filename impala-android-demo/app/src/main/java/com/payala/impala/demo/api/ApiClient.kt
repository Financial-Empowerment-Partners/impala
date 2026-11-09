package com.payala.impala.demo.api

import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.model.TokenRequest
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Thread-safe Retrofit singleton providing access to [BridgeApiService].
 *
 * Uses double-checked locking so the OkHttp client and Retrofit instance are
 * created only once per base-URL. Call [reset] on logout to discard the cached
 * client (and its [AuthInterceptor]).
 */
object ApiClient {

    @Volatile
    private var service: BridgeApiService? = null
    private var currentBaseUrl: String? = null
    private var client: OkHttpClient? = null

    /**
     * Returns a [BridgeApiService] configured for [baseUrl].
     *
     * A new Retrofit instance is built only when the URL changes or after [reset].
     * The OkHttp client includes an [AuthInterceptor] that attaches the stored
     * JWT temporal token to every request (except `/authenticate` and `/token`).
     */
    fun getService(baseUrl: String, tokenManager: TokenManager): BridgeApiService {
        val normalizedUrl = baseUrl.trimEnd('/') + "/"

        if (service != null && currentBaseUrl == normalizedUrl) {
            return service!!
        }

        synchronized(this) {
            if (service != null && currentBaseUrl == normalizedUrl) {
                return service!!
            }

            val logging = buildLoggingInterceptor(BuildConfig.DEBUG)

            // Refreshes the temporal token via POST /token using the current
            // service instance (resolved lazily, only on refresh, so there is
            // no construction cycle with the client being built here). Uses the
            // synchronous refreshToken()/execute() so the nested call is exempt
            // from the dispatcher per-host limit (see BridgeApiService).
            val tokenRefresher = TokenRefresher(tokenManager) { refreshToken ->
                service?.refreshToken(TokenRequest(refresh_token = refreshToken))
                    ?.execute()
                    ?.takeIf { it.isSuccessful }
                    ?.body()
            }

            val okHttpClient = OkHttpClient.Builder()
                .addInterceptor(RetryInterceptor())
                .addInterceptor(AuthInterceptor(tokenManager, tokenRefresher))
                .addInterceptor(logging)
                .authenticator(TokenAuthenticator(tokenManager, tokenRefresher))
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build()

            client = okHttpClient

            val retrofit = Retrofit.Builder()
                .baseUrl(normalizedUrl)
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build()

            service = retrofit.create(BridgeApiService::class.java)
            currentBaseUrl = normalizedUrl
            return service!!
        }
    }

    /** Headers whose values never reach a log line (OkHttp prints them as "██"). */
    internal val REDACTED_HEADERS = listOf("Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie")

    /** Query parameters whose values never reach a log line (account identifiers). */
    internal val REDACTED_QUERY_PARAMS = listOf("account_id", "stellar_account_id")

    /**
     * The HTTP logging policy, pinned by HttpLoggingPolicyTest: request and
     * response HEADERS in debug builds only (never BODY: bodies carry
     * passwords, refresh tokens, card signatures and challenges), nothing in
     * release, credentials and session headers redacted, and account ids
     * redacted from logged URLs.
     */
    internal fun buildLoggingInterceptor(
        debug: Boolean,
        sink: HttpLoggingInterceptor.Logger = HttpLoggingInterceptor.Logger.DEFAULT
    ): HttpLoggingInterceptor = HttpLoggingInterceptor(sink).apply {
        level = if (debug) HttpLoggingInterceptor.Level.HEADERS else HttpLoggingInterceptor.Level.NONE
        REDACTED_HEADERS.forEach(::redactHeader)
        redactQueryParams(*REDACTED_QUERY_PARAMS.toTypedArray())
    }

    /** Discards the cached service instance, forcing re-creation on next call. */
    fun reset() {
        synchronized(this) {
            client?.let {
                it.connectionPool.evictAll()
                it.dispatcher.cancelAll()
            }
            service = null
            currentBaseUrl = null
            client = null
        }
    }
}

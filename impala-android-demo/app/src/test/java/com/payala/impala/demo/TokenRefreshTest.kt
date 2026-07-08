package com.payala.impala.demo

import android.content.Context
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.api.AuthInterceptor
import com.payala.impala.demo.api.TokenAuthenticator
import com.payala.impala.demo.api.TokenRefresher
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.model.TokenResponse
import java.net.Proxy
import java.net.ProxySelector
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager
import kotlin.reflect.KClass
import okhttp3.Authenticator
import okhttp3.Cache
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CertificatePinner
import okhttp3.Connection
import okhttp3.ConnectionPool
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.EventListener
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Tests for the mid-session temporal-token refresh path:
 * [TokenRefresher] (the shared exchange), [AuthInterceptor] (proactive refresh
 * on expiry) and [TokenAuthenticator] (reactive refresh + retry on 401).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24, 36], manifest = Config.NONE)
class TokenRefreshTest {

    private lateinit var prefs: SharedPreferences
    private lateinit var tokenManager: TokenManager
    private var now: Long = 1_000_000L

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        prefs = context.getSharedPreferences("impala_refresh_test_prefs", Context.MODE_PRIVATE)
        tokenManager = TokenManager(prefs, clock = { now })
        tokenManager.clearAll()
    }

    private fun okResponse(refresh: String?, temporal: String?) = TokenResponse(
        success = true,
        message = "ok",
        refresh_token = refresh,
        temporal_token = temporal
    )

    // ── TokenRefresher ──────────────────────────────────────────────────

    @Test
    fun `refresh exchanges refresh token and persists rotated pair`() {
        tokenManager.saveRefreshToken("refresh-1")
        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { rt ->
            calls.incrementAndGet()
            assertEquals("refresh-1", rt)
            okResponse(refresh = "refresh-2", temporal = "temporal-1")
        }

        val token = refresher.refreshTemporalToken(seenTemporalToken = null)

        assertEquals("temporal-1", token)
        assertEquals("temporal-1", tokenManager.getTemporalToken())
        assertEquals("refresh-2", tokenManager.getRefreshToken()) // rotation persisted
        assertEquals(1, calls.get())
    }

    @Test
    fun `refresh returns null and does not call network when no refresh token stored`() {
        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse(null, "t") }

        assertNull(refresher.refreshTemporalToken(seenTemporalToken = null))
        assertEquals(0, calls.get())
    }

    @Test
    fun `refresh returns null when exchange throws`() {
        tokenManager.saveRefreshToken("refresh-1")
        val refresher = TokenRefresher(tokenManager) { throw java.io.IOException("network down") }

        assertNull(refresher.refreshTemporalToken(seenTemporalToken = null))
    }

    @Test
    fun `refresh is deduped when the stored token was already rotated by another caller`() {
        tokenManager.saveRefreshToken("refresh-1")
        tokenManager.saveTokenPair("refresh-2", "temporal-new", expiresInSeconds = 3600)
        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse(null, "t") }

        // Caller last saw the OLD token; the store already holds a newer one.
        val token = refresher.refreshTemporalToken(seenTemporalToken = "temporal-old")

        assertEquals("temporal-new", token)
        assertEquals(0, calls.get()) // no redundant network refresh
    }

    // ── AuthInterceptor (proactive) ─────────────────────────────────────

    @Test
    fun `expired temporal token triggers exactly one refresh and the request carries the new token`() {
        tokenManager.saveRefreshToken("refresh-1")
        tokenManager.saveTokenPair("refresh-1", "temporal-old", expiresInSeconds = 3600)
        now += 3_600_000 // advance past the hard expiry

        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse("refresh-1", "temporal-new") }
        val interceptor = AuthInterceptor(tokenManager, refresher)

        val chain = FakeChain(request("GET", "/account"))
        interceptor.intercept(chain)

        assertEquals(1, calls.get())
        assertEquals("Bearer temporal-new", chain.sentRequest?.header("Authorization"))
    }

    @Test
    fun `valid temporal token is attached without refreshing`() {
        tokenManager.saveRefreshToken("refresh-1")
        tokenManager.saveTokenPair("refresh-1", "temporal-ok", expiresInSeconds = 3600)

        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse(null, "x") }
        val interceptor = AuthInterceptor(tokenManager, refresher)

        val chain = FakeChain(request("GET", "/account"))
        interceptor.intercept(chain)

        assertEquals(0, calls.get())
        assertEquals("Bearer temporal-ok", chain.sentRequest?.header("Authorization"))
    }

    @Test
    fun `auth endpoints are never given a token or refreshed`() {
        tokenManager.saveRefreshToken("refresh-1")
        tokenManager.saveTokenPair("refresh-1", "temporal-old", expiresInSeconds = 3600)
        now += 3_600_000

        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse(null, "x") }
        val interceptor = AuthInterceptor(tokenManager, refresher)

        val chain = FakeChain(request("POST", "/token"))
        interceptor.intercept(chain)

        assertEquals(0, calls.get())
        assertNull(chain.sentRequest?.header("Authorization"))
    }

    // ── TokenAuthenticator (reactive) ───────────────────────────────────

    @Test
    fun `401 refreshes and retries the original request with the new token`() {
        tokenManager.saveRefreshToken("refresh-1")
        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse("refresh-1", "temporal-new") }
        val authenticator = TokenAuthenticator(tokenManager, refresher)

        val original = request("GET", "/account", bearer = "temporal-old")
        val retry = authenticator.authenticate(null, response401(original))

        assertEquals("Bearer temporal-new", retry?.header("Authorization"))
        assertEquals("/account", retry?.url?.encodedPath) // same request, retried
        assertEquals(1, calls.get())
    }

    @Test
    fun `401 gives up (returns null) when refresh fails`() {
        // no refresh token stored → refresher returns null
        val refresher = TokenRefresher(tokenManager) { okResponse(null, "x") }
        val authenticator = TokenAuthenticator(tokenManager, refresher)

        assertNull(authenticator.authenticate(null, response401(request("GET", "/account", bearer = "old"))))
    }

    @Test
    fun `already-retried 401 is not retried again (loop guard)`() {
        tokenManager.saveRefreshToken("refresh-1")
        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse("refresh-1", "temporal-new") }
        val authenticator = TokenAuthenticator(tokenManager, refresher)

        val first = response401(request("GET", "/account", bearer = "old"))
        val second = response401(request("GET", "/account", bearer = "temporal-new"), prior = first)

        assertNull(authenticator.authenticate(null, second))
        assertEquals(0, calls.get()) // guard trips before any refresh
    }

    @Test
    fun `401 from a token endpoint is not refreshed (no loop)`() {
        tokenManager.saveRefreshToken("refresh-1")
        val calls = AtomicInteger()
        val refresher = TokenRefresher(tokenManager) { calls.incrementAndGet(); okResponse("refresh-1", "temporal-new") }
        val authenticator = TokenAuthenticator(tokenManager, refresher)

        assertNull(authenticator.authenticate(null, response401(request("POST", "/token"))))
        assertEquals(0, calls.get())
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private fun request(method: String, path: String, bearer: String? = null): Request {
        val builder = Request.Builder()
            .url("http://10.0.2.2:8080$path")
            .method(method, if (method == "GET") null else "".toRequestBody())
        if (bearer != null) builder.header("Authorization", "Bearer $bearer")
        return builder.build()
    }

    /**
     * A mocked 401 [Response] exposing only what [TokenAuthenticator] reads
     * (`request` and `priorResponse`), sidestepping OkHttp's Response.Builder
     * body/priorResponse validation.
     */
    private fun response401(req: Request, prior: Response? = null): Response = mock {
        on { request } doReturn req
        on { priorResponse } doReturn prior
    }

    /** Minimal single-shot [Interceptor.Chain] that records the request proceed() saw. */
    private class FakeChain(private val request: Request) : Interceptor.Chain {
        var sentRequest: Request? = null
            private set

        override fun request(): Request = request

        override fun proceed(request: Request): Response {
            sentRequest = request
            return Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(EmptyBody())
                .build()
        }

        override fun connection(): Connection? = null
        override fun call(): Call = FakeCall(request)
        override fun connectTimeoutMillis(): Int = 0
        override fun withConnectTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun readTimeoutMillis(): Int = 0
        override fun withReadTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun writeTimeoutMillis(): Int = 0
        override fun withWriteTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this

        override val followSslRedirects: Boolean get() = true
        override val followRedirects: Boolean get() = true
        override val dns: Dns get() = Dns.SYSTEM
        override val socketFactory: SocketFactory get() = SocketFactory.getDefault()
        override val retryOnConnectionFailure: Boolean get() = false
        override val authenticator: Authenticator get() = Authenticator.NONE
        override val cookieJar: CookieJar get() = CookieJar.NO_COOKIES
        override val cache: Cache? get() = null
        override val proxy: Proxy? get() = null
        override val proxySelector: ProxySelector get() = ProxySelector.getDefault()
        override val proxyAuthenticator: Authenticator get() = Authenticator.NONE
        override val sslSocketFactoryOrNull: SSLSocketFactory? get() = null
        override val x509TrustManagerOrNull: X509TrustManager? get() = null
        override val hostnameVerifier: HostnameVerifier get() = HostnameVerifier { _, _ -> false }
        override val certificatePinner: CertificatePinner get() = CertificatePinner.DEFAULT
        override val connectionPool: ConnectionPool get() = ConnectionPool()
        override val eventListener: EventListener get() = EventListener.NONE
        override fun withDns(dns: Dns): Interceptor.Chain = this
        override fun withSocketFactory(socketFactory: SocketFactory): Interceptor.Chain = this
        override fun withRetryOnConnectionFailure(retryOnConnectionFailure: Boolean): Interceptor.Chain = this
        override fun withAuthenticator(authenticator: Authenticator): Interceptor.Chain = this
        override fun withCookieJar(cookieJar: CookieJar): Interceptor.Chain = this
        override fun withCache(cache: Cache?): Interceptor.Chain = this
        override fun withProxy(proxy: Proxy?): Interceptor.Chain = this
        override fun withProxySelector(proxySelector: ProxySelector): Interceptor.Chain = this
        override fun withProxyAuthenticator(proxyAuthenticator: Authenticator): Interceptor.Chain = this
        override fun withSslSocketFactory(
            sslSocketFactory: SSLSocketFactory?,
            x509TrustManager: X509TrustManager?
        ): Interceptor.Chain = this
        override fun withHostnameVerifier(hostnameVerifier: HostnameVerifier): Interceptor.Chain = this
        override fun withCertificatePinner(certificatePinner: CertificatePinner): Interceptor.Chain = this
        override fun withConnectionPool(connectionPool: ConnectionPool): Interceptor.Chain = this
    }

    private class EmptyBody : ResponseBody() {
        override fun contentType(): MediaType? = null
        override fun contentLength(): Long = 0L
        override fun source(): BufferedSource = Buffer()
    }

    private class FakeCall(private val request: Request) : Call {
        override fun request(): Request = request
        override fun execute(): Response = throw UnsupportedOperationException()
        override fun enqueue(responseCallback: Callback) = throw UnsupportedOperationException()
        override fun cancel() = Unit
        override fun isExecuted(): Boolean = false
        override fun isCanceled(): Boolean = false
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = FakeCall(request)
        override fun addEventListener(eventListener: EventListener) = Unit
        override fun <T : Any> tag(type: KClass<T>): T? = null
        override fun <T> tag(type: Class<out T>): T? = null
        override fun <T : Any> tag(type: KClass<T>, computeIfAbsent: () -> T): T =
            throw UnsupportedOperationException()
        override fun <T : Any> tag(type: Class<T>, computeIfAbsent: () -> T): T =
            throw UnsupportedOperationException()
    }
}

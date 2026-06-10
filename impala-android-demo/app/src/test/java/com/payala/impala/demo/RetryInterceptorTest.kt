package com.payala.impala.demo

import com.payala.impala.demo.api.RetryInterceptor
import java.io.IOException
import java.net.Proxy
import java.net.ProxySelector
import java.util.concurrent.TimeUnit
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Unit tests for [RetryInterceptor] using a fake [Interceptor.Chain] that
 * serves a scripted sequence of responses/exceptions and records how many
 * times `proceed` was called.
 */
class RetryInterceptorTest {

    /** One scripted outcome of a `chain.proceed` call. */
    private sealed class Outcome {
        data class Http(val code: Int) : Outcome()
        data class Failure(val exception: IOException) : Outcome()
    }

    /** Empty response body that records whether it was closed. */
    private class TrackedBody : ResponseBody() {
        var closed = false
            private set

        override fun contentType(): MediaType? = null
        override fun contentLength(): Long = 0L
        override fun source(): BufferedSource = Buffer()
        override fun close() {
            closed = true
            super.close()
        }
    }

    private class FakeCall(private val request: Request) : Call {
        var cancelled = false

        override fun request(): Request = request
        override fun execute(): Response = throw UnsupportedOperationException()
        override fun enqueue(responseCallback: Callback) = throw UnsupportedOperationException()
        override fun cancel() { cancelled = true }
        override fun isExecuted(): Boolean = false
        override fun isCanceled(): Boolean = cancelled
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = FakeCall(request)

        // New abstract members in OkHttp 5.x — unused by RetryInterceptor.
        override fun addEventListener(eventListener: EventListener) = Unit
        override fun <T : Any> tag(type: KClass<T>): T? = null
        override fun <T> tag(type: Class<out T>): T? = null
        override fun <T : Any> tag(type: KClass<T>, computeIfAbsent: () -> T): T =
            throw UnsupportedOperationException()
        override fun <T : Any> tag(type: Class<T>, computeIfAbsent: () -> T): T =
            throw UnsupportedOperationException()
    }

    private class FakeChain(
        private val request: Request,
        private val outcomes: List<Outcome>,
        /** Invoked after each proceed with the 1-based attempt number. */
        private val afterProceed: (Int, FakeCall) -> Unit = { _, _ -> }
    ) : Interceptor.Chain {
        val call = FakeCall(request)
        var proceedCount = 0
            private set
        val issuedBodies = mutableListOf<TrackedBody>()

        override fun request(): Request = request

        override fun proceed(request: Request): Response {
            val outcome = outcomes.getOrNull(proceedCount)
                ?: throw AssertionError("proceed called more times than scripted (${outcomes.size})")
            proceedCount++
            try {
                when (outcome) {
                    is Outcome.Failure -> throw outcome.exception
                    is Outcome.Http -> {
                        val body = TrackedBody()
                        issuedBodies.add(body)
                        return Response.Builder()
                            .request(request)
                            .protocol(Protocol.HTTP_1_1)
                            .code(outcome.code)
                            .message("scripted")
                            .body(body)
                            .build()
                    }
                }
            } finally {
                afterProceed(proceedCount, call)
            }
        }

        override fun connection(): Connection? = null
        override fun call(): Call = call
        override fun connectTimeoutMillis(): Int = 0
        override fun withConnectTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun readTimeoutMillis(): Int = 0
        override fun withReadTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun writeTimeoutMillis(): Int = 0
        override fun withWriteTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this

        // New abstract members in OkHttp 5.x — unused by RetryInterceptor.
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

    // Fast interceptor for tests so retries don't actually sleep noticeably.
    private val interceptor = RetryInterceptor(maxRetries = 2, initialDelayMs = 1)

    private fun request(method: String) = Request.Builder()
        .url("http://10.0.2.2:8080/test")
        .method(method, if (method == "GET") null else "".toRequestBody())
        .build()

    @Test
    fun `successful response is returned without retrying`() {
        val chain = FakeChain(request("GET"), listOf(Outcome.Http(200)))

        val response = interceptor.intercept(chain)

        assertEquals(200, response.code)
        assertEquals(1, chain.proceedCount)
    }

    @Test
    fun `4xx response is returned without retrying`() {
        val chain = FakeChain(request("GET"), listOf(Outcome.Http(404)))

        val response = interceptor.intercept(chain)

        assertEquals(404, response.code)
        assertEquals(1, chain.proceedCount)
    }

    @Test
    fun `5xx GET is retried until success`() {
        val chain = FakeChain(
            request("GET"),
            listOf(Outcome.Http(503), Outcome.Http(200))
        )

        val response = interceptor.intercept(chain)

        assertEquals(200, response.code)
        assertEquals(2, chain.proceedCount)
        // The discarded 503 must have been closed before retrying
        assertTrue(chain.issuedBodies[0].closed)
        assertFalse(chain.issuedBodies[1].closed)
    }

    @Test
    fun `5xx GET exhausts maxRetries then returns last response`() {
        val chain = FakeChain(
            request("GET"),
            listOf(Outcome.Http(500), Outcome.Http(502), Outcome.Http(503))
        )

        val response = interceptor.intercept(chain)

        assertEquals(503, response.code)
        // 1 initial attempt + maxRetries(2) retries
        assertEquals(3, chain.proceedCount)
        assertTrue(chain.issuedBodies[0].closed)
        assertTrue(chain.issuedBodies[1].closed)
        assertFalse(chain.issuedBodies[2].closed)
    }

    @Test
    fun `5xx non-GET is never retried`() {
        val chain = FakeChain(request("POST"), listOf(Outcome.Http(500)))

        val response = interceptor.intercept(chain)

        assertEquals(500, response.code)
        assertEquals(1, chain.proceedCount)
    }

    @Test
    fun `IOException is retried until success`() {
        val chain = FakeChain(
            request("GET"),
            listOf(Outcome.Failure(IOException("connection reset")), Outcome.Http(200))
        )

        val response = interceptor.intercept(chain)

        assertEquals(200, response.code)
        assertEquals(2, chain.proceedCount)
    }

    @Test
    fun `IOException exhausting retries is rethrown`() {
        val boom = IOException("still down")
        val chain = FakeChain(
            request("GET"),
            listOf(
                Outcome.Failure(IOException("down 1")),
                Outcome.Failure(IOException("down 2")),
                Outcome.Failure(boom)
            )
        )

        try {
            interceptor.intercept(chain)
            fail("expected IOException")
        } catch (e: IOException) {
            assertSame(boom, e)
        }
        assertEquals(3, chain.proceedCount)
    }

    @Test
    fun `cancelled call is not retried after IOException`() {
        val boom = IOException("connection reset")
        val chain = FakeChain(
            request("GET"),
            listOf(Outcome.Failure(boom), Outcome.Http(200)),
            afterProceed = { _, call -> call.cancel() }
        )

        try {
            interceptor.intercept(chain)
            fail("expected IOException")
        } catch (e: IOException) {
            assertSame(boom, e)
        }
        // Cancellation short-circuits before the second proceed
        assertEquals(1, chain.proceedCount)
    }

    @Test
    fun `cancelled call is not retried after 5xx response`() {
        val chain = FakeChain(
            request("GET"),
            listOf(Outcome.Http(503), Outcome.Http(200)),
            afterProceed = { _, call -> call.cancel() }
        )

        try {
            interceptor.intercept(chain)
            fail("expected IOException")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("cancelled"))
        }
        assertEquals(1, chain.proceedCount)
        // The abandoned 503 must still have been closed
        assertTrue(chain.issuedBodies[0].closed)
    }
}

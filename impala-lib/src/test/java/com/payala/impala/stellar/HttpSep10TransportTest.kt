package com.payala.impala.stellar

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress

/** HttpSep10Transport against a JDK HttpServer on 127.0.0.1 (a local host, so http is allowed). */
class HttpSep10TransportTest {
    private val server = HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0).also { it.start() }
    private val base = "http://127.0.0.1:${server.address.port}"
    private val requests = mutableListOf<String>()

    @After
    fun stop() = server.stop(0)

    private fun route(path: String, status: Int = 200, body: () -> ByteArray, headers: Map<String, String> = emptyMap()) {
        server.createContext(path) { ex: HttpExchange ->
            val reqBody = ex.requestBody.readBytes().toString(Charsets.UTF_8)
            synchronized(requests) {
                requests += "${ex.requestMethod} ${ex.requestURI} ${ex.requestHeaders.getFirst("Content-Type") ?: "-"} $reqBody"
            }
            headers.forEach { (k, v) -> ex.responseHeaders.add(k, v) }
            val b = body()
            ex.sendResponseHeaders(status, if (b.isEmpty()) -1 else b.size.toLong())
            if (b.isNotEmpty()) ex.responseBody.use { it.write(b) }
            ex.close()
        }
    }

    @Test
    fun `GET toml, GET challenge with encoded query, POST JSON`() {
        route("/.well-known/stellar.toml", body = { "SIGNING_KEY = \"G\"\n".toByteArray() })
        route("/auth", body = { "{\"transaction\":\"x\"}".toByteArray() })
        val t = HttpSep10Transport()
        assertEquals("SIGNING_KEY = \"G\"\n", t.fetchToml("127.0.0.1:${server.address.port}"))
        assertEquals("{\"transaction\":\"x\"}", t.getChallenge("$base/auth", "GABC", "a b.example.com"))
        assertEquals("{\"transaction\":\"x\"}", t.postChallenge("$base/auth", "AA+/\"=="))
        assertEquals(
            listOf(
                "GET /.well-known/stellar.toml - ",
                "GET /auth?account=GABC&home_domain=a+b.example.com - ",
                "POST /auth application/json {\"transaction\":\"AA+/\\\"==\"}",
            ),
            requests
        )
    }

    @Test
    fun `non-2xx answers are Sep10HttpException with a printable excerpt`() {
        route("/auth", status = 401, body = { ("{\"error\":\"no\"}\n\u0001" + "x".repeat(500)).toByteArray() })
        val e = assertThrows(Sep10HttpException::class.java) { HttpSep10Transport().postChallenge("$base/auth", "AAAA") }
        assertEquals(401, e.status)
        assertEquals(Sep10HttpException.EXCERPT_LENGTH, e.bodyExcerpt.length)
        assertTrue(e.bodyExcerpt.startsWith("{\"error\":\"no\"}  x"))
        route("/gone", status = 503, body = { ByteArray(0) })
        assertEquals(503, assertThrows(Sep10HttpException::class.java) { HttpSep10Transport().getChallenge("$base/gone", "G", "d") }.status)
    }

    @Test
    fun `redirects are not followed`() {
        route("/auth", status = 302, body = { ByteArray(0) }, headers = mapOf("Location" to "$base/elsewhere"))
        route("/elsewhere", body = { "{}".toByteArray() })
        assertEquals(302, assertThrows(Sep10HttpException::class.java) { HttpSep10Transport().getChallenge("$base/auth", "G", "d") }.status)
        assertTrue(requests.none { it.contains("/elsewhere") })
    }

    @Test
    fun `responses above the cap are refused, declared or streamed`() {
        route("/big", body = { ByteArray(20_000) { 'x'.code.toByte() } })
        assertThrows(IOException::class.java) { HttpSep10Transport().getChallenge("$base/big", "G", "d") }
        // chunked (no Content-Length): the streaming cap applies
        server.createContext("/chunked") { ex ->
            ex.sendResponseHeaders(200, 0)
            ex.responseBody.use { out -> repeat(10) { out.write(ByteArray(4000) { 'y'.code.toByte() }) } }
            ex.close()
        }
        val e = assertThrows(IOException::class.java) { HttpSep10Transport().getChallenge("$base/chunked", "G", "d") }
        assertTrue(e.message!!.contains("cap"))
        // the toml cap is its own, larger one
        route("/.well-known/stellar.toml", body = { ByteArray(StellarToml.MAX_LENGTH + 1) { '#'.code.toByte() } })
        assertThrows(IOException::class.java) { HttpSep10Transport().fetchToml("127.0.0.1:${server.address.port}") }
        assertEquals(1000, HttpSep10Transport(maxTomlBytes = 200_000).let {
            server.removeContext("/.well-known/stellar.toml")
            route("/.well-known/stellar.toml", body = { ByteArray(1000) { '#'.code.toByte() } })
            it.fetchToml("127.0.0.1:${server.address.port}").length
        })
    }

    @Test
    fun `plain http to a public host is refused before any connection`() {
        val t = HttpSep10Transport()
        assertThrows(IllegalArgumentException::class.java) { t.getChallenge("http://auth.example.com/auth", "G", "d") }
        assertThrows(IllegalArgumentException::class.java) { t.postChallenge("http://auth.example.com/auth", "AAAA") }
        assertThrows(IllegalArgumentException::class.java) { t.getChallenge("https://auth.example.com/auth?x=1", "G", "d") }
        assertThrows(IllegalArgumentException::class.java) { t.fetchToml("https://auth.example.com") }
        assertEquals("https://auth.example.com/.well-known/stellar.toml", Sep10Urls.tomlUrl("auth.example.com"))
        assertEquals("http://10.0.2.2:8080/.well-known/stellar.toml", Sep10Urls.tomlUrl("10.0.2.2:8080"))
        assertEquals("http://localhost/.well-known/stellar.toml", Sep10Urls.tomlUrl("localhost"))
        assertTrue(requests.isEmpty())
    }
}

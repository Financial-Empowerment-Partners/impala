package com.payala.impala.demo.lab

import com.payala.impala.demo.ui.lab.BridgeProbe
import com.payala.impala.demo.ui.lab.IssuerFacts
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.UnknownServiceException
import javax.net.ssl.SSLHandshakeException

/**
 * [BridgeProbe] is pure classification over canned responses: no request
 * leaves the JVM (a short-circuiting interceptor answers every call).
 */
class BridgeProbeTest {
    private var now = 0L

    private fun probe(client: OkHttpClient, expected: String = "testnet") =
        BridgeProbe("http://10.0.2.2:8080/", expected, client, clock = { now }, wallClock = { 1_762_594_867_123L })

    private fun failing(e: IOException) = OkHttpClient.Builder().addInterceptor(Interceptor { throw e }).build()

    @Test
    fun `a testnet build on a pubnet bridge raises the network mismatch`() {
        val result = probe(CannedBridge.healthy(network = "pubnet").client).tryRun()!!
        assertTrue(result.networkMismatch)
        assertEquals("pubnet", result.stellarNetwork)
        assertEquals("testnet", result.expectedNetwork)
        assertTrue(result.health.ok)
        assertEquals("healthy", result.healthStatus)
        assertEquals("0.9.1", result.bridgeVersion)
        assertEquals("041", result.schemaVersion)
    }

    @Test
    fun `the same network raises nothing, and an absent network field is not a mismatch`() {
        assertFalse(probe(CannedBridge.healthy(network = "testnet").client).tryRun()!!.networkMismatch)
        assertFalse(probe(CannedBridge.healthy(network = "TESTNET").client).tryRun()!!.networkMismatch)
        val noField = CannedBridge(mapOf("/health" to (200 to """{"status":"healthy"}""")))
        assertFalse(probe(noField.client).tryRun()!!.networkMismatch)
    }

    @Test
    fun `the probe is unauthenticated and asks exactly the three public endpoints`() {
        val bridge = CannedBridge.healthy()
        probe(bridge.client).tryRun()
        assertEquals(listOf("/health", "/version", "/card-issuer"), bridge.requests.map { it.url.encodedPath })
        assertTrue(bridge.requests.all { it.method == "GET" && it.header("Authorization") == null && it.header("Cookie") == null })
    }

    @Test
    fun `429 is RATE_LIMITED and other statuses are HTTP_code`() {
        val bridge = CannedBridge(mapOf("/health" to (429 to "{}"), "/version" to (503 to "{}")))
        val r = probe(bridge.client).tryRun()!!
        assertEquals("RATE_LIMITED", r.health.failure)
        assertEquals(429, r.health.httpCode)
        assertEquals("HTTP_503", r.version.failure)
        assertEquals("HTTP_404", r.issuer.failure)
        assertNull(r.stellarNetwork)
    }

    @Test
    fun `transport failures are classified`() {
        assertEquals("DNS", probe(failing(UnknownHostException("bridge.example"))).tryRun()!!.health.failure)
        assertEquals("CONNECT", probe(failing(ConnectException("refused"))).tryRun()!!.health.failure)
        assertEquals("TIMEOUT", probe(failing(SocketTimeoutException("read timed out"))).tryRun()!!.health.failure)
        assertEquals("TIMEOUT", probe(failing(InterruptedIOException("timeout"))).tryRun()!!.health.failure)
        assertEquals("TLS", probe(failing(SSLHandshakeException("bad cert"))).tryRun()!!.health.failure)
        assertEquals(
            "CLEARTEXT_BLOCKED",
            probe(failing(UnknownServiceException("CLEARTEXT communication to 10.0.2.2 not permitted by network security policy"))).tryRun()!!.health.failure
        )
        assertEquals("DNS", BridgeProbe.classify(IOException("wrapped", UnknownHostException("x"))))
    }

    @Test
    fun `card-issuer maps to the Doctor's issuer facts`() {
        val known = probe(CannedBridge.healthy(issuerJson = CannedBridge.issuer("04" + "ab".repeat(64), "a0".repeat(16))).client).tryRun()!!
        val facts = known.issuerFacts as IssuerFacts.Known
        assertEquals("a0".repeat(16), facts.programIdHex)
        assertEquals("04" + "ab".repeat(64), facts.publicKeyHex)
        assertEquals(true, known.issuerConfigured)
        assertEquals("aa:bb:cc", known.issuerFingerprint)

        assertTrue(probe(CannedBridge.healthy(issuerJson = CannedBridge.UNCONFIGURED).client).tryRun()!!.issuerFacts is IssuerFacts.Unconfigured)
        // An older bridge without the endpoint: 404 counts as unconfigured.
        val missing = CannedBridge(mapOf("/health" to (200 to "{}")))
        assertTrue(probe(missing.client).tryRun()!!.issuerFacts is IssuerFacts.Unconfigured)
        val broken = CannedBridge(mapOf("/card-issuer" to (500 to "{}")))
        val unreachable = probe(broken.client).tryRun()!!.issuerFacts as IssuerFacts.Unreachable
        assertEquals("HTTP_500", unreachable.reason)
        val down = probe(failing(ConnectException("refused"))).tryRun()!!.issuerFacts as IssuerFacts.Unreachable
        assertEquals("CONNECT", down.reason)
    }

    @Test
    fun `a configured flag without a key is not configured`() {
        val half = CannedBridge.healthy(issuerJson = """{"configured":true,"program_id_hex":"aa"}""")
        assertEquals(false, probe(half.client).tryRun()!!.issuerConfigured)
    }

    @Test
    fun `a 10 s cooldown separates runs`() {
        val bridge = CannedBridge.healthy()
        val p = probe(bridge.client)
        assertEquals(0L, p.cooldownRemainingMs())
        assertNotNull(p.tryRun())
        now = 4_000L
        assertNull("inside the cooldown", p.tryRun())
        assertEquals(6_000L, p.cooldownRemainingMs())
        now = 10_000L
        assertNotNull(p.tryRun())
        assertEquals(6, bridge.requests.size)
    }

    @Test
    fun `a base URL without a trailing slash still resolves`() {
        val bridge = CannedBridge.healthy()
        BridgeProbe("http://10.0.2.2:8080", "testnet", bridge.client, clock = { 0L }).tryRun()
        assertEquals("http://10.0.2.2:8080/health", bridge.requests.first().url.toString())
    }
}

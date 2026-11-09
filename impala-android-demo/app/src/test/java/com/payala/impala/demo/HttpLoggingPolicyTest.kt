package com.payala.impala.demo

import com.payala.impala.demo.api.ApiClient
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.logging.HttpLoggingInterceptor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Pins the HTTP logging policy (ApiClient.buildLoggingInterceptor): headers
 * only, and only in debug builds; credential and session headers and account
 * ids in URLs never reach a log line; bodies (passwords, refresh tokens, card
 * signatures, challenges) are never logged at any level.
 */
class HttpLoggingPolicyTest {

    private val bearer = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXRlbXBvcmFs.sig-value-123"
    private val cookie = "__Host-session=cookie-secret-456"
    private val accountId = "GACCOUNTIDSHOULDNEVERBELOGGED7777777777777777777777777777"

    /** Runs one request through the interceptor with a canned response (no network) and returns every log line. */
    private fun logLines(debug: Boolean): List<String> {
        val lines = ArrayList<String>()
        val logging = ApiClient.buildLoggingInterceptor(debug) { lines += it }
        val canned = Interceptor { chain ->
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .header("Set-Cookie", "$cookie; Path=/; Secure")
                .header("Content-Type", "application/json")
                .body("""{"refresh_token":"refresh-secret-789"}""".toResponseBody("application/json".toMediaType()))
                .build()
        }
        val client = OkHttpClient.Builder().addInterceptor(logging).addInterceptor(canned).build()
        val request = Request.Builder()
            .url("https://bridge.example.test/notify/subscriptions?account_id=$accountId&stellar_account_id=$accountId&limit=5")
            .header("Authorization", "Bearer $bearer")
            .header("Proxy-Authorization", "Basic proxy-secret-000")
            .header("Cookie", cookie)
            .post("""{"password":"hunter2-password"}""".toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(request).execute().use { it.body.string() }
        return lines
    }

    @Test
    fun `debug logs headers only, with credentials, cookies and account ids redacted`() {
        val logging = ApiClient.buildLoggingInterceptor(debug = true)
        assertEquals(HttpLoggingInterceptor.Level.HEADERS, logging.level)

        val lines = logLines(debug = true)
        val text = lines.joinToString("\n")
        assertTrue("headers are logged in debug builds", lines.any { it.startsWith("Authorization:") })
        assertTrue("non-sensitive query parameters stay readable", "limit=5" in text)
        for (secret in listOf(bearer, "sig-value-123", "proxy-secret-000", "cookie-secret-456", accountId,
                "hunter2-password", "refresh-secret-789")) {
            assertFalse("a log line contains '$secret':\n$text", secret in text)
        }
        for (header in ApiClient.REDACTED_HEADERS) {
            assertTrue("$header is listed but its line is missing", lines.any { it.startsWith("$header:") })
        }
    }

    @Test
    fun `release logs nothing`() {
        assertEquals(HttpLoggingInterceptor.Level.NONE, ApiClient.buildLoggingInterceptor(debug = false).level)
        assertEquals(emptyList<String>(), logLines(debug = false))
    }

    @Test
    fun `the redaction lists cover the session and account identifiers`() {
        assertEquals(listOf("Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"), ApiClient.REDACTED_HEADERS)
        assertEquals(listOf("account_id", "stellar_account_id"), ApiClient.REDACTED_QUERY_PARAMS)
    }

    @Test
    fun `no app source ever selects body logging`() {
        val root = File("src/main")
        assertTrue("run from the app module directory", root.isDirectory)
        val offenders = root.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java") }
            .filter { f -> Regex("""Level\s*\.\s*BODY\b""").containsMatchIn(f.readText()) }
            .map { it.path }.toList()
        assertEquals("HttpLoggingInterceptor.Level.BODY would log passwords, tokens and card signatures",
            emptyList<String>(), offenders)
    }
}

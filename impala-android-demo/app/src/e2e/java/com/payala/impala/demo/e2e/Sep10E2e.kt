package com.payala.impala.demo.e2e

import com.payala.impala.stellar.HttpSep10Transport
import com.payala.impala.stellar.Sep10Client
import com.payala.impala.stellar.Sep10HttpException
import com.payala.impala.stellar.Sep10Transport
import org.json.JSONObject
import org.junit.Assume.assumeTrue
import retrofit2.HttpException
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * SEP-10 for the T1 lane: where the bridge's SEP-10 lives
 * (IMPALA_E2E_SEP10_HOME_DOMAIN), which third-party servers to sign in to
 * (IMPALA_E2E_SEP10_THIRD_PARTY) and where to leave a machine-readable report
 * (IMPALA_E2E_REPORT_DIR). Without the variable a test needs, it is skipped
 * with that reason.
 */
object Sep10E2e {
    /** The network every server of this lane must be on; a pubnet server is refused, never signed in to. */
    const val TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"

    /** The bridge's SEP-10 home domain, `host[:port]` (the authority of its SEP10_WEB_AUTH_ENDPOINT). */
    val homeDomain: String? = System.getenv("IMPALA_E2E_SEP10_HOME_DOMAIN")?.trim()?.takeIf { it.isNotEmpty() }

    fun requireHomeDomain(): String {
        assumeTrue(
            "IMPALA_E2E_SEP10_HOME_DOMAIN is not set — the SEP-10 e2e tests need a bridge with SEP10_ENABLED=true (see app/src/e2e/README.md)",
            homeDomain != null
        )
        return homeDomain!!
    }

    /** Third-party SEP-10 home domains (testnet), in the order given. */
    val thirdParties: List<String> =
        (System.getenv("IMPALA_E2E_SEP10_THIRD_PARTY") ?: "").split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }

    /**
     * A SEP-10 client for the bridge of this run.
     *
     * The bridge names itself by its home domain (in a demo stack
     * `10.0.2.2:8080`, the Android emulator's name for the host), and this
     * JVM reaches the same listener at IMPALA_E2E_BRIDGE_URL. The transport
     * connects to the reachable address; every name the protocol signs or
     * compares (home domain, web-auth domain, `WEB_AUTH_ENDPOINT`) stays the
     * bridge's own. It is what a hosts-file entry would do.
     */
    fun bridgeClient(): Sep10Client {
        val name = requireHomeDomain()
        val reachable = URI(E2e.requireBridge()).let { uri -> if (uri.port >= 0) "${uri.host}:${uri.port}" else uri.host }
        val http = HttpSep10Transport(TIMEOUT_MS, TIMEOUT_MS)
        val transport: Sep10Transport = if (name == reachable) http else AliasedTransport(http, name, reachable)
        return Sep10Client(name, TESTNET_PASSPHRASE, transport)
    }

    /** A SEP-10 client for a third-party server, over the plain transport (https; no alias). */
    fun thirdPartyClient(domain: String): Sep10Client =
        Sep10Client(domain, TESTNET_PASSPHRASE, HttpSep10Transport(TIMEOUT_MS, TIMEOUT_MS))

    private const val TIMEOUT_MS = 20_000

    /** Sends every request for [name] to [reachable] instead; nothing else changes. */
    class AliasedTransport(
        private val inner: Sep10Transport,
        private val name: String,
        private val reachable: String
    ) : Sep10Transport {
        private fun aliased(url: String): String {
            val uri = URI(url)
            val authority = if (uri.port >= 0) "${uri.host}:${uri.port}" else uri.host
            return if (authority == name) url.replaceFirst("://$name", "://$reachable") else url
        }

        override fun fetchToml(homeDomain: String): String = inner.fetchToml(if (homeDomain == name) reachable else homeDomain)

        override fun getChallenge(webAuthEndpoint: String, account: String, homeDomain: String): String =
            inner.getChallenge(aliased(webAuthEndpoint), account, homeDomain)

        override fun postChallenge(webAuthEndpoint: String, transaction: String): String =
            inner.postChallenge(aliased(webAuthEndpoint), transaction)
    }

    /**
     * Runs a sign-in step, waiting out the bridge's per-source pre-auth
     * budget (30 requests / 60 s, shared by the challenge and token routes of
     * both card mechanisms) instead of failing. Never use it where a 429 is
     * the assertion.
     */
    fun <T> paced(block: () -> T): T {
        var attempt = 0
        while (true) {
            try {
                return block()
            } catch (e: Sep10HttpException) {
                if (e.status != 429 || attempt++ >= 8) throw e
            } catch (e: HttpException) {
                if (e.code() != 429 || attempt++ >= 8) throw e
            }
            println("e2e: pre-auth budget exhausted; waiting 15 s")
            Thread.sleep(15_000)
        }
    }

    /** The claims of a JWT, unverified (its issuer is the verifier), or null when [token] is not a JWT. */
    fun jwtClaims(token: String): JSONObject? = try {
        val parts = token.split(".")
        if (parts.size != 3) null else JSONObject(String(java.util.Base64.getUrlDecoder().decode(parts[1])))
    } catch (_: Exception) {
        null
    }

    /** The `token` of a SEP-10 token response. */
    fun tokenOf(tokenJson: String): String = JSONObject(tokenJson).getString("token")

    /** `KEY = "value"` from a stellar.toml text, or null. */
    fun tomlValue(toml: String, key: String): String? {
        // Top-level keys only: a key of the same name inside a table ([[CURRENCIES]], …) is not this one.
        val top = toml.lineSequence().takeWhile { !it.trimStart().startsWith("[") }.joinToString("\n")
        return Regex("""(?m)^\s*${Regex.escape(key)}\s*=\s*(?:"([^"]*)"|'([^']*)')\s*(#.*)?$""").find(top)
            ?.let { m -> m.groups[1]?.value ?: m.groups[2]?.value }
    }

    /** A GET that returns the status and at most 2000 characters of the body; [bearer] is sent when given. */
    fun httpGet(url: String, bearer: String? = null): Pair<Int, String> {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Accept", "application/json")
            if (bearer != null) conn.setRequestProperty("Authorization", "Bearer $bearer")
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.use { String(it.readNBytes(8_192)) } ?: ""
            return status to body.take(2_000)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Writes [name] into IMPALA_E2E_REPORT_DIR when the run asked for a
     * report. Reports carry public values and claims only: never a token.
     */
    fun writeReport(name: String, json: JSONObject) {
        val dir = System.getenv("IMPALA_E2E_REPORT_DIR")?.takeIf { it.isNotBlank() } ?: return
        File(dir).mkdirs()
        File(dir, name).writeText(json.toString(2) + "\n")
    }
}

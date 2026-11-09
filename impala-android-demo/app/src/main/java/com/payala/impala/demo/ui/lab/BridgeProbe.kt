package com.payala.impala.demo.ui.lab

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.UnknownServiceException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException

/**
 * The Device tab's bridge probe: three **unauthenticated** GETs (`/health`,
 * `/version`, `/card-issuer`) on a client of its own, with no session
 * interceptor, so it works pre-login and never sends a credential. Each call
 * reports its latency and, on failure, a class (`DNS`, `CONNECT`, `TLS`,
 * `CLEARTEXT_BLOCKED`, `TIMEOUT`, `RATE_LIMITED`, `HTTP_<code>`).
 *
 * The probe is rate-limited to one run per [COOLDOWN_MS]: [tryRun] returns
 * null inside the window. [Result.networkMismatch] raises the Stellar network
 * alarm: an APK built for one network talking to a bridge on another is a
 * money hazard nothing else detects.
 *
 * Blocking; call it off the main thread.
 */
class BridgeProbe(
    baseUrl: String,
    private val expectedNetwork: String,
    private val client: OkHttpClient = defaultClient(),
    private val clock: () -> Long = { System.nanoTime() / 1_000_000L },
    private val wallClock: () -> Long = System::currentTimeMillis
) {
    private val base = baseUrl.trim().let { if (it.endsWith("/")) it else "$it/" }

    /** One GET: [failure] is null when the bridge answered 2xx. */
    class Call(val path: String, val httpCode: Int?, val failure: String?, val latencyMs: Long) {
        val ok: Boolean get() = failure == null
        override fun toString(): String = "$path ${failure ?: "OK"} ${latencyMs}ms"
    }

    /** A probe run. Every field comes from a public, unauthenticated endpoint. */
    class Result(
        val atEpochMs: Long,
        val expectedNetwork: String,
        val health: Call,
        val version: Call,
        val issuer: Call,
        val healthStatus: String?,
        val stellarNetwork: String?,
        val bridgeVersion: String?,
        val schemaVersion: String?,
        /** null when `/card-issuer` gave no usable answer. */
        val issuerConfigured: Boolean?,
        val programIdHex: String?,
        val issuerFingerprint: String?,
        val issuerPublicKeyHex: String?
    ) {
        /** The bridge reports a Stellar network other than the one this build was made for. */
        val networkMismatch: Boolean
            get() = stellarNetwork != null && !stellarNetwork.equals(expectedNetwork, ignoreCase = true)

        /** What the Doctor needs from `/card-issuer`. A missing endpoint (404) counts as unconfigured. */
        val issuerFacts: IssuerFacts
            get() = when {
                issuerConfigured == true -> IssuerFacts.Known(programIdHex, issuerPublicKeyHex)
                issuerConfigured == false || issuer.httpCode == 404 -> IssuerFacts.Unconfigured
                else -> IssuerFacts.Unreachable(issuer.failure ?: "PARSE")
            }
    }

    @Volatile
    private var lastRunAt: Long? = null

    /** Milliseconds until [tryRun] may probe again (0 when it may now). */
    fun cooldownRemainingMs(): Long {
        val last = lastRunAt ?: return 0L
        return (COOLDOWN_MS - (clock() - last)).coerceAtLeast(0L)
    }

    /** Runs the probe, or returns null while the cooldown from the previous run lasts. */
    @Synchronized
    fun tryRun(): Result? {
        if (cooldownRemainingMs() > 0L) return null
        lastRunAt = clock()
        return run()
    }

    private fun run(): Result {
        val (health, healthJson) = get("health")
        val (version, versionJson) = get("version")
        val (issuer, issuerJson) = get("card-issuer")
        val configured: Boolean? = issuerJson?.let { j ->
            // The bridge's own rule (CardIssuerResponse.isConfigured): a key and a redemption identity.
            val flag = j.bool("configured")
            if (flag == false) false else j.str("public_key_hex") != null && j.str("redemption_uuid") != null
        }
        return Result(
            atEpochMs = wallClock(),
            expectedNetwork = expectedNetwork,
            health = health,
            version = version,
            issuer = issuer,
            healthStatus = healthJson?.str("status"),
            stellarNetwork = healthJson?.str("stellar_network"),
            bridgeVersion = versionJson?.str("version"),
            schemaVersion = versionJson?.str("schema_version"),
            issuerConfigured = configured,
            programIdHex = issuerJson?.str("program_id_hex"),
            issuerFingerprint = issuerJson?.str("fingerprint"),
            issuerPublicKeyHex = issuerJson?.str("public_key_hex")
        )
    }

    private fun get(path: String): Pair<Call, JsonObject?> {
        val url = "$base$path".toHttpUrlOrNull() ?: return Call("/$path", null, "CONNECT", 0L) to null
        val request = Request.Builder().url(url).get().header("Accept", "application/json").build()
        val start = clock()
        return try {
            client.newCall(request).execute().use { response ->
                val elapsed = clock() - start
                val code = response.code
                val body = try {
                    response.body.string()
                } catch (_: IOException) {
                    ""
                }
                val failure = when {
                    code == 429 -> "RATE_LIMITED"
                    code !in 200..299 -> "HTTP_$code"
                    else -> null
                }
                Call("/$path", code, failure, elapsed) to if (failure == null) parse(body) else null
            }
        } catch (e: IOException) {
            Call("/$path", null, classify(e), clock() - start) to null
        }
    }

    private fun parse(body: String): JsonObject? = try {
        JsonParser.parseString(body).takeIf { it.isJsonObject }?.asJsonObject
    } catch (_: RuntimeException) {
        null
    }

    companion object {
        const val COOLDOWN_MS = 10_000L

        /** A plain client: no auth, no logging, no retry, bounded time per call. */
        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .callTimeout(5, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .followRedirects(false)
            .build()

        /** The failure class of a transport exception. */
        fun classify(e: IOException): String {
            val chain = generateSequence<Throwable>(e) { it.cause }.toList()
            return when {
                chain.any { it is UnknownHostException } -> "DNS"
                chain.any { it is SSLException } -> "TLS"
                // Network-security config refused http:// to this host.
                chain.any { it is UnknownServiceException && it.message.orEmpty().contains("CLEARTEXT", ignoreCase = true) } -> "CLEARTEXT_BLOCKED"
                chain.any { it is SocketTimeoutException } -> "TIMEOUT"
                chain.any { it is ConnectException || it is NoRouteToHostException } -> "CONNECT"
                // callTimeout surfaces as a bare InterruptedIOException("timeout").
                chain.any { it is InterruptedIOException } -> "TIMEOUT"
                else -> "CONNECT"
            }
        }

        private fun JsonObject.str(key: String): String? =
            get(key)?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() }

        private fun JsonObject.bool(key: String): Boolean? =
            get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
    }
}

package com.payala.impala.demo.e2e

import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.tools.issue.CertificateSource
import com.impala.tools.issue.HttpBridgeClient
import com.impala.tools.issue.IssuanceCeremony
import com.impala.tools.issue.IssuanceConfig
import com.impala.tools.issue.IssuanceRecord
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.model.AuthenticateRequest
import com.payala.impala.demo.model.CreateAccountRequest
import com.payala.impala.demo.model.TokenRequest
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assume.assumeTrue
import org.json.JSONObject
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The T1 lane's environment: a LIVE bridge (IMPALA_E2E_BRIDGE_URL) plus how
 * to act as its operator (a bearer with ManageKeys from
 * IMPALA_E2E_OPERATOR_TOKEN_FILE, or an ADMIN_ACCOUNT_IDS account given by
 * IMPALA_E2E_OPERATOR_ACCOUNT + IMPALA_E2E_OPERATOR_PASSWORD_FILE).
 * Without the URL every test is skipped with that reason.
 */
object E2e {
    val bridgeUrl: String? = System.getenv("IMPALA_E2E_BRIDGE_URL")?.trimEnd('/')?.takeIf { it.isNotBlank() }

    fun requireBridge(): String {
        assumeTrue("IMPALA_E2E_BRIDGE_URL is not set — the T1 e2e lane needs a live bridge (see app/src/e2e/README.md)", bridgeUrl != null)
        return bridgeUrl!!
    }

    val slow: Boolean get() = System.getenv("IMPALA_E2E_SLOW") == "1"

    private fun readFile(env: String): String? = System.getenv(env)?.let { File(it).readText().trim() }?.takeIf { it.isNotEmpty() }

    val holderPassword: String by lazy { readFile("IMPALA_E2E_HOLDER_PASSWORD_FILE") ?: "e2e-${UUID.randomUUID()}" }

    /** A Retrofit service sending [bearer] on every request (null = anonymous). */
    fun api(bearer: String? = null): BridgeApiService {
        val client = OkHttpClient.Builder()
            .callTimeout(60, TimeUnit.SECONDS)
            .addInterceptor { chain ->
                val req = chain.request().newBuilder()
                if (bearer != null) req.header("Authorization", "Bearer $bearer")
                chain.proceed(req.build())
            }
            .build()
        return Retrofit.Builder().baseUrl(requireBridge() + "/").client(client)
            .addConverterFactory(GsonConverterFactory.create()).build()
            .create(BridgeApiService::class.java)
    }

    /**
     * Runs a pre-auth call, waiting out the bridge's per-source budget (30
     * requests / 60 s shared by /authenticate, /token, /auth/card*) instead of
     * failing. Never use it where a 429 is the assertion (lockout).
     */
    fun <T> preAuth(block: () -> T): T {
        var attempt = 0
        while (true) {
            try {
                return block()
            } catch (e: HttpException) {
                if (e.code() != 429 || attempt++ >= 8) throw e
                val wait = e.response()?.headers()?.get("Retry-After")?.toLongOrNull() ?: 10L
                println("e2e: pre-auth budget exhausted; waiting ${wait}s")
                Thread.sleep(wait.coerceIn(1, 60) * 1000)
            }
        }
    }

    /** Password login → (refresh, temporal). */
    fun login(accountId: String, password: String): Pair<String, String> = preAuth { loginOnce(accountId, password) }

    private fun loginOnce(accountId: String, password: String): Pair<String, String> = runBlocking {
        val anon = api()
        check(anon.authenticate(AuthenticateRequest(accountId, password)).success) { "authenticate failed for $accountId" }
        val refresh = anon.token(TokenRequest(username = accountId, password = password)).refresh_token
            ?: error("no refresh token for $accountId")
        val temporal = anon.token(TokenRequest(refresh_token = refresh))
        (temporal.refresh_token ?: refresh) to (temporal.temporal_token ?: error("no temporal token for $accountId"))
    }

    /**
     * A fresh holder: UUID payala id, an account row created by the operator
     * (an unauthenticated caller cannot create one), then password credentials
     * registered by the holder (`ALLOW_OPEN_REGISTRATION=true` on the e2e
     * bridge — never on a real deployment). Returns (accountId, temporal bearer).
     */
    fun newHolder(): Pair<String, String> {
        val operator = operatorBearer
            ?: throw AssertionError("the e2e lane needs an operator (IMPALA_E2E_OPERATOR_ACCOUNT + _PASSWORD_FILE, or _TOKEN_FILE) to create holder accounts")
        val id = UUID.randomUUID().toString()
        runBlocking {
            val created = api(operator).createAccount(CreateAccountRequest(StrKey.randomAccountId(), id, "E2E", last_name = "Holder"))
            check(created.success) { "create account failed: ${created.message}" }
        }
        val (_, bearer) = login(id, holderPassword)
        return id to bearer
    }

    /** Holders shared across tests (each test still issues its own cards). */
    val holder: Pair<String, String> by lazy { newHolder() }
    val otherHolder: Pair<String, String> by lazy { newHolder() }

    /** The operator's bearer (ManageKeys), or null when the run has no operator. */
    val operatorBearer: String? by lazy {
        readFile("IMPALA_E2E_OPERATOR_TOKEN_FILE") ?: run {
            val account = System.getenv("IMPALA_E2E_OPERATOR_ACCOUNT") ?: return@run null
            val password = readFile("IMPALA_E2E_OPERATOR_PASSWORD_FILE") ?: return@run null
            login(account, password).second
        }
    }

    /** Ensures the bridge has a card issuer key (generating one as the operator when absent). */
    fun ensureIssuer(): Boolean {
        val client = HttpBridgeClient(requireBridge())
        if (client.cardIssuer() != null) return true
        val operator = operatorBearer ?: return false
        val http = OkHttpClient()
        val resp = http.newCall(
            Request.Builder().url(requireBridge() + "/admin/card-issuer/generate")
                .header("Authorization", "Bearer $operator")
                .post("{}".toRequestBody("application/json".toMediaType()))
                .build()
        ).execute()
        resp.use { check(it.isSuccessful) { "issuer generation failed: HTTP ${it.code} ${it.body?.string()}" } }
        return client.cardIssuer() != null
    }

    /** A fresh simulated card on the GP default keys, as a factory-installed card. */
    fun blankCard(): SimulatorBibo = SimulatorBibo(
        installParams = PersonalizationProtocol.installParams(enforce = true, keys = null, pins = null, program = null)
    )

    private val kmk = ByteArray(16).also { SecureRandom().nextBytes(it) }

    /**
     * Issues [bibo] to [accountId] with the impala-card issuance ceremony:
     * a bridge certificate when the bridge has an issuer and the run has an
     * operator (registration under [holderBearer]), else a local test issuer
     * (login-only) — registered with the bridge when [register].
     */
    fun issue(bibo: SimulatorBibo, accountId: String, holderBearer: String, register: Boolean = true, userPin: String = "2468"): IssuanceRecord {
        val operator = operatorBearer
        val source = if (operator != null && ensureIssuer() && register) {
            CertificateSource.Bridge(HttpBridgeClient(requireBridge()), holderBearer, operator, 7)
        } else {
            CertificateSource.Test(TestIssuer(), if (register) HttpBridgeClient(requireBridge()) to holderBearer else null)
        }
        return IssuanceCeremony(
            bibo,
            IssuanceConfig(accountId, "XLM", 0, kmk, null, userPin.toCharArray(), "14117298".toCharArray()),
            source,
            notice = { println("issue: $it") }
        ).run()
    }

    /** True when the bridge serves the offline lane (D-3). */
    fun offlineLaneDeployed(bearer: String): Boolean = runBlocking {
        try {
            api(bearer).offlineCard("00".repeat(16))
            true
        } catch (e: HttpException) {
            // A 404 with the bridge's JSON error envelope means the route exists
            // and the card does not; Axum's bare 404 (no body) means no route.
            e.code() != 404 || (e.response()?.errorBody()?.string()?.contains("\"error\"") == true)
        }
    }

    fun <T> offMain(block: () -> T): T {
        val ex = Executors.newSingleThreadExecutor()
        try {
            return ex.submit<T> { block() }.get(120, TimeUnit.SECONDS)
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        } finally {
            ex.shutdown()
        }
    }

    /** The JWT `sub` claim (no verification: the bridge is the verifier). */
    fun subOf(jwt: String): String {
        val payload = jwt.split(".")[1]
        return JSONObject(String(java.util.Base64.getUrlDecoder().decode(payload))).getString("sub")
    }

    fun uuidBytes(id: String): ByteArray = UuidBytes.parse(id)
}

/** Stellar strkey for random ed25519-sized public keys (the bridge checks the checksum, not the curve). */
object StrKey {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun randomAccountId(): String {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val payload = byteArrayOf((6 shl 3).toByte()) + key
        val crc = crc16(payload)
        return base32(payload + byteArrayOf((crc and 0xFF).toByte(), (crc ushr 8 and 0xFF).toByte()))
    }

    private fun crc16(data: ByteArray): Int {
        var crc = 0
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 8)
            repeat(8) { crc = if (crc and 0x8000 != 0) (crc shl 1) xor 0x1021 else crc shl 1 }
        }
        return crc and 0xFFFF
    }

    private fun base32(data: ByteArray): String {
        val out = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                out.append(ALPHABET[(buffer ushr (bits - 5)) and 0x1F])
                bits -= 5
            }
        }
        if (bits > 0) out.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        return out.toString()
    }
}

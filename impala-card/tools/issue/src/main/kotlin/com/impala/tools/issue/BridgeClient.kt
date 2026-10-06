package com.impala.tools.issue

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** A bridge refusal: HTTP status plus the `error.code` / `error.message` envelope when present. */
class BridgeException(val status: Int, val code: String?, message: String) :
    RuntimeException("bridge answered HTTP $status${code?.let { " ($it)" } ?: ""}: $message")

/** `POST /admin/cards/{card_id}/certificate` response (spec-bridge §8.2 as amended by the contract addendum §A.7). */
data class CertifyResponse(
    val cardId: String,
    val issuerVersion: Int,
    val issuerCertHex: String,
    val certMessageHex: String?,
    val issuerPublicKeyHex: String,
    val programIdHex: String?,
    val currency: String,
    val cardMinorScale: Int
)

/** Public `GET /card-issuer`. */
data class CardIssuerInfo(
    val version: Int,
    val publicKeyHex: String,
    val fingerprint: String?,
    val redemptionUuid: String?,
    val programIdHex: String
)

/** The bridge calls the ceremony makes. Bearer tokens are passed per call and never stored or printed. */
interface BridgeClient {
    /** `GET /network` → `stellar_network` ("testnet" / "pubnet"), or null when unreadable. */
    fun stellarNetwork(): String?

    /** `POST /card` under the holder's bearer token. */
    fun registerCard(holderToken: String, accountId: String, cardId: String, ecPubkeyHex: String)

    /** `POST /admin/cards/{card_id}/certificate` under the operator's bearer token (ManageKeys). */
    fun certify(operatorToken: String, cardId: String, currency: String, cardMinorScale: Int, recertify: Boolean): CertifyResponse

    /** `GET /card-issuer`, or null when the bridge answers `{configured:false}`. */
    fun cardIssuer(): CardIssuerInfo?
}

class HttpBridgeClient(baseUrl: String, private val timeout: Duration = Duration.ofSeconds(30)) : BridgeClient {
    private val base = baseUrl.trimEnd('/')
    private val http = HttpClient.newBuilder().connectTimeout(timeout).build()
    private val gson = Gson()

    init {
        require(base.startsWith("https://") || base.startsWith("http://")) { "bridge URL must be http(s)" }
    }

    override fun stellarNetwork(): String? = try {
        get("/network", null).get("stellar_network")?.asString
    } catch (_: Exception) {
        null
    }

    override fun registerCard(holderToken: String, accountId: String, cardId: String, ecPubkeyHex: String) {
        val body = JsonObject().apply {
            addProperty("account_id", accountId)
            addProperty("card_id", cardId)
            addProperty("ec_pubkey", ecPubkeyHex)
        }
        val resp = post("/card", holderToken, body)
        if (resp.get("success")?.asBoolean == false) {
            throw BridgeException(200, null, resp.get("message")?.asString ?: "card registration refused")
        }
    }

    override fun certify(operatorToken: String, cardId: String, currency: String, cardMinorScale: Int, recertify: Boolean): CertifyResponse {
        val body = JsonObject().apply {
            addProperty("currency", currency)
            addProperty("card_minor_scale", cardMinorScale)
            if (recertify) addProperty("recertify", true)
        }
        val o = post("/admin/cards/$cardId/certificate", operatorToken, body)
        return CertifyResponse(
            cardId = o.str("card_id") ?: cardId,
            issuerVersion = o.get("issuer_version")?.asInt ?: throw BridgeException(200, null, "certificate response lacks issuer_version"),
            issuerCertHex = o.str("issuer_cert_hex") ?: throw BridgeException(200, null, "certificate response lacks issuer_cert_hex"),
            certMessageHex = o.str("cert_message_hex"),
            issuerPublicKeyHex = o.str("issuer_public_key_hex") ?: throw BridgeException(200, null, "certificate response lacks issuer_public_key_hex"),
            programIdHex = o.str("program_id_hex"),
            currency = o.str("currency") ?: currency,
            cardMinorScale = o.get("card_minor_scale")?.asInt ?: cardMinorScale
        )
    }

    override fun cardIssuer(): CardIssuerInfo? {
        val o = get("/card-issuer", null)
        if (o.get("configured")?.asBoolean == false) return null
        return CardIssuerInfo(
            version = o.get("version")?.asInt ?: throw BridgeException(200, null, "card-issuer lacks version"),
            publicKeyHex = o.str("public_key_hex") ?: throw BridgeException(200, null, "card-issuer lacks public_key_hex"),
            fingerprint = o.str("fingerprint"),
            redemptionUuid = o.str("redemption_uuid"),
            programIdHex = o.str("program_id_hex") ?: throw BridgeException(200, null, "card-issuer lacks program_id_hex")
        )
    }

    private fun JsonObject.str(k: String): String? = get(k)?.takeUnless { it.isJsonNull }?.asString

    private fun get(path: String, token: String?): JsonObject =
        send(HttpRequest.newBuilder(URI.create(base + path)).GET(), token)

    private fun post(path: String, token: String?, body: JsonObject): JsonObject =
        send(
            HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body))),
            token
        )

    private fun send(builder: HttpRequest.Builder, token: String?): JsonObject {
        builder.timeout(timeout).header("Accept", "application/json")
        if (token != null) builder.header("Authorization", "Bearer $token")
        val resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        val parsed = runCatching { JsonParser.parseString(resp.body()).asJsonObject }.getOrNull()
        if (resp.statusCode() !in 200..299) {
            val err = parsed?.getAsJsonObject("error")
            throw BridgeException(
                resp.statusCode(),
                err?.get("code")?.asString,
                err?.get("message")?.asString ?: parsed?.get("message")?.asString ?: "no error body"
            )
        }
        return parsed ?: JsonObject()
    }
}

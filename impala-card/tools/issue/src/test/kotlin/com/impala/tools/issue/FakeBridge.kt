package com.impala.tools.issue

import com.google.gson.JsonParser
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.TestIssuer
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest

/**
 * A bridge that implements just the issuance endpoints with a JCA issuer:
 * `POST /card` (holder token), `POST /admin/cards/{id}/certificate` (operator
 * token, write-once unless recertify), `GET /card-issuer`, `GET /network`.
 */
class FakeBridge(
    val holderToken: String = "holder-token-7c1f",
    val operatorToken: String = "operator-token-91ab",
    val network: String = "testnet"
) : AutoCloseable {
    val issuer = TestIssuer()
    val server = MockWebServer()
    val cards = mutableMapOf<String, Pair<String, String>>() // card_id -> (account_id, ec_pubkey)
    val certified = mutableMapOf<String, String>()
    val requests = mutableListOf<RecordedRequest>()

    init {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = synchronized(this@FakeBridge) {
                requests += request
                handle(request)
            }
        }
        server.start()
    }

    val url: String get() = server.url("/").toString()

    private fun json(code: Int, body: String) = MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)
    private fun error(code: Int, c: String, m: String) = json(code, """{"error":{"code":"$c","message":"$m"}}""")

    private fun handle(r: RecordedRequest): MockResponse {
        val path = r.path ?: ""
        val auth = r.getHeader("Authorization")
        return when {
            r.method == "GET" && path == "/network" -> json(200, """{"stellar_network":"$network"}""")
            r.method == "GET" && path == "/card-issuer" -> json(
                200,
                """{"version":1,"public_key_hex":"${Hex.encode(issuer.pub65)}","fingerprint":"fp","redemption_uuid":"5f0c2b8e-3a1d-4c7e-9b2a-1d4e6f8a0b3c","program_id_hex":"${Hex.encode(issuer.programId)}"}"""
            )
            r.method == "POST" && path == "/card" -> {
                if (auth != "Bearer $holderToken") return error(401, "unauthorized", "Unauthorized")
                val o = JsonParser.parseString(r.body.readUtf8()).asJsonObject
                val cardId = o["card_id"].asString
                if (o.has("rsa_pubkey")) return error(400, "bad_request", "unexpected rsa_pubkey")
                if (cards.containsKey(cardId)) return error(500, "internal", "Database error")
                cards[cardId] = o["account_id"].asString to o["ec_pubkey"].asString
                json(200, """{"success":true,"message":"Card created successfully"}""")
            }
            r.method == "POST" && path.startsWith("/admin/cards/") && path.endsWith("/certificate") -> {
                if (auth != "Bearer $operatorToken") return error(403, "forbidden", "Forbidden")
                val cardId = path.removePrefix("/admin/cards/").removeSuffix("/certificate")
                val (account, pubHex) = cards[cardId] ?: return error(404, "not_found", "card not found")
                val o = JsonParser.parseString(r.body.readUtf8()).asJsonObject
                val recertify = o["recertify"]?.asBoolean == true
                if (certified.containsKey(cardId) && !recertify) return error(409, "already_certified", "card already certified")
                val currency = o["currency"].asString
                val msg = TransferProtocol.certMessage(issuer.programId, UuidBytes.parse(account), TransferProtocol.currencyTag(currency), Hex.decode(pubHex))
                val cert = issuer.certify(UuidBytes.parse(account), TransferProtocol.currencyTag(currency), Hex.decode(pubHex))
                certified[cardId] = Hex.encode(cert)
                json(
                    200,
                    """{"card_id":"$cardId","issuer_version":1,"issuer_cert_hex":"${Hex.encode(cert)}","cert_message_hex":"${Hex.encode(msg)}","issuer_public_key_hex":"${Hex.encode(issuer.pub65)}","program_id_hex":"${Hex.encode(issuer.programId)}","currency":"$currency","card_minor_scale":${o["card_minor_scale"].asInt}}"""
                )
            }
            else -> error(404, "not_found", "no route $path")
        }
    }

    override fun close() = server.shutdown()
}

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
 * token, write-once unless recertify), `GET /card-issuer`, `GET /network`, and
 * `PUT /card/stellar-key` (holder token), which verifies both cross-signatures
 * against the stored card row as the real bridge does.
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
    /** card_id -> the registered Stellar address. */
    val stellarKeys = mutableMapOf<String, String>()
    /** Answer `PUT /card/stellar-key` with this status instead of handling it (to test a lost step 9). */
    var stellarKeyFailure: Int? = null
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
            r.method == "PUT" && path == "/card/stellar-key" -> {
                if (auth != "Bearer $holderToken") return error(401, "unauthorized", "Unauthorized")
                stellarKeyFailure?.let { return error(it, "internal", "injected failure") }
                val o = JsonParser.parseString(r.body.readUtf8()).asJsonObject
                val cardId = o["card_id"].asString
                val (account, pubHex) = cards[cardId] ?: return error(404, "not_found", "Card not found")
                val address = o["stellar_address"].asString
                val stellarPub = com.impala.sdk.stellar.StrKey.decodeAccountId(address)
                val accountBytes = UuidBytes.parse(account)
                val ok = com.impala.simulator.Jca.verifyP256(
                    com.impala.simulator.Jca.jcaPublicKey(Hex.decode(pubHex)),
                    com.impala.sdk.models.StellarCardKey.bindingMessage(accountBytes, Hex.decode(cardId), stellarPub),
                    Hex.decode(o["stellar_binding_sig"].asString)
                ) && com.impala.simulator.Jca.verifyEd25519(
                    stellarPub,
                    com.impala.sdk.models.StellarCardKey.proofMessage(accountBytes, Hex.decode(cardId), Hex.decode(pubHex)),
                    Hex.decode(o["stellar_proof_sig"].asString)
                )
                if (!ok) return error(400, "invalid_stellar_binding", "the cross-signatures do not verify")
                val existing = stellarKeys[cardId]
                if (existing != null && existing != address) return error(409, "stellar_key_already_set", "This card already has a Stellar key")
                stellarKeys[cardId] = address
                json(200, """{"success":true,"message":"Stellar key registered"}""")
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

package com.payala.impala.demo.lab

import android.nfc.Tag
import android.os.Bundle
import android.os.Looper
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.simulator.PersonalizedCard
import com.impala.simulator.TestIssuer
import com.impala.simulator.fund
import com.impala.simulator.personalizedCard
import com.payala.impala.card.CardInspection
import com.payala.impala.card.CardInspector
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.card.LastTransferSummary
import com.payala.impala.card.Masked
import com.payala.impala.demo.offMain
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.robolectric.Shadows.shadowOf
import java.util.concurrent.CopyOnWriteArrayList

/** A jcardsim card issued by a local test issuer, and its read-only Lab inspection. */
internal class SimCard(
    val issuer: TestIssuer = TestIssuer(),
    val accountUuid: String = "10000000-0000-4000-8000-000000000006",
    val balance: Long = 0
) {
    val card: PersonalizedCard = personalizedCard(issuer, UuidBytes.parse(accountUuid))

    init {
        if (balance > 0) fund(card, issuer.externalSender(UuidBytes.parse("20000000-0000-4000-8000-000000000007")), balance, 1_700_000_000L)
    }

    val issuerPubHex: String get() = Hex.encode(issuer.pub65)
    val programIdHex: String get() = Hex.encode(issuer.programId)
    val cardPubHex: String get() = Hex.encode(card.pub65)
    val certHex: String get() = Hex.encode(card.cert)

    /** Inspects the card over a read-only, traced session, off the main thread. */
    fun inspect(trace: MutableList<ApduExchange>? = null): CardInspection = offMain {
        ImpalaCardSession.fromBibo(card.bibo, trace = trace?.let { list -> { e: ApduExchange -> list += e } }, readOnly = true)
            .use { CardInspector.inspect(it) }
    }
}

/** A synthetic inspection with personal values the tests look for, and nothing that verifies. */
internal fun syntheticInspection(
    holder: String = "Card Holder",
    balance: Long = 987_654_321L,
    lastAmount: Long = 1_234_567L,
    account: String = "0f0e0d0c-0b0a-0908-0706-050403020100",
    currency: String = "USDC"
) = CardInspection(
    readAtEpochMs = 1_762_594_867_123L, aidHex = "01020304050607080102", transport = null,
    steps = emptyList(), exchanges = emptyList(), versionLine = "0.2 · r17 · g1a2b3c4d", versionMajor = 0, versionMinor = 2,
    wireCardId = "00112233445566778899aabbccddeeff", accountUuid = account, holderName = Masked(holder),
    cardKeyFingerprint = "01:02:03:04:05:06:07:08:09:0a", stateName = "PERSONALIZED", flagNames = listOf("PERSONALIZED"),
    personalized = true, terminated = false, programIdHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", currency = currency,
    issuerKeyFingerprint = "11:12:13:14:15:16:17:18:19:1a", certificateLength = 71, certIdHex = "c0ffee" + "00".repeat(29),
    certVerifiedByCardIssuer = true, receiveCounter = 3, receiveDigestHex = "ab".repeat(32),
    balanceMinor = Masked(balance),
    lastTransfer = Masked(LastTransferSummary(lastAmount, 4, 1_700_000_001L, "30000000-0000-4000-8000-000000000008", currency, 71)),
    alive = true
)

/** Real (Robolectric) NFC tags built with the platform's hidden `Tag.createMockTag`. */
internal object TestTags {
    private const val NFC_A = 1
    private const val ISO_DEP = 3

    fun isoDepA(id: ByteArray = byteArrayOf(0x04, 0x11, 0x22, 0x33)): Tag {
        val m = Tag::class.java.methods.first { it.name == "createMockTag" }
        val techs = intArrayOf(NFC_A, ISO_DEP)
        val extras = arrayOf(Bundle().apply { putByteArray("atqa", byteArrayOf(0x44, 0x00)); putShort("sak", 0x20) }, Bundle())
        return when (m.parameterCount) {
            4 -> m.invoke(null, id, techs, extras, 0L)
            else -> m.invoke(null, id, techs, extras)
        } as Tag
    }
}

/** Idles the main looper until [done] or ~10 s pass (results posted from worker threads). */
internal fun idleMainUntil(done: () -> Boolean) {
    repeat(500) {
        shadowOf(Looper.getMainLooper()).idle()
        if (done()) return
        Thread.sleep(20)
    }
    shadowOf(Looper.getMainLooper()).idle()
}

/**
 * An OkHttp client that never touches the network: [routes] maps a path to
 * (code, JSON body), anything else is a 404. Every request is recorded.
 */
internal class CannedBridge(private val routes: Map<String, Pair<Int, String>>) {
    val requests = CopyOnWriteArrayList<Request>()

    val client: OkHttpClient = OkHttpClient.Builder().addInterceptor(Interceptor { chain ->
        val req = chain.request()
        requests += req
        val (code, body) = routes[req.url.encodedPath] ?: (404 to "{\"error\":\"not found\"}")
        Response.Builder().request(req).protocol(Protocol.HTTP_1_1).code(code).message("canned")
            .body(body.toResponseBody("application/json".toMediaType())).build()
    }).build()

    companion object {
        fun healthy(network: String = "testnet", issuerJson: String = UNCONFIGURED) = CannedBridge(
            mapOf(
                "/health" to (200 to """{"status":"healthy","database":"ok","redis":"ok","stellar_network":"$network"}"""),
                "/version" to (200 to """{"name":"impala-bridge","version":"0.9.1","build_date":"2026-11-01","rustc_version":"1.90","schema_version":"041"}"""),
                "/card-issuer" to (200 to issuerJson)
            )
        )

        const val UNCONFIGURED = """{"configured":false}"""

        fun issuer(publicKeyHex: String, programIdHex: String) =
            """{"configured":true,"version":1,"public_key_hex":"$publicKeyHex","fingerprint":"aa:bb:cc","redemption_uuid":"40000000-0000-4000-8000-000000000009","program_id_hex":"$programIdHex"}"""
    }
}

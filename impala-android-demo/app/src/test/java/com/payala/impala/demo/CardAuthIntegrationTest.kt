package com.payala.impala.demo

import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.model.CardAuthRequest
import com.payala.impala.demo.model.CardChallengeRequest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Ignore
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * End-to-end skeleton for the card challenge-response flow against a live
 * impala-bridge (`POST /auth/card/challenge` + `POST /auth/card`).
 *
 * Ignored by default: it needs a bridge with the card-auth endpoints running
 * on `localhost:8080` (e.g. `docker compose up` in `impala-bridge/`), which is
 * not available while those endpoints are being built in parallel. Remove the
 * `@Ignore` to run it manually once the bridge is up.
 *
 * The signing step reproduces exactly what a tapped card does in
 * `ImpalaCardReader.signAuthChallenge`: ECDSA-SHA256 (secp256r1, DER) over the
 * pinned card-auth message `"IMPALA-AUTH:" || accountId (16B) || challenge`.
 * Here the key pair is a throwaway, so the bridge must *reject* the exchange;
 * the registered-card happy path is the tracked follow-up (it needs a card
 * registered via `POST /card` under an authenticated session first).
 */
@Ignore("Follow-up e2e: requires a live impala-bridge with /auth/card endpoints on localhost:8080")
class CardAuthIntegrationTest {

    private val api: BridgeApiService = Retrofit.Builder()
        .baseUrl("http://localhost:8080/")
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(BridgeApiService::class.java)

    @Test
    fun `challenge is issued unconditionally and an unregistered signature is rejected`() {
        runBlocking {
            val cardId = UUID.randomUUID().toString()

            // 1. Challenge issuance is unconditional (no card enumeration):
            //    64 hex chars (32 bytes), 60-second TTL.
            val challengeResponse = api.cardChallenge(CardChallengeRequest(cardId))
            assertTrue(challengeResponse.success)
            val challengeHex = challengeResponse.challenge
            assertNotNull(challengeHex)
            assertEquals(64, challengeHex!!.length)
            assertEquals(60L, challengeResponse.expires_in)

            // 2. Sign the pinned message with a throwaway (unregistered) P-256
            //    key — byte-for-byte what the applet signs on-card.
            val keyPair = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            val challenge = challengeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val message = "IMPALA-AUTH:".toByteArray(Charsets.US_ASCII) + ByteArray(16) + challenge
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(keyPair.private)
                update(message)
                sign()
            }
            val signatureHex = signature.joinToString("") { "%02x".format(it) }

            // 3. The exchange must reject the unregistered card/key.
            try {
                val tokenResponse = api.cardTokenExchange(CardAuthRequest(cardId, signatureHex))
                assertFalse("unregistered card must not authenticate", tokenResponse.success)
                assertNull(tokenResponse.refresh_token)
            } catch (e: HttpException) {
                assertTrue("expected a 4xx rejection, got HTTP ${e.code()}", e.code() in 400..499)
            }

            // 4. Challenges are single-use: a second exchange attempt with the
            //    same (already consumed) challenge must also fail.
            try {
                val replay = api.cardTokenExchange(CardAuthRequest(cardId, signatureHex))
                assertFalse("replayed challenge must not authenticate", replay.success)
            } catch (e: HttpException) {
                assertTrue("expected a 4xx rejection, got HTTP ${e.code()}", e.code() in 400..499)
            }

            // Follow-up (needs a registered card): register the EC public key
            // via POST /card under an authenticated session, re-run the flow
            // with that key, and assert a refresh_token + temporal-token
            // round-trip via POST /token {refresh_token}.
        }
    }
}

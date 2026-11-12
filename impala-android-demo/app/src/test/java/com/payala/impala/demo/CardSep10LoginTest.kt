package com.payala.impala.demo

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.stellar.Sep10Exception
import com.impala.simulator.Jca
import com.impala.simulator.PersonalizedCard
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.card.CardStellarKeys
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.card.Sep10Fallback
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.CardSep10
import com.payala.impala.demo.card.TappedStellarKeys
import com.payala.impala.demo.model.CardChallengeResponse
import com.payala.impala.demo.ui.cards.CardsViewModel
import com.payala.impala.demo.ui.login.LoginViewModel
import com.payala.impala.demo.ui.login.LoginViewModel.ErrorType
import com.payala.impala.demo.ui.login.LoginViewModel.LoginState
import com.payala.impala.stellar.Sep10HttpException
import java.security.KeyPairGenerator
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verifyBlocking
import org.robolectric.RobolectricTestRunner

/**
 * Card login and registration with a Stellar key, against the real applet on
 * jcardsim and a SEP-10 test server: SEP-10 is what a card with a Stellar key
 * uses, the legacy challenge is what everything else falls back to, and
 * nothing that should stop a login is turned into a fallback.
 */
@RunWith(RobolectricTestRunner::class)
class CardSep10LoginTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private val challengeHex = "a5".repeat(32)
    private fun api(): BridgeApiService = mock {
        onBlocking { cardChallenge(any()) } doReturn CardChallengeResponse(true, challengeHex, 60)
    }

    private fun card(engine: String?): PersonalizedCard =
        personalizedCard(TestIssuer(), UuidBytes.parse(UUID.randomUUID().toString()), ed25519 = engine)

    private fun tap(card: PersonalizedCard, api: BridgeApiService, server: Sep10TestServer?) = offMain {
        val client = server?.let { CardSep10.clientFor(it.homeDomain, it.passphrase, it) }
        LoginViewModel().signInWithCardTap(ImpalaCardSession.fromBibo(card.bibo), api, client)
    }

    private fun assertLegacySignature(card: PersonalizedCard, signatureHex: String) {
        val message = "IMPALA-AUTH:".encodeToByteArray() + card.accountId + Hex.decode(challengeHex)
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), message, Hex.decode(signatureHex)))
    }

    @Test
    fun `a card with a Stellar key signs in with SEP-10 and the legacy challenge is never requested`() {
        for (engine in listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)) {
            val api = api()
            val server = Sep10TestServer()
            val tap = tap(card(engine), api, server)
            assertEquals(listOf("toml", "challenge", "post"), server.calls)
            assertTrue(engine, tap.sep10TokenJson!!.contains("\"refresh_token\":\"refresh-token\""))
            assertEquals("", tap.signatureHex)
            assertNull(tap.sep10Fallback)
            assertEquals("refresh-token", CardSep10.parseTokens(tap.sep10TokenJson!!)!!.refresh_token)
            verifyBlocking(api, never()) { cardChallenge(any()) }
        }
    }

    @Test
    fun `a card without a Stellar key, or a build without a home domain, uses the legacy challenge`() {
        val api = api()
        val server = Sep10TestServer()
        val legacy = card(SimulatorBibo.ED25519_NONE)
        val tap = tap(legacy, api, server)
        assertTrue(server.calls.isEmpty())
        assertNull(tap.sep10TokenJson)
        assertNull(tap.sep10Fallback)
        assertLegacySignature(legacy, tap.signatureHex)

        val stellar = card(SimulatorBibo.ED25519_SOFT)
        val noDomain = tap(stellar, api, server = null)
        assertEquals(Sep10Fallback.NOT_CONFIGURED, noDomain.sep10Fallback)
        assertLegacySignature(stellar, noDomain.signatureHex)
        verifyBlocking(api, times(2)) { cardChallenge(any()) }
    }

    @Test
    fun `a server without SEP-10 or without this card's key gets the legacy challenge in the same tap`() {
        val cases: List<Triple<String, Sep10Fallback, (Sep10TestServer) -> Unit>> = listOf(
            Triple("no stellar.toml", Sep10Fallback.NOT_OFFERED) { s -> s.tomlAnswer = { throw Sep10HttpException(404, "") } },
            Triple("SEP-10 switched off", Sep10Fallback.NOT_OFFERED) { s -> s.challengeAnswer = { throw Sep10HttpException(503, "") } },
            Triple("card key not registered", Sep10Fallback.NOT_REGISTERED) { s -> s.postAnswer = { throw Sep10HttpException(401, "") } }
        )
        for ((name, fallback, arrange) in cases) {
            val api = api()
            val server = Sep10TestServer().also(arrange)
            val card = card(SimulatorBibo.ED25519_SOFT)
            val tap = tap(card, api, server)
            assertEquals(name, fallback, tap.sep10Fallback)
            assertNull(name, tap.sep10TokenJson)
            assertLegacySignature(card, tap.signatureHex)
            verifyBlocking(api, times(1)) { cardChallenge(any()) }
        }
    }

    @Test
    fun `after a not-registered fallback the legacy login registers the card's Stellar key`() {
        kotlinx.coroutines.Dispatchers.setMain(kotlinx.coroutines.Dispatchers.Unconfined)
        try {
            val card = card(SimulatorBibo.ED25519_SOFT)
            val server = Sep10TestServer().also { it.postAnswer = { throw Sep10HttpException(401, "") } }
            val sent = mutableListOf<com.payala.impala.demo.model.SetCardStellarKeyRequest>()
            val api: BridgeApiService = mock {
                onBlocking { cardChallenge(any()) } doReturn CardChallengeResponse(true, challengeHex, 60)
                onBlocking { cardTokenExchange(any()) } doReturn com.payala.impala.demo.model.TokenResponse(true, "ok", refresh_token = "r")
                onBlocking { token(any()) } doReturn com.payala.impala.demo.model.TokenResponse(true, "ok", temporal_token = "t")
                onBlocking { setCardStellarKey(any()) } doAnswer { invocation ->
                    sent += invocation.getArgument<com.payala.impala.demo.model.SetCardStellarKeyRequest>(0)
                    com.payala.impala.demo.model.CardResponse(true, "Stellar key registered")
                }
            }
            val tap = tap(card, api, server)
            assertEquals(Sep10Fallback.NOT_REGISTERED, tap.sep10Fallback)
            val key = tap.stellarKey!!
            val vm = LoginViewModel()
            assertTrue(vm.tryBeginCardLogin())
            vm.loginWithCard(api, mock(), tap)
            assertTrue("${vm.loginState.value}", vm.loginState.value is LoginState.Success)
            // exactly the card's own key and signatures, for the card's own id
            val request = sent.single()
            assertEquals(tap.identity.wireCardId, request.card_id)
            assertEquals(key.address, request.stellar_address)
            assertEquals(Hex.encode(key.bindingSignature!!), request.stellar_binding_sig)
            assertEquals(Hex.encode(key.proofSignature!!), request.stellar_proof_sig)

            // a refusal or an outage of that step never fails the login
            for (failure in listOf<() -> Nothing>({ throw java.io.IOException("down") }, { throw IllegalStateException("x") })) {
                val failing: BridgeApiService = mock {
                    onBlocking { cardTokenExchange(any()) } doReturn com.payala.impala.demo.model.TokenResponse(true, "ok", refresh_token = "r")
                    onBlocking { token(any()) } doReturn com.payala.impala.demo.model.TokenResponse(true, "ok", temporal_token = "t")
                    onBlocking { setCardStellarKey(any()) } doAnswer { failure() }
                }
                val again = LoginViewModel()
                assertTrue(again.tryBeginCardLogin())
                again.loginWithCard(failing, mock(), tap)
                assertTrue(again.loginState.value is LoginState.Success)
            }

            // no other outcome registers anything: SEP-10 success, a legacy card, the other fallbacks
            val quiet: BridgeApiService = mock {
                onBlocking { cardChallenge(any()) } doReturn CardChallengeResponse(true, challengeHex, 60)
                onBlocking { cardTokenExchange(any()) } doReturn com.payala.impala.demo.model.TokenResponse(true, "ok", refresh_token = "r")
                onBlocking { token(any()) } doReturn com.payala.impala.demo.model.TokenResponse(true, "ok", temporal_token = "t")
            }
            val taps = listOf(
                tap(card(SimulatorBibo.ED25519_SOFT), quiet, Sep10TestServer()),
                tap(card(SimulatorBibo.ED25519_NONE), quiet, Sep10TestServer()),
                tap(card(SimulatorBibo.ED25519_SOFT), quiet, Sep10TestServer().also { it.tomlAnswer = { throw Sep10HttpException(404, "") } }),
                tap(card(SimulatorBibo.ED25519_SOFT), quiet, server = null)
            )
            for (t in taps) {
                val m = LoginViewModel()
                assertTrue(m.tryBeginCardLogin())
                m.loginWithCard(quiet, mock(), t)
                assertTrue("${m.loginState.value}", m.loginState.value is LoginState.Success)
            }
            verifyBlocking(quiet, never()) { setCardStellarKey(any()) }
        } finally {
            kotlinx.coroutines.Dispatchers.resetMain()
        }
    }

    @Test
    fun `a lockout and an unverifiable challenge stop the login and are shown as what they are`() {
        // 429 from the SEP-10 endpoint: no fallback, and the login screen says locked out
        val api = api()
        val locked = Sep10TestServer().also { it.postAnswer = { throw Sep10HttpException(429, "") } }
        val e429 = assertThrows(Sep10HttpException::class.java) { tap(card(SimulatorBibo.ED25519_SOFT), api, locked) }
        verifyBlocking(api, never()) { cardChallenge(any()) }
        val vm = LoginViewModel()
        assertTrue(vm.tryBeginCardLogin())
        vm.cardTapFailed(e429)
        assertEquals(ErrorType.LOCKED_OUT, (vm.loginState.value as LoginState.Error).errorType)
        assertTrue("the slot is released", vm.tryBeginCardLogin())

        // a challenge signed by a key that is not the one in stellar.toml: the card is not asked to sign it
        val impostor = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val hostile = Sep10TestServer()
        hostile.challengeAnswer = { account ->
            "{\"transaction\":\"${hostile.challenge(com.impala.sdk.stellar.StrKey.decodeAccountId(account), by = impostor)}\"," +
                "\"network_passphrase\":\"${hostile.passphrase}\"}"
        }
        val card = card(SimulatorBibo.ED25519_NATIVE)
        val commands = mutableListOf<Int>()
        card.bibo.debugTrace = { cmd, _ -> commands += cmd[1].toInt() and 0xFF }
        val bad = assertThrows(Sep10Exception::class.java) { tap(card, api, hostile) }
        assertFalse("the card signed nothing", 0x38 in commands || 0x25 in commands)
        verifyBlocking(api, never()) { cardChallenge(any()) }
        vm.cardTapFailed(bad)
        val state = vm.loginState.value as LoginState.Error
        assertEquals(ErrorType.SERVER_ERROR, state.errorType)
        assertEquals("The server's sign-in challenge could not be verified", state.message)

        vm.cardTapFailed(Sep10HttpException(500, "boom"))
        assertEquals(ErrorType.SERVER_ERROR, (vm.loginState.value as LoginState.Error).errorType)
    }

    @Test
    fun `registration sends the Stellar key of a card that has one, and only when it verifies`() {
        val vm = CardsViewModel()
        for (engine in listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)) {
            val card = card(engine)
            val (identity, key) = offMain {
                val session = ImpalaCardSession.fromBibo(card.bibo)
                val identity = TappedStellarKeys.readDuringTap(session, session.identity)
                identity to TappedStellarKeys.forCard(identity.wireCardId)
            }
            assertNotNull(engine, key)
            val request = vm.registrationRequest(identity.accountUuid, identity, key)
            assertEquals(key!!.address, request.stellar_address)
            assertEquals(Hex.encode(key.bindingSignature!!), request.stellar_binding_sig)
            assertEquals(128, request.stellar_proof_sig!!.length)
            assertTrue(request.stellar_binding_sig!!.matches(Regex("[0-9a-f]{16,144}")))
            assertTrue(request.stellar_address!!.matches(Regex("G[A-Z2-7]{55}")))
            assertTrue(CardStellarKeys.proofVerifies(identity.pubKey, identity.accountId, identity.cardId, key))

            // the same key presented for another card's identity does not verify: it is left out
            val other = offMain { ImpalaCardSession.fromBibo(card(SimulatorBibo.ED25519_NONE).bibo).identity }
            val plain = vm.registrationRequest(other.accountUuid, other, key)
            assertNull(plain.stellar_address)
            assertNull(plain.stellar_binding_sig)
            assertNull(plain.stellar_proof_sig)
        }
        // a card without a Stellar key registers exactly as before, and is forgotten by the key store
        val legacy = card(SimulatorBibo.ED25519_NONE)
        val identity = offMain {
            val session = ImpalaCardSession.fromBibo(legacy.bibo)
            TappedStellarKeys.readDuringTap(session, session.identity)
        }
        assertNull(TappedStellarKeys.forCard(identity.wireCardId))
        val request = vm.registrationRequest(identity.accountUuid, identity, null)
        assertNull(request.stellar_address)
        // and the JSON a legacy registration sends has no Stellar members at all
        val json = com.google.gson.Gson().toJson(request)
        assertFalse(json, json.contains("stellar"))
    }

    @Test
    fun `the SEP-10 client exists only for a usable home domain`() {
        val passphrase = "Test SDF Network ; September 2015"
        assertNull(CardSep10.clientFor("", passphrase))
        assertNull(CardSep10.clientFor("   ", passphrase))
        assertNull("not a host name", CardSep10.clientFor("https://bridge.example.com/", passphrase))
        assertNull(CardSep10.clientFor("Bridge.Example.com", passphrase))
        assertNull(CardSep10.clientFor("bridge.example.com", ""))
        assertNotNull(CardSep10.clientFor("bridge.example.com", passphrase))
        assertNotNull(CardSep10.clientFor("10.0.2.2:8080", passphrase))
        assertNull(CardSep10.parseTokens("not json"))
        assertEquals("r", CardSep10.parseTokens("{\"token\":\"t\",\"success\":true,\"message\":\"ok\",\"refresh_token\":\"r\"}")!!.refresh_token)
        // this build's default home domain is the bridge's own authority
        assertEquals(
            java.net.URI(BuildConfig.BRIDGE_BASE_URL).let { it.host + (if (it.port >= 0) ":${it.port}" else "") },
            BuildConfig.SEP10_HOME_DOMAIN
        )
    }
}

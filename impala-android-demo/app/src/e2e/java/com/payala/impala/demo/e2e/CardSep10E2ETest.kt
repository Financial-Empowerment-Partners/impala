package com.payala.impala.demo.e2e

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.impala.simulator.SimulatorBibo
import com.impala.tools.issue.IssuanceRecord
import com.payala.impala.card.CardAuthenticator
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.card.Sep10Fallback
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.ui.login.CardLoginTap
import com.payala.impala.demo.ui.login.LoginViewModel
import com.payala.impala.stellar.Sep10Client
import com.payala.impala.stellar.Sep10HttpException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import retrofit2.HttpException

/**
 * E2E-3, SEP-10 card sign-in (T1): jcardsim cards issued by the issuance
 * ceremony against the live bridge sign in through the app's
 * [LoginViewModel] with the bridge's SEP-10 endpoint, on both hardware
 * classes: the default CAP (the software Ed25519 engine) on a simulated
 * JavaCard 3.0.5 card and the native CAP (the platform's EdDSA) on a
 * simulated JavaCard 3.2 card ([E2e.hardwareFor]). Also: a signed challenge
 * is single-use, a card without a Stellar key keeps the legacy login on the
 * same bridge, and an account with a privileged role is never served by
 * SEP-10.
 *
 * Needs IMPALA_E2E_BRIDGE_URL and IMPALA_E2E_SEP10_HOME_DOMAIN (a bridge with
 * `SEP10_ENABLED=true` and an active signing key).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class CardSep10E2ETest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    @Before
    fun setUp() {
        E2e.requireBridge()
        Sep10E2e.requireHomeDomain()
        Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun tokens(): TokenManager =
        TokenManager(RuntimeEnvironment.getApplication().getSharedPreferences("e2e-sep10-${System.nanoTime()}", 0))

    /** A card login tap with SEP-10 on offer, through the app's view model, budget-tolerant. */
    private fun tap(card: SimulatorBibo, api: BridgeApiService, vm: LoginViewModel, sep10: Sep10Client): CardLoginTap =
        Sep10E2e.paced { E2e.offMain { vm.signInWithCardTap(ImpalaCardSession.fromBibo(card), api, sep10) } }

    private fun finish(vm: LoginViewModel, api: BridgeApiService, tokenManager: TokenManager, tap: CardLoginTap): LoginViewModel.LoginState {
        vm.loginWithCard(api, tokenManager, tap)
        val deadline = System.currentTimeMillis() + 30_000
        while (vm.loginState.value !is LoginViewModel.LoginState.Success && vm.loginState.value !is LoginViewModel.LoginState.Error &&
            System.currentTimeMillis() < deadline) Thread.sleep(50)
        return vm.loginState.value!!
    }

    private fun httpCode(block: suspend () -> Unit): Int = try {
        runBlocking { block() }
        200
    } catch (e: HttpException) {
        e.code()
    }

    private fun sep10Status(block: () -> Unit): Int = try {
        block()
        200
    } catch (e: Sep10HttpException) {
        e.status
    }

    @Test
    fun `a card with a Stellar key signs in through SEP-10 with either Ed25519 engine and the session works`() {
        val (account, _) = E2e.holder
        for (engine in listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)) {
            val (card, record) = issued(engine)
            val address = record.stellarAddress
                ?: throw AssertionError("$engine: the ceremony did not read a Stellar key from the card")

            val vm = LoginViewModel()
            val api = E2e.api()
            val tokenManager = tokens()
            assertTrue(vm.tryBeginCardLogin())
            val tap = tap(card, api, vm, Sep10E2e.bridgeClient())
            assertNotNull("$engine: the tap ran SEP-10 to the end (tokens from POST /auth/sep10)", tap.sep10TokenJson)
            assertNull("$engine: no fallback to the legacy challenge", tap.sep10Fallback)
            assertEquals("$engine: no legacy signature was made", "", tap.signatureHex)
            assertEquals(record.cardId, tap.identity.wireCardId)

            val state = finish(vm, api, tokenManager, tap)
            assertTrue("$engine: expected Success, got $state", state is LoginViewModel.LoginState.Success)
            assertEquals(account, (state as LoginViewModel.LoginState.Success).accountId)
            val temporal = tokenManager.getTemporalToken() ?: throw AssertionError("$engine: no temporal token was stored")
            assertEquals("the session is the card's account", account, E2e.subOf(temporal))
            assertEquals("card", tokenManager.getAuthProvider())
            assertEquals(record.cardId, tokenManager.getCardId())
            // The token is a bridge session like any other: an authenticated route answers, and refuses without it.
            assertEquals(200, httpCode { E2e.api(temporal).listNotify() })
            assertEquals(401, httpCode { E2e.api().listNotify() })

            signIns.put(JSONObject().put("engine", engine).put("platform", card.platform.name()).put("javacard", card.platform.level().label())
                .put("card_id", record.cardId).put("stellar_address", address).put("account", account).put("mechanism", "sep10"))
            println("e2e: SEP-10 sign-in, $engine engine on ${card.platform.name()} hardware (JavaCard ${card.platform.level().label()}): card ${record.cardId} ($address) as $account")
        }
    }

    @Test
    fun `a signed challenge is accepted once, and a signature that is not the card's is refused`() {
        val (account, _) = E2e.holder
        val (card, _) = issued(SimulatorBibo.ED25519_SOFT)
        val session = ImpalaCardSession.fromBibo(card)
        val key = E2e.offMain { CardAuthenticator.stellarKey(session) }!!
        val client = Sep10E2e.bridgeClient()

        // Not the card's signature: the generic 401 (the one failure the bridge counts toward the lockout).
        val forged = Sep10E2e.paced { client.prepare(key.publicKey) }
        assertEquals(401, sep10Status { client.submit(forged.webAuthEndpoint, forged.challenge.signedEnvelope(ByteArray(64))) })

        val prepared = Sep10E2e.paced { client.prepare(key.publicKey) }
        val signed = E2e.offMain { CardAuthenticator.signSep10(session, key.publicKey, prepared.challenge) }
        val tokenJson = Sep10E2e.paced { client.submit(prepared.webAuthEndpoint, signed) }
        assertEquals(account, E2e.subOf(Sep10E2e.tokenOf(tokenJson)))
        // The same signed challenge again: refused, the claim on its hash is taken.
        assertEquals(401, sep10Status { client.submit(prepared.webAuthEndpoint, signed) })
    }

    @Test
    fun `a card without a Stellar key signs in with the legacy challenge on the same bridge`() {
        val (account, _) = E2e.holder
        val (card, record) = issued(SimulatorBibo.ED25519_NONE)
        assertNull("a card without an Ed25519 engine has no Stellar address", record.stellarAddress)

        val vm = LoginViewModel()
        val api = E2e.api()
        val tokenManager = tokens()
        assertTrue(vm.tryBeginCardLogin())
        val tap = tap(card, api, vm, Sep10E2e.bridgeClient())
        assertNull("SEP-10 was not attempted", tap.sep10TokenJson)
        assertNull("and there was nothing to fall back from", tap.sep10Fallback)
        assertTrue("the card signed the legacy challenge", tap.signatureHex.startsWith("30"))
        val state = finish(vm, api, tokenManager, tap)
        assertTrue("expected Success, got $state", state is LoginViewModel.LoginState.Success)
        assertEquals(account, E2e.subOf(tokenManager.getTemporalToken()!!))
        signIns.put(JSONObject().put("engine", "none").put("platform", card.platform.name()).put("javacard", card.platform.level().label())
            .put("card_id", record.cardId).put("account", account).put("mechanism", "legacy"))
    }

    @Test
    fun `an account with a privileged role is refused by SEP-10 and its card signs in the legacy way`() {
        val operatorAccount = E2e.operatorAccount
        val operatorBearer = E2e.operatorBearer
        assumeTrue("needs the operator by account (IMPALA_E2E_OPERATOR_ACCOUNT + _PASSWORD_FILE): its card is issued to it", operatorAccount != null && operatorBearer != null)
        val card = E2e.blankCard()
        val record = E2e.issue(card, operatorAccount!!, operatorBearer!!)
        assertNotNull("the operator's card has a registered Stellar key", record.stellarAddress)

        // The endpoint itself: a correct signature by a registered card key, and still the generic 401.
        val session = ImpalaCardSession.fromBibo(card)
        val key = E2e.offMain { CardAuthenticator.stellarKey(session) }!!
        val client = Sep10E2e.bridgeClient()
        val prepared = Sep10E2e.paced { client.prepare(key.publicKey) }
        val signed = E2e.offMain { CardAuthenticator.signSep10(session, key.publicKey, prepared.challenge) }
        assertEquals("SEP-10 never serves a privileged account", 401, sep10Status { client.submit(prepared.webAuthEndpoint, signed) })

        // The app: the same 401 is its "not registered" fallback, and the legacy login carries the operator's role.
        val vm = LoginViewModel()
        val api = E2e.api()
        val tokenManager = tokens()
        assertTrue(vm.tryBeginCardLogin())
        val tap = tap(card, api, vm, client)
        assertNull(tap.sep10TokenJson)
        assertEquals(Sep10Fallback.NOT_REGISTERED, tap.sep10Fallback)
        assertTrue(tap.signatureHex.startsWith("30"))
        val state = finish(vm, api, tokenManager, tap)
        assertTrue("expected Success, got $state", state is LoginViewModel.LoginState.Success)
        val claims = Sep10E2e.jwtClaims(tokenManager.getTemporalToken()!!)!!
        assertEquals(operatorAccount, claims.getString("sub"))
        assertEquals("the legacy card login still mints the operator's session", "admin", claims.getString("role"))
        signIns.put(JSONObject().put("engine", "soft").put("platform", card.platform.name()).put("javacard", card.platform.level().label())
            .put("card_id", record.cardId).put("stellar_address", record.stellarAddress)
            .put("account", operatorAccount).put("mechanism", "legacy").put("sep10", "refused: privileged role"))
    }

    companion object {
        private val signIns = JSONArray()

        private val cards = HashMap<String, Pair<SimulatorBibo, IssuanceRecord>>()

        /**
         * The lane's card with this Ed25519 engine: issued to the lane's
         * holder by the bridge on first use and shared by the tests (each
         * opens its own session). Issuing once per engine keeps the lane
         * inside the bridge's certificate budget (5 per 60 s per operator).
         */
        private fun issued(engine: String): Pair<SimulatorBibo, IssuanceRecord> = synchronized(cards) {
            cards.getOrPut(engine) {
                val (account, bearer) = E2e.holder
                val card = E2e.blankCard(engine, E2e.hardwareFor(engine))
                card to E2e.issue(card, account, bearer)
            }
        }

        @JvmStatic
        @AfterClass
        fun report() {
            Sep10E2e.writeReport("sep10-bridge.json", JSONObject().put("home_domain", Sep10E2e.homeDomain).put("sign_ins", signIns))
        }
    }
}

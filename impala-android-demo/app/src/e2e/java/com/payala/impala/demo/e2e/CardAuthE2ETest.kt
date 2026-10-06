package com.payala.impala.demo.e2e

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.impala.sdk.flows.CardAuthFlow
import com.impala.sdk.flows.Hex
import com.impala.simulator.Jca
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.model.CardAuthRequest
import com.payala.impala.demo.model.CardChallengeRequest
import com.payala.impala.demo.model.TokenRequest
import com.payala.impala.demo.ui.cards.CardsViewModel
import com.payala.impala.demo.ui.login.LoginViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
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
 * E2E-1, card login (T1): a jcardsim card issued by the issuance ceremony
 * against the live bridge, driven through the app's LoginViewModel.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class CardAuthE2ETest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    @Before
    fun setUp() {
        E2e.requireBridge()
        Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun tokens(): TokenManager =
        TokenManager(RuntimeEnvironment.getApplication().getSharedPreferences("e2e-${System.nanoTime()}", 0))

    /** A card login tap (challenge fetch + signature) through the app's view model, budget-tolerant. */
    private fun tap(card: com.impala.simulator.SimulatorBibo, api: com.payala.impala.demo.api.BridgeApiService, vm: LoginViewModel = LoginViewModel()) =
        E2e.preAuth { E2e.offMain { vm.signInWithCardTap(ImpalaCardSession.fromBibo(card), api) } }

    private fun httpCode(block: suspend () -> Unit): Int = try {
        runBlocking { block() }
        200
    } catch (e: HttpException) {
        e.code()
    }

    @Test
    fun `registered simulated card logs in and the refresh token exchanges for a temporal token whose sub is the account UUID`() {
        val (account, bearer) = E2e.holder
        val card = E2e.blankCard()
        val record = E2e.issue(card, account, bearer)
        assertEquals(account, record.accountUuid)

        val vm = LoginViewModel()
        val api = E2e.api()
        val tokenManager = tokens()
        assertTrue(vm.tryBeginCardLogin())
        val tap = tap(card, api, vm)
        assertEquals(record.cardId, tap.identity.wireCardId)
        vm.loginWithCard(api, tokenManager, tap)
        val deadline = System.currentTimeMillis() + 30_000
        while (vm.loginState.value !is LoginViewModel.LoginState.Success && vm.loginState.value !is LoginViewModel.LoginState.Error &&
            System.currentTimeMillis() < deadline) Thread.sleep(50)
        val state = vm.loginState.value
        assertTrue("expected Success, got $state", state is LoginViewModel.LoginState.Success)
        assertEquals(account, (state as LoginViewModel.LoginState.Success).accountId)
        val temporal = tokenManager.getTemporalToken()
        assertNotNull("a temporal token was stored", temporal)
        assertEquals(account, E2e.subOf(temporal!!))
        assertEquals(record.cardId, tokenManager.getCardId())
    }

    @Test
    fun `the same signature presented twice is refused the second time (single-use challenge)`() {
        val (account, bearer) = E2e.holder
        val card = E2e.blankCard()
        E2e.issue(card, account, bearer)
        val api = E2e.api()
        val tap = tap(card, api)
        val request = CardAuthRequest(tap.identity.wireCardId, tap.signatureHex)
        val first = E2e.preAuth { runBlocking { api.cardTokenExchange(request) } }
        assertTrue(first.success && first.refresh_token != null)
        assertEquals(401, httpCode { api.cardTokenExchange(request) })
    }

    @Test
    fun `an unregistered card id gets a challenge but the exchange is a generic 401`() {
        val (account, bearer) = E2e.holder
        val card = E2e.blankCard()
        E2e.issue(card, account, bearer, register = false)
        val api = E2e.api()
        val tap = tap(card, api)
        // The bridge issued a challenge (signInWithCardTap fetched it) and the card signed it.
        assertTrue(tap.signatureHex.startsWith("30"))
        assertEquals(401, httpCode { api.cardTokenExchange(CardAuthRequest(tap.identity.wireCardId, tap.signatureHex)) })
    }

    @Test
    fun `a card personalized for another account is refused by the registration flow client-side`() {
        val (account, bearer) = E2e.holder
        val (other, _) = E2e.otherHolder
        val card = E2e.blankCard()
        E2e.issue(card, other, bearer, register = false)
        val identity = E2e.offMain { ImpalaCardSession.fromBibo(card).identity }
        assertEquals(CardsViewModel.Refusal.ACCOUNT_MISMATCH, CardsViewModel.checkRegistrable(identity, account))
    }

    @Test
    fun `challenge older than 60 s is refused`() {
        assumeTrue("slow test: set IMPALA_E2E_SLOW=1", E2e.slow)
        val (account, bearer) = E2e.holder
        val card = E2e.blankCard()
        E2e.issue(card, account, bearer)
        val api = E2e.api()
        val session = ImpalaCardSession.fromBibo(card)
        val identity = E2e.offMain { session.identity }
        val challenge = E2e.preAuth { runBlocking { api.cardChallenge(CardChallengeRequest(identity.wireCardId)) } }.challenge!!
        val sig = E2e.offMain { CardAuthFlow.sign(session.sdk, challenge) }
        Thread.sleep(61_000)
        assertEquals(401, httpCode { api.cardTokenExchange(CardAuthRequest(identity.wireCardId, sig)) })
    }

    @Test
    fun `five bad signatures over live challenges lock the card for this source, a missing challenge does not count`() {
        val (account, bearer) = E2e.holder
        val card = E2e.blankCard()
        E2e.issue(card, account, bearer)
        val api = E2e.api()
        val session = ImpalaCardSession.fromBibo(card)
        val identity = E2e.offMain { session.identity }
        val wire = identity.wireCardId
        val stranger = Jca.genP256()
        // Start from a fresh per-source window so a 429 below can only be the lockout.
        println("e2e: waiting 61 s for a fresh pre-auth window before the lockout test")
        Thread.sleep(61_000)

        // No outstanding challenge: refused, but not a verified-bad signature.
        assertEquals(401, httpCode { api.cardTokenExchange(CardAuthRequest(wire, "3006020101020101")) })

        repeat(5) {
            val challenge = E2e.preAuth { runBlocking { api.cardChallenge(CardChallengeRequest(wire)) } }.challenge!!
            val msg = "IMPALA-AUTH:".encodeToByteArray() + identity.accountId + Hex.decode(challenge)
            val bad = Hex.encode(Jca.signP256(stranger.private, msg))
            assertEquals(401, httpCode { api.cardTokenExchange(CardAuthRequest(wire, bad)) })
        }
        // The genuine card is now refused from this source.
        val code = httpCode {
            val challenge = api.cardChallenge(CardChallengeRequest(wire)).challenge!!
            val sig = E2e.offMain { CardAuthFlow.sign(session.sdk, challenge) }
            api.cardTokenExchange(CardAuthRequest(wire, sig))
        }
        assertTrue("expected a lockout refusal, got $code", code == 429 || code == 401)
    }

    @Test
    fun `refresh token from a card login rotates and the session survives one refresh`() {
        val (account, bearer) = E2e.holder
        val card = E2e.blankCard()
        E2e.issue(card, account, bearer)
        val api = E2e.api()
        val tap = tap(card, api)
        val refresh = E2e.preAuth { runBlocking { api.cardTokenExchange(CardAuthRequest(tap.identity.wireCardId, tap.signatureHex)) } }.refresh_token!!
        val temporal = E2e.preAuth { runBlocking { api.token(TokenRequest(refresh_token = refresh)) } }
        assertEquals(account, E2e.subOf(temporal.temporal_token!!))
    }
}

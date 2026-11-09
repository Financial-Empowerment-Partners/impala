package com.payala.impala.demo

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.model.CardIssuerResponse
import com.payala.impala.demo.model.CardResponse
import com.payala.impala.demo.model.CreateCardRequest
import com.payala.impala.demo.ui.cards.CardsViewModel
import com.payala.impala.demo.ui.cards.CardsViewModel.Event
import com.payala.impala.demo.ui.cards.CardsViewModel.IssuerState
import com.payala.impala.demo.ui.cards.CardsViewModel.ProgramMismatchPolicy
import com.payala.impala.demo.ui.cards.CardsViewModel.Refusal
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.doSuspendableAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verifyBlocking
import org.robolectric.RobolectricTestRunner
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class CardsViewModelTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private val account = "0f0e0d0c-0b0a-0908-0706-050403020100"
    private lateinit var store: CardStore
    private lateinit var vm: CardsViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        store = CardStore(ctx.getSharedPreferences("cards-test-${System.nanoTime()}", Context.MODE_PRIVATE))
        vm = CardsViewModel()
    }

    @After
    fun tearDown() = Dispatchers.resetMain()

    private val warn = ProgramMismatchPolicy.WARN
    private val refuse = ProgramMismatchPolicy.REFUSE

    /** POST /card succeeds; GET /card-issuer says configured:false unless [issuer] is given. */
    private fun okApi(issuer: CardIssuerResponse = CardIssuerResponse(configured = false)): BridgeApiService = mock {
        onBlocking { createCard(any()) } doReturn CardResponse(true, "Card created successfully")
        onBlocking { cardIssuer() } doReturn issuer
    }

    private fun issuerOf(programIdHex: String) = CardIssuerResponse(
        configured = true, version = 1, public_key_hex = "04" + "11".repeat(64), redemption_uuid = "20000000-0000-4000-8000-000000000001",
        program_id_hex = programIdHex
    )

    private val foreignProgram = "ffffffffffffffffffffffffffffffff"

    @Test
    fun `refuses a card whose on-card account differs from the session account and never calls POST card`() {
        val api = okApi()
        vm.register(api, store, "11111111-2222-3333-4444-555555555555", fakeIdentity(accountUuid = account), warn)
        assertEquals(Event.Refused(Refusal.ACCOUNT_MISMATCH), vm.events.value)
        verifyBlocking(api, never()) { createCard(any()) }
        assertTrue(store.list(account).isEmpty())
    }

    @Test
    fun `accepts dashed and 32-hex session ids that denote the same UUID`() {
        val identity = fakeIdentity(accountUuid = account)
        assertNull(CardsViewModel.checkRegistrable(identity, account))
        assertNull(CardsViewModel.checkRegistrable(identity, account.replace("-", "")))
        assertNull(CardsViewModel.checkRegistrable(identity, account.uppercase()))
        assertEquals(Refusal.NO_SESSION, CardsViewModel.checkRegistrable(identity, null))
    }

    @Test
    fun `sends ec_pubkey as the 130-hex point and no rsa_pubkey`() {
        val api = okApi()
        val identity = fakeIdentity(accountUuid = account)
        vm.register(api, store, account, identity, warn)
        val captor = argumentCaptor<CreateCardRequest>()
        verifyBlocking(api) { createCard(captor.capture()) }
        val req = captor.firstValue
        assertEquals(130, req.ec_pubkey.length)
        assertEquals(identity.pubKeyHex, req.ec_pubkey)
        assertNull(req.rsa_pubkey)
        assertEquals("00112233445566778899aabbccddeeff", req.card_id)
        assertEquals(account, req.account_id)
        // Gson omits the null: the wire body has no rsa_pubkey key at all.
        assertTrue(!com.google.gson.Gson().toJson(req).contains("rsa_pubkey"))
        assertTrue(vm.events.value is Event.Registered)
        assertEquals(listOf(identity.wireCardId), store.list(account).map { it.cardId })
    }

    @Test
    fun `refuses an unpersonalized card with NotPersonalized`() {
        val api = okApi()
        vm.register(api, store, account, fakeIdentity(accountUuid = account, state = 0x01), warn)
        assertEquals(Event.Refused(Refusal.NOT_PERSONALIZED), vm.events.value)
        vm.register(api, store, account, fakeIdentity(accountUuid = account, minor = 1), warn)
        assertEquals(Event.Refused(Refusal.WRONG_VERSION, "0.1"), vm.events.value)
        verifyBlocking(api, never()) { createCard(any()) }
    }

    @Test
    fun `bridge 400 and 409 messages are shown verbatim`() {
        val body = """{"error":{"code":"conflict","message":"Card already registered"}}"""
        val api = mock<BridgeApiService> {
            onBlocking { createCard(any()) } doSuspendableAnswer {
                throw HttpException(Response.error<Any>(409, body.toResponseBody("application/json".toMediaType())))
            }
            onBlocking { cardIssuer() } doReturn CardIssuerResponse(configured = false)
        }
        vm.register(api, store, account, fakeIdentity(accountUuid = account), warn)
        assertEquals(Event.BridgeRefused("Card already registered"), vm.events.value)
        assertTrue(store.list(account).isEmpty())
    }

    // ── Program check at registration (IssuerState) ──

    @Test
    fun `a card of another program raises ProgramMismatch under WARN and posts nothing`() {
        val api = okApi(issuerOf(foreignProgram))
        val identity = fakeIdentity(accountUuid = account)
        vm.register(api, store, account, identity, warn)
        val event = vm.events.value as Event.ProgramMismatch
        assertSame(identity, event.identity)
        assertEquals(foreignProgram, event.bridgeProgramIdHex)
        verifyBlocking(api, never()) { createCard(any()) }
        assertTrue(store.list(account).isEmpty())
    }

    @Test
    fun `acknowledging the mismatch under WARN posts the card`() {
        val api = okApi(issuerOf(foreignProgram))
        vm.register(api, store, account, fakeIdentity(accountUuid = account), warn, acknowledged = true)
        verifyBlocking(api) { createCard(any()) }
        assertTrue(vm.events.value is Event.Registered)
    }

    @Test
    fun `REFUSE refuses a card of another program with WRONG_PROGRAM, even when acknowledged`() {
        val api = okApi(issuerOf(foreignProgram))
        vm.register(api, store, account, fakeIdentity(accountUuid = account), refuse)
        assertEquals(Event.Refused(Refusal.WRONG_PROGRAM), vm.events.value)
        vm.register(api, store, account, fakeIdentity(accountUuid = account), refuse, acknowledged = true)
        assertEquals(Event.Refused(Refusal.WRONG_PROGRAM), vm.events.value)
        verifyBlocking(api, never()) { createCard(any()) }
    }

    @Test
    fun `the bridge's own program registers directly under both policies (hex case ignored)`() {
        val identity = fakeIdentity(accountUuid = account)
        for (policy in ProgramMismatchPolicy.values()) {
            val api = okApi(issuerOf(identity.programIdHex.uppercase()))
            val fresh = CardsViewModel()
            fresh.register(api, store, account, identity, policy)
            verifyBlocking(api) { createCard(any()) }
            assertTrue(fresh.events.value is Event.Registered)
        }
    }

    @Test
    fun `Unknown awaits the issuer fetch before deciding`() {
        val gate = CompletableDeferred<CardIssuerResponse>()
        val api = mock<BridgeApiService> {
            onBlocking { createCard(any()) } doReturn CardResponse(true, "ok")
            onBlocking { cardIssuer() } doSuspendableAnswer { gate.await() }
        }
        assertSame(IssuerState.Unknown, vm.issuer.value)
        vm.register(api, store, account, fakeIdentity(accountUuid = account), warn)
        verifyBlocking(api, never()) { createCard(any()) }
        assertNull(vm.events.value)
        gate.complete(issuerOf(foreignProgram))
        assertTrue(vm.events.value is Event.ProgramMismatch)
        assertTrue(vm.issuer.value is IssuerState.Known)
        verifyBlocking(api, never()) { createCard(any()) }
    }

    @Test
    fun `Unconfigured (configured false, or no endpoint) posts directly`() {
        val api = okApi(CardIssuerResponse(configured = false))
        vm.register(api, store, account, fakeIdentity(accountUuid = account), refuse)
        assertSame(IssuerState.Unconfigured, vm.issuer.value)
        verifyBlocking(api) { createCard(any()) }

        val missing = mock<BridgeApiService> {
            onBlocking { createCard(any()) } doReturn CardResponse(true, "ok")
            onBlocking { cardIssuer() } doSuspendableAnswer {
                throw HttpException(Response.error<Any>(404, "".toResponseBody("text/plain".toMediaType())))
            }
        }
        val fresh = CardsViewModel()
        fresh.register(missing, store, account, fakeIdentity(accountUuid = account), refuse)
        assertSame(IssuerState.Unconfigured, fresh.issuer.value)
        verifyBlocking(missing) { createCard(any()) }
    }

    @Test
    fun `Unreachable raises IssuerUnknown and posts nothing until acknowledged under WARN`() {
        val api = mock<BridgeApiService> {
            onBlocking { createCard(any()) } doReturn CardResponse(true, "ok")
            onBlocking { cardIssuer() } doSuspendableAnswer { throw IOException("unreachable") }
        }
        vm.register(api, store, account, fakeIdentity(accountUuid = account), warn)
        val unknown = vm.events.value as Event.IssuerUnknown
        assertTrue(unknown.canAcknowledge)
        assertSame(IssuerState.Unreachable, vm.issuer.value)
        verifyBlocking(api, never()) { createCard(any()) }

        vm.register(api, store, account, fakeIdentity(accountUuid = account), warn, acknowledged = true)
        verifyBlocking(api) { createCard(any()) }
    }

    @Test
    fun `Unreachable under REFUSE fails closed, even when acknowledged`() {
        val api = mock<BridgeApiService> {
            onBlocking { createCard(any()) } doReturn CardResponse(true, "ok")
            onBlocking { cardIssuer() } doSuspendableAnswer {
                throw HttpException(Response.error<Any>(503, "".toResponseBody("text/plain".toMediaType())))
            }
        }
        vm.register(api, store, account, fakeIdentity(accountUuid = account), refuse, acknowledged = true)
        val unknown = vm.events.value as Event.IssuerUnknown
        assertFalse(unknown.canAcknowledge)
        verifyBlocking(api, never()) { createCard(any()) }
    }

    @Test
    fun `a known issuer is fetched once and reused`() {
        val api = okApi(issuerOf(fakeIdentity().programIdHex))
        vm.loadIssuer(api)
        vm.register(api, store, account, fakeIdentity(accountUuid = account), warn)
        vm.register(api, store, account, fakeIdentity(accountUuid = account, cardUuid = "00112233-4455-6677-8899-aabbccddee00"), warn)
        verifyBlocking(api, times(1)) { cardIssuer() }
        assertEquals(2, store.list(account).size)
    }

    @Test
    fun `client-side refusals come before any issuer fetch`() {
        val api = okApi(issuerOf(foreignProgram))
        vm.register(api, store, account, fakeIdentity(accountUuid = account, state = 0x01), refuse)
        assertEquals(Event.Refused(Refusal.NOT_PERSONALIZED), vm.events.value)
        verifyBlocking(api, never()) { cardIssuer() }
    }
}

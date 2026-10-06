package com.payala.impala.demo

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.model.CardResponse
import com.payala.impala.demo.model.CreateCardRequest
import com.payala.impala.demo.ui.cards.CardsViewModel
import com.payala.impala.demo.ui.cards.CardsViewModel.Event
import com.payala.impala.demo.ui.cards.CardsViewModel.Refusal
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
import org.mockito.kotlin.verifyBlocking
import org.robolectric.RobolectricTestRunner
import retrofit2.HttpException
import retrofit2.Response

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

    private fun okApi(): BridgeApiService = mock {
        onBlocking { createCard(any()) } doReturn CardResponse(true, "Card created successfully")
    }

    @Test
    fun `refuses a card whose on-card account differs from the session account and never calls POST card`() {
        val api = okApi()
        vm.register(api, store, "11111111-2222-3333-4444-555555555555", fakeIdentity(accountUuid = account))
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
        vm.register(api, store, account, identity)
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
        vm.register(api, store, account, fakeIdentity(accountUuid = account, state = 0x01))
        assertEquals(Event.Refused(Refusal.NOT_PERSONALIZED), vm.events.value)
        vm.register(api, store, account, fakeIdentity(accountUuid = account, minor = 1))
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
        }
        vm.register(api, store, account, fakeIdentity(accountUuid = account))
        assertEquals(Event.BridgeRefused("Card already registered"), vm.events.value)
        assertTrue(store.list(account).isEmpty())
    }
}

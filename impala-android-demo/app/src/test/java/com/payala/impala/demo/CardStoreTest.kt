package com.payala.impala.demo

import android.content.Context
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.model.CardResponse
import com.payala.impala.demo.ui.cards.CardsViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import java.time.Instant

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class CardStoreTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val a = "0f0e0d0c-0b0a-0908-0706-050403020100"
    private val b = "11111111-2222-3333-4444-555555555555"

    @Before
    fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After
    fun tearDown() = Dispatchers.resetMain()

    @Test
    fun `cards persist across TokenManager clearAll of a different account and are scoped by account`() {
        val store = CardStore(ctx)
        val card = StoredCard.from(fakeIdentity(accountUuid = a), Instant.parse("2026-10-05T00:00:00Z"))
        store.save(a, card)
        val tokens = TokenManager(ctx.getSharedPreferences("tokens-test", Context.MODE_PRIVATE))
        tokens.saveAccountId(b)
        tokens.clearAll()
        // A fresh store instance (as after logout/login) still has the card.
        val reopened = CardStore(ctx)
        assertEquals(listOf(card), reopened.list(a))
        assertEquals(listOf(card), reopened.list(a.replace("-", "").uppercase()))
        assertTrue(reopened.list(b).isEmpty())
        assertEquals("XLM", card.currency)
        assertEquals("0.2", card.appletVersion)
        assertEquals("01:02:03:04:05:06:07:08:09:0a", card.pubkeyFingerprint)
    }

    @Test
    fun `delete after bridge success removes the row, delete after bridge failure keeps it`() {
        val store = CardStore(ctx.getSharedPreferences("cards-del-${System.nanoTime()}", Context.MODE_PRIVATE))
        val card = StoredCard.from(fakeIdentity(accountUuid = a))
        store.save(a, card)
        val vm = CardsViewModel()

        val failing = mock<BridgeApiService> {
            onBlocking { deleteCard(any()) } doReturn CardResponse(false, "Card not found or already deleted")
        }
        vm.delete(failing, store, a, card.cardId)
        assertEquals(CardsViewModel.Event.DeleteFailed(card.cardId, "Card not found or already deleted"), vm.events.value)
        assertEquals(1, store.list(a).size)

        val ok = mock<BridgeApiService> {
            onBlocking { deleteCard(any()) } doReturn CardResponse(true, "Card deleted successfully")
        }
        vm.delete(ok, store, a, card.cardId)
        assertEquals(CardsViewModel.Event.Deleted(card.cardId), vm.events.value)
        assertTrue(store.list(a).isEmpty())
    }
}

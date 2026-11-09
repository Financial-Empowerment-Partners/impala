package com.payala.impala.demo

import android.os.Looper
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.transfer.IssuanceController
import com.payala.impala.demo.transfer.RedemptionController
import com.payala.impala.demo.ui.transfer.TransfersViewModel
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

/** Review W2 fix check: a redeem whose prepare fails zeroes the PIN it captured. */
@RunWith(RobolectricTestRunner::class)
class W2PrepareFailureTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    @Test
    fun `a failed prepare runs orElse and never then`() {
        val world = TransferWorld()
        val api: BridgeApiService = mock {
            onBlocking { cardIssuer() } doReturn world.issuerResponse(configured = false)
            onBlocking { offlineCard(any()) } doReturn world.offlineCard()
        }
        val store = freshStore()
        val vm = TransfersViewModel()
        vm.bind(RedemptionController(api, store), IssuanceController(api, store), store)
        val pin = "2468".toCharArray()
        var thenRan = false
        vm.prepareRedemption(world.cardId, orElse = { pin.fill('\u0000') }) { thenRan = true }
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse(thenRan)
        assertTrue("PIN zeroed", pin.all { it == '\u0000' })
    }
}

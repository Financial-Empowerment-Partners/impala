package com.payala.impala.demo.tap

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.payala.impala.demo.ui.tap.TapAction
import com.payala.impala.demo.ui.tap.TapPrompt
import com.payala.impala.demo.ui.tap.TapUiState
import com.payala.impala.demo.ui.tap.TapViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Review W2 (money): a host outcome that is not the parked request's own
 * (TransfersFragment's stale `watch` after the 20 s Close) lands on a newer
 * Waiting money sheet; closing that sheet must release the parked request
 * (MainActivity's onCancel delivers TapCancelledException, which zeroes the PIN).
 */
@RunWith(RobolectricTestRunner::class)
class W2MoneyReviewTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    @Test
    fun `a failure shown on a Waiting Sign sheet and then closed leaves no request parked`() {
        val vm = TapViewModel()
        var released = 0
        // MainActivity's hook: take the parked request and deliver TapCancelledException to it.
        vm.onCancel = { if (vm.take() != null) released++ }
        val signRequest = Any()
        vm.arm(TapPrompt.Sign("eeff"), simulated = false, endpoint = null)
        vm.offer(signRequest)

        // TransfersFragment.evaluateSubmitWatch / failOrSnack for an OLDER transfer.
        vm.failed("Outcome unknown - do not repeat", null, warning = true, hasRecovery = false)
        assertTrue(vm.current is TapUiState.Failed)
        assertEquals(listOf(TapAction.CLOSE), (vm.current as TapUiState.Failed).actions)

        vm.perform(TapAction.CLOSE)
        assertTrue(vm.current is TapUiState.Hidden)
        assertNull("the Sign request (and its PIN) must not stay parked once its sheet is gone", vm.peek())
        assertEquals(1, released)
    }
}

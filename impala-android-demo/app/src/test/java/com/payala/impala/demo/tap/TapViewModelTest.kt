package com.payala.impala.demo.tap

import android.os.Looper
import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.impala.sdk.apdu4j.ApduExchange
import com.payala.impala.demo.card.TapProgress
import com.payala.impala.demo.card.TapStep
import com.payala.impala.demo.offMain
import com.payala.impala.demo.ui.tap.TapAction
import com.payala.impala.demo.ui.tap.TapPrompt
import com.payala.impala.demo.ui.tap.TapUiState
import com.payala.impala.demo.ui.tap.TapViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.util.concurrent.TimeUnit

/** The activity-scoped tap owner: request hand-over, threading, stale taps, hooks, watchdog. */
@RunWith(RobolectricTestRunner::class)
class TapViewModelTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private fun select() = ApduExchange(0x00, 0xA4, 0x04, 0x00, 10, 0x9000, 0, 1_000_000, ApduExchange.Outcome.OK, 1)
    private fun signAuth() = ApduExchange(0x00, 0x25, 0x00, 0x00, 32, 0x9000, 72, 1_000_000, ApduExchange.Outcome.OK, 3)

    private fun idleMain() = shadowOf(Looper.getMainLooper()).idle()

    @Test
    fun `the parked request is taken exactly once`() {
        val vm = TapViewModel()
        val request = Any()
        vm.offer(request)
        assertSame(request, vm.peek())
        assertSame(request, vm.take())
        assertNull(vm.take())
        vm.offer(request)
        assertTrue(vm.withdraw(request))
        assertNull(vm.take())
    }

    @Test
    fun `exchanges from the card thread post to main and move Waiting to Busy with a detected haptic`() {
        val vm = TapViewModel()
        vm.arm(TapPrompt.Register, simulated = false, endpoint = null)
        vm.consumeHaptic()
        offMain { vm.onExchange(select()) }
        idleMain()
        assertTrue(vm.current is TapUiState.Busy)
        assertEquals(TapViewModel.Haptic.DETECTED, vm.consumeHaptic())
        assertNull("a haptic is consumed once", vm.consumeHaptic())
    }

    @Test
    fun `steps reported through TapProgress inside runTap reach the sheet and allow cancel for login`() {
        val vm = TapViewModel()
        var cancelled = 0
        vm.onCancel = { cancelled++ }
        vm.arm(TapPrompt.SignIn, simulated = false, endpoint = null)
        offMain { vm.runTap { TapProgress.withSink(vm::onStep) { TapProgress.report(TapStep.CONTACTING_BRIDGE) } } }
        idleMain()
        val busy = vm.current as TapUiState.Busy
        assertTrue(busy.cancelable)
        vm.cancel()
        assertSame(TapUiState.Hidden, vm.current)
        assertEquals(1, cancelled)
    }

    @Test
    fun `an abandoned tap's late exchanges never move a newer sheet`() {
        val vm = TapViewModel()
        vm.arm(TapPrompt.SignIn, simulated = false, endpoint = null)
        val started = java.util.concurrent.CountDownLatch(1)
        val gate = java.util.concurrent.CountDownLatch(1)
        val done = java.util.concurrent.CountDownLatch(1)
        val worker = Thread {
            vm.runTap {
                started.countDown()
                gate.await(10, TimeUnit.SECONDS)
                vm.onExchange(signAuth()) // still running after the user re-armed
            }
            done.countDown()
        }
        worker.start()
        assertTrue(started.await(10, TimeUnit.SECONDS))
        idleMain()
        assertTrue(vm.current is TapUiState.Busy)
        // The user cancels and asks again while the old tap is still running.
        vm.arm(TapPrompt.SignIn, simulated = false, endpoint = null)
        gate.countDown()
        assertTrue(done.await(10, TimeUnit.SECONDS))
        idleMain()
        assertTrue("the new sheet still waits for its own card: ${vm.current}", vm.current is TapUiState.Waiting)
    }

    @Test
    fun `try again re-arms through the host hook, resume closes first`() {
        val vm = TapViewModel()
        var retried = 0
        var resumed = 0
        vm.onRetry = { retried++; vm.arm(TapPrompt.Register, false, null) }
        vm.onResume = { resumed++ }
        vm.arm(TapPrompt.Register, false, null)
        vm.finishing(1)
        vm.failed("x", null, warning = false, hasRecovery = false)
        vm.perform(TapAction.TRY_AGAIN)
        assertEquals(1, retried)
        assertTrue(vm.current is TapUiState.Waiting)

        vm.arm(TapPrompt.Sign("eeff"), false, null)
        vm.finishing(1)
        vm.failed("x", null, warning = false, hasRecovery = true)
        assertEquals(listOf(TapAction.RESUME, TapAction.CLOSE), (vm.current as TapUiState.Failed).actions)
        vm.perform(TapAction.RESUME)
        assertEquals(1, resumed)
        assertSame(TapUiState.Hidden, vm.current)
    }

    @Test
    fun `dismissing a Waiting sheet cancels the request, dismissing a result just closes`() {
        val vm = TapViewModel()
        var cancelled = 0
        vm.onCancel = { cancelled++ }
        vm.arm(TapPrompt.Register, false, null)
        vm.dismissed()
        assertEquals(1, cancelled)
        vm.followUp(TapPrompt.Register, 1)
        vm.succeeded(2)
        assertEquals(TapViewModel.Haptic.SUCCESS, vm.consumeHaptic())
        vm.dismissed()
        assertSame(TapUiState.Hidden, vm.current)
        assertEquals(1, cancelled)
    }

    @Test
    fun `watchdog thresholds come from the clock`() {
        val vm = TapViewModel()
        var now = 1_000L
        vm.clock = { now }
        vm.arm(TapPrompt.Register, false, null)
        vm.finishing(1) // Busy starts at 1 000
        now = 9_000
        vm.tick()
        assertTrue((vm.current as TapUiState.Busy).slow)
        now = 21_000
        vm.tick()
        assertTrue((vm.current as TapUiState.Busy).closable)
        vm.dismissed()
        assertSame(TapUiState.Hidden, vm.current)
    }
}

package com.payala.impala.demo.tap

import com.payala.impala.demo.card.TapStep
import com.payala.impala.demo.ui.tap.TapAction
import com.payala.impala.demo.ui.tap.TapEvent
import com.payala.impala.demo.ui.tap.TapPrompt
import com.payala.impala.demo.ui.tap.TapStateMachine
import com.payala.impala.demo.ui.tap.TapUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The tap sheet's rules (design F6), on the pure reducer. */
class TapStateMachineTest {

    private val reading = 101
    private val signing = 102
    private val contacting = 103
    private val finishingLabel = 104
    private val summary = 105

    private fun run(state: TapUiState, vararg events: TapEvent): TapUiState =
        events.fold(state) { s, e -> TapStateMachine.reduce(s, e) }

    private fun armed(prompt: TapPrompt, simulated: Boolean = false) =
        TapStateMachine.reduce(TapUiState.Hidden, TapEvent.Arm(prompt, simulated, if (simulated) "127.0.0.1:9444" else null))

    private fun fail(warning: Boolean = false, recovery: Boolean = false, readerDisabled: Boolean = false) =
        TapEvent.Failed("nope", "6A80", warning, recovery, readerDisabled)

    // ── Prompts ──

    @Test
    fun `money prompts are exactly Sign and Apply`() {
        assertTrue(TapPrompt.Sign("eeff").moneyMoving)
        assertTrue(TapPrompt.Apply("eeff").moneyMoving)
        assertFalse(TapPrompt.Register.moneyMoving)
        assertFalse(TapPrompt.SignIn.moneyMoving)
        assertFalse(TapPrompt.Read("eeff").moneyMoving)
        assertFalse(TapPrompt.Read(null).moneyMoving)
        assertEquals("eeff", TapPrompt.suffixOf("00112233445566778899aabbccddeeff"))
    }

    // ── Arm, Waiting, early taps ──

    @Test
    fun `arm shows Waiting with the simulated endpoint and Waiting can be cancelled`() {
        val s = armed(TapPrompt.Register, simulated = true)
        s as TapUiState.Waiting
        assertTrue(s.simulated)
        assertEquals("127.0.0.1:9444", s.endpoint)
        assertTrue(TapStateMachine.canCancel(s))
        assertSame(TapUiState.Hidden, TapStateMachine.reduce(s, TapEvent.Cancel))
    }

    @Test
    fun `a simulated tap stays marked simulated through Busy, steps, the watchdog and finishing`() {
        var s = run(armed(TapPrompt.SignIn, simulated = true), TapEvent.TapStarted(reading))
        assertTrue((s as TapUiState.Busy).simulated)
        s = run(s, TapEvent.Exchange(signing), TapEvent.Step(TapStep.CONTACTING_BRIDGE, contacting), TapEvent.Tick(TapStateMachine.SLOW_MS))
        assertTrue((s as TapUiState.Busy).simulated)
        s = run(s, TapEvent.Finishing(finishingLabel))
        assertTrue((s as TapUiState.Busy).simulated)
        // A real card is never marked simulated, and a follow-up with no tap is not either.
        assertFalse((run(armed(TapPrompt.SignIn), TapEvent.TapStarted(reading)) as TapUiState.Busy).simulated)
        assertFalse((run(TapUiState.Hidden, TapEvent.FollowUp(TapPrompt.Register, finishingLabel)) as TapUiState.Busy).simulated)
    }

    @Test
    fun `a tapStarted that arrives before the sheet is shown still renders Busy`() {
        // The debug lane injects the tap right after arm; the sheet reads the current state when it attaches.
        val s = run(TapUiState.Hidden, TapEvent.Arm(TapPrompt.Register, true, null), TapEvent.TapStarted(reading))
        s as TapUiState.Busy
        assertEquals(reading, s.labelRes)
        assertFalse(s.finishing)
    }

    @Test
    fun `the first exchange (SELECT before onTap) moves Waiting to Busy, and a later tapStarted keeps Busy`() {
        val s = run(armed(TapPrompt.Register), TapEvent.Exchange(reading), TapEvent.TapStarted(reading))
        assertTrue(s is TapUiState.Busy)
        // An exchange with no label keeps Waiting (nothing to say yet).
        assertTrue(run(armed(TapPrompt.Register), TapEvent.Exchange(null)) is TapUiState.Waiting)
    }

    @Test
    fun `arm resets any state, including Failed`() {
        val failed = run(armed(TapPrompt.Register), TapEvent.TapStarted(reading), fail())
        assertTrue(failed is TapUiState.Failed)
        assertTrue(TapStateMachine.reduce(failed, TapEvent.Arm(TapPrompt.Register, false, null)) is TapUiState.Waiting)
    }

    // ── Rule 1: cancel ──

    @Test
    fun `cancel is refused while a card command is in flight`() {
        val busy = run(armed(TapPrompt.SignIn), TapEvent.TapStarted(reading))
        assertFalse(TapStateMachine.canCancel(busy))
        assertSame(busy, TapStateMachine.reduce(busy, TapEvent.Cancel))
    }

    @Test
    fun `cancel is allowed only while contacting the bridge in a non-money prompt`() {
        val login = run(armed(TapPrompt.SignIn), TapEvent.TapStarted(reading), TapEvent.Step(TapStep.CONTACTING_BRIDGE, contacting))
        login as TapUiState.Busy
        assertEquals(contacting, login.labelRes)
        assertTrue(login.cancelable)
        assertSame(TapUiState.Hidden, TapStateMachine.reduce(login, TapEvent.Cancel))

        // The card resumes (SIGN_AUTH): no longer cancelable.
        val signingNow = TapStateMachine.reduce(login, TapEvent.Exchange(signing)) as TapUiState.Busy
        assertEquals(signing, signingNow.labelRes)
        assertFalse(signingNow.cancelable)

        // Money prompts are never cancelable in Busy, even while contacting the bridge.
        for (prompt in listOf(TapPrompt.Sign("eeff"), TapPrompt.Apply("eeff"))) {
            val money = run(armed(prompt), TapEvent.TapStarted(reading), TapEvent.Step(TapStep.CONTACTING_BRIDGE, contacting))
            assertFalse(TapStateMachine.canCancel(money))
            assertSame(money, TapStateMachine.reduce(money, TapEvent.Cancel))
        }
    }

    @Test
    fun `finishing is never cancelable, whatever the previous step`() {
        val s = run(
            armed(TapPrompt.SignIn), TapEvent.TapStarted(reading),
            TapEvent.Step(TapStep.CONTACTING_BRIDGE, contacting), TapEvent.Finishing(finishingLabel)
        )
        s as TapUiState.Busy
        assertTrue(s.finishing)
        assertEquals(finishingLabel, s.labelRes)
        assertFalse(s.cancelable)
        // Card exchanges and steps no longer relabel a finishing sheet.
        assertSame(s, TapStateMachine.reduce(s, TapEvent.Exchange(signing)))
        assertSame(s, TapStateMachine.reduce(s, TapEvent.Step(TapStep.CONTACTING_BRIDGE, contacting)))
    }

    // ── Rule 2: watchdog ──

    @Test
    fun `watchdog says still working at 8 s and allows Close at 20 s`() {
        val busy = run(armed(TapPrompt.Register), TapEvent.TapStarted(reading))
        assertSame(busy, TapStateMachine.reduce(busy, TapEvent.Tick(7_999)))
        val slow = TapStateMachine.reduce(busy, TapEvent.Tick(8_000)) as TapUiState.Busy
        assertTrue(slow.slow)
        assertFalse(slow.closable)
        assertSame(slow, TapStateMachine.reduce(slow, TapEvent.Close))

        val closable = TapStateMachine.reduce(slow, TapEvent.Tick(20_000)) as TapUiState.Busy
        assertTrue(closable.closable)
        assertTrue(TapStateMachine.canDismiss(closable))
        assertFalse("closing is not cancelling", TapStateMachine.canCancel(closable))
        assertSame(TapUiState.Hidden, TapStateMachine.reduce(closable, TapEvent.Close))
    }

    @Test
    fun `watchdog flags survive later exchanges and finishing`() {
        val closable = run(armed(TapPrompt.Sign("eeff")), TapEvent.TapStarted(reading), TapEvent.Tick(20_000))
        val after = run(closable, TapEvent.Exchange(signing), TapEvent.Finishing(finishingLabel)) as TapUiState.Busy
        assertTrue(after.slow)
        assertTrue(after.closable)
        assertTrue(after.finishing)
    }

    @Test
    fun `a money sheet closed by the watchdog cancels nothing and ignores the late outcome`() {
        val closed = run(armed(TapPrompt.Sign("eeff")), TapEvent.TapStarted(reading), TapEvent.Tick(20_000), TapEvent.Close)
        assertSame(TapUiState.Hidden, closed)
        for (late in listOf(TapEvent.Finishing(finishingLabel), TapEvent.Succeeded(summary), fail(), TapEvent.Exchange(signing), TapEvent.TapStarted(reading))) {
            assertSame(TapUiState.Hidden, TapStateMachine.reduce(closed, late))
        }
    }

    // ── Rules 3 to 5: failure actions ──

    @Test
    fun `Sign and Apply failures never carry TRY_AGAIN`() {
        for (prompt in listOf(TapPrompt.Sign("eeff"), TapPrompt.Apply("eeff"))) {
            for (recovery in listOf(true, false)) for (warning in listOf(true, false)) for (nfcOff in listOf(true, false)) {
                val s = run(armed(prompt), TapEvent.TapStarted(reading), fail(warning, recovery, nfcOff)) as TapUiState.Failed
                assertFalse("$prompt recovery=$recovery warning=$warning nfcOff=$nfcOff", TapAction.TRY_AGAIN in s.actions)
                assertTrue(TapAction.CLOSE in s.actions)
            }
        }
    }

    @Test
    fun `money failures offer Resume only when a recovery slot exists`() {
        val withSlot = run(armed(TapPrompt.Sign("eeff")), TapEvent.TapStarted(reading), fail(recovery = true)) as TapUiState.Failed
        assertEquals(listOf(TapAction.RESUME, TapAction.CLOSE), withSlot.actions)
        val noSlot = run(armed(TapPrompt.Apply("eeff")), TapEvent.TapStarted(reading), fail(recovery = false)) as TapUiState.Failed
        assertEquals(listOf(TapAction.CLOSE), noSlot.actions)
    }

    @Test
    fun `non-money failures offer Try again and Close`() {
        for (prompt in listOf(TapPrompt.Register, TapPrompt.SignIn, TapPrompt.Read("eeff"), TapPrompt.Read(null))) {
            val s = run(armed(prompt), TapEvent.TapStarted(reading), fail()) as TapUiState.Failed
            assertEquals(listOf(TapAction.TRY_AGAIN, TapAction.CLOSE), s.actions)
            assertEquals("nope", s.message.toString())
            assertEquals("6A80", s.swHex)
        }
    }

    @Test
    fun `an ambiguous outcome is a warning with Close only`() {
        for (prompt in listOf(TapPrompt.Sign("eeff"), TapPrompt.Register)) {
            val s = run(armed(prompt), TapEvent.TapStarted(reading), TapEvent.Finishing(finishingLabel), fail(warning = true, recovery = true)) as TapUiState.Failed
            assertTrue(s.warning)
            assertEquals(listOf(TapAction.CLOSE), s.actions)
        }
    }

    @Test
    fun `NFC off fails straight from Waiting with Open NFC settings`() {
        val s = run(armed(TapPrompt.Register), fail(readerDisabled = true)) as TapUiState.Failed
        assertEquals(listOf(TapAction.OPEN_NFC_SETTINGS, TapAction.CLOSE), s.actions)
        // A money prompt still never offers Try again, and keeps the settings action.
        val m = run(armed(TapPrompt.Sign("eeff")), fail(readerDisabled = true)) as TapUiState.Failed
        assertEquals(listOf(TapAction.OPEN_NFC_SETTINGS, TapAction.CLOSE), m.actions)
    }

    // ── Rule 6: Done only after the real outcome ──

    @Test
    fun `Done only follows Succeeded, after the card half and the bridge follow-up`() {
        val waiting = armed(TapPrompt.Register)
        assertSame("no Done before the card was even read", waiting, TapStateMachine.reduce(waiting, TapEvent.Succeeded(summary)))
        val finishing = run(waiting, TapEvent.TapStarted(reading), TapEvent.Finishing(finishingLabel))
        assertTrue(finishing is TapUiState.Busy)
        val done = TapStateMachine.reduce(finishing, TapEvent.Succeeded(summary)) as TapUiState.Done
        assertEquals(summary, done.summaryRes)
        assertSame(TapPrompt.Register, done.prompt)
        assertTrue(TapStateMachine.canDismiss(done))
        assertSame(TapUiState.Hidden, TapStateMachine.reduce(done, TapEvent.Close))
        // A failure after Done changes nothing (the outcome is already known).
        assertSame(done, TapStateMachine.reduce(done, fail()))
    }

    @Test
    fun `a follow-up with no tap shows Finishing from Hidden and then the outcome`() {
        val s = TapStateMachine.reduce(TapUiState.Hidden, TapEvent.FollowUp(TapPrompt.Register, finishingLabel)) as TapUiState.Busy
        assertTrue(s.finishing)
        assertFalse(s.cancelable)
        assertTrue(TapStateMachine.reduce(s, TapEvent.Succeeded(summary)) is TapUiState.Done)
    }

    // ── Host-driven transitions ──

    @Test
    fun `drop hides a Waiting sheet only, hide hides any sheet`() {
        assertSame(TapUiState.Hidden, TapStateMachine.reduce(armed(TapPrompt.Register), TapEvent.Drop))
        val busy = run(armed(TapPrompt.Register), TapEvent.TapStarted(reading))
        assertSame(busy, TapStateMachine.reduce(busy, TapEvent.Drop))
        assertSame(TapUiState.Hidden, TapStateMachine.reduce(busy, TapEvent.Hide))
    }

    @Test
    fun `a Busy sheet cannot be dismissed until it may be cancelled or closed`() {
        val busy = run(armed(TapPrompt.Sign("eeff")), TapEvent.TapStarted(reading))
        assertFalse(TapStateMachine.canDismiss(busy))
        assertTrue(TapStateMachine.canDismiss(armed(TapPrompt.Sign("eeff"))))
        assertTrue(TapStateMachine.canDismiss(run(busy, fail())))
    }
}

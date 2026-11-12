package com.payala.impala.demo

import android.app.Activity
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.payala.impala.demo.card.DebugCards
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.ui.login.LoginActivity
import com.payala.impala.demo.ui.main.MainActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * T2 card UI lane (C-11): the real login screen with the simulated card
 * served by impala-card's SimulatorApduServer over the debug TCP transport
 * (the emulator has no NFC). Orchestrated by scripts/card-ui-e2e.sh, which
 * issues the card through a live bridge, sets `debug.impala.tcp_card`, and
 * passes `-e cardAccount <uuid>`. Skips when not orchestrated.
 *
 * `-e cardMechanism sep10|legacy` also asserts HOW the card signed in, from
 * the app's own Activity Log: `sep10` when the bridge offers SEP-10 and knows
 * the card's Stellar key (the whole exchange ran in the tap), `legacy` when
 * the tap used the `SIGN_AUTH` challenge. Without the argument either is
 * accepted, as before.
 */
@RunWith(AndroidJUnit4::class)
class CardLoginUiTest {
    private val args = InstrumentationRegistry.getArguments()
    private val app get() = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as ImpalaApp

    @Before
    fun setUp() {
        assumeTrue("not orchestrated: run scripts/card-ui-e2e.sh", args.getString("cardAccount") != null)
        assumeTrue("debug.impala.tcp_card is not set", DebugCards.isConfigured())
        app.tokenManager.clearAll()
        AppLogger.clear()
    }

    @Test
    fun signInWithCardLandsOnMainWithTheCardAccount() {
        ActivityScenario.launch(LoginActivity::class.java).use {
            onView(withId(R.id.btnCard)).perform(click())
            assertTrue("MainActivity was not reached", awaitResumed(MainActivity::class.java, 45_000))
            assertEquals(args.getString("cardAccount"), app.tokenManager.getAccountId())
            assertEquals("card", app.tokenManager.getAuthProvider())
            val log = AppLogger.getEntries().map { it.message }
            val usedSep10 = log.any { it == SEP10_LINE }
            val usedLegacy = log.any { it.startsWith(LEGACY_FALLBACK_PREFIX) }
            when (val expected = args.getString("cardMechanism")) {
                null -> Unit
                "sep10" -> {
                    assertTrue("the card login did not use SEP-10; Activity Log: $log", usedSep10)
                    assertFalse("the card login fell back to the legacy challenge; Activity Log: $log", usedLegacy)
                }
                "legacy" -> assertFalse("the card login used SEP-10, the legacy challenge was expected; Activity Log: $log", usedSep10)
                else -> fail("cardMechanism must be sep10 or legacy, not $expected")
            }
        }
    }

    private companion object {
        /** LoginViewModel.signInWithCardTap's lines for the two outcomes of a tap. */
        const val SEP10_LINE = "Card signed a SEP-10 challenge"
        const val LEGACY_FALLBACK_PREFIX = "Card login used the legacy challenge"
    }

    private fun awaitResumed(type: Class<out Activity>, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            var found = false
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                found = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED).any { type.isInstance(it) }
            }
            if (found) return true
            Thread.sleep(250)
        }
        return false
    }
}

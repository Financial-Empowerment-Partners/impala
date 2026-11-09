package com.payala.impala.demo.card

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.impala.sdk.flows.UuidBytes
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.model.CardChallengeResponse
import com.payala.impala.demo.offMain
import com.payala.impala.demo.ui.login.LoginViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.doSuspendableAnswer
import org.mockito.kotlin.mock
import org.robolectric.RobolectricTestRunner
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * [TapProgress]: the sink lives exactly as long as one `onTap`, on its thread,
 * and a sink failure never breaks the tap. The last test drives the real
 * card-login tap on jcardsim: CONTACTING_BRIDGE is reported after the card is
 * read and before the challenge request leaves.
 */
@RunWith(RobolectricTestRunner::class)
class TapProgressTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    @Test
    fun `report outside a sink is a no-op`() {
        TapProgress.report(TapStep.CONTACTING_BRIDGE) // must not throw
    }

    @Test
    fun `the sink receives reports only while its block runs`() {
        val seen = ArrayList<TapStep>()
        val result = TapProgress.withSink({ seen += it }) {
            TapProgress.report(TapStep.CONTACTING_BRIDGE)
            42
        }
        assertEquals(42, result)
        TapProgress.report(TapStep.CONTACTING_BRIDGE)
        assertEquals(listOf(TapStep.CONTACTING_BRIDGE), seen)
    }

    @Test
    fun `the sink is cleared in finally when the tap throws`() {
        val seen = ArrayList<TapStep>()
        assertThrows(IllegalStateException::class.java) {
            TapProgress.withSink({ seen += it }) { error("card left the field") }
        }
        TapProgress.report(TapStep.CONTACTING_BRIDGE)
        assertTrue("a thrown tap must not leave its sink installed", seen.isEmpty())
    }

    @Test
    fun `two sequential taps on one thread do not leak into each other`() {
        val first = ArrayList<TapStep>()
        val second = ArrayList<TapStep>()
        val worker = Executors.newSingleThreadExecutor()
        try {
            worker.submit { TapProgress.withSink({ first += it }) { TapProgress.report(TapStep.CONTACTING_BRIDGE) } }
                .get(5, TimeUnit.SECONDS)
            worker.submit { TapProgress.withSink({ second += it }) { TapProgress.report(TapStep.CONTACTING_BRIDGE) } }
                .get(5, TimeUnit.SECONDS)
            worker.submit { TapProgress.report(TapStep.CONTACTING_BRIDGE) }.get(5, TimeUnit.SECONDS)
        } finally {
            worker.shutdown()
        }
        assertEquals(1, first.size)
        assertEquals(1, second.size)
    }

    @Test
    fun `a sink on another thread never sees this thread's reports`() {
        val seen = CopyOnWriteArrayList<TapStep>()
        TapProgress.withSink({ seen += it }) {
            offMain { TapProgress.report(TapStep.CONTACTING_BRIDGE) }
        }
        assertTrue(seen.isEmpty())
    }

    @Test
    fun `nested sinks restore the outer sink`() {
        val outer = ArrayList<TapStep>()
        val inner = ArrayList<TapStep>()
        TapProgress.withSink({ outer += it }) {
            TapProgress.withSink({ inner += it }) { TapProgress.report(TapStep.CONTACTING_BRIDGE) }
            TapProgress.report(TapStep.CONTACTING_BRIDGE)
        }
        assertEquals(1, outer.size)
        assertEquals(1, inner.size)
    }

    @Test
    fun `a throwing sink does not fail the tap`() {
        val value = TapProgress.withSink({ throw IllegalStateException("UI gone") }) {
            TapProgress.report(TapStep.CONTACTING_BRIDGE)
            "signed"
        }
        assertEquals("signed", value)
    }

    @Test
    fun `card login reports CONTACTING_BRIDGE before the challenge request`() {
        val events = CopyOnWriteArrayList<String>()
        val api = mock<BridgeApiService> {
            on { cardChallenge(any()) } doSuspendableAnswer {
                events += "challenge-request"
                CardChallengeResponse(true, "a5".repeat(32), 60)
            }
        }
        val card = personalizedCard(TestIssuer(), UuidBytes.parse(UUID.randomUUID().toString()))
        offMain {
            TapProgress.withSink({ events += it.name }) {
                LoginViewModel().signInWithCardTap(ImpalaCardSession.fromBibo(card.bibo), api)
            }
        }
        assertEquals(listOf("CONTACTING_BRIDGE", "challenge-request"), events.toList())
    }
}

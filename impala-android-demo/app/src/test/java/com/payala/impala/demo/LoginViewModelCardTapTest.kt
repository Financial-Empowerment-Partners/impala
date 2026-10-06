package com.payala.impala.demo

import androidx.arch.core.executor.testing.InstantTaskExecutorRule
import com.impala.sdk.ImpalaSDK
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.simulator.Jca
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.model.CardChallengeResponse
import com.payala.impala.demo.ui.login.LoginViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.robolectric.RobolectricTestRunner
import java.util.UUID

/**
 * The card half of card login ([LoginViewModel.signInWithCardTap]) against the
 * real applet on jcardsim: the gates run before any bridge call, and the
 * signature the bridge receives verifies over the pinned AUTH message.
 */
@RunWith(RobolectricTestRunner::class)
class LoginViewModelCardTapTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private val challengeHex = "a5".repeat(32)
    private fun api(): BridgeApiService = mock {
        onBlocking { cardChallenge(any()) } doReturn CardChallengeResponse(true, challengeHex, 60)
    }

    @Test
    fun `card login refuses an unpersonalized card before requesting a challenge`() {
        val api = api()
        // Initialized (has a key) but never personalized.
        val bibo = SimulatorBibo().also { ImpalaSDK(it).setSeed() }
        val e = assertThrows(CardFlowException::class.java) {
            offMain { LoginViewModel().signInWithCardTap(ImpalaCardSession.fromBibo(bibo), api) }
        }
        assertSame(CardError.NotPersonalized, e.error)
        org.mockito.kotlin.verifyBlocking(api, never()) { cardChallenge(any()) }

        // Blank card (no key yet): same typed refusal, still no challenge.
        val blank = assertThrows(CardFlowException::class.java) {
            offMain { LoginViewModel().signInWithCardTap(ImpalaCardSession.fromBibo(SimulatorBibo()), api) }
        }
        assertSame(CardError.NotPersonalized, blank.error)
        org.mockito.kotlin.verifyBlocking(api, never()) { cardChallenge(any()) }
    }

    @Test
    fun `personalized card signs the bridge challenge over the pinned AUTH message`() {
        val account = UuidBytes.parse(UUID.randomUUID().toString())
        val card = personalizedCard(TestIssuer(), account)
        val api = api()
        val tap = offMain { LoginViewModel().signInWithCardTap(ImpalaCardSession.fromBibo(card.bibo), api) }
        assertEquals(UuidBytes.format(account), tap.identity.accountUuid)
        val msg = "IMPALA-AUTH:".encodeToByteArray() + account + Hex.decode(challengeHex)
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), msg, Hex.decode(tap.signatureHex)))
        org.mockito.kotlin.verifyBlocking(api) { cardChallenge(com.payala.impala.demo.model.CardChallengeRequest(tap.identity.wireCardId)) }
    }
}

package com.payala.impala.card

import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.stellar.Ed25519
import com.payala.impala.stellar.HttpSep10Transport
import com.payala.impala.stellar.Sep10Client
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Opt-in conformance run of the CARD against a SEP-10 server nobody here
 * wrote: the SDF reference anchor (https://testanchor.stellar.org, testnet).
 * The real applet under jcardsim, for each Ed25519 engine, parses the anchor's
 * challenge with its own on-card rules and signs it, and the anchor accepts
 * the signature and issues a token. Skipped unless IMPALA_SEP10_LIVE=1; run
 * with `--rerun` so a cached skipped result is not reused.
 */
@RunWith(RobolectricTestRunner::class)
class CardSep10LiveTest {
    @Test
    fun `the reference anchor accepts a challenge signed by the card`() {
        assumeTrue("set IMPALA_SEP10_LIVE=1 to run", System.getenv("IMPALA_SEP10_LIVE") == "1")
        for (engine in listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)) {
            val card = personalizedCard(TestIssuer(), uuidBytes(), ed25519 = engine)
            val commands = mutableListOf<Int>()
            card.bibo.debugTrace = { cmd, _ -> commands += cmd[1].toInt() and 0xFF }
            val client = Sep10Client("testanchor.stellar.org", "Test SDF Network ; September 2015", HttpSep10Transport(), Ed25519)
            val signIn = CardSignIn(client) { error("the reference anchor offers SEP-10: no legacy challenge expected") }
            val result = offMain { ImpalaCardSession.fromBibo(card.bibo).use { signIn.signIn(it) } }
            assertEquals(engine, CardAuthMechanism.SEP10, result.mechanism)
            val token = Regex("\"token\"\\s*:\\s*\"([^\"]+)\"").find((result as CardSignInResult.Sep10).tokenJson)!!.groupValues[1]
            assertEquals("a JWT", 2, token.count { it == '.' })
            assertTrue(0x38 in commands)
            println("SEP-10 live, $engine engine: ${result.stellarAddress} signed in at testanchor.stellar.org (token of ${token.length} characters)")
        }
    }
}

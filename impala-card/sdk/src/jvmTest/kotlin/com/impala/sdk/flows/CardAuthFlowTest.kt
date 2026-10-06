package com.impala.sdk.flows

import com.impala.sdk.ImpalaSDK
import com.impala.simulator.Jca
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class CardAuthFlowTest {
    @Test
    fun `signature over the bridge challenge verifies host-side over IMPALA-AUTH prefix + account + challenge`() {
        val account = uuidBytes()
        val card = personalizedCard(TestIssuer(), account)
        val identity = CardIdentity.read(card.sdk)
        assertEquals(UuidBytes.format(account), identity.accountUuid)
        assertEquals(130, identity.pubKeyHex.length)
        assertEquals(32, identity.wireCardId.length)

        val challengeHex = "a1".repeat(32)
        val sigHex = CardAuthFlow.sign(card.sdk, challengeHex)
        assertEquals(sigHex, sigHex.lowercase())
        val msg = "IMPALA-AUTH:".encodeToByteArray() + account + Hex.decode(challengeHex)
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(identity.pubKey), msg, Hex.decode(sigHex)))
    }

    @Test
    fun `unpersonalized card yields CardError NotPersonalized, not a raw status word`() {
        val sdk = ImpalaSDK(SimulatorBibo())
        sdk.setSeed()
        val e = assertFailsWith<CardFlowException> { CardAuthFlow.sign(sdk, "00".repeat(32)) }
        assertIs<CardError.NotPersonalized>(e.error)
        assertEquals("card_error_not_personalized", e.error.userMessageKey)

        val blank = ImpalaSDK(SimulatorBibo())
        val e2 = assertFailsWith<CardFlowException> { CardIdentity.read(blank) }
        assertIs<CardError.NotPersonalized>(e2.error)
    }

    @Test
    fun `challenge outside 8 to 64 bytes or not hex is refused before any APDU`() {
        var sent = 0
        val bibo = SimulatorBibo().apply { debugTrace = { _, _ -> sent++ } }
        val sdk = ImpalaSDK(bibo)
        for (bad in listOf("00".repeat(7), "00".repeat(65), "zz".repeat(16), "abc")) {
            val e = assertFailsWith<CardFlowException> { CardAuthFlow.sign(sdk, bad) }
            assertIs<CardError.InvalidRequest>(e.error)
        }
        assertEquals(0, sent)
    }
}

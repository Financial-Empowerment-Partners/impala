package com.impala.simulator

import com.impala.sdk.ImpalaSDK
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DistinctKeysTest {
    @Test
    fun `every simulated card gets its own key, and it signs verifiably`() {
        val keys = (1..3).map { ImpalaSDK(SimulatorBibo()).apply { setSeed() }.getECPubKey().hex() }
        assertEquals(3, keys.toSet().size, "simulated cards must not share a key: $keys")
        val account = java.nio.ByteBuffer.allocate(16).putLong(UUID.randomUUID().mostSignificantBits).putLong(1).array()
        val card = personalizedCard(TestIssuer(), account)
        val challenge = ByteArray(16) { 7 }
        val sig = card.sdk.signAuthChallenge(challenge).toByteArray()
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), "IMPALA-AUTH:".encodeToByteArray() + account + challenge, sig))
    }
}

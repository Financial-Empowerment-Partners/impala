package com.impala.simulator

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.models.TransferProtocol
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SimulatorModuleTest {
    @Test
    fun `simulator module installs the applet under the instance AID and answers GET_VERSION 0_2`() {
        val sdk = ImpalaSDK(SimulatorBibo())
        assertEquals("01020304050607080102", SimulatorBibo.APPLET_INSTANCE_AID)
        val v = sdk.requireCertifiedProtocol()
        assertEquals(0, v.major.toInt())
        assertEquals(2, v.minor.toInt())
    }

    @Test
    fun `personalized card signs auth over the pinned message and its certificate verifies under the issuer`() {
        val issuer = TestIssuer()
        val account = uuidBytes(UUID.randomUUID())
        val card = personalizedCard(issuer, account, TransferProtocol.CURRENCY_XLM)
        val p = card.sdk.getPersonalization()
        assertTrue(p.personalized && p.pinProvisioned && !p.scp03KeysDefault)
        assertContentEquals(issuer.programId, p.programId)

        val certMsg = TransferProtocol.certMessage(issuer.programId, account, TransferProtocol.CURRENCY_XLM, card.pub65)
        assertTrue(Jca.verifyP256(issuer.keys.public, certMsg, card.cert))

        val challenge = ByteArray(32) { it.toByte() }
        val sig = card.sdk.signAuthChallenge(challenge).toByteArray()
        val msg = "IMPALA-AUTH:".encodeToByteArray() + account + challenge
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), msg, sig))
    }

    @Test
    fun `debug trace masks the PIN of SIGN_TRANSFER_V2`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, uuidBytes(UUID.randomUUID()), userPin = "4321")
        val seen = mutableListOf<ByteArray>()
        card.bibo.debugTrace = { cmd, _ -> seen += cmd }
        runCatching { card.sdk.signTransferV2("4321", ByteArray(60)) }
        val cmd = seen.single()
        assertEquals(0x30, cmd[1].toInt())
        assertContentEquals(ByteArray(4) { 0x2A }, cmd.copyOfRange(5, 9))
    }

    private fun uuidBytes(u: UUID): ByteArray =
        java.nio.ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()
}

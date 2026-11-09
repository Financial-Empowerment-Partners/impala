package com.payala.impala.card

import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CardCertificatesTest {
    private val issuer = TestIssuer()
    private val account = uuidBytes()
    private val card = personalizedCard(issuer, account)
    private val usdc = TransferProtocol.CURRENCY_USDC

    @Test
    fun `a card's certificate verifies under its issuer key`() {
        assertTrue(CardCertificates.verify(issuer.pub65, issuer.programId, account, usdc, card.pub65, card.cert))
    }

    @Test
    fun `a tampered certificate, another issuer or another field does not verify`() {
        val tampered = card.cert.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFalse(CardCertificates.verify(issuer.pub65, issuer.programId, account, usdc, card.pub65, tampered))
        assertFalse(CardCertificates.verify(TestIssuer().pub65, issuer.programId, account, usdc, card.pub65, card.cert))
        assertFalse(CardCertificates.verify(issuer.pub65, TestIssuer.randomProgramId(), account, usdc, card.pub65, card.cert))
        assertFalse(CardCertificates.verify(issuer.pub65, issuer.programId, uuidBytes(), usdc, card.pub65, card.cert))
        assertFalse(CardCertificates.verify(issuer.pub65, issuer.programId, account, TransferProtocol.CURRENCY_XLM, card.pub65, card.cert))
    }

    @Test
    fun `malformed input is false, never an exception`() {
        assertFalse(CardCertificates.verify(ByteArray(65), issuer.programId, account, usdc, card.pub65, card.cert))
        assertFalse(CardCertificates.verify(issuer.pub65.copyOf(64), issuer.programId, account, usdc, card.pub65, card.cert))
        assertFalse(CardCertificates.verify(issuer.pub65, issuer.programId.copyOf(15), account, usdc, card.pub65, card.cert))
        assertFalse(CardCertificates.verify(issuer.pub65, issuer.programId, account, usdc, card.pub65, byteArrayOf(0x30, 0x00)))
        assertFalse(CardCertificates.verify(issuer.pub65, issuer.programId, account, usdc, card.pub65, ByteArray(0)))
    }

    @Test
    fun `fingerprint is the first 10 bytes of sha256 as colon-separated lower-case hex`() {
        val fp = CardCertificates.fingerprint(issuer.pub65)
        assertTrue(fp, fp.matches(Regex("""[0-9a-f]{2}(:[0-9a-f]{2}){9}""")))
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(issuer.pub65)
        assertEquals(sha.copyOf(10).joinToString(":") { "%02x".format(it) }, fp)
        assertNotEquals(fp, CardCertificates.fingerprint(card.pub65))
    }
}

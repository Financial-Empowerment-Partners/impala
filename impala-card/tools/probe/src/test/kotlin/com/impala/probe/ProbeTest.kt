package com.impala.probe

import com.impala.jcardsim.jc31.CardPlatform
import com.licel.jcardsim.smartcardio.CardSimulator
import com.licel.jcardsim.utils.AIDUtil
import javacard.security.KeyBuilder
import javacardx.crypto.Cipher
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The probe on simulated card models: it must name exactly what each model lacks. */
class ProbeTest {
    private fun probe(platform: CardPlatform): Pair<List<Finding>, Verdict> {
        val card = platform.newCard()
        val simulator = CardSimulator()
        val aid = AIDUtil.create(Probe.APPLET_AID)
        card.execute {
            simulator.installApplet(aid, ProbeApplet::class.java)
            simulator.selectApplet(aid)
        }
        val result = Probe { cmd -> card.call { simulator.transmitCommand(cmd) } }.run()
        println("=== ${platform.name()}")
        print(Probe.render(result.first, result.second))
        return result
    }

    @Test
    fun `the numbers the host sends are the API's`() {
        assertEquals(KeyBuilder.TYPE_RSA_PUBLIC.toInt(), Probe.TYPE_RSA_PUBLIC)
        assertEquals(KeyBuilder.TYPE_EC_FP_PUBLIC.toInt(), Probe.TYPE_EC_FP_PUBLIC)
        assertEquals(KeyBuilder.TYPE_EC_FP_PRIVATE.toInt(), Probe.TYPE_EC_FP_PRIVATE)
        assertEquals(KeyBuilder.TYPE_AES.toInt(), Probe.TYPE_AES)
        assertEquals(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT.toInt(), Probe.TYPE_AES_TRANSIENT_DESELECT)
        assertEquals(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET.toInt(), Probe.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET)
        assertEquals(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT.toInt(), Probe.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT)
        assertEquals(Cipher.ALG_RSA_NOPAD.toInt(), Probe.ALG_RSA_NOPAD)
        assertTrue(Probe.WEI.onCurve(Probe.WEI.g) && Probe.P256.onCurve(Probe.P256.g))
        assertEquals(null, Probe.WEI.mul(Probe.WEI.r, Probe.WEI.g))
        assertEquals(null, Probe.P256.mul(Probe.P256.r, Probe.P256.g))
    }

    @Test
    fun `a full JavaCard 3_0_5 card has everything the soft engine needs`() {
        val (findings, v) = probe(CardPlatform.JC305)
        assertTrue(v.softEngineRuns, v.lines().joinToString("\n"))
        // Every checked line is right on a card with everything, except what jcardsim itself lacks.
        val wrong = findings.filter { it.ok == false && it.detail.contains("WRONG") }
        assertTrue(wrong.isEmpty(), "wrong answers: $wrong")
    }

    @Test
    fun `a card without the XY key agreement is told from one without curve arithmetic`() {
        val (_, noXy) = probe(CardPlatform.JC305_NO_XY)
        assertFalse(noXy.softEngineRuns)
        assertFalse(noXy.ecdhXy)
        assertTrue(noXy.ecdhX, "the X-only ECDH is still there")
        assertTrue(noXy.sha512 && noXy.aes256)

        val (_, fixed) = probe(CardPlatform.JC305_FIXED_CURVES)
        assertFalse(fixed.softEngineRuns)
        assertFalse(fixed.ecdhXy || fixed.ecdhX, "no ECDH on a custom curve")

        val (findings, wrong) = probe(CardPlatform.JC305_WRONG_CURVE_MATH)
        assertFalse(wrong.softEngineRuns)
        assertFalse(wrong.ecdhXy, "a wrong answer is not a present primitive")
        assertTrue(findings.any { it.detail.startsWith("WRONG") })
    }

    @Test
    fun `a missing digest or key object is named`() {
        val (_, noSha) = probe(CardPlatform.JC305_NO_SHA512)
        assertFalse(noSha.sha512)
        assertTrue(noSha.ecdhXy && noSha.aes256)
        assertFalse(noSha.softEngineRuns)

        val (_, noAes) = probe(CardPlatform.JC305_NO_AES256)
        assertFalse(noAes.aes256)
        assertTrue(noAes.ecdhXy && noAes.sha512)
        assertFalse(noAes.softEngineRuns)
    }
}

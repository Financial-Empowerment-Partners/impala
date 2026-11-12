package com.impala.sdk

import com.impala.jcardsim.jc31.CardPlatform
import com.impala.sdk.Sep10TestXdr.challenge
import com.impala.sdk.Sep10TestXdr.ed25519Verify
import com.impala.sdk.Sep10TestXdr.networkId
import com.impala.sdk.Sep10TestXdr.signatureBase
import com.impala.sdk.models.ImpalaException
import com.impala.simulator.CapNotLoadableException
import com.impala.simulator.CapVariant
import com.impala.simulator.SimulatorBibo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The real applet on simulated hardware: each CAP variant
 * (`-Papplet.ed25519=soft|native|none`) on each card model the simulator has,
 * from a JavaCard 3.0.5 card to a JavaCard 3.2 card, and on the cards that
 * lack one of the optional pieces.
 *
 * The contract it pins (impala-card/README.md, "Platform dependencies"):
 * a CAP built for a later level does not load; a card that loads its CAP but
 * lacks a piece of the Ed25519 engine installs and works as a legacy card;
 * every other card signs SEP-10 challenges that the JDK verifies; and the
 * P-256 card login works on all of them.
 */
class CardHardwareInteropTest {
    private val server = ByteArray(32) { (0xC0 + it).toByte() }
    private val testnet = networkId()

    private fun account(n: Int) = ByteArray(16) { (n * 16 + it + 1).toByte() }

    private fun card(platform: CardPlatform?, variant: String?, n: Int = 1): PersonalizedCard =
        personalizedCard(TestIssuer(), account(n), ed25519 = variant, platform = platform)

    private fun bibo(card: PersonalizedCard) = card.bibo as SimulatorBibo

    /** What a personalized card does on any hardware: the P-256 challenge login (`SIGN_AUTH`). */
    private fun assertCardLoginWorks(card: PersonalizedCard, what: String) {
        val nonce = ByteArray(32) { (it * 5 + 1).toByte() }
        val signature = card.sdk.signAuthChallenge(nonce).toByteArray()
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), "IMPALA-AUTH:".encodeToByteArray() + card.accountId + nonce, signature), "$what: SIGN_AUTH")
    }

    /** A card with a Stellar key made by [engine]: bound at personalization, and it signs a SEP-10 challenge the JDK verifies. */
    private fun assertSignsSep10(card: PersonalizedCard, engine: String, what: String) {
        val key = assertNotNull(card.sdk.getStellarKey(), "$what: a Stellar key")
        assertEquals(engine, key.engineName, "$what: the engine")
        assertTrue(key.isBound, "$what: cross-signed at PERSONALIZE")
        assertTrue(card.sdk.getPersonalization().stellarKey, "$what: flag 0x80")
        val tx = challenge(key.publicKey, server)
        val signature = card.sdk.signSep10(testnet, tx)
        assertTrue(ed25519Verify(key.publicKey, signatureBase(testnet, tx), signature), "$what: the SEP-10 signature is Ed25519")
        assertCardLoginWorks(card, what)
    }

    /** A card without a Stellar key: it says so, refuses SEP-10 and does everything a legacy card does. */
    private fun assertLegacyCard(card: PersonalizedCard, what: String) {
        assertNull(card.sdk.getStellarKey(), "$what: no Stellar key")
        val p = card.sdk.getPersonalization()
        assertTrue(p.personalized, "$what: personalized all the same")
        assertFalse(p.stellarKey, "$what: flag 0x80 clear")
        assertEquals(0x623C, swOf(card.bibo.transceive(byteArrayOf(0x00, Constants.INS_GET_STELLAR_KEY, 0, 0))), "$what: GET_STELLAR_KEY")
        val refused = assertFailsWith<ImpalaException> { card.sdk.signSep10(testnet, challenge(ByteArray(32) { 1 }, server)) }
        assertEquals(0x623C, refused.statusWord, "$what: SIGN_SEP10")
        assertCardLoginWorks(card, what)
    }

    // ------------------------------------------------------------------ the two hardware classes

    @Test
    fun `a JavaCard 3_0_5 card runs the software engine and a JavaCard 3_2 card its own EdDSA`() {
        // Name the hardware and the CAP an operator would load on it follows.
        val old = card(CardPlatform.JC305, null, 1)
        assertEquals(CapVariant.SOFT, bibo(old).capVariant)
        assertEquals(CardPlatform.JC305, bibo(old).platform)
        assertSignsSep10(old, "soft", "JavaCard 3.0.5")

        val new = card(CardPlatform.JC32, null, 2)
        assertEquals(CapVariant.NATIVE, bibo(new).capVariant)
        assertEquals(CardPlatform.JC32, bibo(new).platform)
        assertSignsSep10(new, "native", "JavaCard 3.2")

        // Two cards, two keys, and neither accepts a challenge for the other.
        val oldKey = old.sdk.getStellarKey()!!.publicKey
        val newKey = new.sdk.getStellarKey()!!.publicKey
        assertFalse(oldKey.contentEquals(newKey))
        assertFailsWith<ImpalaException> { old.sdk.signSep10(testnet, challenge(newKey, server)) }
        assertFailsWith<ImpalaException> { new.sdk.signSep10(testnet, challenge(oldKey, server)) }
    }

    // ------------------------------------------------------------------ the matrix

    @Test
    fun `every CAP on every card model that loads it`() {
        val soft = "soft"
        val native = "native"
        // hardware, CAP, the engine behind the card's Stellar key (null: a legacy card)
        val expected: List<Triple<CardPlatform, String, String?>> = listOf(
            // JavaCard 3.0.5 with everything the software engine needs
            Triple(CardPlatform.JC305, "soft", soft),
            Triple(CardPlatform.JC305, "none", null),
            // JavaCard 3.0.5 lacking one piece: the card installs, and is a legacy card
            Triple(CardPlatform.JC305_NO_XY, "soft", null),
            Triple(CardPlatform.JC305_NO_SHA512, "soft", null),
            Triple(CardPlatform.JC305_NO_AES256, "soft", null),
            Triple(CardPlatform.JC305_FIXED_CURVES, "soft", null),
            Triple(CardPlatform.JC305_WRONG_CURVE_MATH, "soft", null),
            Triple(CardPlatform.JC305_SMALL_RAM, "soft", null),
            Triple(CardPlatform.JC305_TIGHT_RAM, "soft", null),
            Triple(CardPlatform.JC305_NO_XY, "none", null),
            // JavaCard 3.1
            Triple(CardPlatform.JC31, "native", native),
            Triple(CardPlatform.JC31, "soft", soft),
            Triple(CardPlatform.JC31, "none", null),
            Triple(CardPlatform.JC31_SHA512, "native", native),
            Triple(CardPlatform.JC31_SHA512, "soft", soft),
            // JavaCard 3.2: its EdDSA under either name, and the software engine as on any older card
            Triple(CardPlatform.JC32, "native", native),
            Triple(CardPlatform.JC32, "soft", soft),
            Triple(CardPlatform.JC32, "none", null),
            Triple(CardPlatform.JC32_PER_CURVE, "native", native),
            Triple(CardPlatform.JC32_PER_CURVE, "soft", soft),
            // JavaCard 3.2 without usable EdDSA: the native CAP gives a legacy card, the default CAP still works
            Triple(CardPlatform.JC32_NO_EDDSA, "native", null),
            Triple(CardPlatform.JC32_NO_EDDSA, "soft", soft),
            Triple(CardPlatform.JC32_NO_KEY_IMPORT, "native", null),
            Triple(CardPlatform.JC32_NO_KEY_IMPORT, "soft", soft)
        )
        for ((n, row) in expected.withIndex()) {
            val (platform, variant, engine) = row
            val what = "${platform.name()} + $variant CAP"
            val card = card(platform, variant, n % 14 + 1)
            assertEquals(variant, bibo(card).capVariant.id)
            if (engine == null) assertLegacyCard(card, what) else assertSignsSep10(card, engine, what)
        }
        // Every named card model appears above, so a new preset cannot be added without saying what it does.
        assertEquals(CardPlatform.presets().toSet(), expected.map { it.first }.toSet())
    }

    @Test
    fun `a card refuses a CAP built for a later JavaCard level`() {
        for (platform in CardPlatform.presets().filter { it.level() == CardPlatform.Level.JC305 }) {
            val refused = assertFailsWith<CapNotLoadableException>(platform.name()) { SimulatorBibo(ed25519 = "native", platform = platform) }
            assertEquals(CapVariant.NATIVE, refused.variant)
            assertEquals(platform, refused.platform)
            val message = refused.message!!
            // It says what the CAP imports, what the card has, and what to load instead.
            assertTrue("ImpalaApplet-native.cap" in message && "javacard.framework 1.8" in message && "1.6" in message && "soft CAP" in message, message)
        }
        // The other two CAPs load everywhere, and the native one from JavaCard 3.1 on.
        for (platform in CardPlatform.presets()) {
            assertTrue(CapVariant.SOFT.loadsOn(platform) && CapVariant.NONE.loadsOn(platform), platform.name())
            assertEquals(platform.level() != CardPlatform.Level.JC305, CapVariant.NATIVE.loadsOn(platform), platform.name())
        }
        assertEquals(CardPlatform.Level.JC305, CapVariant.SOFT.minimumLevel)
        assertEquals(CardPlatform.Level.JC305, CapVariant.NONE.minimumLevel)
        assertEquals(CardPlatform.Level.JC31, CapVariant.NATIVE.minimumLevel)
    }

    // ------------------------------------------------------------------ what is not named

    private fun <T> withProperties(vararg pairs: Pair<String, String?>, block: () -> T): T {
        val before = pairs.map { it.first to System.getProperty(it.first) }
        try {
            for ((key, value) in pairs) if (value == null) System.clearProperty(key) else System.setProperty(key, value)
            return block()
        } finally {
            for ((key, value) in before) if (value == null) System.clearProperty(key) else System.setProperty(key, value)
        }
    }

    @Test
    fun `the hardware follows the CAP and the CAP the hardware when only one is named`() {
        fun of(ed25519: String? = null, platform: CardPlatform? = null) = SimulatorBibo(ed25519 = ed25519, platform = platform).let { it.capVariant to it.platform }
        withProperties(SimulatorBibo.ED25519_PROPERTY to null, SimulatorBibo.PLATFORM_PROPERTY to null) {
            // Neither: the default CAP on the hardware it was built for.
            assertEquals(CapVariant.SOFT to CardPlatform.JC305, of())
            // A CAP alone: the lowest hardware that loads it.
            assertEquals(CapVariant.SOFT to CardPlatform.JC305, of(ed25519 = "soft"))
            assertEquals(CapVariant.NONE to CardPlatform.JC305, of(ed25519 = "none"))
            assertEquals(CapVariant.NATIVE to CardPlatform.JC31, of(ed25519 = "native"))
            // Hardware alone: the CAP an operator would load on it.
            assertEquals(CapVariant.SOFT to CardPlatform.JC305, of(platform = CardPlatform.JC305))
            assertEquals(CapVariant.NATIVE to CardPlatform.JC31_SHA512, of(platform = CardPlatform.JC31_SHA512))
            assertEquals(CapVariant.NATIVE to CardPlatform.JC32, of(platform = CardPlatform.JC32))
            assertEquals(CapVariant.NATIVE to CardPlatform.JC32_PER_CURVE, of(platform = CardPlatform.JC32_PER_CURVE))
            assertEquals(CapVariant.SOFT to CardPlatform.JC32_NO_EDDSA, of(platform = CardPlatform.JC32_NO_EDDSA))
            // Both: exactly that.
            assertEquals(CapVariant.SOFT to CardPlatform.JC32, of("soft", CardPlatform.JC32))
            assertFailsWith<IllegalArgumentException> { SimulatorBibo(ed25519 = "hard") }
        }
        // The JVM-wide properties stand in for what the caller does not say, and never override it.
        withProperties(SimulatorBibo.ED25519_PROPERTY to null, SimulatorBibo.PLATFORM_PROPERTY to "jc32-per-curve") {
            assertEquals(CapVariant.NATIVE to CardPlatform.JC32_PER_CURVE, of())
            assertEquals(CapVariant.SOFT to CardPlatform.JC32_PER_CURVE, of(ed25519 = "soft"))
            assertEquals(CapVariant.SOFT to CardPlatform.JC305, of(platform = CardPlatform.JC305))
        }
        withProperties(SimulatorBibo.ED25519_PROPERTY to "native", SimulatorBibo.PLATFORM_PROPERTY to null) {
            assertEquals(CapVariant.NATIVE to CardPlatform.JC31, of())
            assertEquals(CapVariant.NATIVE to CardPlatform.JC32, of(platform = CardPlatform.JC32))
            assertEquals(CapVariant.NONE to CardPlatform.JC305, of(ed25519 = "none"))
        }
        withProperties(SimulatorBibo.ED25519_PROPERTY to "native", SimulatorBibo.PLATFORM_PROPERTY to "jc305") {
            assertFailsWith<CapNotLoadableException> { SimulatorBibo() }
        }
        withProperties(SimulatorBibo.ED25519_PROPERTY to null, SimulatorBibo.PLATFORM_PROPERTY to "jc99") {
            assertFailsWith<IllegalArgumentException> { SimulatorBibo() }
        }
    }

    // ------------------------------------------------------------------ memory

    /**
     * Bytes of transient memory. Cleared on reset: the buffers of the legacy
     * functions and of the secure channel (558) and the validated flag of each
     * of the two PIN objects (the platform's, booked like the rest). Cleared
     * on deselect: the legacy functions, the software engine's work area, and
     * the SEP-10 challenge stage (a 672-byte buffer and two shorts of state).
     */
    private val reset = 558 + 2
    private val legacyDeselect = 179
    private val softWorkArea = 481
    private val stageBuffer = 672
    private val stage = stageBuffer + 4

    @Test
    fun `the applet takes the transient memory the documentation says`() {
        val none = SimulatorBibo(ed25519 = "none").transientMemoryUsed
        val native = SimulatorBibo(ed25519 = "native").transientMemoryUsed
        val soft = SimulatorBibo(ed25519 = "soft").transientMemoryUsed
        // cleared on reset: the same for every CAP
        assertEquals(reset, none.first)
        assertEquals(reset, native.first)
        assertEquals(reset, soft.first)
        // cleared on deselect
        assertEquals(legacyDeselect, none.second)
        assertEquals(legacyDeselect + stage, native.second)
        assertEquals(legacyDeselect + softWorkArea + stage, soft.second)
        // The totals of the README table: about 0.75 KB, 1.4 KB and 1.9 KB.
        assertEquals(739, none.first + none.second)
        assertEquals(1415, native.first + native.second)
        assertEquals(1896, soft.first + soft.second)
    }

    @Test
    fun `a card short of memory loses the Stellar key and nothing else`() {
        fun jc305(deselect: Int) = CardPlatform.builder("x-ram-$deselect", CardPlatform.Level.JC305).transientMemory(-1, deselect).build()
        fun stellarKey(platform: CardPlatform, variant: String): Pair<Boolean, Int> {
            val bibo = SimulatorBibo(ed25519 = variant, platform = platform)
            val sdk = ImpalaSDK(bibo)
            sdk.setSeed()
            return (sdk.getStellarKey() != null) to bibo.transientMemoryUsed.second
        }
        // Exactly enough for the software engine and the challenge stage, and one byte less.
        val all = legacyDeselect + softWorkArea + stage
        assertEquals(true to all, stellarKey(jc305(all), "soft"))
        // Nothing allocated at install can be given back: what was taken before the card ran out stays taken, unused.
        assertEquals(false to all - 4, stellarKey(jc305(all - 1), "soft"), "the stage buffer fits, its state does not")
        assertEquals(false to legacyDeselect + softWorkArea, stellarKey(jc305(legacyDeselect + softWorkArea + stageBuffer - 1), "soft"), "the engine fits, the stage buffer does not")
        // The engine itself does not fit: nothing but the legacy buffers.
        assertEquals(false to legacyDeselect, stellarKey(jc305(legacyDeselect + softWorkArea - 1), "soft"))
        // The two named small cards are those two cases.
        assertEquals(false to legacyDeselect, stellarKey(CardPlatform.JC305_SMALL_RAM, "soft"))
        assertEquals(false to legacyDeselect + softWorkArea, stellarKey(CardPlatform.JC305_TIGHT_RAM, "soft"))
        // The platform's own EdDSA needs no work area: the same budget is enough for the native CAP.
        val tightJc32 = CardPlatform.JC32.toBuilder("x-jc32-1024").transientMemory(-1, 1024).build()
        assertEquals(true to legacyDeselect + stage, stellarKey(tightJc32, "native"))
        assertEquals(false to legacyDeselect + softWorkArea, stellarKey(tightJc32, "soft"))
        // A card that cannot even hold the legacy buffers does not install at all.
        assertFailsWith<Exception> { SimulatorBibo(ed25519 = "none", platform = jc305(legacyDeselect - 1)) }
    }
}

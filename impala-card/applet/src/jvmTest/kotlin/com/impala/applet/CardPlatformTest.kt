package com.impala.applet

import com.impala.jcardsim.jc31.CardPlatform
import com.impala.jcardsim.jc31.CardPlatform.CustomCurves
import com.impala.jcardsim.jc31.CardPlatform.Level
import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Callable
import javacard.framework.JCSystem
import javacard.framework.SystemException
import javacard.security.CryptoException
import javacard.security.ECKey
import javacard.security.ECPrivateKey
import javacard.security.ECPublicKey
import javacard.security.KeyAgreement
import javacard.security.KeyBuilder
import javacard.security.KeyPair
import javacard.security.MessageDigest
import javacard.security.NamedParameterSpec
import javacard.security.Signature
import javacard.security.XECPrivateKey
import javacard.security.XECPublicKey
import javacardx.crypto.Cipher
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The simulated hardware (`:jcardsim-jc31`, [CardPlatform]): what a JavaCard
 * 3.0.5 card, a 3.1 card and a 3.2 card answer an applet, one optional
 * algorithm at a time, and what the two Ed25519 engines make of each card
 * model. The engines must end up with standard Ed25519 or with nothing: a
 * card that lacks a piece is a legacy card, never a card that signs wrongly.
 */
class CardPlatformTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** Runs [block] as a fresh card of [platform]. */
    private fun <T> on(platform: CardPlatform, block: () -> T): T = platform.newCard().call(Callable { block() })

    private fun crypto(block: () -> Unit): Short = assertFailsWith<CryptoException> { block() }.reason

    private fun jdkVerify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(hex("302a300506032b6570032100") + pub))
        return java.security.Signature.getInstance("Ed25519").run { initVerify(key); update(msg); verify(sig) }
    }

    private val privateAttr = (JCSystem.MEMORY_TYPE_PERSISTENT.toInt() or KeyBuilder.ATTR_PRIVATE.toInt()).toShort()
    private val publicAttr = (JCSystem.MEMORY_TYPE_PERSISTENT.toInt() or KeyBuilder.ATTR_PUBLIC.toInt()).toShort()
    private val perCurve: Byte = Signature.SIG_CIPHER_EDDSA_ED25519

    private fun edDsa(digest: Byte, cipher: Byte) = Signature.getInstance(digest, cipher, Cipher.PAD_NULL, false)

    // RFC 8032 section 7.1, TEST 2.
    private val rfcPrivate = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    private val rfcPublic = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    private val rfcMessage = hex("72")
    private val rfcSignature = hex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )

    // ------------------------------------------------------------------ the model

    @Test
    fun `the card models have unique names and are found by name`() {
        val names = CardPlatform.presets().map { it.name() }
        assertEquals(names.size, names.toSet().size)
        assertTrue(names.containsAll(listOf("jc305", "jc31", "jc32")), "the three levels have a plain preset each: $names")
        for (p in CardPlatform.presets()) {
            assertTrue(p === CardPlatform.byName(p.name()), p.name())
            assertTrue(p === CardPlatform.byName(" ${p.name().uppercase()} "), "names are trimmed and case-insensitive")
            assertTrue(p.description().isNotBlank(), "${p.name()} says what it is")
            assertTrue(p.name().startsWith("jc" + p.level().label().replace(".", "")), "${p.name()} starts with its level")
        }
        val unknown = assertFailsWith<IllegalArgumentException> { CardPlatform.byName("jc40") }
        assertTrue(unknown.message!!.contains("jc305") && unknown.message!!.contains("jc32-per-curve"), "an unknown name lists the known ones")
    }

    @Test
    fun `each JavaCard level exports the API package versions of its specification`() {
        // javacard.framework / javacard.security / javacardx.crypto, minor versions (read from the kits' export files).
        assertEquals(listOf(6, 6, 6), Level.JC305.let { listOf(it.frameworkMinor(), it.securityMinor(), it.cryptoMinor()) })
        assertEquals(listOf(8, 7, 7), Level.JC31.let { listOf(it.frameworkMinor(), it.securityMinor(), it.cryptoMinor()) })
        assertEquals(listOf(9, 8, 8), Level.JC32.let { listOf(it.frameworkMinor(), it.securityMinor(), it.cryptoMinor()) })
        // What the two kinds of CAP import: 1.6/1.6/1.6 loads everywhere, 1.8/1.7/1.7 from JavaCard 3.1 on.
        assertEquals(listOf(true, true, true), Level.values().map { it.exports(6, 6, 6) })
        assertEquals(listOf(false, true, true), Level.values().map { it.exports(8, 7, 7) })
        assertEquals(listOf(false, false, true), Level.values().map { it.exports(9, 8, 8) })
    }

    @Test
    fun `a platform cannot claim an API its level does not have`() {
        assertFailsWith<IllegalArgumentException> { CardPlatform.builder("x", Level.JC305).edDsa(true, false, false).build() }
        assertFailsWith<IllegalArgumentException> { CardPlatform.builder("x", Level.JC31).edDsa(true, false, true).build() }
        assertFailsWith<IllegalArgumentException> { CardPlatform.builder("Not A Name", Level.JC32) }
        // The plain preset of a level is what a card has when its maker implemented all of it.
        assertFalse(CardPlatform.JC305.edDsaOffered())
        assertTrue(CardPlatform.JC31.edDsaGenericNull() && !CardPlatform.JC31.edDsaPerCurve())
        assertTrue(CardPlatform.JC32.edDsaGenericNull() && CardPlatform.JC32.edDsaPerCurve())
        for (p in listOf(CardPlatform.JC305, CardPlatform.JC31, CardPlatform.JC32)) {
            assertTrue(p.ecdhPlainXy() && p.sha512() && p.aes256Keys() && p.customCurves() == CustomCurves.SUPPORTED, p.name())
            assertEquals(-1, p.transientDeselectBytes())
        }
    }

    @Test
    fun `outside a card the profile property decides, inside it the card does`() {
        // No card: the permissive default (EdDSA under both digest constants, never the JavaCard 3.2 cipher).
        edDsa(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA)
        edDsa(MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_EDDSA)
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { edDsa(MessageDigest.ALG_NULL, perCurve) })
        val card = CardPlatform.JC305.newCard()
        card.execute {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { edDsa(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA) })
            // A card inside a card: the inner one answers, and the outer one is back afterwards.
            on(CardPlatform.JC32) { edDsa(MessageDigest.ALG_NULL, perCurve) }
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { edDsa(MessageDigest.ALG_NULL, perCurve) })
        }
        edDsa(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA)
        // An exception does not leave the card behind either.
        assertFailsWith<IllegalStateException> { card.execute { throw IllegalStateException("boom") } }
        edDsa(MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_EDDSA)
    }

    // ------------------------------------------------------------------ EdDSA: JavaCard 3.1 and 3.2

    @Test
    fun `EdDSA is answered per platform, cipher and digest constant`() {
        val nul = MessageDigest.ALG_NULL
        val sha = MessageDigest.ALG_SHA_512
        val generic = Signature.SIG_CIPHER_EDDSA
        // platform -> the (digest, cipher) requests it accepts; everything else is NO_SUCH_ALGORITHM
        val accepted = mapOf(
            CardPlatform.JC305 to emptySet(),
            CardPlatform.JC31 to setOf(nul to generic),
            CardPlatform.JC31_SHA512 to setOf(sha to generic),
            CardPlatform.JC32 to setOf(nul to generic, nul to perCurve),
            CardPlatform.JC32_PER_CURVE to setOf(nul to perCurve),
            CardPlatform.JC32_NO_EDDSA to emptySet(),
            CardPlatform.JC32_NO_KEY_IMPORT to setOf(nul to generic, nul to perCurve)
        )
        for ((platform, yes) in accepted) {
            for (digest in listOf(nul, sha)) for (cipher in listOf(generic, perCurve)) {
                on(platform) {
                    if ((digest to cipher) in yes) {
                        val s = edDsa(digest, cipher)
                        assertEquals(cipher, s.cipherAlgorithm, "${platform.name()}: the instance says which cipher it is")
                        assertEquals(digest, s.messageDigestAlgorithm)
                        assertEquals(64, s.length.toInt())
                    } else {
                        assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { edDsa(digest, cipher) }, "${platform.name()} digest $digest cipher $cipher")
                    }
                }
            }
            on(platform) {
                // Pre-hash EdDSA and Ed448 are on no simulated card; a padding other than PAD_NULL is never EdDSA.
                for (cipher in listOf(Signature.SIG_CIPHER_EDDSAPH, Signature.SIG_CIPHER_EDDSA_ED448, Signature.SIG_CIPHER_EDDSAPH_ED25519, Signature.SIG_CIPHER_EDDSAPH_ED448)) {
                    assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { edDsa(nul, cipher) }, "${platform.name()} cipher $cipher")
                }
                assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { Signature.getInstance(nul, generic, Cipher.PAD_PKCS1, false) })
                // jcardsim's own signatures are still there on every card.
                Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false)
            }
        }
    }

    @Test
    fun `the JavaCard 3_2 constants have the values of the 3_2 API`() {
        assertEquals(13, Signature.SIG_CIPHER_EDDSA.toInt())
        assertEquals(14, Signature.SIG_CIPHER_EDDSAPH.toInt())
        assertEquals(15, Signature.SIG_CIPHER_EDDSA_ED25519.toInt())
        assertEquals(16, Signature.SIG_CIPHER_EDDSA_ED448.toInt())
        assertEquals(17, Signature.SIG_CIPHER_EDDSAPH_ED25519.toInt())
        assertEquals(18, Signature.SIG_CIPHER_EDDSAPH_ED448.toInt())
        // The engine carries its own copy of the one it asks for (it is converted against the 3.1 API).
        assertEquals(Signature.SIG_CIPHER_EDDSA_ED25519, Ed25519Native.SIG_CIPHER_EDDSA_ED25519)
    }

    @Test
    fun `the JavaCard 3_2 per-curve cipher is RFC 8032 Ed25519`() {
        on(CardPlatform.JC32_PER_CURVE) {
            val spec = NamedParameterSpec.getInstance(NamedParameterSpec.ED25519)
            val pub = KeyBuilder.buildXECKey(spec, publicAttr, false) as XECPublicKey
            val priv = KeyBuilder.buildXECKey(spec, privateAttr, false) as XECPrivateKey
            val s = edDsa(MessageDigest.ALG_NULL, perCurve)
            pub.setEncoded(rfcPublic, 0, 32)
            s.init(pub, Signature.MODE_VERIFY)
            assertTrue(s.verify(rfcMessage, 0, 1, rfcSignature, 0, 64), "the RFC vector verifies")
            priv.setEncoded(rfcPrivate, 0, 32)
            s.init(priv, Signature.MODE_SIGN)
            val out = ByteArray(64)
            assertEquals(64, s.sign(rfcMessage, 0, 1, out, 0).toInt())
            assertContentEquals(rfcSignature, out, "and signing the RFC key gives the RFC signature")
            // A generated key signs what the JDK verifies.
            KeyPair(pub, priv).genKeyPair()
            val key = ByteArray(32).also { pub.getEncoded(it, 0) }
            val msg = ByteArray(100) { (it * 7).toByte() }
            s.init(priv, Signature.MODE_SIGN)
            s.sign(msg, 0, 100, out, 0)
            assertTrue(jdkVerify(key, msg, out))
        }
    }

    @Test
    fun `a JavaCard 3_0_5 card and a card without EdDSA have no Ed25519 keys`() {
        for (platform in listOf(CardPlatform.JC305, CardPlatform.JC32_NO_EDDSA)) {
            on(platform) {
                assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { NamedParameterSpec.getInstance(NamedParameterSpec.ED25519) }, platform.name())
            }
        }
        // The key classes exist only where the signature does.
        val spec = on(CardPlatform.JC32) { NamedParameterSpec.getInstance(NamedParameterSpec.ED25519) }
        on(CardPlatform.JC305) { assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { KeyBuilder.buildXECKey(spec, privateAttr, false) }) }
    }

    @Test
    fun `a card that will not import a private key still generates one and signs`() {
        on(CardPlatform.JC32_NO_KEY_IMPORT) {
            val spec = NamedParameterSpec.getInstance(NamedParameterSpec.ED25519)
            val pub = KeyBuilder.buildXECKey(spec, publicAttr, false) as XECPublicKey
            val priv = KeyBuilder.buildXECKey(spec, privateAttr, false) as XECPrivateKey
            assertEquals(CryptoException.ILLEGAL_USE, crypto { priv.setEncoded(rfcPrivate, 0, 32) })
            assertFalse(priv.isInitialized)
            pub.setEncoded(rfcPublic, 0, 32) // a public key is not a secret: always loadable
            KeyPair(pub, priv).genKeyPair()
            assertTrue(priv.isInitialized)
            val s = edDsa(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA)
            s.init(priv, Signature.MODE_SIGN)
            val msg = byteArrayOf(1, 2, 3)
            val sig = ByteArray(64)
            s.sign(msg, 0, 3, sig, 0)
            assertTrue(jdkVerify(ByteArray(32).also { pub.getEncoded(it, 0) }, msg, sig))
        }
    }

    // ------------------------------------------------------------------ JavaCard 3.0.5: optional algorithms

    @Test
    fun `the optional algorithms of a JavaCard 3_0_5 card can be missing one at a time`() {
        on(CardPlatform.JC305_NO_XY) {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false) })
            KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false) // the JavaCard 3.0.4 one is still there
            MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false)
        }
        on(CardPlatform.JC305_NO_SHA512) {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false) })
            MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false)
            KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false)
        }
        on(CardPlatform.JC305_NO_AES256) {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false) })
            KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false) // SCP03 needs this one on every card
        }
        // And on the plain card all of them are there.
        on(CardPlatform.JC305) {
            KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false)
            MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false)
            KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false)
        }
    }

    /**
     * jcardsim has no transient EC private keys, so no simulated card has
     * them and the software engine's nonce key is always its fallback here (a
     * persistent key object, cleared after every use). Pinned so that a
     * jcardsim that gains them does not change what the tests cover unnoticed.
     */
    @Test
    fun `no simulated card has transient EC private keys`() {
        for (platform in listOf(CardPlatform.JC305, CardPlatform.JC31, CardPlatform.JC32)) {
            on(platform) {
                assertEquals(CryptoException.NO_SUCH_ALGORITHM, crypto { KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false) }, platform.name())
                KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false)
            }
        }
    }

    /** A 256-bit EC key on Wei25519, the custom curve the software engine computes on. */
    private fun weiKey(type: Byte): ECKey = (KeyBuilder.buildKey(type, KeyBuilder.LENGTH_EC_FP_256, false) as ECKey).also {
        it.setFieldFP(Ed25519Soft.P, 0, 32)
        it.setA(Ed25519Soft.WEI_A, 0, 32)
        it.setB(Ed25519Soft.WEI_B, 0, 32)
        it.setG(Ed25519Soft.WEI_G, 0, 65)
        it.setR(Ed25519Soft.L, 0, 32)
        it.setK(8)
    }

    /** `scalar * G` on Wei25519 from the card's ECDH: 04 || X || Y. */
    private fun mulBase(scalar: ByteArray): ByteArray {
        val key = weiKey(KeyBuilder.TYPE_EC_FP_PRIVATE) as ECPrivateKey
        key.setS(scalar, 0, 32)
        val ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false)
        ecdh.init(key)
        val out = ByteArray(65)
        assertEquals(65, ecdh.generateSecret(Ed25519Soft.WEI_G, 0, 65, out, 0).toInt())
        return out
    }

    private fun p256Agreement() {
        val pair = KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256)
        pair.genKeyPair()
        val w = ByteArray(65).also { (pair.public as ECPublicKey).getW(it, 0) }
        val ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false)
        ecdh.init(pair.private)
        val out = ByteArray(65)
        assertEquals(65, ecdh.generateSecret(w, 0, 65, out, 0).toInt())
    }

    @Test
    fun `a card with fixed curves refuses a custom one and still does P-256`() {
        val scalar = ByteArray(32).also { it[31] = 5 }
        on(CardPlatform.JC305_FIXED_CURVES) {
            assertEquals(CryptoException.ILLEGAL_VALUE, crypto { mulBase(scalar) }, "ECDH refuses the key")
            val pair = KeyPair(weiKey(KeyBuilder.TYPE_EC_FP_PUBLIC) as ECPublicKey, weiKey(KeyBuilder.TYPE_EC_FP_PRIVATE) as ECPrivateKey)
            assertEquals(CryptoException.ILLEGAL_VALUE, crypto { pair.genKeyPair() }, "and so does key generation")
            p256Agreement() // the card's own curve works as ever
        }
    }

    @Test
    fun `a card with wrong curve arithmetic agrees with itself and with nobody else`() {
        val scalar = ByteArray(32).also { it[31] = 5 }
        val right = on(CardPlatform.JC305) { mulBase(scalar) }
        val wrong = on(CardPlatform.JC305_WRONG_CURVE_MATH) { mulBase(scalar) }
        val p = BigInteger(1, Ed25519Soft.P)
        assertContentEquals(right.copyOfRange(0, 33), wrong.copyOfRange(0, 33), "the same X: it is a point of the curve")
        assertEquals(p, BigInteger(1, right.copyOfRange(33, 65)) + BigInteger(1, wrong.copyOfRange(33, 65)), "and the negative of the right one")
        on(CardPlatform.JC305_WRONG_CURVE_MATH) {
            // Its key generation is wrong the same way: the card's ECDH reproduces the card's public point,
            // so comparing the two proves nothing. Only a known answer does (Ed25519Soft.knownAnswer).
            val pub = weiKey(KeyBuilder.TYPE_EC_FP_PUBLIC) as ECPublicKey
            val priv = weiKey(KeyBuilder.TYPE_EC_FP_PRIVATE) as ECPrivateKey
            KeyPair(pub, priv).genKeyPair()
            val w = ByteArray(65).also { pub.getW(it, 0) }
            val ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false)
            ecdh.init(priv)
            val again = ByteArray(65).also { ecdh.generateSecret(Ed25519Soft.WEI_G, 0, 65, it, 0) }
            assertContentEquals(w, again, "key generation and ECDH agree on this card")
            // ...and a right card disagrees with both, for the same scalar.
            val s = ByteArray(32)
            val n = priv.getS(s, 0).toInt()
            val padded = ByteArray(32 - n) + s.copyOf(n)
            val honest = CardPlatform.JC305.newCard().call(Callable { mulBase(padded) })
            assertFalse(honest.contentEquals(w))
            p256Agreement() // P-256 is one of its own curves: unaffected
        }
    }

    // ------------------------------------------------------------------ transient memory

    @Test
    fun `transient memory is booked per card and runs out`() {
        val tiny = CardPlatform.builder("tiny", Level.JC305).transientMemory(100, 50).build()
        val card = tiny.newCard()
        card.execute {
            JCSystem.makeTransientByteArray(40, JCSystem.CLEAR_ON_DESELECT)
            assertEquals(SystemException.NO_TRANSIENT_SPACE, assertFailsWith<SystemException> { JCSystem.makeTransientByteArray(11, JCSystem.CLEAR_ON_DESELECT) }.reason)
            JCSystem.makeTransientByteArray(10, JCSystem.CLEAR_ON_DESELECT) // exactly full
            assertFailsWith<SystemException> { JCSystem.makeTransientBooleanArray(1, JCSystem.CLEAR_ON_DESELECT) }
            // The two kinds of transient memory are separate, and a short is two bytes.
            JCSystem.makeTransientShortArray(50, JCSystem.CLEAR_ON_RESET)
            assertFailsWith<SystemException> { JCSystem.makeTransientByteArray(1, JCSystem.CLEAR_ON_RESET) }
        }
        assertEquals(50, card.transientDeselectBytesUsed())
        assertEquals(100, card.transientResetBytesUsed())
        // Another card of the same platform starts empty.
        assertEquals(0, tiny.newCard().transientDeselectBytesUsed())
        // A platform without a limit, and code outside any card, are never refused.
        on(CardPlatform.JC305) { JCSystem.makeTransientByteArray(20_000, JCSystem.CLEAR_ON_DESELECT) }
        JCSystem.makeTransientByteArray(20_000, JCSystem.CLEAR_ON_RESET)
    }

    // ------------------------------------------------------------------ the native engine on each card

    private fun requestOf(engine: Ed25519): Pair<Byte, Byte> {
        val s = Ed25519Native::class.java.getDeclaredField("signature").apply { isAccessible = true }.get(engine) as Signature
        return s.cipherAlgorithm to s.messageDigestAlgorithm
    }

    /** Generates the card's key and checks that what the engine signs is Ed25519 to the JDK. */
    private fun signsEd25519(engine: Ed25519, what: String) {
        assertTrue(engine.generateKeyPair(), "$what: key generation")
        val pub = ByteArray(32).also { engine.getPublicKey(it, 0) }
        for (len in listOf(1, 32, 255)) {
            val msg = ByteArray(len) { (it * 11 + len).toByte() }
            val sig = ByteArray(64)
            assertEquals(64, engine.sign(msg, 0, len.toShort(), sig, 0).toInt())
            assertTrue(jdkVerify(pub, msg, sig), "$what: a $len-byte message")
        }
    }

    @Test
    fun `the native engine takes the first pure Ed25519 a card offers`() {
        val generic = Signature.SIG_CIPHER_EDDSA
        val expected = mapOf(
            CardPlatform.JC31 to (generic to MessageDigest.ALG_NULL),
            CardPlatform.JC31_SHA512 to (generic to MessageDigest.ALG_SHA_512),
            // A JavaCard 3.2 card that has both keeps the choice a 3.1 card makes.
            CardPlatform.JC32 to (generic to MessageDigest.ALG_NULL),
            // One that has Ed25519 only under the 3.2 name gets it under that name.
            CardPlatform.JC32_PER_CURVE to (perCurve to MessageDigest.ALG_NULL)
        )
        for ((platform, request) in expected) {
            on(platform) {
                val engine = assertNotNull(Ed25519Native.create(), "${platform.name()} has an engine")
                assertEquals(Ed25519.ENGINE_NATIVE, engine.engineId())
                assertEquals(request, requestOf(engine), platform.name())
                assertFalse(engine.hasPublicKey(), "the self-test leaves no key behind")
                signsEd25519(engine, platform.name())
            }
        }
    }

    @Test
    fun `the native engine turns down every card whose Ed25519 it cannot prove`() {
        val refused = listOf(
            CardPlatform.JC305,                 // no EdDSA API (and the native CAP would not even load)
            CardPlatform.JC32_NO_EDDSA,         // the API, but no Ed25519
            CardPlatform.JC32_NO_KEY_IMPORT,    // cannot load the test key: the signing direction stays unproven
            // The JavaCard 3.2 cipher mapped to something that is not pure Ed25519, in both directions or in one.
            CardPlatform.JC32_PER_CURVE.toBuilder("x-per-curve-not-pure").edDsaNotPure(false).build(),
            CardPlatform.JC32_PER_CURVE.toBuilder("x-per-curve-sign-not-pure").edDsaNotPure(true).build(),
            CardPlatform.JC32.toBuilder("x-all-not-pure").edDsaNotPure(false).build()
        )
        for (platform in refused) {
            on(platform) { assertNull(Ed25519Native.create(), "${platform.name()}: no engine, the card is a legacy card") }
        }
    }

    // ------------------------------------------------------------------ the software engine on each card

    @Test
    fun `the software engine works wherever its primitives are, at every level`() {
        for (platform in listOf(CardPlatform.JC305, CardPlatform.JC31, CardPlatform.JC32, CardPlatform.JC32_NO_EDDSA)) {
            on(platform) {
                val engine = assertNotNull(Ed25519Soft.create(), "${platform.name()} has an engine")
                assertEquals(Ed25519.ENGINE_SOFT, engine.engineId())
                signsEd25519(engine, platform.name())
            }
        }
    }

    @Test
    fun `the software engine does not exist on a card that lacks one of its algorithms`() {
        for (platform in listOf(CardPlatform.JC305_NO_XY, CardPlatform.JC305_NO_SHA512, CardPlatform.JC305_NO_AES256)) {
            on(platform) { assertNull(Ed25519Soft.create(), "${platform.name()}: no engine") }
        }
    }

    @Test
    fun `the software engine makes no key on a card that does not compute on its curve`() {
        // The requests at install all succeed: the engine exists. It finds out when it makes the key.
        for (platform in listOf(CardPlatform.JC305_FIXED_CURVES, CardPlatform.JC305_WRONG_CURVE_MATH)) {
            on(platform) {
                val engine = assertNotNull(Ed25519Soft.create(), platform.name())
                assertFalse(engine.generateKeyPair(), "${platform.name()}: no key")
                assertFalse(engine.hasPublicKey())
                assertFalse(engine.isKeyReady)
                assertFailsWith<CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
            }
        }
    }

    @Test
    fun `the software engine needs its work area`() {
        val enough = CardPlatform.builder("x-481", Level.JC305).transientMemory(-1, Ed25519Soft.W_LENGTH.toInt()).build()
        val short = CardPlatform.builder("x-480", Level.JC305).transientMemory(-1, Ed25519Soft.W_LENGTH.toInt() - 1).build()
        on(short) { assertNull(Ed25519Soft.create(), "one byte short: no engine") }
        val card = enough.newCard()
        card.execute { signsEd25519(assertNotNull(Ed25519Soft.create()), "exactly enough") }
        assertEquals(Ed25519Soft.W_LENGTH.toInt(), card.transientDeselectBytesUsed(), "the work area is all the transient memory the engine takes")
    }
}

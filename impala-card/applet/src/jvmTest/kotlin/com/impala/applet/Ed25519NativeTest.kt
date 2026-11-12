package com.impala.applet

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javacard.security.CryptoException
import javacard.security.MessageDigest
import javacard.security.Signature
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The JavaCard 3.1 Ed25519 engine on the simulated JavaCard 3.1 platform
 * (`:jcardsim-jc31`), including the platforms it must turn down: an engine
 * exists only where the card's EdDSA verifies an RFC 8032 vector.
 */
class Ed25519NativeTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun <T> withProfile(profile: String, block: () -> T): T {
        val key = "jcardsim.jc31.eddsa"
        val before = System.getProperty(key)
        System.setProperty(key, profile)
        try {
            return block()
        } finally {
            if (before == null) System.clearProperty(key) else System.setProperty(key, before)
        }
    }

    private fun jdkVerify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(hex("302a300506032b6570032100") + pub))
        return java.security.Signature.getInstance("Ed25519").run { initVerify(key); update(msg); verify(sig) }
    }

    /** The message digest constant the engine settled on. */
    private fun digestOf(engine: Ed25519): Byte {
        val field = Ed25519Native::class.java.getDeclaredField("signature").apply { isAccessible = true }
        return (field.get(engine) as Signature).messageDigestAlgorithm
    }

    private fun exercise(engine: Ed25519): ByteArray {
        assertEquals(Ed25519.ENGINE_NATIVE, engine.engineId())
        assertFalse(engine.hasPublicKey())
        assertFalse(engine.isKeyReady)
        assertFailsWith<CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
        assertTrue(engine.generateKeyPair())
        assertTrue(engine.hasPublicKey())
        assertTrue(engine.isKeyReady)
        val pub = ByteArray(34) { 0x5A }
        engine.getPublicKey(pub, 1)
        assertEquals(0x5A, pub[0].toInt())
        assertEquals(0x5A, pub[33].toInt())
        val key = pub.copyOfRange(1, 33)
        for (len in listOf(1, 32, 110, 255)) {
            val msg = ByteArray(len) { (it * 13 + len).toByte() }
            val buf = ByteArray(70) { 0x5A }
            assertEquals(64, engine.sign(msg, 0, len.toShort(), buf, 3).toInt())
            assertTrue(jdkVerify(key, msg, buf.copyOfRange(3, 67)), "len $len")
            assertContentEquals(byteArrayOf(0x5A, 0x5A, 0x5A), buf.copyOfRange(67, 70))
            val padded = ByteArray(5) + msg + ByteArray(4)
            val sig = ByteArray(64)
            engine.sign(padded, 5, len.toShort(), sig, 0)
            assertTrue(jdkVerify(key, msg, sig), "offset message, len $len")
        }
        return key
    }

    @Test
    fun `the engine generates a key and signs what the JDK verifies`() {
        val engine = assertNotNull(Ed25519Native.create())
        assertEquals(MessageDigest.ALG_NULL, digestOf(engine), "the first candidate that passes the self-test")
        val key = exercise(engine)
        val other = exercise(assertNotNull(Ed25519Native.create()))
        assertFalse(key.contentEquals(other), "two cards, two keys")
    }

    @Test
    fun `a cleared key signs nothing but keeps its public key`() {
        val engine = assertNotNull(Ed25519Native.create())
        val key = exercise(engine)
        engine.clearKey()
        assertFalse(engine.isKeyReady)
        assertTrue(engine.hasPublicKey())
        assertFailsWith<CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
        assertContentEquals(key, ByteArray(32).also { engine.getPublicKey(it, 0) })
    }

    @Test
    fun `a platform that wants ALG_NULL or ALG_SHA_512 gets it`() {
        withProfile("null") {
            val engine = assertNotNull(Ed25519Native.create())
            assertEquals(MessageDigest.ALG_NULL, digestOf(engine))
            exercise(engine)
        }
        withProfile("sha512") {
            val engine = assertNotNull(Ed25519Native.create())
            assertEquals(MessageDigest.ALG_SHA_512, digestOf(engine), "the second candidate")
            exercise(engine)
        }
    }

    @Test
    fun `a platform without pure Ed25519 gets no engine`() {
        withProfile("none") { assertNull(Ed25519Native.create(), "no Ed25519 at all") }
        withProfile("not-pure") { assertNull(Ed25519Native.create(), "EdDSA that fails the RFC 8032 vector") }
    }

    /**
     * Verifying the RFC vector says nothing about signing. A platform whose
     * verification is pure Ed25519 but whose signatures are not would pass a
     * verify-only self-test and then hand out signatures nobody accepts: the
     * engine signs the vector with its private key and checks that too.
     */
    @Test
    fun `a platform that verifies pure Ed25519 but signs something else gets no engine`() {
        withProfile("sign-not-pure") { assertNull(Ed25519Native.create()) }
    }

    @Test
    fun `the self-test leaves no test key behind`() {
        withProfile("any") {
            val engine = assertNotNull(Ed25519Native.create())
            // The RFC 8032 test keys were loaded for the self-test; neither may
            // be mistaken for the card's key, and the engine signs nothing yet.
            assertFalse(engine.hasPublicKey())
            assertFalse(engine.isKeyReady)
            val refused = assertFailsWith<CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
            assertEquals(CryptoException.UNINITIALIZED_KEY, refused.reason)
            assertTrue(engine.generateKeyPair())
            val pub = ByteArray(32).also { engine.getPublicKey(it, 0) }
            assertNotEquals("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", pub.joinToString("") { "%02x".format(it) })
        }
    }

    @Test
    fun `the simulator's provider follows impala_ed25519`() {
        fun with(engine: String?, block: () -> Unit) {
            val before = System.getProperty("impala.ed25519")
            if (engine == null) System.clearProperty("impala.ed25519") else System.setProperty("impala.ed25519", engine)
            try {
                block()
            } finally {
                if (before == null) System.clearProperty("impala.ed25519") else System.setProperty("impala.ed25519", before)
            }
        }
        with(null) { assertEquals(Ed25519.ENGINE_SOFT, assertNotNull(Ed25519Provider.create()).engineId()) }
        with("soft") { assertEquals(Ed25519.ENGINE_SOFT, assertNotNull(Ed25519Provider.create()).engineId()) }
        with("native") { assertEquals(Ed25519.ENGINE_NATIVE, assertNotNull(Ed25519Provider.create()).engineId()) }
        with("none") { assertNull(Ed25519Provider.create()) }
        with("SOFT") { assertFailsWith<IllegalArgumentException> { Ed25519Provider.create() } }
    }
}

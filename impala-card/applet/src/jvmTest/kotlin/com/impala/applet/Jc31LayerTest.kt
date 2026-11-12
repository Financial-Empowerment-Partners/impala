package com.impala.applet

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javacard.framework.JCSystem
import javacard.security.CryptoException
import javacard.security.ECPrivateKey
import javacard.security.ECPublicKey
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
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The JavaCard 3.1 EdDSA layer over jcardsim (`:jcardsim-jc31`): the simulated
 * platform the native Ed25519 engine runs on in tests. Its Ed25519 must be the
 * RFC's, its constants the JavaCard 3.1 API's, and jcardsim's own algorithms
 * must still be reached through the classes it patches or replaces.
 */
class Jc31LayerTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    private val persistentPrivate = (JCSystem.MEMORY_TYPE_PERSISTENT.toInt() or KeyBuilder.ATTR_PRIVATE.toInt()).toShort()
    private val persistentPublic = (JCSystem.MEMORY_TYPE_PERSISTENT.toInt() or KeyBuilder.ATTR_PUBLIC.toInt()).toShort()

    private fun ed25519() = NamedParameterSpec.getInstance(NamedParameterSpec.ED25519)
    private fun privateKey() = KeyBuilder.buildXECKey(ed25519(), persistentPrivate, false) as XECPrivateKey
    private fun publicKey() = KeyBuilder.buildXECKey(ed25519(), persistentPublic, false) as XECPublicKey
    private fun edDsa(md: Byte = MessageDigest.ALG_NULL) =
        Signature.getInstance(md, Signature.SIG_CIPHER_EDDSA, Cipher.PAD_NULL, false)

    private fun reason(block: () -> Unit): Short = assertFailsWith<CryptoException> { block() }.reason

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

    /** RFC 8032 section 7.1: secret key, public key, message, signature. */
    private val rfc8032 = listOf(
        listOf(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
        listOf(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
        listOf(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        )
    )

    @Test
    fun `the added constants are the JavaCard 3_1 API's`() {
        assertEquals(-1, KeyBuilder.TYPE_XEC.toInt())
        assertEquals(0, KeyBuilder.ATTR_PUBLIC.toInt())
        assertEquals(-32768, KeyBuilder.ATTR_PRIVATE.toInt())
        assertEquals(13, Signature.SIG_CIPHER_EDDSA.toInt())
        assertEquals(14, Signature.SIG_CIPHER_EDDSAPH.toInt())
        assertEquals(257, NamedParameterSpec.ED25519.toInt())
        assertEquals(257, ed25519().name.toInt())
    }

    @Test
    fun `RFC 8032 vectors sign and verify through the JavaCard API`() {
        for (md in listOf(MessageDigest.ALG_NULL, MessageDigest.ALG_SHA_512)) {
            for ((seed, pub, msgHex, sigHex) in rfc8032) {
                val msg = hex(msgHex)
                val priv = privateKey().also { it.setEncoded(hex(seed), 0, 32) }
                val signer = edDsa(md).also { it.init(priv, Signature.MODE_SIGN) }
                val out = ByteArray(70) { 0x11 }
                assertEquals(64, signer.sign(msg, 0, msg.size.toShort(), out, 3).toInt())
                assertEquals(sigHex, out.copyOfRange(3, 67).hex())
                assertContentEquals(byteArrayOf(0x11, 0x11, 0x11), out.copyOfRange(67, 70))

                val key = publicKey().also { it.setEncoded(hex(pub), 0, 32) }
                val verifier = edDsa(md).also { it.init(key, Signature.MODE_VERIFY) }
                assertTrue(verifier.verify(msg, 0, msg.size.toShort(), hex(sigHex), 0, 64))
                val bad = hex(sigHex).also { it[10] = (it[10].toInt() xor 4).toByte() }
                assertFalse(verifier.verify(msg, 0, msg.size.toShort(), bad, 0, 64))
                assertFalse(verifier.verify(msg, 0, msg.size.toShort(), hex(sigHex), 0, 63), "a short signature")
                assertFalse(verifier.verify(msg + byteArrayOf(0), 0, (msg.size + 1).toShort(), hex(sigHex), 0, 64))
            }
        }
    }

    @Test
    fun `update accumulates the message and sign resets it`() {
        val (seed, _, _, _) = rfc8032[2]
        val priv = privateKey().also { it.setEncoded(hex(seed), 0, 32) }
        val signer = edDsa().also { it.init(priv, Signature.MODE_SIGN) }
        val out = ByteArray(64)
        signer.update(hex("af"), 0, 1)
        signer.sign(hex("82"), 0, 1, out, 0)
        assertEquals(rfc8032[2][3], out.hex())
        signer.sign(hex("af82"), 0, 2, out, 0)
        assertEquals(rfc8032[2][3], out.hex(), "nothing left over from the first message")
    }

    @Test
    fun `generated pairs are fresh and work`() {
        val seen = HashSet<String>()
        repeat(4) {
            val priv = privateKey()
            val pub = publicKey()
            assertFalse(priv.isInitialized)
            assertFalse(pub.isInitialized)
            KeyPair(pub, priv).genKeyPair()
            assertTrue(priv.isInitialized && pub.isInitialized)
            assertEquals(KeyBuilder.TYPE_XEC, priv.type)
            assertEquals(255, pub.size.toInt())
            assertEquals(32, pub.encodingLength.toInt())
            val enc = ByteArray(34)
            assertEquals(33, pub.getEncoded(enc, 1).toInt(), "the offset after the last byte")
            assertTrue(seen.add(enc.hex()), "every pair differs")

            val msg = ByteArray(40) { (it * 7).toByte() }
            val sig = ByteArray(64)
            edDsa().also { s -> s.init(priv, Signature.MODE_SIGN) }.sign(msg, 0, 40, sig, 0)
            assertTrue(edDsa().also { s -> s.init(pub, Signature.MODE_VERIFY) }.verify(msg, 0, 40, sig, 0, 64))
            // and under the JDK, from the encoded public key
            val jdkKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(hex("302a300506032b6570032100") + enc.copyOfRange(1, 33)))
            assertTrue(java.security.Signature.getInstance("Ed25519").run { initVerify(jdkKey); update(msg); verify(sig) })

            priv.clearKey()
            assertFalse(priv.isInitialized)
            assertEquals(CryptoException.UNINITIALIZED_KEY, reason { edDsa().init(priv, Signature.MODE_SIGN) })
        }
    }

    @Test
    fun `misuse is refused the way a card refuses it`() {
        val priv = privateKey()
        val pub = publicKey()
        assertEquals(CryptoException.UNINITIALIZED_KEY, reason { edDsa().init(priv, Signature.MODE_SIGN) })
        assertEquals(CryptoException.UNINITIALIZED_KEY, reason { pub.getEncoded(ByteArray(32), 0) })
        assertEquals(CryptoException.ILLEGAL_VALUE, reason { pub.setEncoded(ByteArray(31), 0, 31) })
        assertEquals(CryptoException.ILLEGAL_VALUE, reason { priv.setEncoded(ByteArray(33), 0, 33) })
        KeyPair(pub, priv).genKeyPair()
        assertEquals(CryptoException.ILLEGAL_VALUE, reason { edDsa().init(pub, Signature.MODE_SIGN) }, "signing with a public key")
        assertEquals(CryptoException.ILLEGAL_VALUE, reason { edDsa().init(priv, Signature.MODE_VERIFY) }, "verifying with a private key")
        assertEquals(CryptoException.INVALID_INIT, reason { edDsa().sign(ByteArray(1), 0, 1, ByteArray(64), 0) }, "no init")
        val verifier = edDsa().also { it.init(pub, Signature.MODE_VERIFY) }
        assertEquals(CryptoException.INVALID_INIT, reason { verifier.sign(ByteArray(1), 0, 1, ByteArray(64), 0) }, "sign in verify mode")
        val signer = edDsa().also { it.init(priv, Signature.MODE_SIGN) }
        assertEquals(CryptoException.ILLEGAL_USE, reason { signer.signPreComputedHash(ByteArray(64), 0, 64, ByteArray(64), 0) })
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_EDDSA, Cipher.PAD_PKCS1, false) })
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_EDDSA, Cipher.PAD_NULL, false) })
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { Signature.getInstance(MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_EDDSAPH, Cipher.PAD_NULL, false) })
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { NamedParameterSpec.getInstance(NamedParameterSpec.X25519) })
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { KeyBuilder.buildXECKey(ed25519(), persistentPrivate, true) })
        // a public key must be a point of the curve: some 32-byte strings are not
        val verdicts = (0 until 32).map { i ->
            runCatching { publicKey().setEncoded(ByteArray(32) { (it * 31 + i).toByte() }, 0, 32) }.isSuccess
        }
        assertTrue(verdicts.any { it } && verdicts.any { !it }, "accepted ${verdicts.count { it }} of 32")
    }

    @Test
    fun `a pair must be two XEC keys of the right kind`() {
        val ec = KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256)
        assertEquals(CryptoException.ILLEGAL_VALUE, reason { KeyPair(publicKey(), ec.private) })
        assertEquals(CryptoException.ILLEGAL_VALUE, reason { KeyPair(ec.public, privateKey()) })
        assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { KeyPair(publicKey(), privateKey()).genKeyPair(ed25519()) })
        KeyPair(publicKey(), privateKey()).genKeyPair(null)
    }

    @Test
    fun `jcardsim's own algorithms are still behind the patched classes`() {
        // KeyPair (replaced) and the four-argument Signature.getInstance (hooked)
        val pair = SecP256r1.newKeyPair()
        pair.genKeyPair()
        val priv = pair.private as ECPrivateKey
        val pub = pair.public as ECPublicKey
        val msg = ByteArray(33) { it.toByte() }
        val sig = ByteArray(80)
        // The one combination jcardsim offers through this factory: ECDSA over a
        // hash the caller computed. It must still arrive at jcardsim's own class.
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(msg)
        val signer = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, false)
        assertEquals("com.licel.jcardsim.crypto.AsymmetricSignatureImpl", signer.javaClass.name)
        signer.init(priv, Signature.MODE_SIGN)
        val n = signer.sign(hash, 0, 32, sig, 0)
        val verifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false)
        verifier.init(pub, Signature.MODE_VERIFY)
        assertTrue(verifier.verify(msg, 0, 33, sig, 0, n))
        // and what jcardsim refuses there, it still refuses
        assertFailsWith<CryptoException> {
            Signature.getInstance(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1, false)
        }
        assertEquals(Signature.ALG_ECDSA_SHA_256, verifier.algorithm)
        val two = KeyPair(pub, priv)
        assertTrue(two.public === pub && two.private === priv)
        assertNotEquals(0, (KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false)).size.toInt())
    }

    @Test
    fun `platform profiles`() {
        withProfile("null") {
            edDsa(MessageDigest.ALG_NULL)
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { edDsa(MessageDigest.ALG_SHA_512) })
        }
        withProfile("sha512") {
            edDsa(MessageDigest.ALG_SHA_512)
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { edDsa(MessageDigest.ALG_NULL) })
        }
        withProfile("none") {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { ed25519() })
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { edDsa(MessageDigest.ALG_NULL) })
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, reason { edDsa(MessageDigest.ALG_SHA_512) })
        }
        withProfile("not-pure") {
            val (seed, pub, msgHex, sigHex) = rfc8032[1]
            val priv = privateKey().also { it.setEncoded(hex(seed), 0, 32) }
            val out = ByteArray(64)
            edDsa().also { it.init(priv, Signature.MODE_SIGN) }.sign(hex(msgHex), 0, 1, out, 0)
            assertNotEquals(sigHex, out.hex(), "not the pure Ed25519 signature")
            val key = publicKey().also { it.setEncoded(hex(pub), 0, 32) }
            assertFalse(edDsa().also { it.init(key, Signature.MODE_VERIFY) }.verify(hex(msgHex), 0, 1, hex(sigHex), 0, 64))
        }
        withProfile("sign-not-pure") {
            // The two directions disagree: the RFC signature verifies, a fresh one does not.
            val (seed, pub, msgHex, sigHex) = rfc8032[1]
            val key = publicKey().also { it.setEncoded(hex(pub), 0, 32) }
            assertTrue(edDsa().also { it.init(key, Signature.MODE_VERIFY) }.verify(hex(msgHex), 0, 1, hex(sigHex), 0, 64))
            val priv = privateKey().also { it.setEncoded(hex(seed), 0, 32) }
            val out = ByteArray(64)
            edDsa().also { it.init(priv, Signature.MODE_SIGN) }.sign(hex(msgHex), 0, 1, out, 0)
            assertNotEquals(sigHex, out.hex())
            assertFalse(edDsa().also { it.init(key, Signature.MODE_VERIFY) }.verify(hex(msgHex), 0, 1, out, 0, 64))
        }
        assertFailsWith<IllegalArgumentException> { withProfile("bogus") { edDsa() } }
    }
}

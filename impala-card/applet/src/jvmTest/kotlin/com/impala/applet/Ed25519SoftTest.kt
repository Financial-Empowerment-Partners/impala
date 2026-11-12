package com.impala.applet

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The JavaCard 3.0.5 Ed25519 engine against independent references: its
 * big-number routines against [BigInteger], its signatures against the RFC
 * 8032 test vectors (byte for byte, with the nonce hedging turned off) and
 * against the JDK's Ed25519 verifier (as the card runs it, hedged).
 */
class Ed25519SoftTest {
    private val p = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
    private val l = BigInteger.TWO.pow(252) + BigInteger("27742317777372353535851937790883648493")
    private val rnd = Random(0x5EED_25519L)

    private fun be(x: BigInteger, n: Int = 32): ByteArray {
        val raw = x.toByteArray()
        val out = ByteArray(n)
        val len = minOf(n, raw.size)
        System.arraycopy(raw, raw.size - len, out, n - len, len)
        return out
    }

    private fun bi(b: ByteArray, off: Int = 0, len: Int = b.size) = BigInteger(1, b.copyOfRange(off, off + len))
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun work() = ByteArray(Ed25519Soft.W_LENGTH.toInt())

    private fun randomBelow(m: BigInteger): BigInteger = BigInteger(m.bitLength() + 64, rnd).mod(m)

    /** Values that stress carries, borrows and the reduction boundaries. */
    private fun fieldEdges() = listOf(
        BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, p - BigInteger.ONE, p - BigInteger.TWO,
        BigInteger.TWO.pow(255) - BigInteger.valueOf(20), BigInteger.TWO.pow(254), BigInteger.valueOf(19),
        BigInteger.valueOf(38), BigInteger.TWO.pow(128) - BigInteger.ONE, (p - BigInteger.ONE) / BigInteger.TWO
    )

    @Test
    fun `the constants are the curve`() {
        assertEquals(p, bi(Ed25519Soft.P))
        assertEquals(l, bi(Ed25519Soft.L))
        val a = BigInteger.valueOf(486662)
        val inv3 = BigInteger.valueOf(3).modInverse(p)
        assertEquals((a * inv3).mod(p), bi(Ed25519Soft.DELTA))
        assertEquals(((BigInteger.valueOf(3) - a * a) * inv3).mod(p), bi(Ed25519Soft.WEI_A))
        assertEquals(((BigInteger.TWO * a.pow(3) - BigInteger.valueOf(9) * a) * BigInteger.valueOf(27).modInverse(p)).mod(p), bi(Ed25519Soft.WEI_B))
        assertEquals(4, Ed25519Soft.WEI_G[0].toInt())
        val gx = bi(Ed25519Soft.WEI_G, 1, 32)
        val gy = bi(Ed25519Soft.WEI_G, 33, 32)
        assertEquals((gy * gy).mod(p), (gx.pow(3) + bi(Ed25519Soft.WEI_A) * gx + bi(Ed25519Soft.WEI_B)).mod(p))
        assertEquals((BigInteger.valueOf(9) + bi(Ed25519Soft.DELTA)).mod(p), gx)
        val c = bi(Ed25519Soft.SQRT_M486664)
        assertEquals(BigInteger.valueOf(-486664).mod(p), (c * c).mod(p))
    }

    @Test
    fun `mul32 is the 512-bit product`() {
        val cases = fieldEdges().flatMap { x -> fieldEdges().map { x to it } } +
            List(200) { BigInteger(256, rnd) to BigInteger(256, rnd) } +
            listOf(BigInteger.TWO.pow(256) - BigInteger.ONE to BigInteger.TWO.pow(256) - BigInteger.ONE)
        for ((x, y) in cases) {
            val out = ByteArray(64)
            Ed25519Soft.mul32(be(x), 0, be(y), 0, out, 0)
            assertEquals(x * y, bi(out), "$x * $y")
        }
    }

    @Test
    fun `field add, sub and mul match BigInteger`() {
        val values = fieldEdges().filter { it < p } + List(120) { randomBelow(p) }
        for (x in values) for (y in values.shuffled(rnd).take(12)) {
            val w = work()
            val a = be(x); val b = be(y)
            Ed25519Soft.feAdd(w, a, 0, b, 0, Ed25519Soft.W_F)
            assertEquals((x + y).mod(p), bi(w, Ed25519Soft.W_F.toInt(), 32), "add")
            Ed25519Soft.feSub(w, a, 0, b, 0, Ed25519Soft.W_F)
            assertEquals((x - y).mod(p), bi(w, Ed25519Soft.W_F.toInt(), 32), "sub")
            Ed25519Soft.feMul(w, a, 0, b, 0, Ed25519Soft.W_F)
            assertEquals((x * y).mod(p), bi(w, Ed25519Soft.W_F.toInt(), 32), "mul $x $y")
        }
    }

    @Test
    fun `field mul may write over either operand`() {
        repeat(50) {
            val x = randomBelow(p); val y = randomBelow(p)
            val w = work()
            val f = Ed25519Soft.W_F.toInt()
            be(x).copyInto(w, f); be(y).copyInto(w, f + 32)
            Ed25519Soft.feMul(w, w, f.toShort(), w, (f + 32).toShort(), f.toShort())
            assertEquals((x * y).mod(p), bi(w, f, 32))
            be(x).copyInto(w, f)
            Ed25519Soft.feMul(w, w, f.toShort(), w, f.toShort(), f.toShort())
            assertEquals((x * x).mod(p), bi(w, f, 32))
        }
    }

    @Test
    fun `field inversion matches BigInteger`() {
        val values = fieldEdges().filter { it.signum() > 0 && it < p } + List(150) { randomBelow(p - BigInteger.ONE) + BigInteger.ONE }
        for (x in values) {
            val w = work()
            val f = Ed25519Soft.W_F.toInt()
            be(x).copyInto(w, f)
            Ed25519Soft.feInv(w, f.toShort(), (f + 32).toShort())
            assertEquals(x.modInverse(p), bi(w, f + 32, 32), "inv $x")
        }
    }

    @Test
    fun `inverting zero is refused rather than looping`() {
        val w = work()
        assertFailsWith<javacard.security.CryptoException> {
            Ed25519Soft.feInv(w, Ed25519Soft.W_F, (Ed25519Soft.W_F + 32).toShort())
        }
    }

    @Test
    fun `scalar reduction matches BigInteger`() {
        val top = BigInteger.TWO.pow(512) - BigInteger.ONE
        val values = listOf(
            BigInteger.ZERO, BigInteger.ONE, l - BigInteger.ONE, l, l + BigInteger.ONE, l * BigInteger.TWO,
            l * l, l * l - BigInteger.ONE, top, top - l, BigInteger.TWO.pow(511), BigInteger.TWO.pow(252),
            BigInteger.TWO.pow(253) - BigInteger.ONE, l.shiftLeft(259), l.shiftLeft(259) - BigInteger.ONE
        ) + List(400) { BigInteger(512, rnd) } + List(50) { BigInteger(rnd.nextInt(512) + 1, rnd) }
        for (x in values) {
            val w = work()
            be(x, 64).copyInto(w, Ed25519Soft.W_HP.toInt())
            val out = ByteArray(32)
            Ed25519Soft.scReduce(w, Ed25519Soft.W_HP, out, 0)
            assertEquals(x.mod(l), bi(out), "reduce $x")
        }
    }

    /** RFC 8032 section 7.1: secret seed, public key, message, signature. */
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
        ),
        listOf(
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        )
    )

    /** Puts a scalar and a nonce secret into the engine's key objects, as no card command can. */
    private fun engineFromScalar(
        scalar: BigInteger,
        prefix: ByteArray,
        prefixOff: Int = 0,
        hedged: Boolean = true
    ): Ed25519Soft {
        val engine = assertNotNull(Ed25519Soft.create()) as Ed25519Soft
        assertTrue(engine.hedged, "a card hedges its nonces")
        engine.hedged = hedged
        engine.scalarKey.setFieldFP(Ed25519Soft.P, 0, 32)
        engine.scalarKey.setA(Ed25519Soft.WEI_A, 0, 32)
        engine.scalarKey.setB(Ed25519Soft.WEI_B, 0, 32)
        engine.scalarKey.setG(Ed25519Soft.WEI_G, 0, 65)
        engine.scalarKey.setR(Ed25519Soft.L, 0, 32)
        engine.scalarKey.setK(8)
        engine.scalarKey.setS(be(scalar), 0, 32)
        engine.prefixKey.setKey(prefix, prefixOff.toShort())
        engine.derivePublicKey()
        return engine
    }

    /**
     * RFC 8032 key expansion: the clamped scalar (reduced modulo L) and the
     * prefix of a seed. Hedging is off unless asked for: the RFC's signatures
     * are the deterministic ones.
     */
    private fun engineFromSeed(seed: ByteArray, hedged: Boolean = false): Ed25519Soft {
        val h = MessageDigest.getInstance("SHA-512").digest(seed)
        val s = h.copyOfRange(0, 32)
        s[0] = (s[0].toInt() and 248).toByte()
        s[31] = ((s[31].toInt() and 127) or 64).toByte()
        return engineFromScalar(BigInteger(1, s.reversedArray()).mod(l), h, 32, hedged)
    }

    @Test
    fun `RFC 8032 test vectors reproduce byte for byte`() {
        for ((seedHex, pkHex, msgHex, sigHex) in rfc8032) {
            val engine = engineFromSeed(hex(seedHex))
            assertTrue(engine.isKeyReady)
            assertTrue(engine.hasPublicKey())
            val pub = ByteArray(32)
            engine.getPublicKey(pub, 0)
            assertEquals(pkHex, pub.hex(), "public key")
            val msg = hex(msgHex)
            val sig = ByteArray(64)
            assertEquals(64, engine.sign(msg, 0, msg.size.toShort(), sig, 0).toInt())
            assertEquals(sigHex, sig.hex(), "signature over ${msg.size} bytes")
        }
    }

    private fun jdkVerify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val spki = hex("302a300506032b6570032100") + pub
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
        return Signature.getInstance("Ed25519").run { initVerify(key); update(msg); verify(sig) }
    }

    @Test
    fun `hedged signatures of one message differ and all verify`() {
        for ((seedHex, pkHex, msgHex, sigHex) in rfc8032) {
            val engine = engineFromSeed(hex(seedHex), hedged = true)
            val pub = hex(pkHex)
            val msg = hex(msgHex)
            val seen = HashSet<String>()
            repeat(4) {
                val sig = ByteArray(64)
                engine.sign(msg, 0, msg.size.toShort(), sig, 0)
                assertTrue(jdkVerify(pub, msg, sig), "a hedged signature is a valid Ed25519 signature")
                assertTrue(seen.add(sig.copyOfRange(0, 32).hex()), "a fresh nonce, so a fresh R, every time")
                assertFalse(sig.hex() == sigHex, "not the deterministic signature")
            }
        }
    }

    private fun checkSigns(engine: Ed25519, hedged: Boolean = true): String {
        val pub = ByteArray(32)
        engine.getPublicKey(pub, 0)
        for (len in listOf(0, 1, 32, 33, 64, 110, 127, 128, 129, 255)) {
            val msg = ByteArray(len).also { rnd.nextBytes(it) }
            val buf = ByteArray(3 + 64 + 3) { 0x5A }
            assertEquals(64, engine.sign(msg, 0, len.toShort(), buf, 3).toInt())
            val sig = buf.copyOfRange(3, 67)
            assertTrue(jdkVerify(pub, msg, sig), "len $len")
            assertContentEquals(byteArrayOf(0x5A, 0x5A, 0x5A), buf.copyOfRange(0, 3), "nothing before the signature")
            assertContentEquals(byteArrayOf(0x5A, 0x5A, 0x5A), buf.copyOfRange(67, 70), "nothing after the signature")
            // canonical S, bound to the message, and repeatable exactly when not hedged
            val again = ByteArray(64)
            engine.sign(msg, 0, len.toShort(), again, 0)
            assertTrue(jdkVerify(pub, msg, again), "second signature, len $len")
            assertEquals(!hedged, sig.contentEquals(again), "hedged signatures differ, deterministic ones repeat")
            assertTrue(BigInteger(1, sig.copyOfRange(32, 64).reversedArray()) < l)
            if (len > 0) {
                val other = msg.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
                assertFalse(jdkVerify(pub, other, sig))
            }
        }
        return pub.hex()
    }

    @Test
    fun `a card-generated key signs what the JDK verifies`() {
        // jcardsim's key generation is deterministic (a physical card's is not), so
        // one generated key is all this path can show; other keys follow below.
        val engine = assertNotNull(Ed25519Soft.create())
        assertFalse(engine.isKeyReady)
        assertFalse(engine.hasPublicKey())
        assertTrue(engine.generateKeyPair())
        assertTrue(engine.isKeyReady)
        assertTrue(engine.hasPublicKey())
        checkSigns(engine)
    }

    /**
     * The known-answer test of key generation uses RFC 8032 TEST 1: its
     * constants are that vector's secret scalar (reduced modulo L) and public
     * key, derived here from the seed, not copied from the engine.
     */
    @Test
    fun `the known-answer constants are RFC 8032 TEST 1`() {
        val (seedHex, pkHex, _, _) = rfc8032[0]
        val h = MessageDigest.getInstance("SHA-512").digest(hex(seedHex))
        val s = h.copyOfRange(0, 32)
        s[0] = (s[0].toInt() and 248).toByte()
        s[31] = ((s[31].toInt() and 127) or 64).toByte()
        val scalar = BigInteger(1, s.reversedArray()).mod(l)
        assertEquals(scalar, bi(Ed25519Soft.KAT_SCALAR))
        assertTrue(scalar.signum() > 0 && scalar < l, "a private key the platform accepts")
        assertEquals(pkHex, Ed25519Soft.KAT_PUBLIC.hex())
    }

    /**
     * A platform whose curve arithmetic is wrong in a consistent way agrees
     * with itself (the generated public point equals its own ECDH result) and
     * can only be caught by a known answer. jcardsim's arithmetic is right, so
     * the stand-in is a wrong expectation: key generation must then refuse,
     * leave no public key behind, and the card stays a legacy card.
     */
    @Test
    fun `key generation refuses when the known answer does not come out`() {
        val engine = assertNotNull(Ed25519Soft.create())
        val saved = Ed25519Soft.KAT_PUBLIC.copyOf()
        try {
            Ed25519Soft.KAT_PUBLIC[7] = (Ed25519Soft.KAT_PUBLIC[7].toInt() xor 0x01).toByte()
            assertFalse(engine.generateKeyPair())
            assertFalse(engine.hasPublicKey())
            assertFalse(engine.isKeyReady)
            assertFailsWith<javacard.security.CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
        } finally {
            saved.copyInto(Ed25519Soft.KAT_PUBLIC)
        }
        assertTrue(engine.generateKeyPair(), "the same engine generates once the answer is right")
        checkSigns(engine)
    }

    @Test
    fun `many keys sign what the JDK verifies`() {
        val seen = HashSet<String>()
        val scalars = listOf(BigInteger.ONE, BigInteger.TWO, l - BigInteger.ONE, l - BigInteger.TWO, BigInteger.valueOf(8)) +
            List(20) { randomBelow(l - BigInteger.ONE) + BigInteger.ONE }
        for ((i, scalar) in scalars.withIndex()) {
            val prefix = ByteArray(32).also { rnd.nextBytes(it) }
            val hedged = i % 2 == 0
            assertTrue(
                seen.add(checkSigns(engineFromScalar(scalar, prefix, hedged = hedged), hedged)),
                "distinct public keys"
            )
        }
    }

    @Test
    fun `message offsets are honoured`() {
        val engine = assertNotNull(Ed25519Soft.create())
        assertTrue(engine.generateKeyPair())
        val pub = ByteArray(32).also { engine.getPublicKey(it, 0) }
        val msg = ByteArray(32).also { rnd.nextBytes(it) }
        val padded = ByteArray(7) + msg + ByteArray(9)
        val sig = ByteArray(64)
        engine.sign(padded, 7, 32, sig, 0)
        assertTrue(jdkVerify(pub, msg, sig))
    }

    @Test
    fun `a cleared key signs nothing but keeps its public key`() {
        val engine = assertNotNull(Ed25519Soft.create())
        assertTrue(engine.generateKeyPair())
        val pub = ByteArray(32).also { engine.getPublicKey(it, 0) }
        engine.clearKey()
        assertFalse(engine.isKeyReady)
        assertTrue(engine.hasPublicKey(), "the public half outlives the private one")
        assertFailsWith<javacard.security.CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
        assertContentEquals(pub, ByteArray(32).also { engine.getPublicKey(it, 0) })
    }

    @Test
    fun `no key before generation`() {
        val engine = assertNotNull(Ed25519Soft.create())
        assertEquals(Ed25519.ENGINE_SOFT, engine.engineId())
        assertFalse(engine.hasPublicKey())
        assertFalse(engine.isKeyReady)
        assertFailsWith<javacard.security.CryptoException> { engine.sign(ByteArray(32), 0, 32, ByteArray(64), 0) }
    }
}

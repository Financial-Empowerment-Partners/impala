package com.payala.impala.stellar

import com.impala.sdk.flows.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.util.Random

class Ed25519Test {
    private data class Vector(val name: String, val seed: String, val pub: String, val sig: String, val msg: String)

    /** RFC 8032 §7.1, extracted mechanically from the RFC text (and re-checked against the JDK below). */
    private val rfc8032 = listOf(
        Vector("1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ""),
        Vector("2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            "72"),
        Vector("3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            "af82"),
        Vector("1024", "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5", "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e", "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"),
        Vector("SHA(abc)", "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf", "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    )

    private val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val d = BigInteger.valueOf(-121665).mod(p).multiply(BigInteger.valueOf(121666).modInverse(p)).mod(p)

    private fun le32(v: BigInteger): ByteArray {
        val be = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
        return be.reversedArray()
    }

    private fun encode(pt: Ed25519.Point): ByteArray {
        val zi = pt.z.modInverse(p)
        val x = pt.x.multiply(zi).mod(p)
        val y = pt.y.multiply(zi).mod(p)
        return le32(y).also { if (x.testBit(0)) it[31] = (it[31].toInt() or 0x80).toByte() }
    }

    private fun flip(bytes: ByteArray, bit: Int) = bytes.copyOf().also { it[bit / 8] = (it[bit / 8].toInt() xor (1 shl (bit % 8))).toByte() }

    @Test
    fun `the base point and the curve constants are the RFC 8032 ones`() {
        val zi = Ed25519.BASE.z.modInverse(p)
        assertEquals(BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"), Ed25519.BASE.x.multiply(zi).mod(p))
        assertEquals(BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"), Ed25519.BASE.y.multiply(zi).mod(p))
        assertEquals("5866666666666666666666666666666666666666666666666666666666666666", Hex.encode(encode(Ed25519.BASE)))
        assertTrue(Ed25519.equal(Ed25519.multiply(Ed25519.BASE, Ed25519.L), Ed25519.IDENTITY))
        assertEquals(BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555"), d)
    }

    @Test
    fun `every RFC 8032 section 7_1 vector verifies, and the JDK reproduces each one`() {
        assertEquals(listOf("1", "2", "3", "1024", "SHA(abc)"), rfc8032.map { it.name })
        assertEquals(1023, Hex.decode(rfc8032[3].msg).size)
        val kf = KeyFactory.getInstance("Ed25519")
        for (v in rfc8032) {
            val pub = Hex.decode(v.pub)
            val msg = Hex.decode(v.msg)
            val sig = Hex.decode(v.sig)
            assertTrue(v.name, Ed25519.verify(pub, msg, sig))
            // the oracle: deterministic JDK signing from the seed gives the same signature, and the JDK verifies it
            val priv = kf.generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, Hex.decode(v.seed)))
            assertEquals(v.name, v.sig, Hex.encode(Jdk.sign(priv, msg)))
            assertTrue(v.name, Jdk.verify(pub, msg, sig))
        }
    }

    @Test
    fun `a flipped bit anywhere in R, S, A or the message fails`() {
        val v = rfc8032[2]
        val pub = Hex.decode(v.pub)
        val msg = Hex.decode(v.msg)
        val sig = Hex.decode(v.sig)
        for (bit in 0 until 512) assertFalse("sig bit $bit", Ed25519.verify(pub, msg, flip(sig, bit)))
        for (bit in 0 until 256) assertFalse("pub bit $bit", Ed25519.verify(flip(pub, bit), msg, sig))
        for (bit in 0 until msg.size * 8) assertFalse("msg bit $bit", Ed25519.verify(pub, flip(msg, bit), sig))
        assertFalse(Ed25519.verify(pub, msg + byteArrayOf(0), sig))
        assertFalse(Ed25519.verify(pub, ByteArray(0), sig))
        // the other vectors, sampled
        val rnd = Random(1)
        for (w in rfc8032) {
            val wp = Hex.decode(w.pub); val wm = Hex.decode(w.msg); val ws = Hex.decode(w.sig)
            repeat(8) {
                assertFalse(Ed25519.verify(wp, wm, flip(ws, rnd.nextInt(512))))
                assertFalse(Ed25519.verify(flip(wp, rnd.nextInt(256)), wm, ws))
                if (wm.isNotEmpty()) assertFalse(Ed25519.verify(wp, flip(wm, rnd.nextInt(wm.size * 8)), ws))
            }
        }
    }

    @Test
    fun `S plus L (the malleable twin) and S at or above L are refused`() {
        for (v in rfc8032) {
            val sig = Hex.decode(v.sig)
            val s = Ed25519.littleEndian(sig, 32, 64)
            val twin = sig.copyOfRange(0, 32) + le32(s.add(Ed25519.L))
            assertFalse(v.name, Ed25519.verify(Hex.decode(v.pub), Hex.decode(v.msg), twin))
            assertFalse(v.name, Jdk.verify(Hex.decode(v.pub), Hex.decode(v.msg), twin))
        }
        val v = rfc8032[0]
        val r = Hex.decode(v.sig).copyOfRange(0, 32)
        for (s in listOf(Ed25519.L, Ed25519.L.add(BigInteger.ONE), BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE))) {
            assertFalse(Ed25519.verify(Hex.decode(v.pub), ByteArray(0), r + le32(s)))
        }
    }

    @Test
    fun `non-canonical encodings are refused - y at or above p, and x = 0 with the sign bit`() {
        for (j in 0..18) {
            for (sign in 0..1) {
                val e = le32(p.add(BigInteger.valueOf(j.toLong()))).also { if (sign == 1) it[31] = (it[31].toInt() or 0x80).toByte() }
                assertNull("y = p + $j, sign $sign", Ed25519.decode(e))
            }
        }
        // the canonical encodings of those y values that are on the curve do decode
        assertNotNull(Ed25519.decode(le32(BigInteger.ONE)))
        assertNotNull(Ed25519.decode(le32(BigInteger.ZERO)))
        // identity with the sign bit, and (0, -1) with the sign bit: x = 0 has no negative
        assertNull(Ed25519.decode(le32(BigInteger.ONE).also { it[31] = 0x80.toByte() }))
        assertNull(Ed25519.decode(le32(p.subtract(BigInteger.ONE)).also { it[31] = (it[31].toInt() or 0x80).toByte() }))
        assertNull(Ed25519.decode(ByteArray(31)))
        assertNull(Ed25519.decode(ByteArray(33)))

        // in a signature: R and A replaced by non-canonical encodings
        val v = rfc8032[0]
        val sig = Hex.decode(v.sig)
        val nonCanonical = le32(p.add(BigInteger.ONE))
        assertFalse(Ed25519.verify(Hex.decode(v.pub), ByteArray(0), nonCanonical + sig.copyOfRange(32, 64)))
        assertFalse(Ed25519.verify(nonCanonical, ByteArray(0), sig))
    }

    @Test
    fun `off-curve encodings are refused, in agreement with an independent Euler-criterion check`() {
        val exp = p.subtract(BigInteger.ONE).shiftRight(1)
        var offCurve = 0
        for (yi in 0L..300L) {
            val y = BigInteger.valueOf(yi)
            val y2 = y.multiply(y).mod(p)
            val x2 = y2.subtract(BigInteger.ONE).multiply(d.multiply(y2).add(BigInteger.ONE).modInverse(p)).mod(p)
            val onCurve = x2.signum() == 0 || x2.modPow(exp, p) == BigInteger.ONE
            assertEquals("y = $yi", onCurve, Ed25519.decode(le32(y)) != null)
            if (!onCurve) {
                offCurve++
                val v = rfc8032[0]
                val sig = Hex.decode(v.sig)
                assertFalse(Ed25519.verify(le32(y), ByteArray(0), sig))
                assertFalse(Ed25519.verify(Hex.decode(v.pub), ByteArray(0), le32(y) + sig.copyOfRange(32, 64)))
            }
        }
        assertTrue("found $offCurve off-curve y values", offCurve > 100)
    }

    @Test
    fun `all eight small-order public keys are refused, including the trivial forgery they allow`() {
        // collect the torsion subgroup: [L]P for points P outside the prime-order subgroup
        val torsion = LinkedHashSet<String>()
        var y = 2L
        while (torsion.size < 8) {
            val pt = Ed25519.decode(le32(BigInteger.valueOf(y++))) ?: continue
            torsion += Hex.encode(encode(Ed25519.multiply(pt, Ed25519.L)))
            if (y > 10_000) error("torsion collection did not converge")
        }
        // the identity, (0, -1), the two order-4 points and the well-known order-8 encodings
        for (known in listOf(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        )) assertTrue(known, known in torsion)

        val identity = Hex.decode("0100000000000000000000000000000000000000000000000000000000000000")
        for (t in torsion) {
            val a = Hex.decode(t)
            assertTrue(t, Ed25519.isSmallOrder(Ed25519.decode(a)!!))
            // R = identity, S = 0: [0]B = O = R + [k]A whenever [k]A = O
            assertFalse(t, Ed25519.verify(a, "anything".toByteArray(), identity + ByteArray(32)))
        }
        // for A = identity the cofactorless equation genuinely holds, so the small-order check is what refuses it
        val o = Ed25519.decode(identity)!!
        assertTrue(Ed25519.equal(Ed25519.multiply(Ed25519.BASE, BigInteger.ZERO), Ed25519.add(o, Ed25519.multiply(o, BigInteger.valueOf(12345)))))
        // and real keys are not small order
        assertFalse(Ed25519.isSmallOrder(Ed25519.decode(Hex.decode(rfc8032[0].pub))!!))
    }

    @Test
    fun `random JDK keys and messages - JDK signatures verify, and both implementations agree on tampering`() {
        val rnd = SecureRandom()
        repeat(150) { i ->
            val kp = Jdk.keyPair()
            val pub = Jdk.raw(kp.public)
            val msg = ByteArray(rnd.nextInt(200)).also(rnd::nextBytes)
            val sig = Jdk.sign(kp.private, msg)
            assertTrue("iteration $i", Ed25519.verify(pub, msg, sig))
            val bad = flip(sig, rnd.nextInt(512))
            assertEquals(Jdk.verify(pub, msg, bad), Ed25519.verify(pub, msg, bad))
            assertFalse(Ed25519.verify(pub, msg, bad))
            val other = Jdk.raw(Jdk.keyPair().public)
            assertFalse(Ed25519.verify(other, msg, sig))
            assertEquals(Jdk.verify(other, msg, sig), Ed25519.verify(other, msg, sig))
            val garbage = ByteArray(64).also(rnd::nextBytes)
            assertEquals(Jdk.verify(pub, msg, garbage), Ed25519.verify(pub, msg, garbage))
        }
    }

    @Test
    fun `hostile input never throws`() {
        val rnd = Random(3)
        for (pl in listOf(0, 1, 31, 32, 33, 64)) for (sl in listOf(0, 32, 63, 64, 65, 128)) {
            repeat(4) {
                val pub = ByteArray(pl).also(rnd::nextBytes)
                val sig = ByteArray(sl).also(rnd::nextBytes)
                assertFalse(Ed25519.verify(pub, ByteArray(rnd.nextInt(40)).also(rnd::nextBytes), sig))
            }
        }
        val ff = ByteArray(32) { -1 }
        assertFalse(Ed25519.verify(ff, ByteArray(0), ff + ff))
        assertFalse(Ed25519.verify(ByteArray(32), ByteArray(0), ByteArray(64)))
    }
}

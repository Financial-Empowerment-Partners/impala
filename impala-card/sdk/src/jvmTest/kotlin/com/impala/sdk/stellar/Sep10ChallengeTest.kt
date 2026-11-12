package com.impala.sdk.stellar

import com.impala.sdk.stellar.Sep10Exception.Reason
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Sep10ChallengeTest {
    private val f = ChallengeFixture()

    @Test
    fun `a well-formed challenge verifies and exposes the exact transaction slice, network id and hash`() {
        val tx = f.tx()
        val c = f.verify(f.signed(tx))
        assertContentEquals(tx.txBytes(), c.transactionBytes)
        assertContentEquals(sha256(f.passphrase.toByteArray()), c.networkId)
        assertContentEquals(sha256(sha256(f.passphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), tx.txBytes()), c.hash)
        assertEquals(f.now, c.minTime)
        assertEquals(f.now + 900, c.maxTime)
    }

    @Test
    fun `the verifier is called with the server key, the transaction hash and the signature`() {
        val tx = f.tx()
        val envelope = f.signed(tx)
        val calls = mutableListOf<Triple<ByteArray, ByteArray, ByteArray>>()
        Sep10Challenge.verify(envelope, f.expectation(), f.now, Ed25519Verifier { k, m, s -> calls += Triple(k, m, s); Jdk25519.verify(k, m, s) })
        val (key, msg, sig) = calls.single()
        assertContentEquals(f.serverPub, key)
        assertContentEquals(tx.hash(f.passphrase), msg)
        assertContentEquals(Base64.getDecoder().decode(envelope).takeLast(64).toByteArray(), sig)
    }

    @Test
    fun `accepted shapes - auth op alone, extra server data ops up to five, a valueless server op, any fee, window edges`() {
        f.verify(f.signed(f.tx(ops = listOf(f.authOp()))))
        val extra = TestOp(f.serverPub, "note".toByteArray(), null)
        f.verify(f.signed(f.tx(ops = listOf(f.authOp(), f.webAuthOp(), extra, extra, extra))))
        f.verify(f.signed(f.tx().copy(fee = 0)))
        f.verify(f.signed(f.tx().copy(fee = 0xFFFF_FFFFL)))
        // now == minTime - grace, now == maxTime, lifetime == max
        f.verify(f.signed(f.tx()), now = f.now - 300)
        f.verify(f.signed(f.tx()), now = f.now + 900)
        f.verify(f.signed(f.tx(minTime = f.now - 900, maxTime = f.now)))
        // a home_domain auth key at a later position is just server data
        f.verify(f.signed(f.tx(ops = listOf(f.authOp(), f.authOp(source = f.serverPub)))))
    }

    @Test
    fun `signedEnvelope appends the client signature to the server's bytes and both signatures verify`() {
        val tx = f.tx()
        val serverEnvelope = f.signed(tx)
        val c = f.verify(serverEnvelope)
        val clientSig = Jdk25519.sign(f.client.private, c.hash)
        val signed = Base64.getDecoder().decode(c.signedEnvelope(clientSig))

        val original = Base64.getDecoder().decode(serverEnvelope)
        val txEnd = 4 + tx.txBytes().size
        // envelope type + tx unchanged, count 1 -> 2, the server signature unchanged, the client signature appended
        assertContentEquals(original.copyOfRange(0, txEnd), signed.copyOfRange(0, txEnd))
        assertContentEquals(byteArrayOf(0, 0, 0, 2), signed.copyOfRange(txEnd, txEnd + 4))
        assertContentEquals(original.copyOfRange(txEnd + 4, original.size), signed.copyOfRange(txEnd + 4, original.size))
        val tail = signed.copyOfRange(original.size, signed.size)
        assertEquals(4 + 4 + 64, tail.size)
        assertContentEquals(f.clientPub.copyOfRange(28, 32), tail.copyOfRange(0, 4))
        assertContentEquals(byteArrayOf(0, 0, 0, 64), tail.copyOfRange(4, 8))
        assertContentEquals(clientSig, tail.copyOfRange(8, 72))

        // re-parse independently: both signatures verify over the hash under their keys
        val expected = tx.envelope(listOf(f.serverPub.copyOfRange(28, 32) to original.takeLast(64).toByteArray(), f.clientPub.copyOfRange(28, 32) to clientSig))
        assertContentEquals(expected, signed)
        assertTrue(Jdk25519.verify(f.serverPub, tx.hash(f.passphrase), original.takeLast(64).toByteArray()))
        assertTrue(Jdk25519.verify(f.clientPub, tx.hash(f.passphrase), clientSig))
        // and the doubly-signed envelope is no longer a challenge
        assertEquals(Reason.SIGNATURE_COUNT, reasonOf(Base64.getEncoder().encodeToString(signed)))
        assertFailsWith<IllegalArgumentException> { c.signedEnvelope(ByteArray(63)) }
    }

    @Test
    fun `byte arrays handed out are copies`() {
        val c = f.verify(f.signed())
        c.hash[0] = (c.hash[0] + 1).toByte()
        c.transactionBytes[0] = 9
        assertContentEquals(f.tx().hash(f.passphrase), c.hash)
        assertContentEquals(f.tx().txBytes(), c.transactionBytes)
    }

    @Test
    fun `a recorded challenge from the SDF reference anchor verifies`() {
        // GET https://testanchor.stellar.org/auth?account=GA7Q…&home_domain=testanchor.stellar.org, 2026-11-12;
        // SIGNING_KEY from its stellar.toml. Its op[0] source is the server's own decoding of the
        // SEP-23 vector address, so this also cross-checks StrKey against another implementation.
        val envelope = "AAAAAgAAAACOs4wuUbSbMTAM1yX25vNd8kro1MEFZuK9rh7ZGr+trQAAAMgAAAAAAAAAAAAAAAEAAAAAavVoyQAAAABq9WxNAAAAAAAAAAIAAAABAAAAAD8MNL+TrQ2ZcdBMzJD3BVEcg4qtlzSkovsNegP8f+iaAAAACgAAABt0ZXN0YW5jaG9yLnN0ZWxsYXIub3JnIGF1dGgAAAAAAQAAAEB2RFdiRTNENFdJTktzejF0ZnovdzhoVnlWODV5U05LTk1ZaWt2OVRidmp1VFUvSjdJM3B1Y3VGdElKdThlWHhnAAAAAQAAAACOs4wuUbSbMTAM1yX25vNd8kro1MEFZuK9rh7ZGr+trQAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAWdGVzdGFuY2hvci5zdGVsbGFyLm9yZwAAAAAAAAAAAAEav62tAAAAQOeYjY20LYH3r5s5Jsn4ZfoVXU9iANWOTQCn3JeKtZgMgJXkkRKmSVoPwRze+uG+iQ/hxO8bF7sHA+wB9beFEQw="
        val expect = Sep10Expectation(
            StrKey.decodeAccountId("GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR"),
            "Test SDF Network ; September 2015", "testanchor.stellar.org", "testanchor.stellar.org",
            StrKey.decodeAccountId("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"),
        )
        val c = Sep10Challenge.verify(envelope, expect, 1_794_468_041L, Jdk25519.verifier)
        assertEquals(900, c.maxTime - c.minTime)
        assertContentEquals(Base64.getDecoder().decode(envelope).copyOfRange(4, 404 - 76), c.transactionBytes)
        // the same bytes under another network passphrase do not verify
        val other = Sep10Expectation(expect.serverSigningKey, "Public Global Stellar Network ; September 2015", expect.homeDomain, expect.webAuthDomain, expect.clientKey)
        assertEquals(Reason.SERVER_SIGNATURE, assertFailsWith<Sep10Exception> { Sep10Challenge.verify(envelope, other, 1_794_468_041L, Jdk25519.verifier) }.reason)
    }

    private fun reasonOf(envelope: String, now: Long = f.now, expect: Sep10Expectation = f.expectation()): Reason =
        assertFailsWith<Sep10Exception> { Sep10Challenge.verify(envelope, expect, now, Jdk25519.verifier) }.reason

    private fun bytes(b64: String) = Base64.getDecoder().decode(b64)
    private fun enc(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test
    fun `every rejection rule, with its reason`() {
        val good = f.signed()
        val goodBytes = bytes(good)
        val third = Jdk25519.raw(Jdk25519.keyPair().public)
        val cases = mutableListOf<Pair<String, () -> Reason>>()
        fun case(name: String, expected: Reason, run: () -> Reason) { cases += name to { run().also { assertEquals(expected, it, name) } } }
        fun signedCase(name: String, expected: Reason, tx: TestTx, now: Long = f.now) = case(name, expected) { reasonOf(f.signed(tx), now) }

        // MALFORMED
        case("not base64", Reason.MALFORMED) { reasonOf("!!!!") }
        case("empty", Reason.MALFORMED) { reasonOf("") }
        case("whitespace in base64", Reason.MALFORMED) { reasonOf(good.substring(0, 8) + "\n" + good.substring(8)) }
        case("unpadded base64", Reason.MALFORMED) { reasonOf(good.trimEnd('=')) }
        case("url-safe base64", Reason.MALFORMED) { reasonOf(Base64.getUrlEncoder().encodeToString(goodBytes).also { check(it != good) }) }
        case("over the size cap", Reason.MALFORMED) { reasonOf("A".repeat(Sep10Challenge.MAX_ENVELOPE_BASE64_LENGTH + 4)) }
        case("truncated", Reason.MALFORMED) { reasonOf(enc(goodBytes.copyOf(goodBytes.size - 1))) }
        case("truncated to the header", Reason.MALFORMED) { reasonOf(enc(goodBytes.copyOf(8))) }
        case("trailing byte", Reason.MALFORMED) { reasonOf(enc(goodBytes + byteArrayOf(0, 0, 0, 0))) }
        case("unknown source key type", Reason.MALFORMED) { reasonOf(f.signed(f.tx().copy(sourceKeyType = 7))) }
        case("ext 1", Reason.MALFORMED) { reasonOf(f.signed(f.tx().copy(ext = 1))) }
        case("data name over 64 bytes", Reason.MALFORMED) {
            reasonOf(f.signed(f.tx(ops = listOf(f.authOp(), TestOp(f.serverPub, ByteArray(65) { 'a'.code.toByte() }, null)))))
        }
        case("data value over 64 bytes", Reason.MALFORMED) {
            reasonOf(f.signed(f.tx(ops = listOf(f.authOp(), TestOp(f.serverPub, "x".toByteArray(), ByteArray(65))))))
        }
        case("non-zero padding", Reason.MALFORMED) {
            // "web_auth_domain" is 15 bytes: one pad byte follows it
            val b = goodBytes.copyOf()
            val name = "web_auth_domain".toByteArray()
            val at = indexOf(b, name) + name.size
            check(b[at] == 0.toByte())
            b[at] = 1
            reasonOf(enc(b))
        }
        case("optional flag 2", Reason.MALFORMED) {
            val b = goodBytes.copyOf()
            // op[0]'s source-present flag sits right after the operation count, at 4 + 4+32 + 4 + 8 + 4+16 + 4 + 4
            val at = 4 + 36 + 4 + 8 + 20 + 4 + 4
            check(b[at + 3] == 1.toByte())
            b[at + 3] = 2
            reasonOf(enc(b))
        }
        case("unknown op source key type", Reason.MALFORMED) {
            val b = goodBytes.copyOf()
            val at = 4 + 36 + 4 + 8 + 20 + 4 + 4 + 4
            b[at + 3] = 3
            reasonOf(enc(b))
        }
        case("signature over 64 bytes", Reason.MALFORMED) {
            reasonOf(b64(f.tx().envelope(listOf(f.serverPub.copyOfRange(28, 32) to ByteArray(68)))))
        }
        case("more than 20 signatures", Reason.MALFORMED) {
            reasonOf(b64(f.tx().envelope(List(21) { f.serverPub.copyOfRange(28, 32) to ByteArray(64) })))
        }
        // ENVELOPE_TYPE
        signedCase("v0 envelope", Reason.ENVELOPE_TYPE, f.tx().copy(envelopeType = 0))
        signedCase("fee bump envelope", Reason.ENVELOPE_TYPE, f.tx().copy(envelopeType = 5))
        signedCase("unknown envelope type", Reason.ENVELOPE_TYPE, f.tx().copy(envelopeType = 7))
        // SERVER_KEY
        signedCase("another source", Reason.SERVER_KEY, f.tx().copy(source = third))
        signedCase("client as source", Reason.SERVER_KEY, f.tx().copy(source = f.clientPub))
        signedCase("muxed source", Reason.SERVER_KEY, f.tx().copy(muxedSource = true))
        // SEQUENCE
        signedCase("sequence 1", Reason.SEQUENCE, f.tx().copy(seq = 1))
        signedCase("sequence -1", Reason.SEQUENCE, f.tx().copy(seq = -1))
        // TIME_BOUNDS_*
        signedCase("PRECOND_NONE", Reason.TIME_BOUNDS_MISSING, f.tx().copy(cond = 0))
        case("PRECOND_V2", Reason.TIME_BOUNDS_MISSING) {
            val b = goodBytes.copyOf()
            b[4 + 36 + 4 + 8 + 3] = 2
            reasonOf(enc(b))
        }
        signedCase("maxTime 0", Reason.TIME_BOUNDS_MISSING, f.tx(minTime = 0, maxTime = 0))
        signedCase("minTime after maxTime", Reason.TIME_BOUNDS_INVALID, f.tx(minTime = f.now + 10, maxTime = f.now))
        signedCase("uint64 maxTime above 2^63", Reason.TIME_BOUNDS_INVALID, f.tx(maxTime = -1L))
        signedCase("uint64 minTime above 2^63", Reason.TIME_BOUNDS_INVALID, f.tx(minTime = Long.MIN_VALUE))
        signedCase("lifetime 901 s", Reason.TIME_BOUNDS_LIFETIME, f.tx(maxTime = f.now + 901))
        signedCase("minTime 0", Reason.TIME_BOUNDS_LIFETIME, f.tx(minTime = 0, maxTime = f.now + 300))
        signedCase("too early", Reason.TIME_BOUNDS_TOO_EARLY, f.tx(), now = f.now - 301)
        signedCase("expired", Reason.TIME_BOUNDS_EXPIRED, f.tx(), now = f.now + 901)
        // MEMO
        signedCase("memo text", Reason.MEMO, f.tx().copy(memoText = "hi"))
        // OPERATION_COUNT
        signedCase("no operations", Reason.OPERATION_COUNT, f.tx(ops = emptyList()))
        signedCase("six operations", Reason.OPERATION_COUNT, f.tx(ops = listOf(f.authOp()) + List(5) { f.webAuthOp() }))
        // OPERATION_TYPE
        signedCase("payment op", Reason.OPERATION_TYPE, f.tx(ops = listOf(f.authOp().copy(type = 1))))
        signedCase("set options as op 1", Reason.OPERATION_TYPE, f.tx(ops = listOf(f.authOp(), f.webAuthOp().copy(type = 5))))
        // OPERATION_SOURCE
        signedCase("op 0 without source", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp(source = null))))
        signedCase("op 0 sourced by the server", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp(source = f.serverPub))))
        signedCase("op 0 sourced by a third key", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp(source = third))))
        signedCase("op 0 muxed", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp().copy(muxedSource = true))))
        signedCase("op 1 sourced by the client", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp(), f.webAuthOp(source = f.clientPub))))
        signedCase("op 1 sourced by a third key", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp(), f.webAuthOp(source = third))))
        signedCase("op 1 without source", Reason.OPERATION_SOURCE, f.tx(ops = listOf(f.authOp(), f.webAuthOp(source = null))))
        // HOME_DOMAIN_KEY
        signedCase("other home domain", Reason.HOME_DOMAIN_KEY, f.tx(ops = listOf(f.authOp(name = "evil.example.com auth"))))
        signedCase("case differs", Reason.HOME_DOMAIN_KEY, f.tx(ops = listOf(f.authOp(name = "Bridge.example.com auth"))))
        signedCase("trailing space", Reason.HOME_DOMAIN_KEY, f.tx(ops = listOf(f.authOp(name = "${f.homeDomain} auth "))))
        signedCase("no auth suffix", Reason.HOME_DOMAIN_KEY, f.tx(ops = listOf(f.authOp(name = f.homeDomain))))
        signedCase("web_auth_domain first", Reason.HOME_DOMAIN_KEY, f.tx(ops = listOf(f.webAuthOp(source = f.clientPub), f.authOp(source = f.serverPub))))
        // NONCE_LENGTH
        signedCase("nonce absent", Reason.NONCE_LENGTH, f.tx(ops = listOf(f.authOp(value = null))))
        signedCase("nonce empty", Reason.NONCE_LENGTH, f.tx(ops = listOf(f.authOp(value = ByteArray(0)))))
        signedCase("nonce 63 bytes", Reason.NONCE_LENGTH, f.tx(ops = listOf(f.authOp(value = ByteArray(63)))))
        // WEB_AUTH_DOMAIN
        signedCase("other web auth domain", Reason.WEB_AUTH_DOMAIN, f.tx(ops = listOf(f.authOp(), f.webAuthOp(value = "evil.example.com".toByteArray()))))
        signedCase("web auth domain absent value", Reason.WEB_AUTH_DOMAIN, f.tx(ops = listOf(f.authOp(), f.webAuthOp(value = null))))
        signedCase("second web auth domain differs", Reason.WEB_AUTH_DOMAIN, f.tx(ops = listOf(f.authOp(), f.webAuthOp(), f.webAuthOp(value = "x".toByteArray()))))
        // SIGNATURE_COUNT
        case("unsigned", Reason.SIGNATURE_COUNT) { reasonOf(b64(f.tx().envelope(emptyList()))) }
        case("two server signatures", Reason.SIGNATURE_COUNT) {
            val sig = Jdk25519.sign(f.server.private, f.tx().hash(f.passphrase))
            val hint = f.serverPub.copyOfRange(28, 32)
            reasonOf(b64(f.tx().envelope(listOf(hint to sig, hint to sig))))
        }
        // SERVER_SIGNATURE
        case("signed by another key under the server hint", Reason.SERVER_SIGNATURE) {
            reasonOf(f.signed(by = Jdk25519.keyPair(), hint = f.serverPub.copyOfRange(28, 32)))
        }
        case("hint not the server's", Reason.SERVER_SIGNATURE) { reasonOf(f.signed(hint = byteArrayOf(1, 2, 3, 4))) }
        case("signed for another network", Reason.SERVER_SIGNATURE) { reasonOf(f.signed(passphrase = "Public Global Stellar Network ; September 2015")) }
        case("flipped signature bit", Reason.SERVER_SIGNATURE) {
            val b = goodBytes.copyOf(); b[b.size - 1] = (b[b.size - 1].toInt() xor 1).toByte(); reasonOf(enc(b))
        }
        case("63-byte signature", Reason.SERVER_SIGNATURE) {
            reasonOf(b64(f.tx().envelope(listOf(f.serverPub.copyOfRange(28, 32) to ByteArray(63)))))
        }
        case("expectation under another passphrase", Reason.SERVER_SIGNATURE) { reasonOf(good, expect = f.expectation(passphrase = "Other")) }
        case("verifier says no", Reason.SERVER_SIGNATURE) {
            assertFailsWith<Sep10Exception> { Sep10Challenge.verify(good, f.expectation(), f.now, Ed25519Verifier { _, _, _ -> false }) }.reason
        }

        val hit = cases.map { (_, run) -> run() }.toSet()
        // NETWORK is raised by clients comparing passphrases, never by verify()
        assertEquals(Reason.entries.toSet() - Reason.NETWORK, hit)
        assertTrue(cases.size >= 60, "matrix has ${cases.size} cases")
    }

    @Test
    fun `the expectation refuses malformed inputs`() {
        val k = f.serverPub
        val c = f.clientPub
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(ByteArray(31), "p", "d", "w", c) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "d", "w", ByteArray(33)) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "d", "w", k) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "", "d", "w", c) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "", "w", c) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "a".repeat(60), "w", c) }
        Sep10Expectation(k, "p", "a".repeat(59), "w", c)
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "d", "", c) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "d", "w", c, minTimeGraceSeconds = -1) }
        assertFailsWith<IllegalArgumentException> { Sep10Expectation(k, "p", "d", "w", c, maxLifetimeSeconds = 0) }
        val e = Sep10Expectation(k, "p", "d", "w", c)
        e.serverSigningKey[0] = (e.serverSigningKey[0] + 1).toByte()
        assertContentEquals(k, e.serverSigningKey)
    }

    @Test
    fun `random single-byte corruption never verifies and never escapes as another exception`() {
        val good = bytes(f.signed())
        val rnd = java.util.Random(7)
        repeat(2000) {
            val b = good.copyOf()
            val i = rnd.nextInt(b.size)
            b[i] = (b[i].toInt() xor (1 + rnd.nextInt(255))).toByte()
            val e = assertFailsWith<Sep10Exception>("byte $i") { Sep10Challenge.verify(enc(b), f.expectation(), f.now, Jdk25519.verifier) }
            assertFalse(e.message.isNullOrEmpty())
        }
        // and every truncation
        for (n in 0 until good.size) {
            assertFailsWith<Sep10Exception> { Sep10Challenge.verify(enc(good.copyOf(n)), f.expectation(), f.now, Jdk25519.verifier) }
        }
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray): Int =
        (0..hay.size - needle.size).first { i -> needle.indices.all { hay[i + it] == needle[it] } }
}

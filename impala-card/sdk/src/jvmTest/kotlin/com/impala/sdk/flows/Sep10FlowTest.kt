package com.impala.sdk.flows

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.PersonalizedCard
import com.impala.sdk.TestIssuer
import com.impala.sdk.apdu4j.ReadOnlyBibo
import com.impala.sdk.personalizedCard
import com.impala.sdk.stellar.ChallengeFixture
import com.impala.sdk.stellar.Jdk25519
import com.impala.sdk.stellar.Sep10Challenge
import com.impala.sdk.stellar.StrKey
import com.impala.sdk.stellar.TestOp
import com.impala.simulator.SimulatorBibo
import java.nio.ByteBuffer
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The whole client side of a card SEP-10 sign-in: a server-signed challenge
 * verified by the SDK's codec, signed by the real applet under jcardsim (each
 * Ed25519 engine), and the resulting envelope checked the way a SEP-10 server
 * checks it, with the JDK as the only cryptographic oracle.
 */
class Sep10FlowTest {
    private val engines = listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)

    private fun card(engine: String, n: Int = 1): PersonalizedCard =
        personalizedCard(TestIssuer(), ByteArray(16) { (n * 16 + it + 1).toByte() }, ed25519 = engine)

    /** A server-signed challenge for [cardKey], verified by the client codec. */
    private fun challengeFor(f: ChallengeFixture, cardKey: ByteArray, extra: List<TestOp> = emptyList()): Sep10Challenge =
        f.verify(f.signed(f.tx(ops = listOf(f.authOp(source = cardKey), f.webAuthOp()) + extra)), expect = f.expectation(clientKey = cardKey))

    /** What a SEP-10 server does with a posted envelope: two signatures, the server's and the client's, over the hash. */
    private fun serverAccepts(f: ChallengeFixture, envelopeBase64: String, clientKey: ByteArray, challenge: Sep10Challenge): Boolean {
        val env = Base64.getDecoder().decode(envelopeBase64)
        val tx = challenge.transactionBytes
        val buf = ByteBuffer.wrap(env)
        if (buf.int != 2) return false
        val body = ByteArray(tx.size).also { buf.get(it) }
        if (!body.contentEquals(tx)) return false
        if (buf.int != 2) return false
        val signatures = (0 until 2).map {
            val hint = ByteArray(4).also { h -> buf.get(h) }
            check(buf.int == 64)
            hint to ByteArray(64).also { s -> buf.get(s) }
        }
        if (buf.hasRemaining()) return false
        val (serverHint, serverSig) = signatures[0]
        val (clientHint, clientSig) = signatures[1]
        return serverHint.contentEquals(f.serverPub.copyOfRange(28, 32)) && Jdk25519.verify(f.serverPub, challenge.hash, serverSig) &&
            clientHint.contentEquals(clientKey.copyOfRange(28, 32)) && Jdk25519.verify(clientKey, challenge.hash, clientSig)
    }

    @Test
    fun `a card signs a verified challenge and a server would accept the envelope`() {
        for (engine in engines) {
            val f = ChallengeFixture()
            val card = card(engine)
            val key = card.sdk.getStellarKey()!!
            assertTrue(StrKey.isValidAccountId(key.address))
            assertContentEquals(key.publicKey, StrKey.decodeAccountId(key.address))
            assertEquals('G', key.address[0])

            val challenge = challengeFor(f, key.publicKey)
            val envelope = Sep10Flow.sign(card.sdk, key.publicKey, challenge, Jdk25519.verifier)
            assertTrue(serverAccepts(f, envelope, key.publicKey, challenge), "$engine: the signed envelope")
            // a second sign-in is a new challenge and a new envelope
            val f2 = ChallengeFixture()
            val challenge2 = challengeFor(f2, key.publicKey)
            assertTrue(serverAccepts(f2, Sep10Flow.sign(card.sdk, key.publicKey, challenge2, Jdk25519.verifier), key.publicKey, challenge2))
        }
    }

    @Test
    fun `a challenge for one card is refused by another`() {
        val f = ChallengeFixture()
        val a = card(SimulatorBibo.ED25519_SOFT, 1)
        val b = card(SimulatorBibo.ED25519_NATIVE, 2)
        val keyA = a.sdk.getStellarKey()!!.publicKey
        val challenge = challengeFor(f, keyA)
        val e = assertFailsWith<CardFlowException> { Sep10Flow.sign(b.sdk, keyA, challenge, Jdk25519.verifier) }
        assertIs<CardError.ChallengeRefused>(e.error)
        assertEquals("6243", e.error.statusWordHex)
    }

    @Test
    fun `a signature that is not the expected key's never leaves the flow`() {
        val f = ChallengeFixture()
        val card = card(SimulatorBibo.ED25519_SOFT)
        val key = card.sdk.getStellarKey()!!.publicKey
        val challenge = challengeFor(f, key)
        // the caller names another key: the card signs (the challenge is for the card), the check fails
        val other = Jdk25519.raw(Jdk25519.keyPair().public)
        val e = assertFailsWith<CardFlowException> { Sep10Flow.sign(card.sdk, other, challenge, Jdk25519.verifier) }
        assertIs<CardError.Other>(e.error)
        assertTrue(e.cause!!.message!!.contains("does not verify"))
        // a verifier that says no has the same effect
        assertFailsWith<CardFlowException> { Sep10Flow.sign(card.sdk, key, challenge) { _, _, _ -> false } }
        assertIs<CardError.InvalidRequest>(assertFailsWith<CardFlowException> { Sep10Flow.sign(card.sdk, ByteArray(31), challenge, Jdk25519.verifier) }.error)
    }

    @Test
    fun `a challenge the codec accepts but the card cannot hold is refused before any command`() {
        val f = ChallengeFixture()
        val card = card(SimulatorBibo.ED25519_SOFT)
        val key = card.sdk.getStellarKey()!!.publicKey
        // five entries with full-size names and values: valid SEP-10, more than 640 bytes
        val big = List(3) { f.webAuthOp().copy(name = ByteArray(64) { 'n'.code.toByte() }, value = ByteArray(64) { 1 }) }
        val challenge = challengeFor(f, key, big)
        assertTrue(challenge.transactionBytes.size > Sep10Flow.MAX_TRANSACTION_BYTES, "${challenge.transactionBytes.size} bytes")
        val sent = mutableListOf<ByteArray>()
        card.bibo.debugTrace = { cmd, _ -> sent += cmd }
        val e = assertFailsWith<CardFlowException> { Sep10Flow.sign(card.sdk, key, challenge, Jdk25519.verifier) }
        assertIs<CardError.InvalidRequest>(e.error)
        assertTrue(sent.isEmpty(), "nothing was sent to the card")
    }

    @Test
    fun `the flow reports the card's own refusals and a read-only session`() {
        val f = ChallengeFixture()
        // a legacy card: no Stellar key
        val legacy = personalizedCard(TestIssuer(), ByteArray(16) { 7 }, ed25519 = SimulatorBibo.ED25519_NONE)
        val someKey = Jdk25519.raw(Jdk25519.keyPair().public)
        val forSomeKey = challengeFor(f, someKey)
        assertEquals("623C", assertFailsWith<CardFlowException> { Sep10Flow.sign(legacy.sdk, someKey, forSomeKey, Jdk25519.verifier) }.error.statusWordHex)

        val card = card(SimulatorBibo.ED25519_NATIVE)
        val key = card.sdk.getStellarKey()!!.publicKey
        val challenge = challengeFor(f, key)
        val readOnly = ImpalaSDK(ReadOnlyBibo(card.bibo))
        val refused = assertFailsWith<CardFlowException> { Sep10Flow.sign(readOnly, key, challenge, Jdk25519.verifier) }
        assertEquals("ReadOnlyRefused(SIGN_SEP10)", refused.error.toString())
    }
}

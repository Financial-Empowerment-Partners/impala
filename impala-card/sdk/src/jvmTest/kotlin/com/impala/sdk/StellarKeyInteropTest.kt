package com.impala.sdk

import com.impala.sdk.Sep10TestXdr.challenge
import com.impala.sdk.Sep10TestXdr.challengeOfSize
import com.impala.sdk.Sep10TestXdr.ed25519Verify
import com.impala.sdk.Sep10TestXdr.networkId
import com.impala.sdk.Sep10TestXdr.op
import com.impala.sdk.Sep10TestXdr.signatureBase
import com.impala.sdk.Sep10TestXdr.tx
import com.impala.sdk.Sep10TestXdr.u32
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaChallengeException
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.StellarCardKey
import com.impala.simulator.SimulatorBibo
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The card's Stellar key and SEP-10 signing (applet 0.3), on the real applet
 * under jcardsim, for each Ed25519 engine a CAP can be built with: `soft`
 * (JavaCard 3.0.5), `native` (JavaCard 3.1, on the `:jcardsim-jc31` layer) and
 * `none` (the legacy card). Signatures are checked by the JDK, never by the
 * code under test.
 */
class StellarKeyInteropTest {
    private val engines = listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)
    private val server = ByteArray(32) { (0xC0 + it).toByte() }
    private val testnet = networkId()

    private fun account(n: Int) = ByteArray(16) { (n * 16 + it + 1).toByte() }

    private fun card(engine: String?, n: Int = 1, provisionPin: Boolean = true) =
        personalizedCard(TestIssuer(), account(n), ed25519 = engine, provisionPin = provisionPin)

    private fun sw(block: () -> Unit): Int = assertNotNull(assertFailsWith<ImpalaException> { block() }.statusWord, "a card status word")

    private fun raw(card: PersonalizedCard, p1: Int, data: ByteArray, p2: Int = 0): Int =
        swOf(card.bibo.transceive(CommandAPDU(0x00, Constants.INS_SIGN_SEP10.toInt(), p1, p2, data).bytes))

    private fun stellarKey(card: PersonalizedCard): StellarCardKey = assertNotNull(card.sdk.getStellarKey(), "the card has a Stellar key")

    // ---------------------------------------------------------------- lifecycle

    @Test
    fun `the applet is version 0_3`() {
        val v = ImpalaSDK(SimulatorBibo()).getImpalaAppletVersion()
        assertEquals("0.3", "${v.major}.${v.minor}")
    }

    @Test
    fun `a card gets its Stellar key at INITIALIZE and its cross-signatures at PERSONALIZE`() {
        for (engine in engines) {
            val keys = customKeys()
            val bibo = SimulatorBibo(installParams = PersonalizationProtocol.installParams(false, keys, null, null), ed25519 = engine)
            val sdk = ImpalaSDK(bibo, keys)

            // blank: no key, the flag is clear, and nothing can be signed
            assertNull(sdk.getStellarKey(), "$engine: no key before INITIALIZE")
            assertFalse(sdk.getPersonalization().stellarKey)
            assertEquals(0x623C, swOf(bibo.transceive(byteArrayOf(0x00, Constants.INS_GET_STELLAR_KEY, 0, 0))))
            assertEquals(0x6234, sw { sdk.signSep10(testnet, challenge(ByteArray(32), server)) })

            // initialized: the key exists, unbound
            sdk.setSeed()
            val before = assertNotNull(sdk.getStellarKey(), "$engine: a key after INITIALIZE")
            assertEquals(if (engine == SimulatorBibo.ED25519_SOFT) StellarCardKey.ENGINE_SOFT else StellarCardKey.ENGINE_NATIVE, before.engine)
            assertEquals(engine, before.engineName)
            assertEquals(32, before.publicKey.size)
            assertNull(before.bindingSignature, "$engine: no binding signature before PERSONALIZE")
            assertNull(before.proofSignature, "$engine: no proof signature before PERSONALIZE")
            assertFalse(before.isBound)
            assertTrue(sdk.getPersonalization().stellarKey, "$engine: flag 0x80")
            assertEquals(0x6234, sw { sdk.signSep10(testnet, challenge(before.publicKey, server)) }, "$engine: not personalized")

            // personalized: both signatures, over the committed identity
            val issuer = TestIssuer()
            val ecPub = sdk.getECPubKey().toByteArray()
            sdk.openSecureChannel()
            sdk.personalize(account(7), USDC, issuer.programId, issuer.certify(account(7), USDC, ecPub), issuer.pub65)
            sdk.closeSecureChannel()
            val after = assertNotNull(sdk.getStellarKey())
            assertContentEquals(before.publicKey, after.publicKey, "$engine: the key does not change")
            assertTrue(after.isBound)
            val cardId = sdk.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data.copyOfRange(16, 32)
            val binding = StellarCardKey.bindingMessage(account(7), cardId, after.publicKey)
            val proof = StellarCardKey.proofMessage(account(7), cardId, ecPub)
            assertEquals(77, binding.size)
            assertEquals(110, proof.size)
            assertTrue(Jca.verifyP256(Jca.jcaPublicKey(ecPub), binding, after.bindingSignature!!), "$engine: binding signature")
            assertTrue(ed25519Verify(after.publicKey, proof, after.proofSignature!!), "$engine: proof of possession")
            // bound to this account and this card, not to any other
            assertFalse(ed25519Verify(after.publicKey, StellarCardKey.proofMessage(account(8), cardId, ecPub), after.proofSignature!!))
            assertFalse(ed25519Verify(after.publicKey, StellarCardKey.proofMessage(account(7), account(9), ecPub), after.proofSignature!!))
            assertFalse(Jca.verifyP256(Jca.jcaPublicKey(ecPub), StellarCardKey.bindingMessage(account(8), cardId, after.publicKey), after.bindingSignature!!))
        }
    }

    @Test
    fun `a ceremony that fails leaves the key unbound`() {
        for (engine in engines) {
            val keys = customKeys()
            val bibo = SimulatorBibo(installParams = PersonalizationProtocol.installParams(false, keys, null, null), ed25519 = engine)
            val sdk = ImpalaSDK(bibo, keys)
            sdk.setSeed()
            val issuer = TestIssuer()
            val ecPub = sdk.getECPubKey().toByteArray()
            sdk.openSecureChannel()
            // a certificate for another account: part C fails its self-check (0x6677)
            assertEquals(0x6677, sw { sdk.personalize(account(1), USDC, issuer.programId, issuer.certify(account(2), USDC, ecPub), issuer.pub65) })
            assertFalse(stellarKeyOf(sdk).isBound, "$engine: nothing to report while not personalized")
            // the next, correct ceremony binds the key to the account it commits
            sdk.personalize(account(3), USDC, issuer.programId, issuer.certify(account(3), USDC, ecPub), issuer.pub65)
            sdk.closeSecureChannel()
            val key = stellarKeyOf(sdk)
            val cardId = sdk.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data.copyOfRange(16, 32)
            assertTrue(ed25519Verify(key.publicKey, StellarCardKey.proofMessage(account(3), cardId, ecPub), key.proofSignature!!))
            assertTrue(Jca.verifyP256(Jca.jcaPublicKey(ecPub), StellarCardKey.bindingMessage(account(3), cardId, key.publicKey), key.bindingSignature!!))
        }
    }

    private fun stellarKeyOf(sdk: ImpalaSDK) = assertNotNull(sdk.getStellarKey())

    @Test
    fun `every simulated card has its own Stellar key`() {
        for (engine in engines) {
            val keys = (1..4).map { ImpalaSDK(SimulatorBibo(ed25519 = engine)).apply { setSeed() }.getStellarKey()!!.publicKey.toList() }
            assertEquals(4, keys.toSet().size, "$engine: cards must not share a Stellar key")
        }
    }

    @Test
    fun `a card built without an engine is a legacy card`() {
        val card = card(SimulatorBibo.ED25519_NONE)
        assertNull(card.sdk.getStellarKey())
        val p = card.sdk.getPersonalization()
        assertTrue(p.personalized)
        assertFalse(p.stellarKey, "flag 0x80 clear")
        assertEquals(0x623C, sw { card.sdk.signSep10(testnet, challenge(ByteArray(32) { 1 }, server)) })
        assertEquals(0x623C, raw(card, 0x00, testnet + ByteArray(4)))
        // and everything a legacy card does still works
        val challenge = ByteArray(32) { it.toByte() }
        val sig = card.sdk.signAuthChallenge(challenge).toByteArray()
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), "IMPALA-AUTH:".encodeToByteArray() + card.accountId + challenge, sig))
    }

    // ------------------------------------------------------------------ signing

    @Test
    fun `the card signs a SEP-10 challenge addressed to it`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            for (passphrase in listOf(Sep10TestXdr.TESTNET, Sep10TestXdr.PUBNET)) {
                val network = networkId(passphrase)
                val challenge = challenge(key, server)
                val signature = card.sdk.signSep10(network, challenge)
                assertEquals(64, signature.size)
                assertTrue(ed25519Verify(key, signatureBase(network, challenge), signature), "$engine on $passphrase")
                // a signature for this transaction on this network only
                assertFalse(ed25519Verify(key, signatureBase(networkId("another network"), challenge), signature))
                assertFalse(ed25519Verify(key, signatureBase(network, challenge(key, server, nonce = ByteArray(64) { 9 })), signature))
            }
            // the P-256 login is untouched
            val nonce = ByteArray(32) { (it * 3).toByte() }
            assertTrue(Jca.verifyP256(Jca.jcaPublicKey(card.pub65), "IMPALA-AUTH:".encodeToByteArray() + card.accountId + nonce,
                card.sdk.signAuthChallenge(nonce).toByteArray()))
        }
    }

    @Test
    fun `challenges of every size up to the limit are staged and signed`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            // around the part boundaries: 223 bytes fit BEGIN, then 255 per part
            for (size in listOf(148, 220, 224, 228, 264, 268, 316, 476, 480, 484, 636, 640)) {
                val challenge = challengeOfSize(key, server, size)
                val signature = card.sdk.signSep10(testnet, challenge)
                assertTrue(ed25519Verify(key, signatureBase(testnet, challenge), signature), "$engine, $size bytes")
            }
            // one byte at a time is the same transaction
            val challenge = challenge(key, server)
            assertEquals(0x9000, raw(card, 0x00, testnet + challenge.copyOfRange(0, 1)))
            for (i in 1 until challenge.size - 1) assertEquals(0x9000, raw(card, 0x01, challenge.copyOfRange(i, i + 1)), "byte $i")
            val resp = card.bibo.transceive(CommandAPDU(0x00, Constants.INS_SIGN_SEP10.toInt(), 0x02, 0x00, challenge.copyOfRange(challenge.size - 1, challenge.size)).bytes)
            assertEquals(0x9000, swOf(resp))
            assertTrue(ed25519Verify(key, signatureBase(testnet, challenge), resp.copyOfRange(0, 64)), "$engine, byte by byte")
        }
    }

    @Test
    fun `the software engine hedges its nonce and the result still verifies`() {
        val card = card(SimulatorBibo.ED25519_SOFT)
        val key = stellarKey(card).publicKey
        val challenge = challenge(key, server)
        val signatures = (1..3).map { card.sdk.signSep10(testnet, challenge) }
        signatures.forEach { assertTrue(ed25519Verify(key, signatureBase(testnet, challenge), it)) }
        assertEquals(3, signatures.map { it.toList() }.toSet().size, "the same challenge never signs the same way twice")
    }

    // ---------------------------------------------------------------- refusals

    @Test
    fun `the card signs nothing but a challenge for its own key`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            val other = ByteArray(32) { (0x70 + it).toByte() }
            val nonce = ByteArray(64) { 0x41 }
            val auth = op(key, "bridge.example.org auth", nonce)
            val web = op(server, "web_auth_domain", "bridge.example.org".toByteArray())
            val refusals = listOf(
                // the property everything rests on: a transaction a network could accept is never signed
                0x6241 to tx(server, listOf(auth, web), sequence = 1),
                0x6241 to tx(server, listOf(auth, web), sequence = 4_294_967_296L),
                // a payment (type 1) dressed up as the auth entry, and one hidden behind it
                0x6242 to tx(server, listOf(op(key, "bridge.example.org auth", nonce, type = 1), web)),
                0x6242 to tx(server, listOf(auth, op(server, "web_auth_domain", nonce, type = 1))),
                0x6242 to tx(server, listOf(auth, web, op(other, "x", null, type = 8))),      // account merge
                0x6242 to tx(server, listOf(auth, web, op(other, "x", null, type = 5))),      // set options
                0x6242 to tx(server, emptyList()),
                0x6242 to tx(server, listOf(op(key, "a auth", byteArrayOf(1))) + List(5) { op(server, "x", null) }),  // six operations
                // somebody else's challenge, and anything that would put this key to other use
                0x6243 to tx(server, listOf(op(other, "bridge.example.org auth", nonce), web)),
                0x6243 to tx(server, listOf(auth, op(key, "web_auth_domain", nonce))),
                0x6243 to tx(key, listOf(auth, web)),
                0x6244 to tx(server, listOf(op(key, "bridge.example.org", nonce), web)),
                0x6244 to tx(server, listOf(op(key, "bridge.example.org auth", null), web)),
                0x6244 to tx(server, listOf(op(key, " auth", nonce), web)),
                0x6245 to tx(server, listOf(auth, web), condType = 0),
                0x6245 to tx(server, listOf(auth, web), condType = 2),
                0x6245 to tx(server, listOf(auth, web), maxTime = 0),
                0x6240 to tx(server, listOf(auth, web), memo = u32(1) + u32(4) + "memo".toByteArray()),
                0x6240 to tx(server, listOf(auth, web), ext = u32(1)),
                0x6240 to tx(server, listOf(auth, web)) + byteArrayOf(0),
                0x6240 to tx(server, listOf(auth, web)).let { it.copyOfRange(0, it.size - 1) },
                0x6240 to tx(server, listOf(auth, web)).let { it.copyOfRange(0, 40) }
            )
            for ((want, bytes) in refusals) {
                val e = assertFailsWith<ImpalaException>("$engine: ${"%04X".format(want)}") { card.sdk.signSep10(testnet, bytes) }
                assertEquals("%04X".format(want), "%04X".format(e.statusWord), "$engine, ${bytes.size} bytes")
                assertIs<ImpalaChallengeException>(e)
                // the refusal discarded the stage: there is nothing left to finish
                assertEquals(0x6985, raw(card, 0x02, ByteArray(0)), "$engine: stage cleared after ${"%04X".format(want)}")
            }
            // and the card still signs a good challenge afterwards
            val good = challenge(key, server)
            assertTrue(ed25519Verify(key, signatureBase(testnet, good), card.sdk.signSep10(testnet, good)))
        }
    }

    @Test
    fun `one card does not sign another card's challenge`() {
        val a = card(SimulatorBibo.ED25519_SOFT, 1)
        val b = card(SimulatorBibo.ED25519_NATIVE, 2)
        val forA = challenge(stellarKey(a).publicKey, server)
        assertEquals(0x6243, sw { b.sdk.signSep10(testnet, forA) })
        assertTrue(ed25519Verify(stellarKey(a).publicKey, signatureBase(testnet, forA), a.sdk.signSep10(testnet, forA)))
    }

    @Test
    fun `parts out of order, oversize and unknown parts are refused`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            val challenge = challenge(key, server)
            assertEquals(0x6985, raw(card, 0x01, ByteArray(8)), "$engine: CONTINUE without BEGIN")
            assertEquals(0x6985, raw(card, 0x02, ByteArray(0)), "$engine: FINISH without BEGIN")
            // BEGIN needs the whole network id and at least one transaction byte
            assertEquals(0x6700, raw(card, 0x00, ByteArray(0)))
            assertEquals(0x6700, raw(card, 0x00, testnet.copyOfRange(0, 31)))
            assertEquals(0x6700, raw(card, 0x00, testnet))
            assertEquals(0x6985, raw(card, 0x02, ByteArray(0)), "$engine: a refused BEGIN stages nothing")
            // unknown part, non-zero P2: refused, and they discard a stage in progress
            for ((p1, p2) in listOf(0x03 to 0, 0xFF to 0, 0x00 to 1, 0x02 to 0x80)) {
                assertEquals(0x9000, raw(card, 0x00, testnet + challenge.copyOfRange(0, 100)))
                assertEquals(0x6A86, raw(card, p1, challenge.copyOfRange(100, 110), p2), "$engine: P1=$p1 P2=$p2")
                assertEquals(0x6985, raw(card, 0x02, ByteArray(0)), "$engine: stage discarded")
            }
            // 640 transaction bytes fit, 641 do not
            assertEquals(0x9000, raw(card, 0x00, testnet + ByteArray(223)))
            assertEquals(0x9000, raw(card, 0x01, ByteArray(255)))
            assertEquals(0x9000, raw(card, 0x01, ByteArray(162)))
            assertEquals(0x6700, raw(card, 0x01, ByteArray(1)), "$engine: byte 641")
            assertEquals(0x6985, raw(card, 0x02, ByteArray(0)), "$engine: the overflow discarded the stage")
            assertEquals(0x9000, raw(card, 0x00, testnet + ByteArray(223)))
            assertEquals(0x9000, raw(card, 0x01, ByteArray(255)))
            assertEquals(0x6700, raw(card, 0x02, ByteArray(163)), "$engine: FINISH past the limit")
            // the SDK refuses an oversize transaction before sending anything
            assertFailsWith<IllegalArgumentException> { card.sdk.signSep10(testnet, ByteArray(641)) }
            assertFailsWith<IllegalArgumentException> { card.sdk.signSep10(testnet, ByteArray(0)) }
            assertFailsWith<IllegalArgumentException> { card.sdk.signSep10(ByteArray(31), challenge) }
        }
    }

    /**
     * A staged challenge survives one thing only, the next part being
     * accepted. Any other command, and any refusal that happens before the
     * SIGN_SEP10 handler runs (an unknown instruction; the same part sent
     * with the secured CLA inside an open secure channel), ends it, so a
     * later FINISH has nothing to sign.
     */
    @Test
    fun `any other command or refusal in between discards the stage`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            val challenge = challenge(key, server)
            val begin = testnet + challenge.copyOfRange(0, 200)
            val rest = challenge.copyOfRange(200, challenge.size)

            // a read-only command in between
            assertEquals(0x9000, raw(card, 0x00, begin))
            assertEquals(0x9000, swOf(card.bibo.transceive(CommandAPDU(Constants.INS_GET_VERSION).bytes)))
            assertEquals(0x6985, raw(card, 0x02, rest), "$engine: GET_VERSION ended the stage")

            // a command the card refuses outright
            assertEquals(0x9000, raw(card, 0x00, begin))
            assertEquals(0x6D00, swOf(card.bibo.transceive(CommandAPDU(0x00, 0x06, 0x00, 0x00).bytes)))
            assertEquals(0x6985, raw(card, 0x02, rest), "$engine: a refused command ended the stage")

            // inside an open secure channel, FINISH sent with the secured CLA is refused
            // by the guard in front of the handler (6E00); the stage does not survive it
            card.sdk.openSecureChannel()
            assertEquals(0x9000, raw(card, 0x00, begin))
            // (a few bytes: a secured command carries at most 111 bytes of plaintext)
            assertEquals(0x6E00, sw { card.sdk.secureTx(CommandAPDU(0x84, Constants.INS_SIGN_SEP10.toInt(), 0x02, 0x00, rest.copyOfRange(0, 8))) })
            assertEquals(0x6985, raw(card, 0x02, rest), "$engine: the guard's refusal ended the stage")
            card.sdk.closeSecureChannel()

            // a CONTINUE that is accepted keeps it, and the card then signs
            assertEquals(0x9000, raw(card, 0x00, begin))
            assertEquals(0x9000, raw(card, 0x01, rest.copyOfRange(0, 10)))
            val resp = card.bibo.transceive(CommandAPDU(0x00, Constants.INS_SIGN_SEP10.toInt(), 0x02, 0x00, rest.copyOfRange(10, rest.size)).bytes)
            assertEquals(0x9000, swOf(resp))
            assertTrue(ed25519Verify(key, signatureBase(testnet, challenge), resp.copyOfRange(0, 64)))
        }
    }

    @Test
    fun `BEGIN starts over and a signature consumes the stage`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            val first = challenge(key, server, nonce = ByteArray(64) { 1 })
            val second = challenge(key, server, nonce = ByteArray(64) { 2 })
            // an abandoned first challenge leaves no trace in the second
            assertEquals(0x9000, raw(card, 0x00, testnet + first.copyOfRange(0, 200)))
            assertEquals(0x9000, raw(card, 0x00, testnet + second.copyOfRange(0, 200)))
            val resp = card.bibo.transceive(CommandAPDU(0x00, Constants.INS_SIGN_SEP10.toInt(), 0x02, 0x00, second.copyOfRange(200, second.size)).bytes)
            assertEquals(0x9000, swOf(resp))
            assertTrue(ed25519Verify(key, signatureBase(testnet, second), resp.copyOfRange(0, 64)))
            assertFalse(ed25519Verify(key, signatureBase(testnet, first), resp.copyOfRange(0, 64)))
            // signed once: FINISH again has nothing to sign
            assertEquals(0x6985, raw(card, 0x02, ByteArray(0)), "$engine: the stage is consumed")
            assertEquals(0x6985, raw(card, 0x01, ByteArray(4)))
        }
    }

    @Test
    fun `a reset discards a challenge in progress`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card).publicKey
            val challenge = challenge(key, server)
            assertEquals(0x9000, raw(card, 0x00, testnet + challenge.copyOfRange(0, 200)))
            card.bibo.reset()
            val aid = SimulatorBibo.APPLET_INSTANCE_AID.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            assertEquals(0x9000, swOf(card.bibo.transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid)))
            assertEquals(0x6985, raw(card, 0x02, challenge.copyOfRange(200, challenge.size)), "$engine: nothing staged after a reset")
            // the key and its signatures are persistent
            assertTrue(stellarKey(card).isBound)
            assertContentEquals(key, stellarKey(card).publicKey)
            assertTrue(ed25519Verify(key, signatureBase(testnet, challenge), card.sdk.signSep10(testnet, challenge)))
        }
    }

    // ------------------------------------------------------------------- gates

    @Test
    fun `the secure channel does not carry the Stellar commands`() {
        for (engine in engines) {
            val card = card(engine)
            card.sdk.openSecureChannel()
            assertEquals(0x6E00, sw { card.sdk.secureTx(CommandAPDU(0x84, Constants.INS_GET_STELLAR_KEY.toInt(), 0, 0)) })
            assertEquals(0x6E00, sw { card.sdk.secureTx(CommandAPDU(0x84, Constants.INS_SIGN_SEP10.toInt(), 0, 0, testnet + ByteArray(8))) })
            card.sdk.closeSecureChannel()
        }
    }

    @Test
    fun `the provisioning gate covers SEP-10 signing`() {
        for (engine in engines) {
            // ENFORCE without a provisioned user PIN: the card is personalized but may not sign yet
            val card = card(engine, provisionPin = false)
            val key = stellarKey(card)
            assertTrue(key.isBound, "$engine: personalization does not need the PIN")
            assertEquals(0x6985, sw { card.sdk.signSep10(testnet, challenge(key.publicKey, server)) })
            assertEquals(0x6985, sw { card.sdk.signAuthChallenge(ByteArray(16)) }, "the same gate as SIGN_AUTH")
            card.sdk.openSecureChannel()
            card.sdk.provisionUserPIN("4321")
            card.sdk.closeSecureChannel()
            val challenge = challenge(key.publicKey, server)
            assertTrue(ed25519Verify(key.publicKey, signatureBase(testnet, challenge), card.sdk.signSep10(testnet, challenge)))
        }
    }

    @Test
    fun `a terminated card keeps its public key and signs nothing`() {
        for (engine in engines) {
            val card = card(engine)
            val key = stellarKey(card)
            val challenge = challenge(key.publicKey, server)
            assertEquals(0x9000, raw(card, 0x00, testnet + challenge.copyOfRange(0, 100)))
            card.sdk.openSecureChannel()
            card.sdk.terminate(card.accountId)
            card.sdk.closeSecureChannel()
            assertEquals(0x6687, sw { card.sdk.signSep10(testnet, challenge) }, "$engine: terminated")
            assertEquals(0x6687, raw(card, 0x02, challenge.copyOfRange(100, challenge.size)))
            // inspection still works, as for the P-256 key
            val after = stellarKey(card)
            assertContentEquals(key.publicKey, after.publicKey)
            assertTrue(after.isBound)
            val p = card.sdk.getPersonalization()
            assertTrue(p.terminated && p.stellarKey)
        }
    }

    @Test
    fun `a read-only session reads the key and refuses to sign`() {
        val card = card(SimulatorBibo.ED25519_SOFT)
        val key = stellarKey(card).publicKey
        val readOnly = ImpalaSDK(com.impala.sdk.apdu4j.ReadOnlyBibo(card.bibo))
        assertContentEquals(key, readOnly.getStellarKey()!!.publicKey)
        val e = assertFailsWith<ImpalaException> { readOnly.signSep10(testnet, challenge(key, server)) }
        assertIs<com.impala.sdk.apdu4j.ReadOnlyViolationException>(e.cause)
        assertEquals("ReadOnlyRefused(SIGN_SEP10)", com.impala.sdk.flows.CardError.from(e).toString())
    }
}

package com.payala.impala.card

import com.impala.jcardsim.jc31.CardPlatform
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.stellar.Sep10Exception
import com.impala.sdk.stellar.StrKey
import com.impala.simulator.Jca
import com.impala.simulator.PersonalizedCard
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.stellar.Ed25519
import com.payala.impala.stellar.FakeTransport
import com.payala.impala.stellar.Jdk
import com.payala.impala.stellar.Sep10Client
import com.payala.impala.stellar.Sep10ClientException
import com.payala.impala.stellar.Sep10HttpException
import com.payala.impala.stellar.TestAnchor
import com.payala.impala.stellar.sha256
import java.io.IOException
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The sign-in compatibility layer end to end: the real applet under jcardsim
 * (each Ed25519 engine, and a card without one), a test SEP-10 server that
 * checks the posted envelope the way a server does, and the legacy challenge.
 */
@RunWith(RobolectricTestRunner::class)
class CardSignInTest {
    private val now = 1_800_000_000L
    private val legacyChallengeHex = "5a".repeat(32)

    private class Setup(
        val card: PersonalizedCard,
        val anchor: TestAnchor,
        val transport: FakeTransport,
        val signIn: CardSignIn,
        val legacyFetches: MutableList<String>,
        val cardCommands: MutableList<Int>,
        val steps: MutableList<CardSignIn.Step>
    )

    /** The token a correct envelope earns; anything else is a 401, as from a real server. */
    private fun serverPost(anchor: TestAnchor, requestedAccount: () -> String?): (String, String) -> String = { _, transaction ->
        val env = Base64.getDecoder().decode(transaction)
        val tx = env.copyOfRange(4, env.size - 4 - 2 * 72)
        val hash = sha256(sha256(anchor.passphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), tx)
        val sigs = env.copyOfRange(env.size - 2 * 72, env.size)
        val serverSig = sigs.copyOfRange(8, 72)
        val clientHint = sigs.copyOfRange(72, 76)
        val clientSig = sigs.copyOfRange(80, 144)
        val client = StrKey.decodeAccountId(requestedAccount()!!)
        val ok = env.copyOfRange(env.size - 4 - 2 * 72, env.size - 2 * 72).contentEquals(byteArrayOf(0, 0, 0, 2)) &&
            Jdk.verify(Jdk.raw(anchor.signer.public), hash, serverSig) &&
            clientHint.contentEquals(client.copyOfRange(28, 32)) && Jdk.verify(client, hash, clientSig)
        if (!ok) throw Sep10HttpException(401, "invalid challenge")
        "{\"token\":\"header.payload.sig\",\"success\":true,\"refresh_token\":\"refresh\"}"
    }

    private fun setup(engine: String?, withSep10: Boolean = true, platform: CardPlatform? = null): Setup {
        val card = personalizedCard(TestIssuer(), uuidBytes(), ed25519 = engine, platform = platform)
        val anchor = TestAnchor()
        var account: String? = null
        val transport = FakeTransport(
            toml = { anchor.toml() },
            challenge = { _, acct, _ -> account = acct; anchor.challengeJson(anchor.challenge(StrKey.decodeAccountId(acct), now)) }
        )
        transport.post = serverPost(anchor) { account }
        val legacyFetches = mutableListOf<String>()
        val client = if (withSep10) Sep10Client(anchor.homeDomain, anchor.passphrase, transport, Ed25519) { now } else null
        val signIn = CardSignIn(client) { cardId -> legacyFetches += cardId; legacyChallengeHex }
        val commands = mutableListOf<Int>()
        card.bibo.debugTrace = { cmd, _ -> commands += cmd[1].toInt() and 0xFF }
        return Setup(card, anchor, transport, signIn, legacyFetches, commands, mutableListOf())
    }

    private fun run(s: Setup): CardSignInResult =
        offMain {
            ImpalaCardSession.fromBibo(s.card.bibo).use { session ->
                s.signIn.signIn(session, listener = { step -> s.steps += step })
            }
        }

    private fun assertLegacySignature(s: Setup, result: CardSignInResult.Legacy) {
        val message = "IMPALA-AUTH:".toByteArray() + s.card.accountId + ByteArray(32) { 0x5a }
        val der = ByteArray(result.signatureHex.length / 2) { result.signatureHex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(s.card.pub65), message, der))
    }

    @Test
    fun `a card with a Stellar key signs in with SEP-10`() {
        for (engine in listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)) {
            val s = setup(engine)
            val result = run(s) as CardSignInResult.Sep10
            assertEquals(CardAuthMechanism.SEP10, result.mechanism)
            assertTrue(result.tokenJson, result.tokenJson.contains("header.payload.sig"))
            assertTrue(StrKey.isValidAccountId(result.stellarAddress))
            assertEquals(listOf("toml", "challenge", "post"), s.transport.calls.map { it.substringBefore(' ') })
            assertTrue("$engine: the account asked for is the card's", s.transport.calls[1].contains(result.stellarAddress))
            assertTrue("$engine: the legacy challenge was never requested", s.legacyFetches.isEmpty())
            assertTrue("$engine: SIGN_SEP10 was used", 0x38 in s.cardCommands)
            assertFalse("$engine: SIGN_AUTH was not", 0x25 in s.cardCommands)
            assertEquals(
                listOf(CardSignIn.Step.READING_CARD, CardSignIn.Step.CONTACTING_SERVER, CardSignIn.Step.SIGNING, CardSignIn.Step.SUBMITTING),
                s.steps
            )
            assertEquals(s.card.accountId.toList(), result.identity.accountId.toList())
        }
    }

    /**
     * The layer asks the card what it has, never what it was meant to have: the
     * same CAP is a SEP-10 card on hardware that could make the Stellar key and
     * a legacy card on hardware that could not (impala-card README, "Platform
     * dependencies"). Both hardware classes sign in with SEP-10: a JavaCard
     * 3.0.5 card on the software engine, a JavaCard 3.2 card on its own EdDSA.
     */
    @Test
    fun `the hardware under the card decides between SEP-10 and the legacy challenge`() {
        val expected = listOf(
            Triple(CardPlatform.JC305, SimulatorBibo.ED25519_SOFT, CardAuthMechanism.SEP10),
            Triple(CardPlatform.JC32, SimulatorBibo.ED25519_NATIVE, CardAuthMechanism.SEP10),
            // Ed25519 only under the JavaCard 3.2 constant, and the default CAP on JavaCard 3.2 hardware
            Triple(CardPlatform.JC32_PER_CURVE, SimulatorBibo.ED25519_NATIVE, CardAuthMechanism.SEP10),
            Triple(CardPlatform.JC32, SimulatorBibo.ED25519_SOFT, CardAuthMechanism.SEP10),
            // the CAP loaded, the platform could not make the key
            Triple(CardPlatform.JC305_NO_XY, SimulatorBibo.ED25519_SOFT, CardAuthMechanism.LEGACY),
            Triple(CardPlatform.JC305_WRONG_CURVE_MATH, SimulatorBibo.ED25519_SOFT, CardAuthMechanism.LEGACY),
            Triple(CardPlatform.JC305_SMALL_RAM, SimulatorBibo.ED25519_SOFT, CardAuthMechanism.LEGACY),
            Triple(CardPlatform.JC32_NO_EDDSA, SimulatorBibo.ED25519_NATIVE, CardAuthMechanism.LEGACY)
        )
        for ((platform, cap, mechanism) in expected) {
            val what = "${platform.name()} + $cap CAP"
            val s = setup(cap, platform = platform)
            val result = run(s)
            assertEquals(what, mechanism, result.mechanism)
            if (result is CardSignInResult.Legacy) {
                assertNull("$what: not a fallback, this card has no other way", result.fallback)
                assertTrue("$what: the server was never asked", s.transport.calls.isEmpty())
                assertFalse(0x38 in s.cardCommands)
                assertLegacySignature(s, result)
            } else {
                assertTrue("$what: the legacy challenge was never requested", s.legacyFetches.isEmpty())
                assertTrue("$what: SIGN_SEP10 was used", 0x38 in s.cardCommands)
                assertEquals(listOf("toml", "challenge", "post"), s.transport.calls.map { it.substringBefore(' ') })
            }
        }
    }

    @Test
    fun `a card without a Stellar key signs the legacy challenge and never touches SEP-10`() {
        val s = setup(SimulatorBibo.ED25519_NONE)
        val result = run(s) as CardSignInResult.Legacy
        assertEquals(CardAuthMechanism.LEGACY, result.mechanism)
        assertNull("not a fallback: this card has no other way", result.fallback)
        assertTrue(s.transport.calls.isEmpty())
        assertEquals(listOf(result.identity.wireCardId), s.legacyFetches)
        assertFalse(0x38 in s.cardCommands)
        assertFalse("a legacy card is not even asked for a Stellar key", 0x37 in s.cardCommands)
        assertLegacySignature(s, result)
        assertEquals(listOf(CardSignIn.Step.READING_CARD, CardSignIn.Step.CONTACTING_SERVER, CardSignIn.Step.SIGNING), s.steps)
    }

    @Test
    fun `without a configured home domain a Stellar card uses the legacy challenge`() {
        val s = setup(SimulatorBibo.ED25519_SOFT, withSep10 = false)
        val result = run(s) as CardSignInResult.Legacy
        assertEquals(Sep10Fallback.NOT_CONFIGURED, result.fallback)
        assertTrue(s.transport.calls.isEmpty())
        assertFalse(0x38 in s.cardCommands)
        assertLegacySignature(s, result)
    }

    @Test
    fun `a server that does not offer SEP-10 gets the legacy challenge in the same tap`() {
        val cases: List<Pair<String, (Setup) -> Unit>> = listOf(
            "no stellar.toml" to { s -> s.transport.toml = { throw Sep10HttpException(404, "") } },
            "stellar.toml without a web-auth endpoint" to { s -> s.transport.toml = { s.anchor.toml(endpoint = null) } },
            "endpoint not mounted" to { s -> s.transport.challenge = { _, _, _ -> throw Sep10HttpException(404, "") } },
            "SEP-10 switched off or without a signing key" to { s -> s.transport.challenge = { _, _, _ -> throw Sep10HttpException(503, "") } }
        )
        for ((name, arrange) in cases) {
            val s = setup(SimulatorBibo.ED25519_SOFT)
            arrange(s)
            val result = run(s) as CardSignInResult.Legacy
            assertEquals(name, Sep10Fallback.NOT_OFFERED, result.fallback)
            assertFalse("$name: nothing was signed with the Stellar key", 0x38 in s.cardCommands)
            assertEquals(name, 1, s.legacyFetches.size)
            assertLegacySignature(s, result)
            assertEquals(name, CardSignIn.Step.FALLING_BACK, s.steps[2])
        }
    }

    @Test
    fun `a server that does not know the card's Stellar key gets the legacy challenge in the same tap`() {
        val s = setup(SimulatorBibo.ED25519_NATIVE)
        s.transport.post = { _, _ -> throw Sep10HttpException(401, "{\"error\":\"unauthorized\"}") }
        val result = run(s) as CardSignInResult.Legacy
        assertEquals(Sep10Fallback.NOT_REGISTERED, result.fallback)
        assertEquals(listOf("toml", "challenge", "post"), s.transport.calls.map { it.substringBefore(' ') })
        assertTrue("both signatures were made in one session", 0x38 in s.cardCommands && 0x25 in s.cardCommands)
        assertLegacySignature(s, result)
        assertEquals(
            listOf(CardSignIn.Step.READING_CARD, CardSignIn.Step.CONTACTING_SERVER, CardSignIn.Step.SIGNING, CardSignIn.Step.SUBMITTING,
                CardSignIn.Step.FALLING_BACK, CardSignIn.Step.CONTACTING_SERVER, CardSignIn.Step.SIGNING),
            s.steps
        )
    }

    @Test
    fun `a lockout, a transport failure and a bad challenge are errors, never a fallback`() {
        // 429: the lockout is shown as what it is
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            s.transport.post = { _, _ -> throw Sep10HttpException(429, "") }
            assertEquals(429, assertThrows(Sep10HttpException::class.java) { run(s) }.status)
            assertTrue(s.legacyFetches.isEmpty())
            assertFalse(0x25 in s.cardCommands)
        }
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            s.transport.challenge = { _, _, _ -> throw Sep10HttpException(429, "") }
            assertThrows(Sep10HttpException::class.java) { run(s) }
            assertTrue(s.legacyFetches.isEmpty())
        }
        // the network is down: the legacy path would fare no better
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            s.transport.toml = { throw IOException("no route") }
            assertThrows(IOException::class.java) { run(s) }
            assertTrue(s.legacyFetches.isEmpty())
        }
        // a 500 is a broken server, not "no SEP-10 here"
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            s.transport.post = { _, _ -> throw Sep10HttpException(500, "") }
            assertThrows(Sep10HttpException::class.java) { run(s) }
            assertTrue(s.legacyFetches.isEmpty())
        }
        // a challenge signed by someone other than stellar.toml's key: the card is never asked to sign it
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            val impostor = Jdk.keyPair()
            s.transport.challenge = { _, acct, _ -> s.anchor.challengeJson(s.anchor.challenge(StrKey.decodeAccountId(acct), now, signWith = impostor)) }
            assertEquals(Sep10Exception.Reason.SERVER_SIGNATURE, assertThrows(Sep10Exception::class.java) { run(s) }.reason)
            assertFalse("the card signed nothing", 0x38 in s.cardCommands || 0x25 in s.cardCommands)
            assertTrue(s.legacyFetches.isEmpty())
        }
        // a challenge for some other account than the card's
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            val other = Jdk.raw(Jdk.keyPair().public)
            s.transport.challenge = { _, _, _ -> s.anchor.challengeJson(s.anchor.challenge(other, now)) }
            assertEquals(Sep10Exception.Reason.OPERATION_SOURCE, assertThrows(Sep10Exception::class.java) { run(s) }.reason)
            assertFalse(0x38 in s.cardCommands || 0x25 in s.cardCommands)
        }
        // a stellar.toml for another network
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            s.transport.toml = { s.anchor.toml(passphrase = "Public Global Stellar Network ; September 2015") }
            assertEquals(Sep10Exception.Reason.NETWORK, assertThrows(Sep10Exception::class.java) { run(s) }.reason)
            assertTrue(s.legacyFetches.isEmpty())
        }
        // a malformed stellar.toml is not "no SEP-10 here" either
        setup(SimulatorBibo.ED25519_SOFT).let { s ->
            s.transport.toml = { "SIGNING_KEY = \"not a key\"\nWEB_AUTH_ENDPOINT = \"https://auth.example.com/auth/sep10\"\n" }
            assertEquals(Sep10ClientException.Kind.TOML_INVALID, assertThrows(Sep10ClientException::class.java) { run(s) }.kind)
            assertTrue(s.legacyFetches.isEmpty())
        }
    }

    @Test
    fun `the fallback rule is exactly three cases`() {
        assertEquals(Sep10Fallback.NOT_OFFERED, CardSignIn.fallbackFor(Sep10ClientException(Sep10ClientException.Kind.NOT_OFFERED, "x")))
        assertEquals(Sep10Fallback.NOT_OFFERED, CardSignIn.fallbackFor(Sep10HttpException(404, "")))
        assertEquals(Sep10Fallback.NOT_OFFERED, CardSignIn.fallbackFor(Sep10HttpException(503, "")))
        assertEquals(Sep10Fallback.NOT_REGISTERED, CardSignIn.fallbackFor(Sep10HttpException(401, "")))
        for (status in listOf(400, 403, 409, 422, 429, 500, 502, 504, 301, 302)) {
            assertNull("HTTP $status", CardSignIn.fallbackFor(Sep10HttpException(status, "")))
        }
        for (kind in Sep10ClientException.Kind.values().filter { it != Sep10ClientException.Kind.NOT_OFFERED }) {
            assertNull(kind.name, CardSignIn.fallbackFor(Sep10ClientException(kind, "x")))
        }
        for (reason in Sep10Exception.Reason.values()) assertNull(reason.name, CardSignIn.fallbackFor(Sep10Exception(reason, "x")))
        assertNull(CardSignIn.fallbackFor(IOException("down")))
        assertNull(CardSignIn.fallbackFor(CardFlowException(CardError.ChallengeRefused(0x6241))))
        assertNull(CardSignIn.fallbackFor(CardFlowException(CardError.TagLost)))
        assertNull(CardSignIn.fallbackFor(IllegalStateException("x")))
    }

    @Test
    fun `an unissued card fails before any request`() {
        val anchor = TestAnchor()
        val transport = FakeTransport(toml = { anchor.toml() }, challenge = { _, _, _ -> error("not reached") })
        val fetched = mutableListOf<String>()
        val signIn = CardSignIn(Sep10Client(anchor.homeDomain, anchor.passphrase, transport, Ed25519) { now }) { fetched += it; legacyChallengeHex }
        val blank = SimulatorBibo().also { com.impala.sdk.ImpalaSDK(it).setSeed() }
        val e = assertThrows(CardFlowException::class.java) { offMain { ImpalaCardSession.fromBibo(blank).use { signIn.signIn(it) } } }
        assertTrue(e.error is CardError.NotPersonalized)
        assertTrue(transport.calls.isEmpty() && fetched.isEmpty())
    }

    @Test
    fun `signing in on the main thread is refused`() {
        val s = setup(SimulatorBibo.ED25519_SOFT)
        assertThrows(IllegalStateException::class.java) { s.signIn.signIn(ImpalaCardSession.fromBibo(s.card.bibo)) }
    }

    @Test
    fun `the card-facing steps are available on their own`() {
        for ((engine, mechanism) in listOf(
            SimulatorBibo.ED25519_SOFT to CardAuthMechanism.SEP10,
            SimulatorBibo.ED25519_NATIVE to CardAuthMechanism.SEP10,
            SimulatorBibo.ED25519_NONE to CardAuthMechanism.LEGACY
        )) {
            val card = personalizedCard(TestIssuer(), uuidBytes(), ed25519 = engine)
            // a read-only session can tell the mechanism and read the key, but not sign
            val readOnly = ImpalaCardSession.fromBibo(card.bibo, readOnly = true)
            assertEquals(engine, mechanism, offMain { CardAuthenticator.mechanism(readOnly) })
            val key = offMain { CardAuthenticator.stellarKey(readOnly) }
            assertEquals(engine, mechanism == CardAuthMechanism.SEP10, key != null)
            if (key != null) {
                val identity = offMain { readOnly.identity }
                assertTrue(CardStellarKeys.bindingVerifies(identity.pubKey, identity.accountId, identity.cardId, key))
                assertTrue(CardStellarKeys.proofVerifies(identity.pubKey, identity.accountId, identity.cardId, key))
                assertFalse(CardStellarKeys.bindingVerifies(identity.pubKey, uuidBytes(), identity.cardId, key))
                assertFalse(CardStellarKeys.proofVerifies(identity.pubKey, identity.accountId, uuidBytes(), key))
                assertFalse(CardStellarKeys.proofVerifies(ByteArray(65), identity.accountId, identity.cardId, key))
                assertFalse(CardStellarKeys.bindingVerifies(ByteArray(64), identity.accountId, identity.cardId, key))

                val anchor = TestAnchor()
                val transport = FakeTransport(
                    toml = { anchor.toml() },
                    challenge = { _, acct, _ -> anchor.challengeJson(anchor.challenge(StrKey.decodeAccountId(acct), now)) }
                )
                val prepared = Sep10Client(anchor.homeDomain, anchor.passphrase, transport, Ed25519) { now }.prepare(key.publicKey)
                val refused = assertThrows(CardFlowException::class.java) { offMain { CardAuthenticator.signSep10(readOnly, key.publicKey, prepared.challenge) } }
                assertEquals("ReadOnlyRefused(SIGN_SEP10)", refused.error.toString())
                val envelope = offMain { CardAuthenticator.signSep10(ImpalaCardSession.fromBibo(card.bibo), key.publicKey, prepared.challenge) }
                assertTrue(envelope.length > 400)
            }
            assertThrows(IllegalStateException::class.java) { CardAuthenticator.mechanism(ImpalaCardSession.fromBibo(card.bibo)) }
            assertThrows(IllegalStateException::class.java) { CardAuthenticator.stellarKey(ImpalaCardSession.fromBibo(card.bibo)) }
        }
    }

    // ── MFA extras (docs/mfa-card-pin-biometrics.md) ───────────────────────

    /** The challenge hash a SEP-10 envelope was signed over (as a server recomputes it). */
    private fun challengeHashOf(anchor: TestAnchor, transaction: String): ByteArray {
        val env = Base64.getDecoder().decode(transaction)
        val tx = env.copyOfRange(4, env.size - 4 - 2 * 72)
        return sha256(sha256(anchor.passphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), tx)
    }

    @Test
    fun `a SEP-10 sign-in with the user PIN attaches a verifying PIN proof`() {
        val s = setup(SimulatorBibo.ED25519_SOFT)
        var postedTx: String? = null
        val inner = s.transport.post
        s.transport.post = { endpoint, tx -> postedTx = tx; inner(endpoint, tx) }

        val result = offMain {
            ImpalaCardSession.fromBibo(s.card.bibo).use { session ->
                s.signIn.signIn(session, null, SignInOptions(pin = "1111"))
            }
        } as CardSignInResult.Sep10
        assertTrue(result.tokenJson.contains("header.payload.sig"))

        // The PIN proof rode the POST and verifies under the card's P-256 key
        // over "IMPALA-APIN:" ‖ accountId ‖ challengeHash — a different tag from
        // the "IMPALA-AUTH:" sign-in message.
        val proofHex = s.transport.lastPostExtras.pinProofHex!!
        val hash = challengeHashOf(s.anchor, postedTx!!)
        val der = ByteArray(proofHex.length / 2) { proofHex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
        val pub = Jca.jcaPublicKey(s.card.pub65)
        assertTrue(Jca.verifyP256(pub, "IMPALA-APIN:".toByteArray() + s.card.accountId + hash, der))
        assertFalse(Jca.verifyP256(pub, "IMPALA-AUTH:".toByteArray() + s.card.accountId + hash, der))
        assertTrue("VERIFY_PIN was used", 0x18 in s.cardCommands)
    }

    @Test
    fun `a SEP-10 sign-in with a device signer attaches a verifying device assertion`() {
        val s = setup(SimulatorBibo.ED25519_SOFT)
        var postedTx: String? = null
        val inner = s.transport.post
        s.transport.post = { endpoint, tx -> postedTx = tx; inner(endpoint, tx) }

        val deviceKey = Jca.genP256()
        val devicePub = Jca.uncompressedPoint(deviceKey.public as java.security.interfaces.ECPublicKey)
        val accountId = "device-account-1"
        val signer = DeviceAssertionSigner { purpose, challenge ->
            val msg = DeviceKeyProtocol.message(purpose, accountId, challenge)
            DeviceAssertion("key-123", Jca.signP256(deviceKey.private, msg).let { der -> der.joinToString("") { "%02x".format(it) } })
        }

        offMain {
            ImpalaCardSession.fromBibo(s.card.bibo).use { session ->
                s.signIn.signIn(session, null, SignInOptions(deviceSigner = signer))
            }
        }
        assertEquals("key-123", s.transport.lastPostExtras.deviceKeyId)
        val sigHex = s.transport.lastPostExtras.deviceSignatureHex!!
        val der = ByteArray(sigHex.length / 2) { sigHex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
        val hash = challengeHashOf(s.anchor, postedTx!!)
        val expected = DeviceKeyProtocol.message(DeviceKeyProtocol.PURPOSE_SEP10_SIGN_IN, accountId, hash)
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(devicePub), expected, der))
    }

    @Test
    fun `a legacy sign-in with the user PIN carries a PIN proof on the result`() {
        val s = setup(SimulatorBibo.ED25519_NONE) // no Stellar key: the legacy path
        val result = offMain {
            ImpalaCardSession.fromBibo(s.card.bibo).use { session ->
                s.signIn.signIn(session, null, SignInOptions(pin = "1111"))
            }
        } as CardSignInResult.Legacy
        val proofHex = result.pinProofHex!!
        val der = ByteArray(proofHex.length / 2) { proofHex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
        val challenge = ByteArray(32) { 0x5a }
        val pub = Jca.jcaPublicKey(s.card.pub65)
        assertTrue(Jca.verifyP256(pub, "IMPALA-APIN:".toByteArray() + s.card.accountId + challenge, der))
    }

    @Test
    fun `mfa domain tags match the bridge byte for byte`() {
        // Shared card/bridge vectors (scripts/check-shared-vectors.sh).
        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
        assertEquals("494d50414c412d4150494e3a", hex("IMPALA-APIN:".toByteArray()))
        assertEquals("494d50414c412d444b45593a", hex(DeviceKeyProtocol.DOMAIN_TAG))
    }

    @Test
    fun `device key protocol message is a fixed layout`() {
        val msg = DeviceKeyProtocol.message(DeviceKeyProtocol.PURPOSE_STEP_UP, "acct-1", ByteArray(32) { it.toByte() })
        assertEquals(12 + 1 + 1 + 32 + 32, msg.size)
        assertEquals("IMPALA-DKEY:", String(msg.copyOfRange(0, 12)))
        assertEquals(1, msg[12].toInt())
        assertEquals(DeviceKeyProtocol.PURPOSE_STEP_UP, msg[13])
    }
}

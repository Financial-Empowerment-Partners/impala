package com.impala.sdk

import com.impala.sdk.Sep10TestXdr.challenge
import com.impala.sdk.Sep10TestXdr.challengeOfSize
import com.impala.sdk.Sep10TestXdr.ed25519Verify
import com.impala.sdk.Sep10TestXdr.networkId
import com.impala.sdk.Sep10TestXdr.signatureBase
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.PcscBibo
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.StellarCardKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Opt-in: the Stellar key and SEP-10 signing on a card in a PC/SC reader. Run it with
 * `IMPALA_PCSC_TEST=1 ./gradlew :sdk:jvmTest --tests '*PhysicalCardSep10Test*'`
 * (`IMPALA_PCSC_READER` filters the reader by name; `IMPALA_PCSC_SEP10_MAX` is
 * the largest challenge to try, 640 unless the CAP was built with less) against
 * a freshly installed applet on the GP default SCP03 keys. Without the
 * variable the test does nothing.
 *
 * The JDK's Ed25519 is the oracle for what the card signs. One-shot, like
 * [PhysicalCardTransferTest]: reinstall the applet before running it again.
 */
class PhysicalCardSep10Test {
    private fun account() = ByteArray(16) { (it + 0x61).toByte() }

    private fun <T> timed(what: String, block: () -> T): T {
        val t0 = System.nanoTime()
        val r = block()
        println("  ${(System.nanoTime() - t0) / 1_000_000} ms  $what")
        return r
    }

    @Test
    fun `a card in a reader makes a Stellar key and signs SEP-10 challenges with it`() {
        if (System.getenv("IMPALA_PCSC_TEST") != "1") {
            println("PhysicalCardSep10Test: not run (set IMPALA_PCSC_TEST=1 with a freshly installed card in a reader)")
            return
        }
        val largest = System.getenv("IMPALA_PCSC_SEP10_MAX")?.toInt() ?: Constants.SEP10_MAX_TX_LENGTH.toInt()
        val bibo = PcscBibo(System.getenv("IMPALA_PCSC_READER")).connect()
        println("reader: ${bibo.terminalName}")
        val plain = ImpalaSDK(bibo)
        println("applet: ${plain.requireCertifiedProtocol()}")
        val before = plain.getPersonalization()
        assertFalse(before.personalized, "the card is already personalized: reinstall the applet first")
        assertTrue(before.scp03KeysDefault, "the card is not on the GP default SCP03 keys: reinstall the applet first")
        if (!before.initialized) timed("INITIALIZE (P-256 key pair and the Stellar key)") { plain.setSeed() }

        val unbound = assertNotNull(plain.getStellarKey(), "the card has no Stellar key (GET_STELLAR_KEY 623C): no usable Ed25519 engine")
        println("  Stellar key: ${unbound.address} (engine ${unbound.engineName})")
        assertTrue(plain.getPersonalization().stellarKey, "flag 0x80")
        assertFalse(unbound.isBound, "no cross-signatures before PERSONALIZE")

        val server = ByteArray(32) { (it * 5 + 2).toByte() }
        val testnet = networkId()
        assertFailsWith<ImpalaException>("not personalized: nothing is signed") { plain.signSep10(testnet, challenge(unbound.publicKey, server)) }

        // --- personalization: the Stellar key signs its proof message -------
        val pub = plain.getECPubKey().toByteArray()
        val issuer = TestIssuer(PROGRAM_A)
        val keys = customKeys()
        ImpalaSDK(bibo, defaultKeys()).let { transport ->
            transport.openSecureChannel()
            transport.rotateScp03Keys(keys.first, keys.second, keys.third)
        }
        val card = ImpalaSDK(bibo, keys)
        card.openSecureChannel()
        timed("PERSONALIZE A, B, C (certificate check, then the Stellar key's proof signature)") {
            card.personalize(account(), USDC, issuer.programId, issuer.certify(account(), USDC, pub), issuerPubKey = issuer.pub65)
        }
        card.provisionMasterPIN("31415926")
        card.provisionUserPIN("4821")
        card.closeSecureChannel()

        val key = assertNotNull(card.getStellarKey())
        assertTrue(key.isBound, "both cross-signatures after PERSONALIZE")
        assertTrue(key.publicKey.contentEquals(unbound.publicKey), "PERSONALIZE does not change the key")
        val cardId = card.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data.copyOfRange(16, 32)
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(pub), StellarCardKey.bindingMessage(account(), cardId, key.publicKey), key.bindingSignature!!),
            "the P-256 key's binding signature verifies host-side")
        assertTrue(ed25519Verify(key.publicKey, StellarCardKey.proofMessage(account(), cardId, pub), key.proofSignature!!),
            "the Stellar key's proof of possession verifies host-side (JDK Ed25519)")

        // --- SEP-10 ----------------------------------------------------------
        val first = challenge(key.publicKey, server)
        val sig1 = timed("SIGN_SEP10: a ${first.size}-byte challenge") { card.signSep10(testnet, first) }
        assertEquals(64, sig1.size)
        assertTrue(ed25519Verify(key.publicKey, signatureBase(testnet, first), sig1), "the signature must verify (JDK Ed25519)")
        assertFalse(ed25519Verify(key.publicKey, signatureBase(networkId("another network"), first), sig1))

        // hedged nonce: the same challenge signed again gives another, valid signature
        val sig2 = timed("SIGN_SEP10: the same challenge again") { card.signSep10(testnet, first) }
        assertFalse(sig1.contentEquals(sig2), "the nonce is hedged")
        assertTrue(ed25519Verify(key.publicKey, signatureBase(testnet, first), sig2))

        val big = challengeOfSize(key.publicKey, server, largest - largest % 4)
        val sig3 = timed("SIGN_SEP10: a ${big.size}-byte challenge (the largest tried)") { card.signSep10(testnet, big) }
        assertTrue(ed25519Verify(key.publicKey, signatureBase(testnet, big), sig3))

        // a challenge for another key is refused, and the card still signs its own afterwards
        val other = ByteArray(32) { (it + 7).toByte() }
        val refused = assertFailsWith<ImpalaException> { card.signSep10(testnet, challenge(other, server)) }
        assertEquals(0x6243, refused.statusWord, "a challenge for another key")
        println("  refused as pinned  a challenge addressed to another key -> 6243")

        // the legacy sign-in is untouched
        val nonce = ByteArray(32) { (it * 3).toByte() }
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(pub), "IMPALA-AUTH:".encodeToByteArray() + account() + nonce,
            timed("SIGN_AUTH (the legacy challenge)") { card.signAuthChallenge(nonce) }.toByteArray()))
        bibo.close()
        println("physical card: Stellar key and SEP-10 checks passed")
    }
}

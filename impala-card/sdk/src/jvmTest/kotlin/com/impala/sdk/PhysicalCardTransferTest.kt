package com.impala.sdk

import com.impala.sdk.apdu4j.PcscBibo
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.TransferProtocol
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Opt-in: the money path on a card in a PC/SC reader. Run it with
 * `IMPALA_PCSC_TEST=1 ./gradlew :sdk:jvmTest --tests '*PhysicalCardTransferTest*'`
 * (`IMPALA_PCSC_READER` filters the reader by name) against a card that holds
 * a freshly installed applet (`gp --install`, no install parameters: the GP
 * default SCP03 keys). Without the variable the test does nothing.
 *
 * The card is personalized under a throwaway [TestIssuer] (so the test can
 * mint a certified funding key, which a bridge's sealed issuer key never
 * gives), then exchanges value with a simulated card of the same program.
 * JCA is the oracle for everything the card signs. The run is one-shot:
 * INITIALIZE and PERSONALIZE are irreversible, so reinstall the applet before
 * running it again.
 */
class PhysicalCardTransferTest {
    private val userPin = "4821"
    private val masterPin = "31415926"
    private fun cardAccount() = ByteArray(16) { (it + 0x51).toByte() }
    private fun peerAccount() = ByteArray(16) { (it + 0x40).toByte() }
    private fun treasuryAccount() = ByteArray(16) { (it + 0x90).toByte() }

    private fun expectSw(hex: String, what: String, block: () -> Unit) {
        val ex = assertFailsWith<ImpalaException>(what) { block() }
        assertTrue(ex.message!!.uppercase().contains(hex.uppercase()), "$what: expected $hex, got '${ex.message}'")
        println("  refused as pinned  $what -> $hex")
    }

    private fun <T> timed(what: String, block: () -> T): T {
        val t0 = System.nanoTime()
        val r = block()
        println("  ${(System.nanoTime() - t0) / 1_000_000} ms  $what")
        return r
    }

    @Test
    fun `a card in a reader is personalized, funded, pays and is paid, and keeps its rules`() {
        if (System.getenv("IMPALA_PCSC_TEST") != "1") {
            println("PhysicalCardTransferTest: not run (set IMPALA_PCSC_TEST=1 with a freshly installed card in a reader)")
            return
        }
        var bibo = PcscBibo(System.getenv("IMPALA_PCSC_READER")).connect()
        println("reader: ${bibo.terminalName}")
        var plain = ImpalaSDK(bibo)
        val version = plain.requireCertifiedProtocol()
        println("applet: $version")
        val before = plain.getPersonalization()
        assertFalse(before.personalized, "the card is already personalized: reinstall the applet first")
        assertTrue(before.scp03KeysDefault, "the card is not on the GP default SCP03 keys: reinstall the applet first")

        // --- personalization under a test issuer -------------------------
        if (!before.initialized) timed("INITIALIZE (card key pair)") { plain.setSeed() }
        val pub = plain.getECPubKey().toByteArray()
        assertEquals(65, pub.size)
        val issuer = TestIssuer(PROGRAM_A)
        val cert = issuer.certify(cardAccount(), USDC, pub)
        val keys = customKeys()
        ImpalaSDK(bibo, defaultKeys()).let { transport ->
            timed("SCP03 open on the default keys") { transport.openSecureChannel() }
            timed("APPLET_UPDATE: SCP03 key rotation") { transport.rotateScp03Keys(keys.first, keys.second, keys.third) }
        }
        val card = ImpalaSDK(bibo, keys)
        timed("SCP03 open on the rotated keys") { card.openSecureChannel() }
        timed("PERSONALIZE A, B, C (the card verifies its certificate)") {
            card.personalize(cardAccount(), USDC, issuer.programId, cert, issuerPubKey = issuer.pub65, initialReceiveCounter = 0)
        }
        timed("PROVISION_PIN master + user") {
            card.provisionMasterPIN(masterPin)
            card.provisionUserPIN(userPin)
        }
        card.closeSecureChannel()
        val p = card.getPersonalization()
        assertTrue(p.personalized && p.pinProvisioned && !p.scp03KeysDefault, "flags after the ceremony: ${p.flags}")
        assertContentEquals(issuer.programId, p.programId)
        assertContentEquals(issuer.pub65, p.issuerPubKey)
        assertContentEquals(cert, p.certificate)

        // a certificate the issuer did not sign is refused by a second, blank simulated card's rule too;
        // here: the old default keys no longer open a channel
        assertFalse(runCatching { ImpalaSDK(bibo, defaultKeys()).openSecureChannel() }.getOrDefault(false),
            "the GP default keys must no longer open a secure channel")
        println("  refused as pinned  SCP03 on the default keys after rotation")

        // --- funding and transfers ---------------------------------------
        val peer = personalizedCard(issuer, peerAccount())
        val treasury = issuer.externalSender(treasuryAccount())
        val seq = SeqAllocator()
        fun nextCounter(sdk: ImpalaSDK) = TransferProtocol.nextReceiveCounter(sdk.getReceiveState().counter)

        assertEquals(0L, card.getBalance())
        val fundEnv = treasury.envelope(signable(treasury.accountId, cardAccount(), 1000, nextCounter(card), seq))
        timed("VERIFY_TRANSFER_V2: credit 1000 (two ECDSA verifications on the card)") { card.verifyTransferV2(fundEnv) }
        assertEquals(1000L, card.getBalance())

        // replaying the credit is refused and credits nothing
        expectSw("6233", "the same credit presented again") { card.verifyTransferV2(fundEnv) }
        assertEquals(1000L, card.getBalance())

        // physical card pays the simulated card
        val s1 = signable(cardAccount(), peerAccount(), 250, nextCounter(peer.sdk), seq)
        val env1 = timed("SIGN_TRANSFER_V2: debit 250 with the user PIN") { card.signTransferV2(userPin, s1) }
        val cardKey = Jca.jcaPublicKey(pub)
        assertTrue(Jca.verifyP256(cardKey, TransferProtocol.xferMessage(issuer.programId, s1), env1.signature),
            "the card's transfer signature must verify host-side (JCA)")
        assertFalse(Jca.verifyP256(cardKey, s1, env1.signature), "it must not verify over the bare signable")
        assertContentEquals(pub, env1.pubKey)
        assertContentEquals(cert, env1.certificate)
        peer.sdk.verifyTransferV2(env1)
        assertEquals(750L, card.getBalance())
        assertEquals(250L, peer.sdk.getBalance())

        // an identical signable replays the cached answer: no second debit
        val env1b = card.signTransferV2(userPin, s1)
        assertContentEquals(env1.tail209(), env1b.tail209())
        assertEquals(750L, card.getBalance())

        // the simulated card pays the physical card
        val s2 = signable(peerAccount(), cardAccount(), 100, nextCounter(card), seq)
        val env2 = peer.sdk.signTransferV2("1111", s2)
        timed("VERIFY_TRANSFER_V2: credit 100 from the simulated card") { card.verifyTransferV2(env2) }
        assertEquals(850L, card.getBalance())
        assertEquals(150L, peer.sdk.getBalance())
        assertEquals(TransferProtocol.transferId(issuer.programId, s2).hex(), card.getReceiveState().lastDigest.hex())

        // --- refusals -----------------------------------------------------
        expectSw("6233", "a replayed transfer from the simulated card") { card.verifyTransferV2(env2) }

        val s3 = signable(peerAccount(), cardAccount(), 50, nextCounter(card), seq)
        val env3 = peer.sdk.signTransferV2("1111", s3)
        val badSig = env3.signature.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        assertFailsWith<ImpalaException>("a tampered signature") { card.verifyTransferV2(s3, badSig, env3.pubKey, env3.certificate) }
        println("  refused as pinned  a transfer with a tampered signature")
        // the refusal consumed nothing: the genuine envelope is still accepted afterwards
        card.verifyTransferV2(env3)
        assertEquals(900L, card.getBalance())
        assertEquals(100L, peer.sdk.getBalance())

        val rogue = Jca.genP256()
        val roguePub = Jca.uncompressedPoint(rogue.public as java.security.interfaces.ECPublicKey)
        val s4 = signable(peerAccount(), cardAccount(), 50, nextCounter(card), seq)
        val selfCert = Jca.signP256(rogue.private, TransferProtocol.certMessage(issuer.programId, peerAccount(), USDC, roguePub))
        expectSw("0022", "a key certified by itself, not by the issuer") {
            card.verifyTransferV2(s4, Jca.signP256(rogue.private, TransferProtocol.xferMessage(issuer.programId, s4)), roguePub, selfCert)
        }
        assertEquals(900L, card.getBalance())

        expectSw("6224", "a debit larger than the balance") {
            card.signTransferV2(userPin, signable(cardAccount(), peerAccount(), 100_000, nextCounter(peer.sdk), seq))
        }
        val wrong = if (userPin == "9753") "1357" else "9753"
        val ex = assertFailsWith<ImpalaException> {
            card.signTransferV2(wrong, signable(cardAccount(), peerAccount(), 10, nextCounter(peer.sdk), seq))
        }
        assertTrue(ex.message!!.uppercase().contains("4 TRIES"), "a wrong PIN must leave 4 tries: ${ex.message}")
        println("  refused as pinned  a debit with a wrong PIN (4 tries left)")
        assertEquals(900L, card.getBalance())
        // the right PIN works again and resets the try counter
        val s5 = signable(cardAccount(), peerAccount(), 10, nextCounter(peer.sdk), seq)
        peer.sdk.verifyTransferV2(card.signTransferV2(userPin, s5))
        assertEquals(5, card.getUserVerification()!!.userPinTriesLeft, "the try counter is reset by a correct PIN")
        assertEquals(890L, card.getBalance())
        assertEquals(110L, peer.sdk.getBalance())

        // --- the card after a power cycle ---------------------------------
        val receive = card.getReceiveState()
        bibo.close()
        bibo = PcscBibo(System.getenv("IMPALA_PCSC_READER")).connect()
        plain = ImpalaSDK(bibo)
        assertEquals(890L, plain.getBalance(), "the balance survives a reset")
        assertEquals(receive.counter, plain.getReceiveState().counter)
        assertEquals(receive.lastDigest.hex(), plain.getReceiveState().lastDigest.hex())
        assertTrue(plain.getPersonalization().personalized)
        // value is conserved: 1000 came in from the treasury
        assertEquals(1000L, plain.getBalance() + peer.sdk.getBalance())
        bibo.close()
        println("physical card: all checks passed; balance 890, peer 110")
    }
}

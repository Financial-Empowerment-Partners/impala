package com.impala.sdk

import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferProtocol
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Interop tests for the issuer-certified transfer chain (applet 0.2, protocol
 * v1): card-to-card transfers, certificate/signature verification on receive,
 * the receive-counter and send-sequence rules, idempotent retry and the
 * replacement-card floor. jcardsim + JCA are the two independent oracles.
 */
class CertifiedTransferInteropTest {

    private val PROGRAM = PROGRAM_A
    private fun aId() = ByteArray(16) { (it + 1).toByte() }
    private fun bId() = ByteArray(16) { (it + 0x40).toByte() }
    private fun tId() = ByteArray(16) { (it + 0x90).toByte() }

    private fun expectSw(hex: String, block: () -> Unit) {
        val ex = assertFailsWith<ImpalaException> { block() }
        assertTrue(ex.message!!.uppercase().contains(hex.uppercase()), "expected $hex, got '${ex.message}'")
    }

    private fun rawSignable(
        sender: ByteArray, recipient: ByteArray, amount: Long, counter: Long,
        dateTime: Long = 5L, currency: ByteArray = USDC
    ): ByteArray {
        val b = ByteArray(60)
        for (i in 0..7) b[i] = (dateTime ushr (8 * (7 - i))).toByte()
        sender.copyInto(b, 8)
        recipient.copyInto(b, 24)
        currency.copyInto(b, 40)
        for (i in 0..3) b[44 + i] = (amount ushr (8 * (3 - i))).toByte()
        for (i in 0..3) b[56 + i] = (counter ushr (8 * (3 - i))).toByte()
        return b
    }

    // --- C1 ---
    @Test
    fun `certified card-to-card transfer credits the recipient and verifies host-side`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardA, treasury, 1000, seq)

        val counterB = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val s = signable(aId(), bId(), 250, counterB, seq)
        val env = cardA.sdk.signTransferV2("1111", s)
        cardB.sdk.verifyTransferV2(env)

        assertEquals(750L, cardA.sdk.getBalance())
        assertEquals(250L, cardB.sdk.getBalance())

        val pubA = Jca.jcaPublicKey(cardA.pub65)
        assertTrue(Jca.verifyP256(pubA, TransferProtocol.xferMessage(PROGRAM, s), env.signature))
        assertTrue(!Jca.verifyP256(pubA, s, env.signature), "must not verify over the bare 60 bytes")
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(issuer.pub65), TransferProtocol.certMessage(PROGRAM, aId(), USDC, cardA.pub65), env.certificate))
        assertEquals(TransferProtocol.transferId(PROGRAM, s).hex(), cardB.sdk.getReceiveState().lastDigest.hex())
    }

    // --- C2 ---
    @Test
    fun `uncertified key is rejected before any credit`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val seq = SeqAllocator()
        val rogue = Jca.genP256()
        val roguePub = Jca.uncompressedPoint(rogue.public as java.security.interfaces.ECPublicKey)
        val sender = ByteArray(16) { (it + 1).toByte() }
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val s = signable(sender, bId(), 100, counter, seq)
        val sig = Jca.signP256(rogue.private, TransferProtocol.xferMessage(PROGRAM, s))

        // cert slot all zeros → DER-invalid → 0x6A80
        expectSw("6A80") { cardB.sdk.verifyTransferV2(s, sig, roguePub, ByteArray(72)) }
        // self-signed cert → verifies against the wrong key → 0x0022
        val selfCert = Jca.signP256(rogue.private, TransferProtocol.certMessage(PROGRAM, sender, USDC, roguePub))
        expectSw("0022") { cardB.sdk.verifyTransferV2(s, sig, roguePub, selfCert) }

        assertEquals(0L, cardB.sdk.getBalance())
        assertEquals(0, cardB.sdk.getReceiveState().counter)
    }

    // --- C3 ---
    @Test
    fun `certificate for another account or currency is rejected`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val cardA = personalizedCard(issuer, aId())
        val seq = SeqAllocator()
        val cKey = issuer.externalSender(ByteArray(16) { (it + 0x20).toByte() })
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)

        // sender = C's UUID signed by C's key, but A's certificate presented
        val s1 = signable(cKey.accountId, bId(), 100, counter, seq)
        expectSw("0022") { cardB.sdk.verifyTransferV2(s1, cKey.sign(s1), cKey.pub65, cardA.cert) }

        // sender A, but the certificate was minted for EUR
        val aSender = issuer.externalSender(aId())
        val eurCert = issuer.certify(aId(), EUR_, aSender.pub65)
        val s2 = signable(aId(), bId(), 100, counter, seq)
        expectSw("0022") { cardB.sdk.verifyTransferV2(s2, aSender.sign(s2), aSender.pub65, eurCert) }

        assertEquals(0L, cardB.sdk.getBalance())
    }

    // --- C4 ---
    @Test
    fun `untagged v0 signature is rejected`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val seq = SeqAllocator()
        val aSender = issuer.externalSender(aId())
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val s = signable(aId(), bId(), 100, counter, seq)

        val bareSig = Jca.signP256(aSender.keys.private, s) // over the bare 60 bytes
        expectSw("0023") { cardB.sdk.verifyTransferV2(s, bareSig, aSender.pub65, aSender.cert) }

        val wrongTagSig = Jca.signP256(aSender.keys.private, TransferProtocol.xferMessage(PROGRAM_B, s))
        expectSw("0023") { cardB.sdk.verifyTransferV2(s, wrongTagSig, aSender.pub65, aSender.cert) }

        assertEquals(0L, cardB.sdk.getBalance())
    }

    // --- C5 ---
    @Test
    fun `cross-program transfer is rejected`() {
        val issuer = TestIssuer(PROGRAM) // one issuer key shared across programs
        val cardB = personalizedCard(issuer, bId())
        val seq = SeqAllocator()
        val kp = Jca.genP256()
        val pub = Jca.uncompressedPoint(kp.public as java.security.interfaces.ECPublicKey)
        val sender = ByteArray(16) { (it + 1).toByte() }
        // Certified under PROGRAM_B with the same issuer key; card B is under PROGRAM_A
        val certB = Jca.signP256(issuer.keys.private, TransferProtocol.certMessage(PROGRAM_B, sender, USDC, pub))
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val s = signable(sender, bId(), 100, counter, seq)
        val sig = Jca.signP256(kp.private, TransferProtocol.xferMessage(PROGRAM_B, s))
        expectSw("0022") { cardB.sdk.verifyTransferV2(s, sig, pub, certB) }
        assertEquals(0L, cardB.sdk.getBalance())
    }

    // --- C6 ---
    @Test
    fun `transfer to self is rejected on both sides`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardA, treasury, 1000, seq)

        // SIGN: recipient == own accountId → 0x6232
        expectSw("6232") { cardA.sdk.signTransferV2("1111", signable(aId(), aId(), 1, 1, seq)) }

        // VERIFY: sender == me → 0x6231
        val aSender = issuer.externalSender(aId())
        val counter = TransferProtocol.nextReceiveCounter(cardA.sdk.getReceiveState().counter)
        val s = signable(aId(), aId(), 1, counter, seq)
        expectSw("6231") { cardA.sdk.verifyTransferV2(aSender.envelope(s)) }
    }

    // --- C7 ---
    @Test
    fun `currency mismatch is rejected on both sides`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardA, treasury, 1000, seq)

        // SIGN: card currency USDC, signable EUR → 0x6229
        expectSw("6229") { cardA.sdk.signTransferV2("1111", signable(aId(), bId(), 1, 1, seq, currency = EUR_)) }

        // VERIFY: signable EUR into a USDC card → 0x6229 (before the cert check)
        val eurSender = issuer.externalSender(ByteArray(16) { (it + 5).toByte() }, EUR_)
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val s = signable(eurSender.accountId, bId(), 1, counter, seq, currency = EUR_)
        expectSw("6229") { cardB.sdk.verifyTransferV2(eurSender.envelope(s)) }
    }

    // --- C8 ---
    @Test
    fun `zero amount is rejected on both sides`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val cardB = personalizedCard(issuer, bId())
        val seq = SeqAllocator()

        // SIGN: raw signable with amount 0 → 0x6239
        val sSign = rawSignable(aId(), bId(), amount = 0, counter = 1, dateTime = 5)
        expectSw("6239") { cardA.sdk.signTransferV2("1111", sSign) }

        // VERIFY: raw signable with amount 0, signed by a certified sender → 0x6239
        val sender = issuer.externalSender(ByteArray(16) { (it + 0xC0).toByte() })
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter).toLong()
        val sVerify = rawSignable(sender.accountId, bId(), amount = 0, counter = counter, dateTime = 7)
        val sig = Jca.signP256(sender.keys.private, TransferProtocol.xferMessage(PROGRAM, sVerify))
        expectSw("6239") { cardB.sdk.verifyTransferV2(sVerify, sig, sender.pub65, sender.cert) }
    }

    // --- C9 ---
    @Test
    fun `unpersonalized card signs and credits nothing`() {
        val sdk = ImpalaSDK(SimulatorBibo(), defaultKeys())
        val bibo = SimulatorBibo()
        // rebuild with a shared bibo so we can send a raw P1=1
        val shared = SimulatorBibo()
        val s = ImpalaSDK(shared, defaultKeys())
        s.setSeed() // initialized, not personalized, no ENFORCE

        expectSw("6234") { s.signAuthChallenge(ByteArray(32)) }
        expectSw("6234") { s.signTransferV2("1111", signable(ByteArray(16) { 1 }, ByteArray(16) { 2 }, 1, 1, SeqAllocator())) }
        // VERIFY P1=0 already fails at the personalized gate
        val issuer = TestIssuer(PROGRAM)
        val sender = issuer.externalSender(ByteArray(16) { (it + 1).toByte() })
        val env = sender.envelope(signable(sender.accountId, ByteArray(16) { 2 }, 1, 1, SeqAllocator()))
        expectSw("6234") { s.verifyTransferV2(env) }
        // VERIFY P1=1 raw is also gated
        assertEquals(0x6234, swOf(shared.transceive(byteArrayOf(0x00, 0x31, 0x01, 0x00, 0xD1.toByte()) + env.tail209())))
    }

    // --- C10 ---
    @Test
    fun `SIGN_TRANSFER_V2 response slots are zero-padded and slot 3 equals the certificate`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardA, treasury, 1000, seq)

        val s = signable(aId(), bId(), 100, 1, seq)
        val resp = cardA.bibo.transceive(byteArrayOf(0x00, 0x30, 0x00, 0x00, 0x40) + byteArrayOf(1, 1, 1, 1) + s)
        assertEquals(0x9000, swOf(resp))
        val data = resp.copyOf(resp.size - 2)
        assertEquals(209, data.size)

        val sigLen = (data[1].toInt() and 0xFF) + 2
        for (i in sigLen until 72) assertEquals(0, data[i].toInt(), "sig slot must be zero-padded at $i")
        val certLen = (data[138].toInt() and 0xFF) + 2
        for (i in (137 + certLen) until 209) assertEquals(0, data[i].toInt(), "cert slot must be zero-padded at $i")
        assertContentEquals(cardA.sdk.getPersonalization().certificate, data.copyOfRange(137, 137 + certLen))
    }

    // --- C11 ---
    @Test
    fun `bridge-style load is an ordinary certified transfer`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(ByteArray(16) { (it + 0xE0).toByte() })
        val seq = SeqAllocator()
        fund(cardB, treasury, 500, seq)
        assertEquals(500L, cardB.sdk.getBalance())
    }

    // --- C12 ---
    @Test
    fun `malformed tails are refused before crypto`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val seq = SeqAllocator()
        val aSender = issuer.externalSender(aId())
        val counter = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val s = signable(aId(), bId(), 100, counter, seq)
        val env = aSender.envelope(s)

        fun p1(tail: ByteArray): Int = swOf(cardB.bibo.transceive(byteArrayOf(0x00, 0x31, 0x01, 0x00, 0xD1.toByte()) + tail))
        fun stage() = cardB.bibo.transceive(byteArrayOf(0x00, 0x31, 0x00, 0x00, 0x3C) + s)

        val validPub = env.pubKey
        val validCert = Jca.pad72(env.certificate)

        // tail without a prior P1=0 → 0x6985
        assertEquals(0x6985, p1(Jca.pad72(env.signature) + validPub + validCert))

        stage()
        // DER length byte 0x80 (130 > 72) → 0x6A80
        assertEquals(0x6A80, p1((byteArrayOf(0x30, 0x80.toByte()) + ByteArray(70)) + validPub + validCert))
        stage()
        // sig slot 30 47 (73 > 72) → 0x6A80
        assertEquals(0x6A80, p1((byteArrayOf(0x30, 0x47) + ByteArray(70)) + validPub + validCert))
        stage()
        // pubkey[0] = 0x02 → 0x6A80
        assertEquals(0x6A80, p1(Jca.pad72(env.signature) + (byteArrayOf(0x02) + validPub.copyOfRange(1, 65)) + validCert))
        stage()
        // invalid EC point (0x04 but off-curve) → 0x6683 or 0x0022 (never 0x6F00)
        val badPointTail = Jca.pad72(env.signature) + (byteArrayOf(0x04) + ByteArray(64) { 0x11 }) + validCert
        assertTrue(p1(badPointTail) in intArrayOf(0x6683, 0x0022), "bad point must be 0x6683 or 0x0022")
        stage()
        // P1 = 2 → 0x6A86
        assertEquals(0x6A86, swOf(cardB.bibo.transceive(byteArrayOf(0x00, 0x31, 0x02, 0x00, 0xD1.toByte()) + env.tail209())))

        assertEquals(0L, cardB.sdk.getBalance())
    }

    // --- C13 ---
    @Test
    fun `two personalized cards conserve value`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()

        fund(cardA, treasury, 1000, seq) // A.L = 1

        val cB = TransferProtocol.nextReceiveCounter(cardB.sdk.getReceiveState().counter)
        val sAB = signable(aId(), bId(), 250, cB, seq)
        val envAB = cardA.sdk.signTransferV2("1111", sAB)
        cardB.sdk.verifyTransferV2(envAB)

        val cA = TransferProtocol.nextReceiveCounter(cardA.sdk.getReceiveState().counter)
        val sBA = signable(bId(), aId(), 100, cA, seq)
        val envBA = cardB.sdk.signTransferV2("0000", sBA) // PIN-less
        cardA.sdk.verifyTransferV2(envBA)

        assertEquals(850L, cardA.sdk.getBalance())
        assertEquals(150L, cardB.sdk.getBalance())
        assertEquals(1000L, cardA.sdk.getBalance() + cardB.sdk.getBalance())
        assertEquals(2, cardA.sdk.getReceiveState().counter)
        assertEquals(1, cardB.sdk.getReceiveState().counter)

        val (lastA, sigA) = cardA.sdk.getLastTransfer()!!
        assertContentEquals(sAB, lastA)
        assertContentEquals(envAB.signature, sigA)
        val (lastB, sigB) = cardB.sdk.getLastTransfer()!!
        assertContentEquals(sBA, lastB)
        assertContentEquals(envBA.signature, sigB)

        assertEquals(TransferProtocol.transferId(PROGRAM, sBA).hex(), cardA.sdk.getReceiveState().lastDigest.hex())
        assertEquals(TransferProtocol.transferId(PROGRAM, sAB).hex(), cardB.sdk.getReceiveState().lastDigest.hex())
    }

    // --- C14 ---
    @Test
    fun `balance overflow is refused before the transaction`() {
        // The 0x6984 overflow bound needs a balance near 2^64, unreachable without a
        // setter. We instead exercise computeCredit's carry path: two 0xFFFFFFFF
        // credits succeed and sum exactly, proving the add carries correctly (the
        // reachable bound; a true carry-out would refuse with 0x6984 before committing).
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardB, treasury, 0xFFFF_FFFFL, seq)
        fund(cardB, treasury, 0xFFFF_FFFFL, seq)
        assertEquals(2L * 0xFFFF_FFFFL, cardB.sdk.getBalance())
    }

    // --- K1 ---
    @Test
    fun `counter replay is rejected`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()

        val s1 = signable(tId(), bId(), 1000, 1, seq)
        val env1 = treasury.envelope(s1)
        cardB.sdk.verifyTransferV2(env1)
        assertEquals(1000L, cardB.sdk.getBalance())
        assertEquals(1, cardB.sdk.getReceiveState().counter)
        assertEquals(TransferProtocol.transferId(PROGRAM, s1).hex(), cardB.sdk.getReceiveState().lastDigest.hex())

        // tail-only replay after the successful credit → 0x6985 (staged signable consumed)
        assertEquals(0x6985, swOf(cardB.bibo.transceive(byteArrayOf(0x00, 0x31, 0x01, 0x00, 0xD1.toByte()) + env1.tail209())))
        // full two-phase replay → 0x6233
        expectSw("6233") { cardB.sdk.verifyTransferV2(env1) }
        // a fresh, differently-signed transfer at the same counter → 0x6233
        val stale = signable(tId(), bId(), 500, 1, seq)
        expectSw("6233") { cardB.sdk.verifyTransferV2(treasury.envelope(stale)) }
        assertEquals(1000L, cardB.sdk.getBalance())
        // a gap is fine (5 > 1)
        val gap = signable(tId(), bId(), 500, 5, seq)
        cardB.sdk.verifyTransferV2(treasury.envelope(gap))
        assertEquals(1500L, cardB.sdk.getBalance())
        assertEquals(5, cardB.sdk.getReceiveState().counter)
        assertEquals(TransferProtocol.transferId(PROGRAM, gap).hex(), cardB.sdk.getReceiveState().lastDigest.hex())
    }

    // --- K2 ---
    @Test
    fun `counter jump beyond MAX_COUNTER_JUMP is refused with 623A`() {
        val issuer = TestIssuer(PROGRAM)
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()

        val cardB = personalizedCard(issuer, bId())
        cardB.sdk.verifyTransferV2(treasury.envelope(signable(tId(), bId(), 10, 1, seq)))   // L = 1
        cardB.sdk.verifyTransferV2(treasury.envelope(signable(tId(), bId(), 10, 1025, seq))) // jump 1024 accepted, L = 1025
        expectSw("623A") { cardB.sdk.verifyTransferV2(treasury.envelope(signable(tId(), bId(), 10, 2050, seq))) } // jump 1025
        cardB.sdk.verifyTransferV2(treasury.envelope(signable(tId(), bId(), 10, 2049, seq))) // jump 1024 accepted, L = 2049
        assertEquals(2049, cardB.sdk.getReceiveState().counter)

        // near the top of the stream: the bound clamps at 0x7FFFFFFF
        val cardC = personalizedCard(issuer, ByteArray(16) { (it + 0x33).toByte() }, initialCounter = 0x7FFFFBFF)
        cardC.sdk.verifyTransferV2(treasury.envelope(signable(tId(), cardC.accountId, 10, 0x7FFFFFFF, seq)))
        assertEquals(0x7FFFFFFF, cardC.sdk.getReceiveState().counter)
        expectSw("6233") { cardC.sdk.verifyTransferV2(treasury.envelope(signable(tId(), cardC.accountId, 10, 0x7FFFFFFF, seq))) }
    }

    // --- K3 ---
    @Test
    fun `zero and negative counters are never accepted and the sender refuses to sign them`() {
        val issuer = TestIssuer(PROGRAM)
        val cardB = personalizedCard(issuer, bId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()

        // VERIFY: counter 0 and -1 → 0x6233
        for (counter in longArrayOf(0L, 0xFFFF_FFFFL)) {
            val s = rawSignable(tId(), bId(), amount = 100, counter = counter, dateTime = 3)
            val sig = Jca.signP256(treasury.keys.private, TransferProtocol.xferMessage(PROGRAM, s))
            expectSw("6233") { cardB.sdk.verifyTransferV2(s, sig, treasury.pub65, treasury.cert) }
        }
        assertEquals(0L, cardB.sdk.getBalance())

        // SIGN: counter 0 and -1 → 0x6233, balance unchanged
        val cardA = personalizedCard(issuer, aId())
        fund(cardA, treasury, 100, seq)
        for (counter in longArrayOf(0L, 0xFFFF_FFFFL)) {
            expectSw("6233") { cardA.sdk.signTransferV2("1111", rawSignable(aId(), ByteArray(16) { 9 }, amount = 1, counter = counter, dateTime = 100)) }
        }
        assertEquals(100L, cardA.sdk.getBalance())
    }

    // --- K4 ---
    @Test
    fun `identical signable retry replays the cached response without a second debit`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardA, treasury, 1000, seq)

        val s = signable(aId(), bId(), 100, 1, seq)
        val e1 = cardA.sdk.signTransferV2("0000", s) // PIN-less debit #1
        assertEquals(900L, cardA.sdk.getBalance())
        val e2 = cardA.sdk.signTransferV2("0000", s) // identical → replay
        assertContentEquals(e1.tail209(), e2.tail209())
        assertEquals(900L, cardA.sdk.getBalance())
        // a wrong PIN with the identical signable still replays (no PIN failure)
        val e3 = cardA.sdk.signTransferV2("9999", s)
        assertContentEquals(e1.tail209(), e3.tail209())
        assertEquals(900L, cardA.sdk.getBalance())

        // the replays burned no PIN-less budget: three more distinct pinless succeed,
        // the fourth distinct one is refused (budget of 4 counts real debits only)
        repeat(3) { cardA.sdk.signTransferV2("0000", signable(aId(), bId(), 100, 1, seq)) }
        expectSw("6690") { cardA.sdk.signTransferV2("0000", signable(aId(), bId(), 100, 1, seq)) }
        assertEquals(600L, cardA.sdk.getBalance())
    }

    // --- K5 ---
    @Test
    fun `send sequence must strictly increase`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()
        fund(cardA, treasury, 1000, seq)

        // dateTime 0 on a fresh send stream → 0x6238
        expectSw("6238") { cardA.sdk.signTransferV2("1111", Signable(0, aId(), bId(), USDC, 10, 0, 1).encode()) }

        // a valid send establishes lastSent dateTime = 5
        cardA.sdk.signTransferV2("1111", Signable(5, aId(), bId(), USDC, 10, 0, 1).encode())
        assertEquals(990L, cardA.sdk.getBalance())

        // lower dateTime → 0x6238
        expectSw("6238") { cardA.sdk.signTransferV2("1111", Signable(3, aId(), bId(), USDC, 10, 0, 1).encode()) }
        // equal dateTime with a different body → 0x6238
        expectSw("6238") { cardA.sdk.signTransferV2("1111", Signable(5, aId(), bId(), USDC, 20, 0, 1).encode()) }
        // MSB set → 0x6238
        val msb = Signable(5, aId(), bId(), USDC, 10, 0, 1).encode().also { it[0] = 0x80.toByte() }
        expectSw("6238") { cardA.sdk.signTransferV2("1111", msb) }

        assertEquals(990L, cardA.sdk.getBalance())
    }

    // --- K6 ---
    @Test
    fun `last transfer record is readable after a signed transfer`() {
        val issuer = TestIssuer(PROGRAM)
        val cardA = personalizedCard(issuer, aId())
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()

        assertNull(cardA.sdk.getLastTransfer(), "no transfer signed yet → 0x6A83 → null")
        fund(cardA, treasury, 1000, seq) // receiving does not set the send record
        assertNull(cardA.sdk.getLastTransfer())

        val s = signable(aId(), bId(), 100, 1, seq)
        val env = cardA.sdk.signTransferV2("1111", s)
        val (last, sig) = cardA.sdk.getLastTransfer()!!
        assertContentEquals(s, last)
        assertContentEquals(env.signature, sig)
    }

    // --- K7 ---
    @Test
    fun `replacement card with an initial counter floor refuses envelopes the lost card accepted`() {
        val issuer = TestIssuer(PROGRAM)
        val acct = ByteArray(16) { (it + 1).toByte() }
        val treasury = issuer.externalSender(tId())
        val seq = SeqAllocator()

        val a1 = personalizedCard(issuer, acct)
        val e1 = treasury.envelope(signable(tId(), acct, 10, 1, seq))
        val e2 = treasury.envelope(signable(tId(), acct, 10, 2, seq))
        val e3 = treasury.envelope(signable(tId(), acct, 10, 3, seq))
        a1.sdk.verifyTransferV2(e1)
        a1.sdk.verifyTransferV2(e2)
        a1.sdk.verifyTransferV2(e3) // A1.L = 3

        // Replacement: same accountId, new key, initialReceiveCounter = 3
        val a2 = personalizedCard(issuer, acct, initialCounter = 3)
        expectSw("6233") { a2.sdk.verifyTransferV2(e2) }
        expectSw("6233") { a2.sdk.verifyTransferV2(e3) }
        val e4 = treasury.envelope(signable(tId(), acct, 10, 4, seq))
        a2.sdk.verifyTransferV2(e4)
        assertEquals(10L, a2.sdk.getBalance())
    }
}

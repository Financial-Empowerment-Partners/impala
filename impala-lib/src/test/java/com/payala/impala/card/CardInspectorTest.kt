package com.payala.impala.card

import com.impala.sdk.apdu4j.ApduNames
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.fund
import com.impala.simulator.personalizedCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CardInspectorTest {
    private val holder = "Card Holder"

    private fun inspect(bibo: com.impala.sdk.apdu4j.BIBO): CardInspection =
        offMain { ImpalaCardSession.fromBibo(bibo, readOnly = true).use { CardInspector.inspect(it) } }

    @Test
    fun `a personalized test-issuer card inspects fully, verified by its own issuer`() {
        val issuer = TestIssuer()
        val account = uuidBytes()
        val card = personalizedCard(issuer, account)
        card.sdk.setUserName(holder)
        val sent = mutableListOf<Int>()
        card.bibo.debugTrace = { cmd, _ -> sent += cmd[1].toInt() and 0xFF }

        val i = inspect(card.bibo)

        assertTrue(i.steps.joinToString(), i.complete)
        assertEquals(
            listOf("GET_VERSION", "GET_PERSONALIZATION", "GET_USER_DATA", "GET_EC_PUB_KEY", "IS_CARD_ALIVE",
                "GET_RECEIVE_STATE", "GET_LAST_TRANSFER", "GET_BALANCE", "GET_STELLAR_KEY"),
            i.steps.map { it.name }
        )
        // the simulated card is the default build: it has a Stellar key, bound at personalization
        assertTrue(i.stellarAddress!!, com.impala.sdk.stellar.StrKey.isValidAccountId(i.stellarAddress!!))
        assertEquals("soft", i.stellarEngine)
        assertEquals(true, i.stellarBindingVerified)
        assertEquals(true, i.stellarProofVerified)
        assertTrue("STELLAR_KEY" in i.flagNames)
        assertEquals(i.steps.map { it.name }, i.exchanges.map { it.insName })
        assertEquals(true, i.certVerifiedByCardIssuer)
        assertEquals(true, i.certificateVerifiesUnder(Hex.encode(issuer.pub65)))
        assertEquals(false, i.certificateVerifiesUnder(Hex.encode(TestIssuer().pub65)))
        assertNull(i.certificateVerifiesUnder("not hex"))
        assertEquals(0, i.receiveCounter)
        assertEquals(64, i.receiveDigestHex!!.length)
        assertNull(i.lastTransfer!!.reveal())
        assertEquals(true, i.alive)
        assertEquals(0L, i.balanceMinor!!.reveal())
        assertEquals(UuidBytes.format(account), i.accountUuid)
        assertEquals(32, i.wireCardId!!.length)
        assertEquals(holder, i.holderName!!.reveal())
        assertEquals(0, i.versionMajor); assertEquals(4, i.versionMinor)
        assertTrue(i.versionLine!!, i.versionLine.matches(Regex("""0\.4 · r\d+ · g[0-9a-f]{8}""")))
        assertEquals("PERSONALIZED", i.stateName)
        assertTrue("PERSONALIZED" in i.flagNames && "PIN_PROVISIONED" in i.flagNames)
        assertEquals(true, i.personalized); assertEquals(false, i.terminated)
        assertEquals(Hex.encode(issuer.programId), i.programIdHex)
        assertEquals("USDC", i.currency)
        assertEquals(CardCertificates.fingerprint(issuer.pub65), i.issuerKeyFingerprint)
        assertEquals(CardCertificates.fingerprint(card.pub65), i.cardKeyFingerprint)
        assertEquals(card.cert.size, i.certificateLength)
        val certMessage = TransferProtocol.certMessage(issuer.programId, account, TransferProtocol.CURRENCY_USDC, card.pub65)
        assertEquals(Hex.encode(java.security.MessageDigest.getInstance("SHA-256").digest(certMessage)), i.certIdHex)
        assertNull(i.aidHex)
        assertNull(i.transport)

        // Every command the inspection issued, and every one that reached the card, is on the read-only allow-list.
        assertTrue(i.exchanges.joinToString(), i.exchanges.all { ApduNames.isReadOnly(it.cla, it.ins) && it.outcome != com.impala.sdk.apdu4j.ApduExchange.Outcome.REFUSED })
        assertTrue("sent $sent", sent.all { it in ApduNames.READ_ONLY_INS })
    }

    @Test
    fun `a card without a Stellar key is not asked for one`() {
        val card = personalizedCard(TestIssuer(), uuidBytes(), ed25519 = SimulatorBibo.ED25519_NONE)
        val sent = mutableListOf<Int>()
        card.bibo.debugTrace = { cmd, _ -> sent += cmd[1].toInt() and 0xFF }
        val i = inspect(card.bibo)
        assertTrue(i.steps.joinToString(), i.complete)
        assertEquals(8, i.steps.size)
        assertFalse("GET_STELLAR_KEY" in i.steps.map { it.name })
        assertFalse("sent $sent", 0x37 in sent)
        assertNull(i.stellarAddress)
        assertNull(i.stellarEngine)
        assertNull(i.stellarBindingVerified)
        assertNull(i.stellarProofVerified)
        assertFalse("STELLAR_KEY" in i.flagNames)
    }

    @Test
    fun `the Stellar key of a JavaCard 3_1 card is reported the same way`() {
        val i = inspect(personalizedCard(TestIssuer(), uuidBytes(), ed25519 = SimulatorBibo.ED25519_NATIVE).bibo)
        assertTrue(i.complete)
        assertEquals("native", i.stellarEngine)
        assertEquals(true, i.stellarBindingVerified)
        assertEquals(true, i.stellarProofVerified)
    }

    @Test
    fun `a Stellar key that is not bound yet, or bound to something else, does not verify`() {
        // initialized but not personalized: the key exists, the signatures do not
        val fresh = SimulatorBibo().also { com.impala.sdk.ImpalaSDK(it).setSeed() }
        val unbound = inspect(fresh)
        assertEquals(56, unbound.stellarAddress!!.length)
        assertNull(unbound.stellarBindingVerified)
        assertNull(unbound.stellarProofVerified)

        // a flipped byte in either signature shows as a failed check, not as an error
        val card = personalizedCard(TestIssuer(), uuidBytes())
        for ((offset, bindingOk, proofOk) in listOf(Triple(1 + 32 + 10, false, true), Triple(1 + 32 + 72 + 10, true, false))) {
            val faulty = FaultInjectingBibo(card.bibo)
            faulty.responseRewrites[0x37] = { resp -> resp[offset] = (resp[offset].toInt() xor 0x01).toByte(); resp }
            val i = inspect(faulty)
            assertEquals("binding with byte $offset flipped", bindingOk, i.stellarBindingVerified)
            assertEquals("proof with byte $offset flipped", proofOk, i.stellarProofVerified)
        }
        // another account's identity in GET_USER_DATA: neither signature is for it
        val swapped = FaultInjectingBibo(card.bibo)
        swapped.responseRewrites[0x1E] = { resp -> resp[0] = (resp[0].toInt() xor 0x01).toByte(); resp }
        inspect(swapped).let {
            assertEquals(false, it.stellarBindingVerified)
            assertEquals(false, it.stellarProofVerified)
        }
    }

    @Test
    fun `toString and the masked fields never carry the holder name, balance or transfer`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        card.sdk.setUserName(holder)
        val i = inspect(card.bibo)
        val text = "$i ${i.holderName} ${i.balanceMinor} ${i.lastTransfer} ${i.steps}"
        assertFalse(text, text.contains(holder))
        assertEquals("••••", i.holderName.toString())
        assertEquals("••••", i.balanceMinor.toString())
        assertTrue(i.toString().contains(i.wireCardId!!))
    }

    @Test
    fun `a flipped certificate byte is false under the card's own issuer`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, uuidBytes())
        val faulty = FaultInjectingBibo(card.bibo)
        faulty.responseRewrites[0x34] = { resp ->
            val certStart = 87
            val derLen = (resp[certStart + 1].toInt() and 0xFF) + 2
            resp[certStart + derLen - 1] = (resp[certStart + derLen - 1].toInt() xor 0x01).toByte()
            resp
        }
        val i = inspect(faulty)
        assertEquals(false, i.certVerifiedByCardIssuer)
        assertEquals(false, i.certificateVerifiesUnder(Hex.encode(issuer.pub65)))
    }

    @Test
    fun `a card that sent a transfer shows it, masked, with its balance`() {
        val issuer = TestIssuer()
        val account = uuidBytes()
        val card = personalizedCard(issuer, account)
        fund(card, issuer.externalSender(uuidBytes()), amount = 500, sendSequence = 1)
        val recipient = uuidBytes()
        card.sdk.signTransferV2("1111", Signable(7, account, recipient, TransferProtocol.CURRENCY_USDC, 120, 0, 1).encode())

        val i = inspect(card.bibo)
        assertTrue(i.complete)
        assertEquals(380L, i.balanceMinor!!.reveal())
        assertEquals(1, i.receiveCounter)
        val last = i.lastTransfer!!.reveal()!!
        assertEquals(120L, last.amountMinor)
        assertEquals(1, last.counter)
        assertEquals(7L, last.sendSequence)
        assertEquals(UuidBytes.format(recipient), last.recipientUuid)
        assertEquals("USDC", last.currency)
        assertTrue(last.signatureLength in 8..72)
        assertFalse(last.toString().contains("120"))
    }

    @Test
    fun `a blank card yields a partial inspection with reasons, not an exception`() {
        val i = inspect(SimulatorBibo())
        assertFalse(i.complete)
        assertTrue(i.steps.first { it.name == "GET_VERSION" }.ok)
        assertEquals("0.4", "${i.versionMajor}.${i.versionMinor}")
        val key = i.steps.first { it.name == "GET_EC_PUB_KEY" }
        assertFalse(key.ok)
        assertNotNull(key.error)
        assertEquals("BLANK", i.stateName)
        assertNull(i.cardKeyFingerprint)
        assertNull(i.certVerifiedByCardIssuer)
        assertNull(i.certificateVerifiesUnder(Hex.encode(TestIssuer().pub65)))
        assertNull(i.certIdHex)
        assertEquals(8, i.steps.size)
    }

    @Test
    fun `a tag loss ends the inspection early without throwing`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val faulty = FaultInjectingBibo(card.bibo).apply { loseTagOnIns = 0x2E }
        val i = inspect(faulty)
        assertEquals(listOf("GET_VERSION", "GET_PERSONALIZATION", "GET_USER_DATA", "GET_EC_PUB_KEY", "IS_CARD_ALIVE"), i.steps.map { it.name })
        assertTrue(i.steps.last().error is CardError.TagLost)
        assertNull(i.alive)
        assertNull(i.balanceMinor)
        assertNull(i.lastTransfer)
        assertNotNull(i.accountUuid)
        assertEquals(1, i.exchanges.count { it.outcome == com.impala.sdk.apdu4j.ApduExchange.Outcome.TAG_LOST })
    }

    @Test
    fun `a terminated card reads alive false`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val faulty = FaultInjectingBibo(card.bibo)
        faulty.responseRewrites[0x2E] = { byteArrayOf(0x66, 0x87.toByte()) }
        val i = inspect(faulty)
        assertEquals(false, i.alive)
        assertTrue(i.steps.first { it.name == "IS_CARD_ALIVE" }.ok)
    }

    @Test
    fun `a session that is not read-only is refused`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val e = assertThrows(IllegalStateException::class.java) {
            offMain { ImpalaCardSession.fromBibo(card.bibo).use { CardInspector.inspect(it) } }
        }
        assertTrue(e.message!!.contains("read-only"))
    }

    @Test
    fun `inspecting on the main thread is refused`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val session = ImpalaCardSession.fromBibo(card.bibo, readOnly = true)
        val e = assertThrows(IllegalStateException::class.java) { CardInspector.inspect(session) }
        assertTrue(e.message!!.contains("main thread"))
    }

    @Test
    fun `version line, state names and currency text`() {
        assertEquals("0.2 · r17 · g1a2b3c4d", CardInspector.versionLine(com.impala.sdk.models.ImpalaVersion(0, 2, 17, "1a2b3c4d")))
        assertEquals("TERMINATED", CardInspector.stateName(0xFF))
        assertEquals("UNKNOWN_0x07", CardInspector.stateName(0x07))
        assertEquals("XLM", CardInspector.currencyText(TransferProtocol.CURRENCY_XLM))
        assertEquals("01020304", CardInspector.currencyText(byteArrayOf(1, 2, 3, 4)))
    }

    /**
     * Default selection (live flavour, empty AID) on a foreign card: GET_VERSION answers 6D00, and
     * the remaining INS bytes mean something else on that applet (ISO 0x04 DEACTIVATE FILE, 0x24
     * CHANGE REFERENCE DATA), so nothing after GET_VERSION may be sent.
     */
    @Test
    fun `a foreign default applet gets GET_VERSION only`() {
        val bibo = ScriptedBibo(emptyMap()) // 6D00 to everything
        val i = offMain { ImpalaCardSession.fromBibo(bibo, null, null, true).use { CardInspector.inspect(it) } }
        assertEquals(listOf(0x64), bibo.sent.map { it[1].toInt() and 0xFF })
        assertEquals(listOf("GET_VERSION"), i.steps.map { it.name })
        assertTrue(i.steps.single().error is CardError.AppletNotFound)
    }
}

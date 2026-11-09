package com.payala.impala.demo.lab

import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOTagLostException
import com.impala.sdk.flows.CardError
import com.impala.simulator.TestIssuer
import com.payala.impala.card.CardInspector
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.R
import com.payala.impala.demo.offMain
import com.payala.impala.demo.ui.lab.BridgeCardFacts
import com.payala.impala.demo.ui.lab.CardDoctor
import com.payala.impala.demo.ui.lab.CheckAction
import com.payala.impala.demo.ui.lab.CheckId
import com.payala.impala.demo.ui.lab.CheckStatus
import com.payala.impala.demo.ui.lab.DoctorCheck
import com.payala.impala.demo.ui.lab.DoctorInput
import com.payala.impala.demo.ui.lab.IssuerFacts
import com.payala.impala.demo.ui.lab.ReaderState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * [CardDoctor] on real inspections of jcardsim cards: the honest
 * PASS / FAIL / WARN / SKIP / INFO matrix. FAIL only when the card or the
 * bridge positively says no; an unanswered question is SKIP.
 */
@RunWith(RobolectricTestRunner::class)
class CardDoctorTest {
    private val sim = SimCard()
    private val inspection = sim.inspect()

    private fun run(input: DoctorInput): Map<CheckId, DoctorCheck> = CardDoctor.run(input).associateBy { it.id }

    private fun input(
        issuer: IssuerFacts = IssuerFacts.Known(sim.programIdHex, sim.issuerPubHex),
        bridgeCard: BridgeCardFacts = BridgeCardFacts.Found(certified = true),
        session: String? = sim.accountUuid,
        local: Boolean? = true,
        reader: ReaderState = ReaderState.NFC_ENABLED
    ) = DoctorInput(
        reader = reader, inspection = inspection, exchanges = inspection.exchanges, issuer = issuer,
        bridgeCard = bridgeCard, sessionAccountId = session, localRecord = if (session == null) null else local
    )

    @Test
    fun `a card of this bridge's program with a matching session passes everything it can check`() {
        val checks = run(input())
        for (id in listOf(
            CheckId.READER, CheckId.APPLET_SELECTED, CheckId.APPLET_VERSION, CheckId.PERSONALIZED, CheckId.CERT_CARD_ISSUER,
            CheckId.ISSUER_MATCHES_BRIDGE, CheckId.CERT_BRIDGE_KEY, CheckId.BRIDGE_KNOWS_CARD, CheckId.LOCAL_RECORD, CheckId.ACCOUNT_MATCHES
        )) assertEquals("$id", CheckStatus.PASS, checks.getValue(id).status)
        // A jcardsim session has no radio facts: the ISO check cannot be answered.
        assertEquals(CheckStatus.SKIP, checks.getValue(CheckId.ISO14443_4).status)
        assertEquals(CheckStatus.INFO, checks.getValue(CheckId.FIELD_QUALITY).status)
        assertEquals(R.string.lab_doc_bridge_card_certified, checks.getValue(CheckId.BRIDGE_KNOWS_CARD).detailRes)
        assertNull("no selected-card check unless the Lab was opened for a card", checks[CheckId.SELECTED_CARD])
    }

    @Test
    fun `a test-issuer card on a configured bridge fails the issuer checks with the login-only remedy`() {
        val bridge = TestIssuer() // the bridge's own program, not the card's
        val checks = run(input(issuer = IssuerFacts.Known(com.impala.sdk.flows.Hex.encode(bridge.programId), com.impala.sdk.flows.Hex.encode(bridge.pub65))))
        val issuer = checks.getValue(CheckId.ISSUER_MATCHES_BRIDGE)
        assertEquals(CheckStatus.FAIL, issuer.status)
        assertEquals(R.string.lab_doc_issuer_mismatch, issuer.detailRes)
        assertEquals(R.string.lab_doc_issuer_mismatch_fix, issuer.remedyRes)
        assertEquals(listOf(sim.programIdHex, com.impala.sdk.flows.Hex.encode(bridge.programId)), issuer.detailArgs)
        val cert = checks.getValue(CheckId.CERT_BRIDGE_KEY)
        assertEquals(CheckStatus.FAIL, cert.status)
        assertEquals(R.string.lab_doc_issuer_mismatch_fix, cert.remedyRes)
        // The card's own certificate is still fine.
        assertEquals(CheckStatus.PASS, checks.getValue(CheckId.CERT_CARD_ISSUER).status)
    }

    @Test
    fun `configured false and an unreachable bridge are SKIP, not FAIL`() {
        for (facts in listOf(IssuerFacts.Unconfigured, IssuerFacts.Unreachable("CONNECT"), IssuerFacts.NotChecked)) {
            val checks = run(input(issuer = facts))
            assertEquals("$facts", CheckStatus.SKIP, checks.getValue(CheckId.ISSUER_MATCHES_BRIDGE).status)
            assertEquals("$facts", CheckStatus.SKIP, checks.getValue(CheckId.CERT_BRIDGE_KEY).status)
        }
        assertEquals(R.string.lab_doc_bridge_unconfigured, run(input(issuer = IssuerFacts.Unconfigured)).getValue(CheckId.ISSUER_MATCHES_BRIDGE).detailRes)
        assertEquals(listOf("CONNECT"), run(input(issuer = IssuerFacts.Unreachable("CONNECT"))).getValue(CheckId.CERT_BRIDGE_KEY).detailArgs)
    }

    @Test
    fun `offline 404 for a card this phone did not record is WARN with the register remedy, 503 is WARN, 401 and 403 are SKIP`() {
        for ((code, local) in listOf(404 to false, 503 to false, 503 to true)) {
            val c = run(input(bridgeCard = BridgeCardFacts.Http(code), local = local)).getValue(CheckId.BRIDGE_KNOWS_CARD)
            assertEquals("$code local=$local", CheckStatus.WARN, c.status)
            assertEquals(R.string.lab_doc_bridge_card_missing, c.detailRes)
            assertEquals(R.string.lab_doc_bridge_card_missing_fix, c.remedyRes)
            assertEquals(listOf(code.toString()), c.detailArgs)
        }
        for (code in listOf(401, 403)) {
            val c = run(input(bridgeCard = BridgeCardFacts.Http(code))).getValue(CheckId.BRIDGE_KNOWS_CARD)
            assertEquals(CheckStatus.SKIP, c.status)
            assertEquals(R.string.lab_doc_session_expired, c.detailRes)
        }
        assertEquals(CheckStatus.SKIP, run(input(bridgeCard = BridgeCardFacts.Http(500))).getValue(CheckId.BRIDGE_KNOWS_CARD).status)
        assertEquals(CheckStatus.SKIP, run(input(bridgeCard = BridgeCardFacts.Network("TIMEOUT"))).getValue(CheckId.BRIDGE_KNOWS_CARD).status)
        assertEquals(R.string.lab_doc_bridge_card_known, run(input(bridgeCard = BridgeCardFacts.Found(false))).getValue(CheckId.BRIDGE_KNOWS_CARD).detailRes)
    }

    @Test
    fun `offline 404 for a card recorded on this phone is INFO, not a register-the-card warning`() {
        // POST /card succeeded from this phone; GET /offline/cards/{id} answers 404 when the offline
        // lane is not deployed, so the Doctor must not contradict "Recorded on this phone".
        val checks = run(input(bridgeCard = BridgeCardFacts.Http(404), local = true))
        val c = checks.getValue(CheckId.BRIDGE_KNOWS_CARD)
        assertEquals(CheckStatus.INFO, c.status)
        assertEquals(R.string.lab_doc_bridge_card_no_offline_record, c.detailRes)
        assertEquals(listOf("404"), c.detailArgs)
        assertNull("no remedy telling the user to register again", c.remedyRes)
        assertEquals(CheckStatus.PASS, checks.getValue(CheckId.LOCAL_RECORD).status)
        // No session: the local record is unknown and the bridge is not asked.
        assertEquals(CheckStatus.SKIP, run(input(bridgeCard = BridgeCardFacts.Http(404), session = null)).getValue(CheckId.BRIDGE_KNOWS_CARD).status)
    }

    @Test
    fun `AppletNotFound fails the applet check and skips every later card check`() {
        val checks = CardDoctor.run(DoctorInput(reader = ReaderState.NFC_ENABLED, readError = CardError.AppletNotFound(0x6A82), sessionAccountId = sim.accountUuid))
        val applet = checks.single { it.id == CheckId.APPLET_SELECTED }
        assertEquals(CheckStatus.FAIL, applet.status)
        assertEquals(listOf("6A82"), applet.detailArgs)
        assertEquals(R.string.lab_doc_applet_not_found_fix, applet.remedyRes)
        val later = checks.dropWhile { it.id != CheckId.APPLET_SELECTED }.drop(1).filter { it.id.needsApplet }
        assertTrue(later.isNotEmpty())
        later.forEach { assertEquals("${it.id}", CheckStatus.SKIP, it.status) }
        assertEquals(CheckStatus.PASS, checks.single { it.id == CheckId.READER }.status)
    }

    @Test
    fun `default selection passes the applet check only when GET_VERSION answered`() {
        // A foreign card whose default application answers every command with one SW (null: the tag is lost).
        fun foreign(sw: Int?) = offMain {
            val bibo = object : BIBO {
                override fun transceive(bytes: ByteArray?): ByteArray =
                    if (sw == null) throw BIBOTagLostException("lost") else byteArrayOf((sw shr 8).toByte(), sw.toByte())
                override fun close() {}
            }
            ImpalaCardSession.fromBibo(bibo, aidHex = null, readOnly = true).use { CardInspector.inspect(it) }
        }
        for (sw in listOf(0x6E00, 0x6700, 0x6985, 0x6F00)) {
            val insp = foreign(sw)
            val applet = run(DoctorInput(ReaderState.NFC_ENABLED, inspection = insp, exchanges = insp.exchanges)).getValue(CheckId.APPLET_SELECTED)
            assertEquals("SW %04X".format(sw), CheckStatus.FAIL, applet.status)
            assertEquals(listOf("%04X".format(sw)), applet.detailArgs)
        }
        val lost = foreign(null)
        assertEquals(CheckStatus.SKIP, run(DoctorInput(ReaderState.NFC_ENABLED, inspection = lost, exchanges = lost.exchanges)).getValue(CheckId.APPLET_SELECTED).status)
        // A real Impala card under default selection still passes.
        assertEquals(CheckStatus.PASS, run(input()).getValue(CheckId.APPLET_SELECTED).status)
    }

    @Test
    fun `a card that is not ISO 14443-4 fails that check`() {
        val checks = run(DoctorInput(reader = ReaderState.NFC_ENABLED, readError = CardError.InvalidRequest("tag is not an ISO 14443-4 card")))
        assertEquals(CheckStatus.FAIL, checks.getValue(CheckId.ISO14443_4).status)
        assertEquals(CheckStatus.SKIP, checks.getValue(CheckId.APPLET_SELECTED).status)
    }

    @Test
    fun `without a session the bridge-card, local-record and account checks are SKIP`() {
        val checks = run(input(session = null, bridgeCard = BridgeCardFacts.NoSession))
        for (id in listOf(CheckId.BRIDGE_KNOWS_CARD, CheckId.LOCAL_RECORD, CheckId.ACCOUNT_MATCHES)) {
            assertEquals("$id", CheckStatus.SKIP, checks.getValue(id).status)
            assertEquals("$id", R.string.lab_doc_no_session, checks.getValue(id).detailRes)
        }
        // Public card facts are still checked pre-login.
        assertEquals(CheckStatus.PASS, checks.getValue(CheckId.CERT_BRIDGE_KEY).status)
    }

    @Test
    fun `another account's card fails the account check and an unrecorded card warns`() {
        val checks = run(input(session = "50000000-0000-4000-8000-00000000000a", local = false))
        val account = checks.getValue(CheckId.ACCOUNT_MATCHES)
        assertEquals(CheckStatus.FAIL, account.status)
        assertEquals(listOf(sim.accountUuid), account.detailArgs)
        assertEquals(CheckStatus.WARN, checks.getValue(CheckId.LOCAL_RECORD).status)
        // A non-UUID session id never matches (fail closed).
        assertEquals(CheckStatus.FAIL, run(input(session = "alice")).getValue(CheckId.ACCOUNT_MATCHES).status)
    }

    @Test
    fun `NFC off fails the reader check and offers the settings action`() {
        val reader = run(input(reader = ReaderState.NFC_DISABLED)).getValue(CheckId.READER)
        assertEquals(CheckStatus.FAIL, reader.status)
        assertEquals(CheckAction.OPEN_NFC_SETTINGS, reader.action)
        assertEquals(CheckStatus.PASS, run(input(reader = ReaderState.SIMULATED)).getValue(CheckId.READER).status)
        assertEquals(CheckStatus.FAIL, run(input(reader = ReaderState.NFC_ABSENT)).getValue(CheckId.READER).status)
    }

    @Test
    fun `before any read every card check is SKIP and nothing fails but the reader`() {
        val checks = CardDoctor.run(DoctorInput(reader = ReaderState.NFC_ENABLED))
        assertTrue(checks.filter { it.id != CheckId.READER && it.id != CheckId.FIELD_QUALITY }.all { it.status == CheckStatus.SKIP })
        assertEquals(CheckStatus.INFO, checks.last().status)
    }

    @Test
    fun `a simulated-card failure without a card error skips the card checks`() {
        val checks = run(DoctorInput(reader = ReaderState.SIMULATED, readFailed = true, simulated = true))
        assertEquals(CheckStatus.SKIP, checks.getValue(CheckId.APPLET_SELECTED).status)
        assertEquals(R.string.lab_doc_iso_simulated, checks.getValue(CheckId.ISO14443_4).detailRes)
    }

    @Test
    fun `opened for one card, reading another warns`() {
        val other = DoctorInput(reader = ReaderState.NFC_ENABLED, inspection = inspection, expectedCardId = "ff".repeat(16))
        assertEquals(CheckStatus.WARN, run(other).getValue(CheckId.SELECTED_CARD).status)
        val same = DoctorInput(reader = ReaderState.NFC_ENABLED, inspection = inspection, expectedCardId = inspection.wireCardId!!.uppercase())
        assertEquals(CheckStatus.PASS, run(same).getValue(CheckId.SELECTED_CARD).status)
    }

    @Test
    fun `field quality reports counts and the slowest instruction`() {
        val field = run(input()).getValue(CheckId.FIELD_QUALITY)
        assertEquals(R.string.lab_doc_field, field.detailRes)
        assertEquals(inspection.exchanges.size.toString(), field.detailArgs[0])
        assertEquals("0", field.detailArgs[1])
    }

    @Test
    fun `detail arguments carry identifiers and counts, never the holder name`() {
        val all = CardDoctor.run(input(session = "50000000-0000-4000-8000-00000000000a")).flatMap { it.detailArgs }
        val name = inspection.holderName?.reveal().orEmpty()
        if (name.isNotBlank()) assertTrue(all.none { it.contains(name) })
        assertTrue(all.none { it.contains(sim.cardPubHex) || it.contains(sim.certHex) })
    }
}

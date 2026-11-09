package com.payala.impala.demo.lab

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.impala.sdk.apdu4j.ApduExchange
import com.payala.impala.demo.R
import com.payala.impala.demo.ui.lab.BuildInfo
import com.payala.impala.demo.ui.lab.CardDoctor
import com.payala.impala.demo.ui.lab.DoctorInput
import com.payala.impala.demo.ui.lab.IssuerFacts
import com.payala.impala.demo.ui.lab.LabReport
import com.payala.impala.demo.ui.lab.LabRow
import com.payala.impala.demo.ui.lab.ReaderState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * [LabReport]: the export has no way to carry personal data (no PII
 * parameter, nothing personal rendered), and the screen reveals the name,
 * balance and last transfer only when told the session owns the card.
 */
@RunWith(RobolectricTestRunner::class)
class LabReportTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val res = ctx.resources

    private fun export(inspection: com.payala.impala.card.CardInspection, exchanges: List<ApduExchange> = inspection.exchanges): String {
        val checks = CardDoctor.run(DoctorInput(ReaderState.NFC_ENABLED, inspection = inspection, exchanges = exchanges, issuer = IssuerFacts.Unconfigured))
        return LabReport.export(res, BuildInfo.rows(ctx, ReaderState.NFC_ENABLED), null, inspection, checks, exchanges, nowEpochMs = 0L)
    }

    @Test
    fun `the export never contains the holder name, balance or last transfer`() {
        val text = export(syntheticInspection(holder = "Card Holder", balance = 987_654_321L, lastAmount = 1_234_567L))
        assertFalse(text, text.contains("Card Holder"))
        assertFalse(text, text.contains("987654321"))
        assertFalse(text, text.contains("1234567"))
        assertFalse(text, text.contains("30000000-0000-4000-8000-000000000008")) // the last transfer's recipient
        assertFalse(text, text.contains("••••")) // not even masked placeholders: the fields are simply absent
        assertTrue(text.contains("holder name, balance, last transfer: not exported"))
    }

    @Test
    fun `the export carries ids, program, cert_id and fingerprints but no raw key or certificate`() {
        val sim = SimCard(balance = 123_456_789)
        val inspection = sim.inspect()
        val text = export(inspection)
        assertTrue(text.contains("card_id: ${inspection.wireCardId}"))
        assertTrue(text.contains("program_id: ${sim.programIdHex}"))
        assertTrue(text.contains("cert_id: ${inspection.certIdHex}"))
        assertTrue(text.contains(inspection.cardKeyFingerprint!!))
        assertFalse("the 130-hex card key leaked", text.contains(sim.cardPubHex, ignoreCase = true))
        assertFalse("the certificate leaked", text.contains(sim.certHex, ignoreCase = true))
        assertFalse("the issuer key leaked", text.contains(sim.issuerPubHex, ignoreCase = true))
        assertFalse("the balance leaked", text.contains("123456789"))
        assertTrue("header-only trace lines", text.contains("GET_VERSION  Lc 0 → 9000 OK"))
    }

    @Test
    fun `export has no parameter that could include personal data`() {
        val export = LabReport::class.java.declaredMethods.filter { it.name == "export" || it.name.startsWith("export$") }
        assertTrue(export.isNotEmpty())
        for (m in export) {
            for (p in m.parameterTypes) {
                assertFalse("export takes a Boolean switch: $m", p == Boolean::class.javaPrimitiveType || p == java.lang.Boolean::class.java)
                assertFalse("export takes a Masked value: $m", p.name.contains("Masked"))
            }
        }
        // The only reveal() in the Lab is in screen().
        val src = File("src/main/java/com/payala/impala/demo/ui/lab/LabReport.kt").readText()
        assertEquals(1, Regex("""\.reveal\(\)""").findAll(src).count())
        val exportBody = src.substringAfter("fun export(")
        assertFalse(exportBody.contains("reveal()"))
        assertFalse(exportBody.contains("holderName"))
        assertFalse(exportBody.contains("balanceMinor"))
        assertFalse(exportBody.contains("lastTransfer"))
    }

    @Test
    fun `screen masks personal rows unless the session owns the card`() {
        val inspection = syntheticInspection()
        val masked = LabReport.screen(res, inspection, reveal = false).filterIsInstance<LabRow.Item>()
        val hint = ctx.getString(R.string.lab_pii_hint)
        for (label in listOf(R.string.lab_row_holder, R.string.lab_row_balance, R.string.lab_row_last_transfer).map(ctx::getString)) {
            val row = masked.single { it.label == label }
            assertEquals(label, hint, row.value)
            assertTrue(row.masked)
            assertFalse("masked rows are never copyable", row.copyable)
        }
        assertTrue(masked.none { it.value.contains("Card Holder") || it.value.contains("987654321") })

        val revealed = LabReport.screen(res, inspection, reveal = true).filterIsInstance<LabRow.Item>()
        val holder = revealed.single { it.label == ctx.getString(R.string.lab_row_holder) }
        assertEquals("Card Holder", holder.value)
        assertTrue(holder.personal)
        assertFalse(holder.copyable)
        assertFalse("a revealed row never prints its value", holder.toString().contains("Card Holder"))
        assertTrue(revealed.single { it.label == ctx.getString(R.string.lab_row_balance) }.value.startsWith("987654321 minor units"))
        assertTrue(revealed.single { it.label == ctx.getString(R.string.lab_row_last_transfer) }.value.contains("1234567"))
    }

    @Test
    fun `identifier rows are copyable`() {
        val rows = LabReport.screen(res, syntheticInspection(), reveal = false).filterIsInstance<LabRow.Item>().associateBy { it.label }
        for (id in listOf(R.string.lab_row_card_id, R.string.lab_row_account, R.string.lab_row_program, R.string.lab_row_cert_id, R.string.lab_row_card_key)) {
            assertTrue(ctx.getString(id), rows.getValue(ctx.getString(id)).copyable)
        }
        assertFalse(rows.getValue(ctx.getString(R.string.lab_row_state)).copyable)
    }

    @Test
    fun `a card that never signed shows none, and an unread balance says not read`() {
        val sim = SimCard()
        val rows = LabReport.screen(res, sim.inspect(), reveal = true).filterIsInstance<LabRow.Item>().associateBy { it.label }
        assertEquals(ctx.getString(R.string.lab_last_transfer_none), rows.getValue(ctx.getString(R.string.lab_row_last_transfer)).value)
        assertEquals("0 minor units USDC", rows.getValue(ctx.getString(R.string.lab_row_balance)).value)
    }

    @Test
    fun `an XLM balance shows the formatted amount at the card scale and the raw minor units`() {
        assertEquals("0.0000000 XLM · 0 minor units", LabReport.amountText(res, 0L, "XLM"))
        assertEquals("98.7654321 XLM · 987654321 minor units", LabReport.amountText(res, 987_654_321L, "XLM"))
        assertEquals("0.0000001 xlm · 1 minor units", LabReport.amountText(res, 1L, "xlm"))
        // An unknown card scale stays in minor units only (never a guessed decimal point).
        assertEquals("5 minor units USDC", LabReport.amountText(res, 5L, "USDC"))
        val rows = LabReport.screen(res, syntheticInspection(currency = "XLM"), reveal = true).filterIsInstance<LabRow.Item>().associateBy { it.label }
        assertEquals("98.7654321 XLM · 987654321 minor units", rows.getValue(ctx.getString(R.string.lab_row_balance)).value)
        assertTrue(rows.getValue(ctx.getString(R.string.lab_row_last_transfer)).value.startsWith("0.1234567 XLM · 1234567 minor units · counter 4"))
    }

    @Test
    fun `identifiers are marked for monospace and prose values are not`() {
        val rows = LabReport.screen(res, syntheticInspection(), reveal = true).filterIsInstance<LabRow.Item>().associateBy { it.label }
        for (id in listOf(R.string.lab_row_card_id, R.string.lab_row_account, R.string.lab_row_card_key, R.string.lab_row_program, R.string.lab_row_aid)) {
            assertTrue(ctx.getString(id), rows.getValue(ctx.getString(id)).identifier)
        }
        for (id in listOf(R.string.lab_row_cert_verified, R.string.lab_row_steps, R.string.lab_row_last_transfer, R.string.lab_row_balance, R.string.lab_row_holder)) {
            assertFalse(ctx.getString(id), rows.getValue(ctx.getString(id)).identifier)
        }
        val simulated = LabReport.screen(res, syntheticInspection(), reveal = false).filterIsInstance<LabRow.Item>()
            .single { it.label == ctx.getString(R.string.lab_row_link) }
        assertFalse("\"Simulated card (no radio)\" is prose", simulated.identifier)
    }

    @Test
    fun `the bridge issuer key fingerprint uses the Inspector's format and matches the card's issuer key`() {
        val sim = SimCard()
        val inspection = sim.inspect()
        val fp = LabReport.issuerKeyFingerprint(sim.issuerPubHex)
        assertEquals(inspection.issuerKeyFingerprint, fp)
        assertTrue(fp!!, Regex("""^([0-9a-f]{2}:){9}[0-9a-f]{2}$""").matches(fp))
        assertEquals(null, LabReport.issuerKeyFingerprint("04abcd"))
        assertEquals(null, LabReport.issuerKeyFingerprint(null))
        val bridge = CannedBridge.healthy(issuerJson = """{"configured":true,"version":1,"public_key_hex":"${sim.issuerPubHex}","fingerprint":"6696efc3d3b026c6f1c9","redemption_uuid":"40000000-0000-4000-8000-000000000009","program_id_hex":"${sim.programIdHex}"}""")
        val probe = com.payala.impala.demo.ui.lab.BridgeProbe("https://bridge.example.test", "testnet", bridge.client).tryRun()!!
        val rows = LabReport.device(res, BuildInfo.rows(ctx, com.payala.impala.demo.ui.lab.ReaderState.NFC_ENABLED), probe, null, null)
            .filterIsInstance<LabRow.Item>().associateBy { it.label }
        assertEquals(fp, rows.getValue(ctx.getString(R.string.lab_row_bridge_issuer_fp)).value)
        assertEquals("6696efc3d3b026c6f1c9", rows.getValue(ctx.getString(R.string.lab_row_bridge_operator_fp)).value)
    }

    @Test
    fun `the Device tab names the Stellar network once`() {
        val network = ctx.getString(R.string.lab_row_bridge_network)
        assertEquals(network, ctx.getString(R.string.lab_build_network))
        val build = BuildInfo.rows(ctx, com.payala.impala.demo.ui.lab.ReaderState.NFC_ENABLED)
        val probe = com.payala.impala.demo.ui.lab.BridgeProbe("https://bridge.example.test", "testnet", CannedBridge.healthy().client).tryRun()!!
        val probed = LabReport.device(res, build, probe, null, null).filterIsInstance<LabRow.Item>()
        assertEquals(1, probed.count { it.label == network })
        assertTrue("the bridge row carries the build's network", probed.single { it.label == network }.value.contains("(this build: testnet)"))
        // Not probed yet: the build's row is the only one.
        assertEquals(1, LabReport.device(res, build, null, null, null).filterIsInstance<LabRow.Item>().count { it.label == network })
    }

    @Test
    fun `the Doctor summary pluralises the warning count`() {
        fun checks(warn: Int) = List(warn) {
            com.payala.impala.demo.ui.lab.DoctorCheck(com.payala.impala.demo.ui.lab.CheckId.LOCAL_RECORD, com.payala.impala.demo.ui.lab.CheckStatus.WARN, 0, 0)
        } + com.payala.impala.demo.ui.lab.DoctorCheck(com.payala.impala.demo.ui.lab.CheckId.READER, com.payala.impala.demo.ui.lab.CheckStatus.PASS, 0, 0)
        assertEquals("1 passed · 0 failed · 0 warnings · 0 skipped", LabReport.doctorSummary(res, checks(0)))
        assertEquals("1 passed · 0 failed · 1 warning · 0 skipped", LabReport.doctorSummary(res, checks(1)))
        assertEquals("1 passed · 0 failed · 2 warnings · 0 skipped", LabReport.doctorSummary(res, checks(2)))
    }

    @Test
    fun `a degraded bridge is not shown as a passing health check`() {
        // The bridge answers /health with HTTP 200 and status "degraded" when its database or Redis is down.
        val bridge = CannedBridge(mapOf("/health" to (200 to """{"status":"degraded","database":"error","redis":"ok","stellar_network":"testnet"}""")))
        val probe = com.payala.impala.demo.ui.lab.BridgeProbe("https://bridge.example.test", "testnet", bridge.client).tryRun()!!
        val health = LabReport.device(res, emptyList(), probe, null, null).filterIsInstance<LabRow.Item>().single { it.label == "/health" }
        assertTrue("value ${health.value}", health.value.startsWith("degraded"))
        assertFalse("a degraded bridge is tinted ${health.tone}", health.tone == com.payala.impala.demo.ui.lab.CheckStatus.PASS)
    }

    @Test
    fun `the trace line is header-only`() {
        val e = ApduExchange(0x00, 0x34, 0, 0, 0, 0x9000, 159, 11_000_000L, ApduExchange.Outcome.OK, 3)
        assertEquals("GET_PERSONALIZATION  Lc 0 → 9000 OK  159 B  11 ms", LabReport.exchangeLine(e))
        val lost = ApduExchange(0x00, 0x04, 0, 0, 0, null, 0, 2_000_000L, ApduExchange.Outcome.TAG_LOST, 4)
        assertTrue(LabReport.exchangeLine(lost).contains("TAG_LOST"))
    }
}

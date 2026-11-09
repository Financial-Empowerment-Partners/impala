package com.payala.impala.demo.lab

import android.app.Application
import android.content.Context
import android.view.View
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.tabs.TabLayout
import com.impala.sdk.apdu4j.ApduExchange
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.offMain
import com.payala.impala.demo.ui.lab.CheckId
import com.payala.impala.demo.ui.lab.CheckStatus
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.lab.LabRow
import com.payala.impala.demo.ui.lab.LabViewModel
import com.payala.impala.demo.ui.lab.adapters.KeyValueAdapter
import com.payala.impala.demo.ui.nfc.NfcDebugActivity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import java.io.File

/**
 * The Card Lab activity (Robolectric): its own session factory is read-only
 * and traced; it reads the session through `(application as? ImpalaApp)`
 * and so runs with no session at all (the default test Application), masking
 * every personal row; LabIntents' tab and card extras are honoured; the
 * bridge probe stays unauthenticated.
 */
@RunWith(RobolectricTestRunner::class)
class NfcDebugActivityTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private lateinit var bridge: CannedBridge
    private var controller: ActivityController<NfcDebugActivity>? = null

    @Before
    fun setUp() {
        bridge = CannedBridge.healthy(network = BuildConfig.STELLAR_NETWORK)
        LabViewModel.probeClient = bridge.client
    }

    @After
    fun tearDown() {
        controller?.pause()?.stop()?.destroy()
        LabViewModel.probeClient = null
        LabViewModel.apiOverride = null
    }

    private fun launch(tab: String = LabIntents.TAB_INSPECTOR, cardId: String? = null): NfcDebugActivity {
        val c = Robolectric.buildActivity(NfcDebugActivity::class.java, LabIntents.open(ctx, tab, cardId)).setup()
        controller = c
        return c.get()
    }

    private fun NfcDebugActivity.rows(id: Int): List<LabRow> =
        (findViewById<RecyclerView>(id).adapter as KeyValueAdapter).currentList

    @Test
    fun `the test application is not ImpalaApp, and the Lab still runs with no session`() {
        assertFalse(ApplicationProvider.getApplicationContext<Application>() is com.payala.impala.demo.ImpalaApp)
        val lab = launch()
        assertEquals(null, lab.viewModel.sessionAccountId)
        assertEquals(ctx.getString(R.string.title_nfc_debug), lab.supportActionBar?.title ?: lab.title)
    }

    @Test
    fun `the Lab's session factory opens read-only, traced sessions`() {
        val lab = launch()
        val session: ImpalaCardSession = offMain { lab.openLabSession(TestTags.isoDepA(), aid = null) }
        session.use {
            assertTrue("Lab sessions must be read-only", it.isReadOnly)
            assertNotNull("opened on the tag, with its radio facts", it.transport)
        }
        // With an AID, the SELECT goes through the Lab's trace (the shadow tag does not answer it).
        val seen = ArrayList<ApduExchange>()
        runCatching { offMain { lab.openLabSession(TestTags.isoDepA(), aid = "01020304050607080102") } }
        idleMainUntil { lab.viewModel.phase.value == LabViewModel.Phase.READING }
        lab.viewModel.onTapResult(Result.failure(IllegalStateException("shadow tag")))
        seen += lab.viewModel.read.value!!.exchanges
        assertEquals("SELECT", seen.single().insName)
    }

    @Test
    fun `the reader-mode tap path uses the Lab's read-only factory`() {
        val lab = launch()
        val reader = NfcDebugActivity::class.java.getDeclaredField("cardReader").apply { isAccessible = true }.get(lab)
        val factoryField = reader.javaClass.getDeclaredField("sessionFactory").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val factory = factoryField.get(reader) as (android.nfc.Tag) -> ImpalaCardSession
        // The controller's factory is the Lab's own (not CardReaderController's read-write default) ...
        assertTrue("factory ${factory.javaClass.name}", factory.javaClass.name.startsWith(NfcDebugActivity::class.java.name))
        // ... and, where the shadow tag can be opened (no SELECT: default selection), it is read-only.
        if (com.payala.impala.demo.ui.lab.BuildInfo.appletAid == null) {
            offMain { factory(TestTags.isoDepA()) }.use { assertTrue("a Lab tap opens a read-only session", it.isReadOnly) }
        }
    }

    @Test
    fun `a late Reading post never hides a delivered result`() {
        val lab = launch()
        val sim = SimCard()
        // The read's "Reading" posts are still queued on main when its result arrives.
        offMain { lab.viewModel.beginRead() }
        val inspection = sim.inspect()
        lab.viewModel.onTapResult(Result.success(inspection))
        idleMainUntil { lab.viewModel.phase.value == LabViewModel.Phase.DONE }
        assertEquals(LabViewModel.Phase.DONE, lab.viewModel.phase.value)
    }

    @Test
    fun `every Lab session in the app is opened read-only`() {
        for (path in listOf(
            "src/main/java/com/payala/impala/demo/ui/nfc/NfcDebugActivity.kt",
            "src/main/java/com/payala/impala/demo/ui/lab/LabViewModel.kt"
        )) {
            val src = File(path).readText()
            val opens = Regex("""(ImpalaCardSession\.open|ImpalaCardSession\.fromBibo|DebugCards\.openSession)\(([^)]*)\)""").findAll(src).toList()
            assertTrue("$path opens a session", opens.isNotEmpty())
            // The literal argument, not an expression that merely starts with it (`readOnly = true && …`).
            for (m in opens) assertTrue("$path: ${m.value} is not read-only", Regex("""\breadOnly\s*=\s*true\s*(,|$)""").containsMatchIn(m.groupValues[2]))
            assertFalse(src.contains("readOnly = false"))
        }
    }

    @Test
    fun `no session masks the holder name, balance and last transfer`() {
        val lab = launch()
        val sim = SimCard(balance = 123_456_789)
        val inspection = sim.inspect()
        lab.viewModel.onTapResult(Result.success(inspection))
        idleMainUntil { lab.rows(R.id.rvInspector).isNotEmpty() }
        val items = lab.rows(R.id.rvInspector).filterIsInstance<LabRow.Item>()
        val hint = ctx.getString(R.string.lab_pii_hint)
        for (label in listOf(R.string.lab_row_holder, R.string.lab_row_balance, R.string.lab_row_last_transfer).map(ctx::getString)) {
            val row = items.single { it.label == label }
            assertEquals(label, hint, row.value)
            assertFalse(row.copyable)
        }
        assertTrue(items.none { it.value.contains("123456789") })
        assertFalse(lab.revealsPersonalData(lab.viewModel.read.value))
        // Public facts are shown and copyable.
        assertTrue(items.single { it.label == ctx.getString(R.string.lab_row_card_id) }.copyable)
    }

    @Test
    fun `only the card's own account reveals personal rows`() {
        val lab = launch()
        val sim = SimCard(balance = 123_456_789)
        lab.viewModel.setSession("50000000-0000-4000-8000-00000000000a") // someone else
        lab.viewModel.onTapResult(Result.success(sim.inspect()))
        idleMainUntil { lab.rows(R.id.rvInspector).isNotEmpty() }
        assertFalse(lab.revealsPersonalData(lab.viewModel.read.value))
        assertTrue(lab.rows(R.id.rvInspector).filterIsInstance<LabRow.Item>().none { it.value.contains("123456789") })

        lab.viewModel.setSession(sim.accountUuid.uppercase())
        assertTrue(lab.revealsPersonalData(lab.viewModel.read.value))
    }

    @Test
    fun `LabIntents extras pick the tab and the expected card`() {
        val cardId = "00112233445566778899aabbccddeeff"
        val lab = launch(LabIntents.TAB_DOCTOR, cardId)
        assertEquals(1, lab.findViewById<TabLayout>(R.id.tabs).selectedTabPosition)
        assertEquals(View.VISIBLE, lab.findViewById<View>(R.id.paneDoctor).visibility)
        assertEquals(View.GONE, lab.findViewById<View>(R.id.paneInspector).visibility)
        assertEquals(cardId, lab.viewModel.expectedCardId)
        controller?.pause()?.stop()?.destroy()

        val device = launch(LabIntents.TAB_DEVICE)
        assertEquals(3, device.findViewById<TabLayout>(R.id.tabs).selectedTabPosition)
        assertEquals(View.VISIBLE, device.findViewById<View>(R.id.paneDevice).visibility)
    }

    @Test
    fun `the Doctor runs before any read and the bridge probe is unauthenticated`() {
        val lab = launch(LabIntents.TAB_DEVICE)
        idleMainUntil { lab.viewModel.probe.value != null }
        val probe = lab.viewModel.probe.value!!
        assertFalse(probe.networkMismatch)
        assertTrue(bridge.requests.isNotEmpty())
        assertTrue(bridge.requests.all { it.header("Authorization") == null })
        val reader = lab.viewModel.checks.value!!.single { it.id == CheckId.READER }
        assertTrue(reader.status == CheckStatus.PASS || reader.status == CheckStatus.FAIL)
        // The Device rows include the probe's results.
        assertTrue(lab.rows(R.id.rvDevice).filterIsInstance<LabRow.Item>().any { it.label == "/health" })
    }

    @Test
    fun `a bridge on the other Stellar network shows the mismatch banner`() {
        val other = if (BuildConfig.STELLAR_NETWORK == "testnet") "pubnet" else "testnet"
        LabViewModel.probeClient = CannedBridge.healthy(network = other).client
        val lab = launch(LabIntents.TAB_DEVICE)
        idleMainUntil { lab.findViewById<View>(R.id.bannerNetwork).visibility == View.VISIBLE }
        assertEquals(View.VISIBLE, lab.findViewById<View>(R.id.bannerNetwork).visibility)
    }
}

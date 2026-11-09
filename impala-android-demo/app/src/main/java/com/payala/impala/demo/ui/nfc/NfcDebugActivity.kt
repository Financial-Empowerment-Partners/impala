package com.payala.impala.demo.ui.nfc

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.provider.Settings
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.viewModels
import androidx.annotation.VisibleForTesting
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.tabs.TabLayout
import com.impala.sdk.apdu4j.ApduStats
import com.impala.sdk.flows.UuidBytes
import com.payala.impala.card.CardInspector
import com.payala.impala.card.CardReaderController
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.card.ApduTraceLog
import com.payala.impala.demo.card.DebugCards
import com.payala.impala.demo.databinding.ActivityNfcDebugBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.ui.common.applyEdgeToEdge
import com.payala.impala.demo.ui.common.padForSystemBars
import com.payala.impala.demo.ui.lab.BuildInfo
import com.payala.impala.demo.ui.lab.CheckAction
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.lab.LabRead
import com.payala.impala.demo.ui.lab.LabReport
import com.payala.impala.demo.ui.lab.LabRow
import com.payala.impala.demo.ui.lab.LabViewModel
import com.payala.impala.demo.ui.lab.ReaderState
import com.payala.impala.demo.ui.lab.adapters.DoctorAdapter
import com.payala.impala.demo.ui.lab.adapters.KeyValueAdapter
import com.payala.impala.demo.ui.lab.adapters.TraceAdapter
import com.payala.impala.demo.ui.lab.adapters.TraceItem
import java.text.DateFormat
import java.util.Date

/**
 * The Card Lab: Inspector, Doctor, Trace and Device tabs for "is it the card,
 * the bridge, or me?". The class name, manifest entry and menu id are kept
 * from the old NFC debug screen; callers open it through [LabIntents].
 *
 * Read-only by construction: the Lab owns its own [CardReaderController]
 * (production reader flags and presence check) whose session factory opens
 * every session with `readOnly = true`, the simulated card is read the same
 * way, and `CardInspector.inspect` refuses any other session. Nothing here
 * signs, verifies a PIN, or touches the pending-transfer, card or session
 * stores (it only reads the signed-in account id).
 *
 * Reachable before login: then nothing personal is revealed, and the bridge
 * is only probed through its public endpoints. The holder name, balance and
 * last transfer show only while the signed-in account is the card's account.
 */
class NfcDebugActivity : AppCompatActivity() {

    private lateinit var binding: ActivityNfcDebugBinding
    internal val viewModel: LabViewModel by viewModels()
    private lateinit var cardReader: CardReaderController
    private var nfcAdapter: NfcAdapter? = null

    private lateinit var inspectorAdapter: KeyValueAdapter
    private lateinit var deviceAdapter: KeyValueAdapter
    private lateinit var doctorAdapter: DoctorAdapter
    private lateinit var traceAdapter: TraceAdapter

    private val aidHex: String? get() = BuildInfo.appletAid

    override fun onCreate(savedInstanceState: Bundle?) {
        applyEdgeToEdge()
        super.onCreate(savedInstanceState)
        binding = ActivityNfcDebugBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener { finish() }

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        cardReader = CardReaderController(
            this,
            adapter = nfcAdapter,
            aidHex = aidHex,
            trace = viewModel.traceHook,
            sessionFactory = { tag -> openLabSession(tag) }
        )

        setUpLists()
        setUpTabs(savedInstanceState?.getInt(STATE_TAB, -1) ?: -1)
        setUpButtons()
        observe()
        handleIntent(intent, initial = savedInstanceState == null)

        if (viewModel.probe.value == null) viewModel.probeBridge()
        if (viewModel.simulator.value == null) viewModel.probeSimulator()
        AppLogger.i(TAG, "Card Lab opened")
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent, initial = true)
    }

    override fun onResume() {
        super.onResume()
        viewModel.setSession(sessionAccountId())
        viewModel.setReader(readerState())
        // The callback runs on the NFC binder thread with the read-only session open.
        cardReader.enableReaderMode(onTap = { session -> CardInspector.inspect(session) }, onResult = viewModel::onTapResult)
        // The session may have changed while the Lab was in the background: re-apply the PII gate.
        renderInspector(viewModel.read.value)
        renderReader()
        renderDevice()
        if (binding.tabs.selectedTabPosition == TAB_INDEX_TRACE) renderTrace()
    }

    override fun onPause() {
        super.onPause()
        cardReader.disableReaderMode()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(STATE_TAB, binding.tabs.selectedTabPosition)
    }

    /**
     * The Lab's session factory (binder thread): always read-only and traced,
     * so a mutating command is refused before it reaches the card. [aid]
     * defaults to this build's applet AID (null = the card's default selection).
     */
    @VisibleForTesting
    internal fun openLabSession(tag: Tag, aid: String? = aidHex): ImpalaCardSession {
        viewModel.beginRead()
        return ImpalaCardSession.open(tag, aidHex = aid, trace = viewModel.traceHook, readOnly = true)
    }

    /** The signed-in account, or null (pre-login, or an application without a session store). */
    private fun sessionAccountId(): String? = (application as? ImpalaApp)?.tokenManager?.getAccountId()

    private fun nfcHardwareState(): ReaderState {
        val adapter = nfcAdapter ?: return ReaderState.NFC_ABSENT
        return if (adapter.isEnabled) ReaderState.NFC_ENABLED else ReaderState.NFC_DISABLED
    }

    /** What the Doctor's Reader check sees: the simulated card stands in on a device without NFC. */
    private fun readerState(): ReaderState {
        val hw = nfcHardwareState()
        return if (hw == ReaderState.NFC_ABSENT && DebugCards.isConfigured()) ReaderState.SIMULATED else hw
    }

    private fun handleIntent(intent: Intent?, initial: Boolean) {
        val cardId = intent?.getStringExtra(LabIntents.EXTRA_CARD_ID)?.takeIf { it.isNotBlank() }
        viewModel.setExpectedCard(cardId)
        if (initial) {
            val tab = intent?.getStringExtra(LabIntents.EXTRA_TAB)
            val index = LabIntents.TABS.indexOf(tab).takeIf { it >= 0 } ?: 0
            binding.tabs.getTabAt(index)?.select()
            showPane(index)
        }
        renderReader()
    }

    // ---- setup ----

    private fun setUpLists() {
        inspectorAdapter = KeyValueAdapter(::copyIdentifier)
        deviceAdapter = KeyValueAdapter(::copyIdentifier)
        doctorAdapter = DoctorAdapter { action ->
            when (action) {
                CheckAction.OPEN_NFC_SETTINGS -> openNfcSettings()
            }
        }
        traceAdapter = TraceAdapter()
        for ((list, adapter) in listOf(
            binding.rvInspector to inspectorAdapter,
            binding.rvDoctor to doctorAdapter,
            binding.rvTrace to traceAdapter,
            binding.rvDevice to deviceAdapter
        )) {
            list.layoutManager = LinearLayoutManager(this)
            list.adapter = adapter
            list.padForSystemBars(bottom = true)
        }
    }

    private fun setUpTabs(restored: Int) {
        binding.tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) = showPane(tab.position)
            override fun onTabUnselected(tab: TabLayout.Tab) = Unit
            override fun onTabReselected(tab: TabLayout.Tab) {
                if (tab.position == TAB_INDEX_TRACE) renderTrace()
            }
        })
        if (restored in 0 until binding.tabs.tabCount) {
            binding.tabs.getTabAt(restored)?.select()
            showPane(restored)
        }
    }

    private fun showPane(index: Int) {
        binding.paneInspector.visibility = if (index == 0) View.VISIBLE else View.GONE
        binding.paneDoctor.visibility = if (index == 1) View.VISIBLE else View.GONE
        binding.rvTrace.visibility = if (index == TAB_INDEX_TRACE) View.VISIBLE else View.GONE
        binding.paneDevice.visibility = if (index == 3) View.VISIBLE else View.GONE
        if (index == TAB_INDEX_TRACE) renderTrace()
    }

    private fun setUpButtons() {
        binding.btnReadSimulated.visibility = if (DebugCards.isConfigured()) View.VISIBLE else View.GONE
        binding.btnReadSimulated.setOnClickListener { viewModel.readSimulated() }
        binding.btnOpenNfcSettings.setOnClickListener { openNfcSettings() }
        // The Doctor tab's own read action (it is where Cards → Inspect in Card Lab lands).
        binding.btnDoctorRead.setOnClickListener { viewModel.readSimulated() }
        binding.btnDoctorNfcSettings.setOnClickListener { openNfcSettings() }
        binding.btnProbeBridge.setOnClickListener {
            if (!viewModel.probeBridge()) {
                val seconds = (viewModel.probeCooldownMs() + 999) / 1000
                if (seconds > 0) snackbar(getString(R.string.lab_probe_cooldown, seconds.toInt()))
            }
        }
        binding.btnProbeSimulator.visibility = if (DebugCards.isConfigured()) View.VISIBLE else View.GONE
        binding.btnProbeSimulator.setOnClickListener { viewModel.probeSimulator() }
    }

    private fun observe() {
        viewModel.phase.observe(this) { renderReader() }
        viewModel.read.observe(this) { read ->
            renderInspector(read)
            renderReader()
            if (binding.tabs.selectedTabPosition == TAB_INDEX_TRACE) renderTrace()
        }
        viewModel.checks.observe(this) { checks ->
            doctorAdapter.submitList(checks)
            renderDoctorSummary()
        }
        viewModel.probe.observe(this) { renderDevice() }
        viewModel.probing.observe(this) { busy ->
            binding.probeProgress.visibility = if (busy) View.VISIBLE else View.GONE
            binding.btnProbeBridge.isEnabled = !busy
        }
        viewModel.simulator.observe(this) { renderDevice() }
    }

    // ---- rendering ----

    /** True only while a session exists and its account is the card's account. */
    @VisibleForTesting
    internal fun revealsPersonalData(read: LabRead?): Boolean {
        val session = viewModel.sessionAccountId ?: return false
        val cardAccount = read?.inspection?.accountUuid ?: return false
        return UuidBytes.same(session, cardAccount)
    }

    private fun renderInspector(read: LabRead?) {
        val inspection = read?.inspection
        val rows: List<LabRow> = if (inspection == null) emptyList()
        else LabReport.screen(resources, inspection, revealsPersonalData(read), DebugCards.endpointText().takeIf { read.simulated })
        inspectorAdapter.submitList(rows)
    }

    private fun renderReader() {
        if (!::binding.isInitialized) return
        val phase = viewModel.phase.value ?: LabViewModel.Phase.IDLE
        val read = viewModel.read.value
        val state = nfcHardwareState()
        val simulated = DebugCards.isConfigured()
        val expected = viewModel.expectedCardId
        val (title, detail) = when (phase) {
            LabViewModel.Phase.READING -> getString(R.string.lab_reader_reading) to getString(R.string.lab_reader_hold_still)
            LabViewModel.Phase.DONE -> getString(R.string.lab_reader_done, time(read?.atEpochMs)) to getString(R.string.lab_reader_again)
            LabViewModel.Phase.FAILED -> getString(R.string.lab_reader_failed) to failureText(read)
            LabViewModel.Phase.IDLE -> when (state) {
                ReaderState.NFC_ENABLED -> getString(R.string.lab_reader_waiting) to
                    (expected?.let { getString(R.string.lab_reader_expected, it) } ?: getString(R.string.lab_reader_read_only))
                ReaderState.NFC_DISABLED -> getString(R.string.lab_reader_nfc_off) to getString(R.string.lab_reader_nfc_off_detail)
                else -> if (simulated) getString(R.string.lab_reader_simulated) to getString(R.string.lab_reader_read_only)
                else getString(R.string.lab_reader_no_nfc) to getString(R.string.lab_reader_no_nfc_detail)
            }
        }
        binding.tvReaderTitle.text = title
        binding.tvReaderDetail.text = detail
        val waiting = phase == LabViewModel.Phase.READING || (phase == LabViewModel.Phase.IDLE && state == ReaderState.NFC_ENABLED)
        // Animations off (the verification emulator, accessibility settings): show the static glyph instead.
        val animate = waiting && animationsEnabled()
        binding.readerProgress.visibility = if (animate) View.VISIBLE else View.GONE
        binding.readerIcon.visibility = if (animate) View.GONE else View.VISIBLE
        binding.readerIcon.setImageResource(
            when (phase) {
                LabViewModel.Phase.DONE -> R.drawable.ic_check_circle
                LabViewModel.Phase.FAILED -> R.drawable.ic_error
                else -> R.drawable.ic_contactless
            }
        )
        binding.btnOpenNfcSettings.visibility = if (state == ReaderState.NFC_DISABLED) View.VISIBLE else View.GONE
        binding.btnReadSimulated.isEnabled = phase != LabViewModel.Phase.READING
        binding.btnDoctorRead.visibility = if (simulated) View.VISIBLE else View.GONE
        binding.btnDoctorRead.isEnabled = phase != LabViewModel.Phase.READING
        binding.btnDoctorNfcSettings.visibility = if (state == ReaderState.NFC_DISABLED) View.VISIBLE else View.GONE
        binding.doctorActions.visibility =
            if (simulated || state == ReaderState.NFC_DISABLED) View.VISIBLE else View.GONE
        renderDoctorSummary()
    }

    private fun failureText(read: LabRead?): String {
        if (read == null) return ""
        read.failureText?.let { return it }
        return read.error?.let { LabReport.errorText(resources, it) } ?: getString(R.string.lab_failed)
    }

    private fun renderDoctorSummary() {
        if (!::binding.isInitialized) return
        val read = viewModel.read.value
        binding.tvDoctorSummary.text = if (read == null) doctorIntro()
        else LabReport.doctorSummary(resources, viewModel.checks.value.orEmpty())
    }

    /** Before any read: how to run the checks on this device (hold the card, or read the simulated one). */
    private fun doctorIntro(): String {
        val expected = viewModel.expectedCardId
        return when {
            DebugCards.isConfigured() -> getString(R.string.lab_doctor_intro_simulated)
            nfcHardwareState() == ReaderState.NFC_ENABLED ->
                expected?.let { getString(R.string.lab_doctor_intro_expected, it) } ?: getString(R.string.lab_doctor_intro_nfc)
            else -> getString(R.string.lab_doctor_intro)
        }
    }

    private fun renderTrace() {
        val items = ArrayList<TraceItem>()
        val read = viewModel.read.value
        items += TraceItem.Section(
            getString(R.string.lab_trace_lab_reads),
            if (read == null) getString(R.string.lab_trace_none)
            else getString(R.string.lab_trace_read_subtitle, time(read.atEpochMs), read.exchanges.size),
            "lab"
        )
        if (read != null && read.exchanges.isNotEmpty()) {
            items += TraceItem.Stats(ApduStats.of(read.exchanges), "lab-stats-${read.atEpochMs}")
            read.exchanges.forEach { items += TraceItem.Exchange(it, "lab-${read.atEpochMs}-${it.sequence}") }
        }
        if (BuildConfig.DEBUG) {
            val taps = ApduTraceLog.taps()
            items += TraceItem.Section(
                getString(R.string.lab_trace_production),
                if (taps.isEmpty()) getString(R.string.lab_trace_production_none) else getString(R.string.lab_trace_production_note),
                "prod"
            )
            for (tap in taps.asReversed()) {
                val key = "tap-${tap.startedAtMs}-${tap.source}"
                items += TraceItem.Section(
                    getString(R.string.lab_trace_tap_title, tap.source, time(tap.startedAtMs)),
                    getString(R.string.lab_trace_tap_subtitle, tap.outcome, tap.exchanges.size),
                    key
                )
                tap.exchanges.forEach { items += TraceItem.Exchange(it, "$key-${it.sequence}") }
            }
        }
        traceAdapter.submitList(items)
    }

    private fun renderDevice() {
        if (!::binding.isInitialized) return
        val probe = viewModel.probe.value
        val build = BuildInfo.rows(this, nfcHardwareState())
        deviceAdapter.submitList(LabReport.device(resources, build, probe, DebugCards.endpointText(), viewModel.simulator.value))
        val mismatch = probe?.networkMismatch == true
        binding.bannerNetwork.visibility = if (mismatch) View.VISIBLE else View.GONE
        if (mismatch) {
            binding.tvNetworkMismatch.text = getString(R.string.lab_network_mismatch_body, probe.expectedNetwork, probe.stellarNetwork)
        }
    }

    // ---- actions ----

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(Menu.NONE, MENU_SHARE, Menu.NONE, R.string.lab_share_report)
            .setIcon(R.drawable.ic_share)
            .setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        MENU_SHARE -> {
            shareReport()
            true
        }
        else -> super.onOptionsItemSelected(item)
    }

    private fun shareReport() {
        val read = viewModel.read.value
        val text = LabReport.export(
            resources,
            BuildInfo.rows(this, nfcHardwareState()),
            viewModel.probe.value,
            read?.inspection,
            viewModel.checks.value.orEmpty(),
            read?.exchanges.orEmpty()
        )
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, getString(R.string.lab_report_subject, BuildConfig.VERSION_NAME))
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(send, getString(R.string.lab_share_report)))
    }

    /** Identifiers only (ids, fingerprints, AIDs): rows with personal values have no copy action. */
    private fun copyIdentifier(label: String, value: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
        snackbar(getString(R.string.lab_copied, label))
    }

    private fun openNfcSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
            } catch (_: Exception) {
                snackbar(getString(R.string.nfc_disabled))
            }
        }
    }

    private fun snackbar(text: CharSequence) = Snackbar.make(binding.root, text, Snackbar.LENGTH_SHORT).show()

    private fun time(epochMs: Long?): String =
        if (epochMs == null) "" else DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(epochMs))

    private fun animationsEnabled(): Boolean = try {
        Settings.Global.getFloat(contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) != 0f
    } catch (_: Exception) {
        true
    }

    companion object {
        private const val TAG = "CardLab"
        private const val STATE_TAB = "lab.tab"
        private const val MENU_SHARE = 1
        private const val TAB_INDEX_TRACE = 2
    }
}

package com.payala.impala.demo.ui.nfc

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.Hex
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ActivityNfcDebugBinding
import com.payala.impala.demo.log.AppLogger
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Developer tool for debugging NFC events and testing device capabilities.
 *
 * Provides:
 * - Device NFC hardware capabilities report (adapter state, supported
 *   technologies, host-card-emulation support, reader mode support)
 * - Live NFC tap test in reader mode that displays raw tag information (UID,
 *   tech list, ATQA/SAK for NfcA, NDEF records) and, for Impala cards, an
 *   [ImpalaCardSession] read-out: applet version, identity, personalization
 *   state and flags, receive state, balance and whether a signed transfer is
 *   recorded. Only non-mutating commands are sent.
 * - An event log of what this screen saw
 * - Instructions for enabling Android developer options and NFC debugging
 *
 * Accessible from the overflow menu (Build Info > NFC Debug) or directly
 * from the main options menu.
 */
class NfcDebugActivity : AppCompatActivity() {

    private lateinit var binding: ActivityNfcDebugBinding
    private var nfcAdapter: NfcAdapter? = null
    private var testModeActive = false

    private val eventLog = CopyOnWriteArrayList<String>()
    private val timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityNfcDebugBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        binding.toolbar.setNavigationOnClickListener { finish() }

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        AppLogger.i(TAG, "NFC Debug opened")

        refreshCapabilities()

        binding.btnRefreshCapabilities.setOnClickListener { refreshCapabilities() }

        binding.btnTestTap.setOnClickListener {
            if (testModeActive) {
                stopTestMode()
            } else {
                startTestMode()
            }
        }

        binding.btnClearEvents.setOnClickListener {
            eventLog.clear()
            refreshEventLog()
        }

        binding.btnCopyEvents.setOnClickListener {
            copyEventsToClipboard()
        }

        binding.btnOpenNfcSettings.setOnClickListener {
            try {
                startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
            } catch (_: Exception) {
                startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
            }
        }

        binding.btnOpenDevSettings.setOnClickListener {
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            } catch (_: Exception) {
                Snackbar.make(
                    binding.root,
                    R.string.nfc_debug_dev_settings_unavailable,
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (testModeActive) {
            enableReaderMode()
        }
    }

    override fun onPause() {
        super.onPause()
        disableReaderMode()
    }

    override fun onDestroy() {
        super.onDestroy()
        AppLogger.i(TAG, "NFC Debug closed")
    }

    // ---- Capabilities ----

    private fun refreshCapabilities() {
        val adapter = nfcAdapter
        val info = buildString {
            appendLine("NFC Hardware")
            appendLine("  Adapter present:  ${adapter != null}")
            appendLine("  NFC enabled:      ${adapter?.isEnabled == true}")
            appendLine()

            if (adapter != null) {
                appendLine("Device Info")
                appendLine("  Manufacturer:  ${Build.MANUFACTURER}")
                appendLine("  Model:         ${Build.MODEL}")
                appendLine("  Android:       ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                appendLine()

                appendLine("NFC Features")
                val pm = packageManager
                appendLine("  NFC:           ${pm.hasSystemFeature("android.hardware.nfc")}")
                appendLine("  HCE:           ${pm.hasSystemFeature("android.hardware.nfc.hce")}")
                appendLine("  HCE-F:         ${pm.hasSystemFeature("android.hardware.nfc.hcef")}")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    appendLine("  Secure NFC:    ${adapter.isSecureNfcSupported}")
                    appendLine("  Secure NFC on: ${adapter.isSecureNfcEnabled}")
                }
                appendLine()

                appendLine("Supported Technologies")
                appendLine("  ISO-DEP (ISO 14443-4)")
                appendLine("  NfcA (ISO 14443-3A)")
                appendLine("  NfcB (ISO 14443-3B)")
                appendLine("  NfcF (JIS 6319-4 / FeliCa)")
                appendLine("  NfcV (ISO 15693)")
                appendLine("  Ndef / NdefFormatable")
                appendLine("  MifareClassic / MifareUltralight")
                appendLine()

                appendLine("Impala Card Session (impala-lib)")
                appendLine("  Transport:       reader mode -> ImpalaCardSession")
                appendLine("  Applet AID:      ${BuildConfig.CARD_APPLET_AID.ifEmpty { "(default selection)" }}")
                appendLine("  Reads:           GET_VERSION, GET_PERSONALIZATION, GET_USER_DATA,")
                appendLine("                   GET_EC_PUB_KEY, GET_RECEIVE_STATE, GET_BALANCE,")
                appendLine("                   GET_LAST_TRANSFER (no state-changing command)")
            } else {
                appendLine("NFC hardware is not available on this device.")
                appendLine()
                appendLine("To test NFC features, use a device with NFC support.")
            }
        }
        binding.tvNfcCapabilities.text = info
    }

    // ---- Test Mode ----

    private fun startTestMode() {
        val adapter = nfcAdapter
        if (adapter == null) {
            Snackbar.make(binding.root, R.string.nfc_not_available, Snackbar.LENGTH_SHORT).show()
            return
        }
        if (!adapter.isEnabled) {
            Snackbar.make(binding.root, R.string.nfc_disabled, Snackbar.LENGTH_SHORT).show()
            return
        }

        testModeActive = true
        binding.btnTestTap.text = getString(R.string.nfc_debug_stop_test)
        binding.tvTestResult.visibility = View.VISIBLE
        binding.tvTestResult.text = getString(R.string.nfc_debug_waiting_for_tag)
        enableReaderMode()

        addEvent("TEST", "Test mode activated — waiting for tag")
        AppLogger.d(TAG, "NFC test mode started")
    }

    private fun stopTestMode() {
        testModeActive = false
        binding.btnTestTap.text = getString(R.string.nfc_debug_start_test)
        disableReaderMode()

        addEvent("TEST", "Test mode deactivated")
        AppLogger.d(TAG, "NFC test mode stopped")
    }

    /** Reader mode for every tag family; the callback runs on the NFC binder thread. */
    private fun enableReaderMode() {
        val adapter = nfcAdapter ?: return
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_NFC_F or NfcAdapter.FLAG_READER_NFC_V
        val extras = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250) }
        adapter.enableReaderMode(this, { tag -> onDebugTag(tag) }, flags, extras)
    }

    private fun disableReaderMode() {
        nfcAdapter?.disableReaderMode(this)
    }

    /** Binder thread: describe the tag, try an Impala session, then render on the main thread. */
    private fun onDebugTag(tag: Tag) {
        val tagId = tag.id
        val techList = tag.techList
        val result = buildString {
            appendLine("Tag Discovered")
            appendLine("  UID:  ${tagId?.toHexString() ?: "N/A"}")
            appendLine("  Tech: ${techList.joinToString(", ") { it.substringAfterLast('.') }}")
            appendLine()

            NfcA.get(tag)?.let { nfcA ->
                appendLine("NfcA (ISO 14443-3A)")
                appendLine("  ATQA: ${nfcA.atqa?.toHexString() ?: "N/A"}")
                appendLine("  SAK:  0x${Integer.toHexString(nfcA.sak.toInt() and 0xFF)}")
                appendLine("  Max transceive: ${nfcA.maxTransceiveLength}B")
                appendLine()
            }
            NfcB.get(tag)?.let { nfcB ->
                appendLine("NfcB (ISO 14443-3B)")
                appendLine("  App data: ${nfcB.applicationData?.toHexString() ?: "N/A"}")
                appendLine("  Protocol: ${nfcB.protocolInfo?.toHexString() ?: "N/A"}")
                appendLine()
            }

            appendLine("Impala Card")
            try {
                ImpalaCardSession.open(tag, aidHex = BuildConfig.CARD_APPLET_AID.ifEmpty { null }).use { session ->
                    val identity = session.identity
                    appendIdentity(identity)
                    val receive = session.sdk.getReceiveState()
                    appendLine("  Receive ctr:  ${receive.counter}")
                    appendLine("  Balance:      ${session.sdk.getBalance()} (card minor units)")
                    appendLine("  Last signed:  ${if (session.sdk.getLastTransfer() != null) "present" else "none"}")
                    appendLine("  Status:       OK")
                    runOnUiThread { addEvent("CARD", "Read OK: card ${identity.wireCardId}") }
                }
            } catch (e: Exception) {
                val err = CardError.from(e)
                appendLine("  Not read: $err")
                runOnUiThread { addEvent("CARD", "Not read: $err") }
            }
            appendLine()

            Ndef.get(tag)?.let { ndef ->
                appendLine("NDEF")
                appendLine("  Type:     ${ndef.type}")
                appendLine("  Max size: ${ndef.maxSize}B")
                appendLine("  Writable: ${ndef.isWritable}")
                ndef.cachedNdefMessage?.let { msg ->
                    appendLine("  Records:  ${msg.records.size}")
                    for ((j, record) in msg.records.withIndex()) {
                        val type = String(record.type, Charsets.US_ASCII)
                        appendLine("    [$j] TNF=${record.tnf} type=$type payload=${record.payload?.size ?: 0}B")
                    }
                }
                appendLine()
            }
            MifareClassic.get(tag)?.let { mifare ->
                appendLine("MIFARE Classic")
                appendLine("  Type:    ${mifare.type}")
                appendLine("  Size:    ${mifare.size}B")
                appendLine("  Sectors: ${mifare.sectorCount}")
                appendLine()
            }
            MifareUltralight.get(tag)?.let { ul ->
                appendLine("MIFARE Ultralight")
                appendLine("  Type: ${ul.type}")
                appendLine()
            }
        }
        runOnUiThread {
            addEvent("TAG", "UID=${tagId?.toHexString() ?: "?"} tech=${techList.joinToString(",") { it.substringAfterLast('.') }}")
            binding.tvTestResult.visibility = View.VISIBLE
            binding.tvTestResult.text = result
        }
    }

    private fun StringBuilder.appendIdentity(identity: CardIdentity) {
        appendLine("  Applet:       ${identity.versionString}")
        appendLine("  Account ID:   ${identity.accountUuid}")
        appendLine("  Card ID:      ${identity.wireCardId}")
        if (identity.fullName.isNotBlank()) appendLine("  Name:         ${identity.fullName}")
        appendLine("  EC pubkey:    ${identity.pubKeyHex.take(20)}...")
        appendLine("  State:        0x${"%02X".format(identity.state)} (${stateName(identity.state)})")
        val p = identity.personalization
        appendLine(
            "  Flags:        0x${"%02X".format(identity.flags)} " +
                listOfNotNull(
                    "INITIALIZED".takeIf { p.initialized }, "PROGRAM_BOUND".takeIf { p.programBound },
                    "PERSONALIZED".takeIf { p.personalized }, "SCP03_KEYS_DEFAULT".takeIf { p.scp03KeysDefault },
                    "PIN_PROVISIONED".takeIf { p.pinProvisioned }, "ENFORCED".takeIf { p.provisioningEnforced },
                    "TERMINATED".takeIf { p.terminated }
                ).joinToString("|")
        )
        appendLine("  Program ID:   ${identity.programIdHex}")
        appendLine("  Currency:     ${identity.currency.decodeToString().trimEnd('\u0000')}")
        appendLine("  Certificate:  ${identity.certificate?.let { "${it.size}B ${Hex.encode(it).take(16)}..." } ?: "none"}")
    }

    private fun stateName(state: Int): String = when (state) {
        CardIdentity.STATE_BLANK -> "blank"
        CardIdentity.STATE_INITIALIZED -> "initialized"
        CardIdentity.STATE_PERSONALIZED -> "personalized"
        CardIdentity.STATE_TERMINATED -> "terminated"
        else -> "unknown"
    }

    // ---- Event Log ----

    private fun addEvent(category: String, message: String) {
        val timestamp = LocalDateTime.now().format(timeFormatter)
        val entry = "[$timestamp] $category: $message"
        eventLog.add(entry)
        refreshEventLog()
    }

    private fun refreshEventLog() {
        if (eventLog.isEmpty()) {
            binding.tvEventLog.text = getString(R.string.nfc_debug_no_events)
            binding.tvEventCount.text = ""
        } else {
            binding.tvEventLog.text = eventLog.joinToString("\n")
            binding.tvEventCount.text = getString(R.string.nfc_debug_event_count, eventLog.size)
        }
    }

    private fun copyEventsToClipboard() {
        if (eventLog.isEmpty()) {
            Snackbar.make(binding.root, R.string.nfc_debug_no_events, Snackbar.LENGTH_SHORT).show()
            return
        }
        val export = buildString {
            appendLine("=== Impala NFC Debug Event Log ===")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
            appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            appendLine("NFC Adapter: ${if (nfcAdapter != null) "present" else "absent"}")
            appendLine("NFC Enabled: ${nfcAdapter?.isEnabled == true}")
            appendLine("Events: ${eventLog.size}")
            appendLine("==================================")
            appendLine()
            for (entry in eventLog) {
                appendLine(entry)
            }
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("NFC Debug Log", export))
        Snackbar.make(binding.root, R.string.nfc_debug_events_copied, Snackbar.LENGTH_SHORT).show()
    }

    // ---- Helpers ----

    private fun ByteArray.toHexString(): String =
        joinToString("") { String.format("%02X", it.toInt() and 0xFF) }

    companion object {
        private const val TAG = "NfcDebug"
    }
}

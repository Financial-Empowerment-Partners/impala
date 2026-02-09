package com.payala.impala.demo.ui.nfc

import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NdefMessage
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import android.nfc.tech.NfcF
import android.nfc.tech.NfcV
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ActivityNfcDebugBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.nfc.APDUBIBO
import com.payala.impala.demo.nfc.BIBOException
import com.payala.impala.demo.nfc.CardUser
import com.payala.impala.demo.nfc.CommandAPDU
import com.payala.impala.demo.nfc.ImpalaCardReader
import com.payala.impala.demo.nfc.IsoDepBibo
import com.payala.impala.demo.nfc.NfcEventHandler
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Developer tool for debugging NFC events and testing device capabilities.
 *
 * Provides:
 * - Device NFC hardware capabilities report (adapter state, supported
 *   technologies, host-card-emulation support, reader mode support)
 * - Live NFC tap test that activates foreground dispatch and displays raw
 *   tag information including UID, tech list, ATQA/SAK for NfcA, and
 *   APDU card reader results for IsoDep tags
 * - Real-time event log capturing all NFC events dispatched through
 *   [NfcEventHandler] while the debug screen is active
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

    // Save previous listeners so we can restore them on exit
    private var previousApduListener: NfcEventHandler.ApduEventListener? = null
    private var previousNdefListener: NfcEventHandler.NdefEventListener? = null

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
        registerEventListeners()

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
            enableForegroundDispatch()
        }
    }

    override fun onPause() {
        super.onPause()
        disableForegroundDispatch()
    }

    override fun onDestroy() {
        super.onDestroy()
        // No listener restore needed — ImpalaApp will re-register its own
        // listeners on next NFC event, and the singleton pattern replaces anyway
        AppLogger.i(TAG, "NFC Debug closed")
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (testModeActive) {
            processDebugTag(intent)
        }
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
                appendLine("  IsoDep (ISO 14443-4)")
                appendLine("  NfcA (ISO 14443-3A)")
                appendLine("  NfcB (ISO 14443-3B)")
                appendLine("  NfcF (JIS 6319-4 / FeliCa)")
                appendLine("  NfcV (ISO 15693)")
                appendLine("  Ndef / NdefFormatable")
                appendLine("  MifareClassic / MifareUltralight")
                appendLine()

                appendLine("Impala Card Reader")
                appendLine("  APDU protocol:   ISO 7816-4")
                appendLine("  Transport:       IsoDep -> IsoDepBibo -> APDUBIBO")
                appendLine("  INS commands:")
                appendLine("    GET_USER_DATA      0x${hex(ImpalaCardReader.INS_GET_USER_DATA)}")
                appendLine("    GET_EC_PUB_KEY     0x${hex(ImpalaCardReader.INS_GET_EC_PUB_KEY)}")
                appendLine("    GET_RSA_PUB_KEY    0x${hex(ImpalaCardReader.INS_GET_RSA_PUB_KEY)}")
                appendLine("    SIGN_AUTH          0x${hex(ImpalaCardReader.INS_SIGN_AUTH)}")
                appendLine("    VERIFY_PIN         0x${hex(ImpalaCardReader.INS_VERIFY_PIN)}")
                appendLine("    GET_CARD_NONCE     0x${hex(ImpalaCardReader.INS_GET_CARD_NONCE)}")
                appendLine("    GET_VERSION        0x${hex(ImpalaCardReader.INS_GET_VERSION)}")
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
        enableForegroundDispatch()

        addEvent("TEST", "Test mode activated — waiting for tag")
        AppLogger.d(TAG, "NFC test mode started")
    }

    private fun stopTestMode() {
        testModeActive = false
        binding.btnTestTap.text = getString(R.string.nfc_debug_start_test)
        disableForegroundDispatch()

        addEvent("TEST", "Test mode deactivated")
        AppLogger.d(TAG, "NFC test mode stopped")
    }

    private fun enableForegroundDispatch() {
        val adapter = nfcAdapter ?: return
        val intent = Intent(this, javaClass).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        // Catch all tag types for debugging
        val filters = arrayOf(
            IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED),
            IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED),
            IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED)
        )
        val techList = arrayOf(
            arrayOf(IsoDep::class.java.name),
            arrayOf(NfcA::class.java.name),
            arrayOf(NfcB::class.java.name),
            arrayOf(NfcF::class.java.name),
            arrayOf(NfcV::class.java.name),
            arrayOf(Ndef::class.java.name),
            arrayOf(NdefFormatable::class.java.name)
        )
        adapter.enableForegroundDispatch(this, pendingIntent, filters, techList)
    }

    private fun disableForegroundDispatch() {
        nfcAdapter?.disableForegroundDispatch(this)
    }

    @Suppress("DEPRECATION")
    private fun processDebugTag(intent: Intent) {
        val action = intent.action ?: return
        addEvent("INTENT", "Action: $action")

        val tag: Tag? = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        if (tag == null) {
            // Could be NDEF-only
            val rawMessages = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)
            if (rawMessages != null && rawMessages.isNotEmpty()) {
                processDebugNdef(rawMessages)
            } else {
                addEvent("WARN", "No tag or NDEF data in intent")
                binding.tvTestResult.text = getString(R.string.nfc_debug_no_tag_data)
            }
            return
        }

        val tagId = tag.id
        val techList = tag.techList

        val result = buildString {
            appendLine("Tag Discovered")
            appendLine("  UID:  ${tagId?.toHexString() ?: "N/A"}")
            appendLine("  Tech: ${techList.joinToString(", ") { it.substringAfterLast('.') }}")
            appendLine()

            // NfcA details (ATQA + SAK)
            val nfcA = NfcA.get(tag)
            if (nfcA != null) {
                appendLine("NfcA (ISO 14443-3A)")
                appendLine("  ATQA: ${nfcA.atqa?.toHexString() ?: "N/A"}")
                appendLine("  SAK:  0x${Integer.toHexString(nfcA.sak.toInt() and 0xFF)}")
                appendLine("  Max transceive: ${nfcA.maxTransceiveLength}B")
                appendLine()
            }

            // NfcB details
            val nfcB = NfcB.get(tag)
            if (nfcB != null) {
                appendLine("NfcB (ISO 14443-3B)")
                appendLine("  App data: ${nfcB.applicationData?.toHexString() ?: "N/A"}")
                appendLine("  Protocol: ${nfcB.protocolInfo?.toHexString() ?: "N/A"}")
                appendLine("  Max transceive: ${nfcB.maxTransceiveLength}B")
                appendLine()
            }

            // IsoDep details
            val isoDep = IsoDep.get(tag)
            if (isoDep != null) {
                appendLine("IsoDep (ISO 14443-4)")
                appendLine("  Hist bytes: ${isoDep.historicalBytes?.toHexString() ?: "N/A"}")
                appendLine("  Hi-layer:   ${isoDep.hiLayerResponse?.toHexString() ?: "N/A"}")
                appendLine("  Max transceive: ${isoDep.maxTransceiveLength}B")
                appendLine("  Extended APDU:  ${isoDep.isExtendedLengthApduSupported}")
                appendLine()

                // Try Impala card read
                appendLine("Impala Card Read...")
                try {
                    isoDep.connect()
                    isoDep.timeout = 5000
                    val bibo = IsoDepBibo(isoDep)
                    val reader = ImpalaCardReader(bibo)

                    val user = reader.getUserData()
                    appendLine("  Account ID:  ${user.accountId}")
                    appendLine("  Card ID:     ${user.cardId}")
                    appendLine("  Name:        ${user.fullName}")

                    val ecPubKey = reader.getECPubKey()
                    appendLine("  EC PubKey:   ${ecPubKey.size}B ${ecPubKey.take(8).toByteArray().toHexString()}...")

                    try {
                        val nonce = reader.getNonce()
                        appendLine("  Card Nonce:  $nonce (0x${Integer.toHexString(nonce)})")
                    } catch (_: Exception) {
                        appendLine("  Card Nonce:  N/A")
                    }

                    appendLine("  Status:      OK")

                    addEvent("CARD", "Read OK: ${user.accountId} / ${user.cardId}")
                    NfcEventHandler.dispatchCardRead(user, ecPubKey, tagId)
                } catch (e: BIBOException) {
                    appendLine("  Error: ${e.message}")
                    addEvent("CARD", "BIBO Error: ${e.message}")
                    NfcEventHandler.dispatchCardError(e.message ?: "BIBO error")
                } catch (e: Exception) {
                    appendLine("  Error: ${e.message}")
                    addEvent("CARD", "Error: ${e.message}")
                    NfcEventHandler.dispatchCardError(e.message ?: "Card read failed")
                } finally {
                    try { isoDep.close() } catch (_: Exception) { }
                }
            }

            // NDEF details
            val ndef = Ndef.get(tag)
            if (ndef != null) {
                appendLine("NDEF")
                appendLine("  Type:     ${ndef.type}")
                appendLine("  Max size: ${ndef.maxSize}B")
                appendLine("  Writable: ${ndef.isWritable}")
                val msg = ndef.cachedNdefMessage
                if (msg != null) {
                    appendLine("  Records:  ${msg.records.size}")
                    for ((j, record) in msg.records.withIndex()) {
                        val tnf = record.tnf
                        val type = String(record.type, Charsets.US_ASCII)
                        val payloadSize = record.payload?.size ?: 0
                        appendLine("    [$j] TNF=$tnf type=$type payload=${payloadSize}B")
                    }
                }
                appendLine()
            }

            // MifareClassic
            val mifare = MifareClassic.get(tag)
            if (mifare != null) {
                appendLine("MIFARE Classic")
                appendLine("  Type:    ${mifare.type}")
                appendLine("  Size:    ${mifare.size}B")
                appendLine("  Sectors: ${mifare.sectorCount}")
                appendLine("  Blocks:  ${mifare.blockCount}")
                appendLine()
            }

            // MifareUltralight
            val mifareUl = MifareUltralight.get(tag)
            if (mifareUl != null) {
                appendLine("MIFARE Ultralight")
                appendLine("  Type: ${mifareUl.type}")
                appendLine("  Max transceive: ${mifareUl.maxTransceiveLength}B")
                appendLine()
            }
        }

        addEvent("TAG", "UID=${tagId?.toHexString() ?: "?"} tech=${techList.joinToString(",") { it.substringAfterLast('.') }}")
        binding.tvTestResult.visibility = View.VISIBLE
        binding.tvTestResult.text = result
        AppLogger.d(TAG, "Debug tag processed: UID=${tagId?.toHexString()}")
    }

    @Suppress("DEPRECATION")
    private fun processDebugNdef(rawMessages: Array<android.os.Parcelable>) {
        val messages = rawMessages.map { it as NdefMessage }.toTypedArray()
        val result = buildString {
            appendLine("NDEF Messages: ${messages.size}")
            for ((i, msg) in messages.withIndex()) {
                appendLine("  Message $i: ${msg.records.size} record(s)")
                for ((j, record) in msg.records.withIndex()) {
                    val tnf = record.tnf
                    val type = String(record.type, Charsets.US_ASCII)
                    val payload = record.payload
                    val payloadHex = payload?.take(32)?.toByteArray()?.toHexString() ?: ""
                    val truncated = if ((payload?.size ?: 0) > 32) "..." else ""
                    appendLine("    [$j] TNF=$tnf type=$type size=${payload?.size ?: 0}B")
                    appendLine("         $payloadHex$truncated")
                }
            }
        }

        addEvent("NDEF", "${messages.size} message(s)")
        binding.tvTestResult.visibility = View.VISIBLE
        binding.tvTestResult.text = result
        NfcEventHandler.dispatchNdef(messages)
    }

    // ---- Event Log ----

    private fun registerEventListeners() {
        NfcEventHandler.setApduEventListener(object : NfcEventHandler.ApduEventListener {
            override fun onCardRead(user: CardUser, ecPubKey: ByteArray, tagId: ByteArray?) {
                runOnUiThread {
                    addEvent("APDU", "Card read: ${user.accountId} / ${user.cardId} (${user.fullName})")
                    addEvent("APDU", "EC pubkey: ${ecPubKey.size}B, Tag ID: ${tagId?.toHexString() ?: "N/A"}")
                }
            }

            override fun onCardError(message: String) {
                runOnUiThread {
                    addEvent("APDU", "Error: $message")
                }
            }
        })

        NfcEventHandler.setNdefEventListener(object : NfcEventHandler.NdefEventListener {
            override fun onNdefReceived(messages: Array<NdefMessage>) {
                runOnUiThread {
                    addEvent("NDEF", "Received ${messages.size} message(s)")
                    for ((i, msg) in messages.withIndex()) {
                        for ((j, record) in msg.records.withIndex()) {
                            val type = String(record.type, Charsets.US_ASCII)
                            addEvent("NDEF", "  [$i][$j] TNF=${record.tnf} type=$type ${record.payload?.size ?: 0}B")
                        }
                    }
                }
            }
        })
    }

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

    private fun hex(b: Byte): String = String.format("%02X", b.toInt() and 0xFF)

    private fun ByteArray.toHexString(): String =
        joinToString("") { String.format("%02X", it.toInt() and 0xFF) }

    companion object {
        private const val TAG = "NfcDebug"
    }
}

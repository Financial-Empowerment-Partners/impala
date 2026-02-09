package com.payala.impala.demo.nfc

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.nfc.NdefMessage
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.payala.impala.demo.R
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.ui.main.MainActivity

/**
 * Foreground service that processes NFC events in the background.
 *
 * When the app receives an NFC intent (via [NfcDispatchActivity] or forwarded
 * from an activity), it starts this service with the intent data. The service
 * processes the tag on a background [HandlerThread]:
 *
 * - **IsoDep tags**: connects via [IsoDepBibo], creates an [ImpalaCardReader],
 *   reads the card's user data and EC public key, then transmits the tag ID
 *   as a [CommandAPDU] (mirroring impala-lib's `NfcContactActivity`). Results
 *   are dispatched through [NfcEventHandler].
 *
 * - **NDEF messages**: extracts [NdefMessage] array from the intent and
 *   dispatches through [NfcEventHandler] (mirroring impala-lib's
 *   `NdefDispatchActivity` + `ImpalaNdefHandler`).
 *
 * Runs as a foreground service with a persistent notification so Android
 * does not kill the processing while a card tap is being handled.
 */
class NfcWatcherService : Service() {

    companion object {
        private const val TAG = "NfcWatcher"
        private const val CHANNEL_ID = "nfc_watcher_channel"
        private const val NOTIFICATION_ID = 1001

        const val ACTION_PROCESS_TAG = "com.payala.impala.demo.ACTION_PROCESS_TAG"
        const val ACTION_PROCESS_NDEF = "com.payala.impala.demo.ACTION_PROCESS_NDEF"

        /** Convenience to start the service with an NFC intent. */
        fun processNfcIntent(context: Context, intent: Intent) {
            val action = intent.action ?: return

            val serviceIntent = Intent(context, NfcWatcherService::class.java)

            when (action) {
                NfcAdapter.ACTION_TECH_DISCOVERED,
                NfcAdapter.ACTION_TAG_DISCOVERED -> {
                    serviceIntent.action = ACTION_PROCESS_TAG
                    // Forward the tag and ID extras
                    serviceIntent.putExtra(
                        NfcAdapter.EXTRA_TAG,
                        intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
                    )
                    serviceIntent.putExtra(
                        NfcAdapter.EXTRA_ID,
                        intent.getByteArrayExtra(NfcAdapter.EXTRA_ID)
                    )
                }
                NfcAdapter.ACTION_NDEF_DISCOVERED -> {
                    serviceIntent.action = ACTION_PROCESS_NDEF
                    @Suppress("DEPRECATION")
                    serviceIntent.putExtra(
                        NfcAdapter.EXTRA_NDEF_MESSAGES,
                        intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)
                    )
                }
                else -> return
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        }
    }

    private lateinit var handlerThread: HandlerThread
    private lateinit var backgroundHandler: Handler

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Listening for NFC events"))

        handlerThread = HandlerThread("NfcWatcherThread").also { it.start() }
        backgroundHandler = Handler(handlerThread.looper)

        AppLogger.i(TAG, "NFC watcher service started")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_PROCESS_TAG -> {
                backgroundHandler.post { handleTagIntent(intent) }
            }
            ACTION_PROCESS_NDEF -> {
                backgroundHandler.post { handleNdefIntent(intent) }
            }
        }
        // If the service is killed, don't restart with the last intent
        // (the NFC event would be stale)
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        handlerThread.quitSafely()
        AppLogger.i(TAG, "NFC watcher service stopped")
    }

    /**
     * Process an IsoDep tag on the background thread.
     *
     * Mirrors impala-lib's `NfcContactActivity.handleIntent()`:
     * 1. Extracts the tag from the intent
     * 2. Gets an IsoDep connection
     * 3. Wraps in IsoDepBibo → ImpalaCardReader
     * 4. Reads card user data + EC public key
     * 5. Transmits the tag ID as a CommandAPDU (impala-lib pattern)
     * 6. Dispatches results through NfcEventHandler
     */
    private fun handleTagIntent(intent: Intent) {
        AppLogger.d(TAG, "Processing IsoDep tag event")

        @Suppress("DEPRECATION")
        val tag: Tag? = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        if (tag == null) {
            AppLogger.w(TAG, "No tag in intent")
            NfcEventHandler.dispatchCardError("No NFC tag found")
            stopSelfIfIdle()
            return
        }

        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            AppLogger.w(TAG, "Tag does not support IsoDep")
            NfcEventHandler.dispatchCardError("Tag does not support IsoDep")
            stopSelfIfIdle()
            return
        }

        // Extract tag ID (impala-lib uses this to create a CommandAPDU)
        val tagId = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID) ?: tag.id

        try {
            isoDep.connect()
            isoDep.timeout = 5000
            AppLogger.d(TAG, "IsoDep connected (timeout: 5000ms)")

            val bibo = IsoDepBibo(isoDep)
            val reader = ImpalaCardReader(bibo)

            // Read card identity and EC public key
            val user = reader.getUserData()
            AppLogger.i(TAG, "Card read: ${user.accountId} / ${user.cardId} (${user.fullName})")

            val ecPubKey = reader.getECPubKey()
            AppLogger.d(TAG, "EC pubkey: ${ecPubKey.size} bytes")

            // Transmit the tag ID as a CommandAPDU (impala-lib NfcContactActivity pattern)
            if (tagId != null && tagId.isNotEmpty()) {
                try {
                    val cmd = CommandAPDU(tagId)
                    val channel = APDUBIBO(bibo)
                    channel.transmit(cmd)
                    AppLogger.d(TAG, "Tag ID APDU transmitted (${tagId.size} bytes)")
                } catch (e: Exception) {
                    // Non-fatal: tag ID APDU is best-effort
                    AppLogger.d(TAG, "Tag ID APDU transmission skipped: ${e.message}")
                }
            }

            // Dispatch to registered listeners
            NfcEventHandler.dispatchCardRead(user, ecPubKey, tagId)

            updateNotification("Card read: ${user.fullName}")
        } catch (e: Exception) {
            AppLogger.e(TAG, "Card processing failed: ${e.message}")
            NfcEventHandler.dispatchCardError(e.message ?: "Card read failed")
        } finally {
            try { isoDep.close() } catch (_: Exception) { }
            stopSelfIfIdle()
        }
    }

    /**
     * Process NDEF messages on the background thread.
     *
     * Mirrors impala-lib's `NdefDispatchActivity.handleIntent()` +
     * `ImpalaNdefHandler.handle_nfc_ndef()`:
     * 1. Extracts NdefMessage array from the intent
     * 2. Dispatches through NfcEventHandler to registered listeners
     */
    private fun handleNdefIntent(intent: Intent) {
        AppLogger.d(TAG, "Processing NDEF message event")

        @Suppress("DEPRECATION")
        val rawMessages = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)
        if (rawMessages == null || rawMessages.isEmpty()) {
            AppLogger.w(TAG, "No NDEF messages in intent")
            stopSelfIfIdle()
            return
        }

        val messages = rawMessages.map { it as NdefMessage }.toTypedArray()
        AppLogger.i(TAG, "NDEF messages received: ${messages.size} message(s)")

        for ((i, msg) in messages.withIndex()) {
            val records = msg.records
            AppLogger.d(TAG, "  Message $i: ${records.size} record(s)")
            for ((j, record) in records.withIndex()) {
                val tnf = record.tnf
                val type = String(record.type, Charsets.US_ASCII)
                val payloadSize = record.payload?.size ?: 0
                AppLogger.d(TAG, "    Record $j: TNF=$tnf type=$type payload=${payloadSize}B")
            }
        }

        // Dispatch to registered NDEF listener (impala-lib ImpalaNdefHandler pattern)
        NfcEventHandler.dispatchNdef(messages)

        updateNotification("NDEF: ${messages.size} message(s)")
        stopSelfIfIdle()
    }

    /** Stop the service if no more work is queued. */
    private fun stopSelfIfIdle() {
        // Post a delayed stop — if new work arrives before this runs,
        // the handler will process it first
        backgroundHandler.postDelayed({ stopSelf() }, 2000)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "NFC Watcher",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Background NFC event processing"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.nfc_watcher_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_cards)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }
}

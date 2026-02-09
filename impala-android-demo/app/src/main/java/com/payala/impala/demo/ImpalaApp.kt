package com.payala.impala.demo

import android.app.Application
import android.nfc.NdefMessage
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.nfc.CardUser
import com.payala.impala.demo.nfc.NfcEventHandler

/**
 * Application subclass that initialises app-wide singletons.
 *
 * Declared in `AndroidManifest.xml` via `android:name=".ImpalaApp"` so that
 * [tokenManager] is available as soon as any Activity starts.
 */
class ImpalaApp : Application() {

    /** Encrypted token storage shared across all activities and fragments. */
    lateinit var tokenManager: TokenManager
        private set

    override fun onCreate() {
        super.onCreate()
        tokenManager = TokenManager(this)
        AppLogger.i("App", "Impala Demo v${BuildConfig.VERSION_NAME} started")
        if (tokenManager.hasValidSession()) {
            AppLogger.i("App", "Existing session found (provider: ${tokenManager.getAuthProvider() ?: "unknown"})")
        }

        // Register default NFC event listeners for background logging
        NfcEventHandler.setApduEventListener(object : NfcEventHandler.ApduEventListener {
            override fun onCardRead(user: CardUser, ecPubKey: ByteArray, tagId: ByteArray?) {
                AppLogger.i("NfcBg", "Background card read: ${user.accountId} / ${user.cardId} (${user.fullName})")
            }

            override fun onCardError(message: String) {
                AppLogger.w("NfcBg", "Background card error: $message")
            }
        })

        NfcEventHandler.setNdefEventListener(object : NfcEventHandler.NdefEventListener {
            override fun onNdefReceived(messages: Array<NdefMessage>) {
                AppLogger.i("NfcBg", "Background NDEF received: ${messages.size} message(s)")
            }
        })
    }
}

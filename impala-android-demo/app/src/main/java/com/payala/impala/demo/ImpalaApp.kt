package com.payala.impala.demo

import android.app.Application
import android.nfc.NdefMessage
import com.google.firebase.messaging.FirebaseMessaging
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.RegisterDeviceTokenRequest
import com.payala.impala.demo.nfc.CardUser
import com.payala.impala.demo.nfc.NfcEventHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

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

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        tokenManager = TokenManager(this)
        AppLogger.i("App", "Impala Demo v${BuildConfig.VERSION_NAME} started")
        if (tokenManager.hasValidSession()) {
            AppLogger.i("App", "Existing session found (provider: ${tokenManager.getAuthProvider() ?: "unknown"})")
            registerFcmToken()
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

    /**
     * Retrieves the current FCM device token and registers it with the
     * impala-bridge backend. Called on app startup when a valid session exists.
     */
    private fun registerFcmToken() {
        FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
            AppLogger.i("App", "FCM token obtained, registering with bridge")
            appScope.launch {
                try {
                    val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, tokenManager)
                    api.registerDeviceToken(RegisterDeviceTokenRequest(token = token))
                } catch (e: Exception) {
                    AppLogger.w("App", "FCM token registration failed: ${e.message}")
                }
            }
        }.addOnFailureListener { e ->
            AppLogger.w("App", "Failed to get FCM token: ${e.message}")
        }
    }
}

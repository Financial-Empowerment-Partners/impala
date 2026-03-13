package com.payala.impala.demo.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.RegisterDeviceTokenRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Firebase Cloud Messaging service that handles incoming push notifications
 * and device token registration with the impala-bridge backend.
 */
class ImpalaPushService : FirebaseMessagingService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onNewToken(token: String) {
        super.onNewToken(token)
        AppLogger.i(TAG, "FCM token refreshed")
        registerTokenWithBridge(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        AppLogger.i(TAG, "Push received from: ${message.from}")

        val title = message.notification?.title
            ?: message.data["title"]
            ?: getString(R.string.app_name)
        val body = message.notification?.body
            ?: message.data["body"]
            ?: "You have a new notification"

        showNotification(title, body)
    }

    private fun showNotification(title: String, body: String) {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager

        // Create notification channel (required for Android O+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Impala Notifications",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Security alerts and account activity notifications"
            }
            manager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()

        manager.notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun registerTokenWithBridge(token: String) {
        val app = application as? ImpalaApp ?: return
        if (!app.tokenManager.hasValidSession()) return

        scope.launch {
            try {
                val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)
                val response = api.registerDeviceToken(
                    RegisterDeviceTokenRequest(token = token)
                )
                if (response.success) {
                    AppLogger.i(TAG, "Device token registered with bridge")
                } else {
                    AppLogger.w(TAG, "Device token registration rejected: ${response.message}")
                }
            } catch (e: Exception) {
                AppLogger.e(TAG, "Failed to register device token: ${e.message}")
            }
        }
    }

    companion object {
        private const val TAG = "ImpalaPush"
        const val CHANNEL_ID = "impala_notifications"
    }
}

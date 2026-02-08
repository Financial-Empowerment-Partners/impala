package com.payala.impala.demo

import android.app.Application
import com.payala.impala.demo.auth.TokenManager
import com.payala.impala.demo.log.AppLogger

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
    }
}

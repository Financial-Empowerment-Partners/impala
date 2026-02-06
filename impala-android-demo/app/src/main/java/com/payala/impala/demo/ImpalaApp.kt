package com.payala.impala.demo

import android.app.Application
import com.payala.impala.demo.auth.TokenManager

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
    }
}

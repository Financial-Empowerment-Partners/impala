package com.payala.impala.demo.ui.main

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.payala.impala.demo.R
import com.payala.impala.demo.auth.NfcCardAuthHelper
import com.payala.impala.demo.auth.NfcCardResult
import com.payala.impala.demo.databinding.ActivityMainBinding

/**
 * Main screen with a [BottomNavigationView] hosting three tabs:
 * Cards (start destination), Transfers, and Settings.
 *
 * Uses Jetpack Navigation with a [NavHostFragment] defined in
 * `activity_main.xml`. The toolbar title updates automatically when the
 * user switches tabs.
 *
 * Also manages NFC foreground dispatch so that fragments (e.g., [CardsFragment])
 * can register cards by tapping an NFC smartcard while the app is open.
 * Fragments set [nfcCallback] to receive tag events.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    lateinit var nfcHelper: NfcCardAuthHelper
        private set

    /**
     * Callback for NFC tag events. Fragments set this to receive card read
     * results when the user taps a smartcard. Set to `null` when not listening.
     */
    var nfcCallback: ((NfcCardResult) -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        nfcHelper = NfcCardAuthHelper(this)

        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController

        binding.bottomNav.setupWithNavController(navController)

        navController.addOnDestinationChangedListener { _, destination, _ ->
            binding.toolbar.title = destination.label
        }
    }

    override fun onResume() {
        super.onResume()
        nfcHelper.enableForegroundDispatch()
    }

    override fun onPause() {
        super.onPause()
        nfcHelper.disableForegroundDispatch()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val callback = nfcCallback ?: return
        val result = nfcHelper.processTag(intent)
        callback(result)
    }
}

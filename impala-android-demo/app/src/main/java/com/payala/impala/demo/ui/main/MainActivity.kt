package com.payala.impala.demo.ui.main

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.NavHostFragment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.payala.impala.card.CardReaderController
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.card.DebugCards
import com.payala.impala.demo.databinding.ActivityMainBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.ui.log.LogViewerActivity
import com.payala.impala.demo.ui.nfc.NfcDebugActivity

/**
 * Main screen with a [BottomNavigationView] hosting three tabs:
 * Cards (start destination), Transfers, and Settings.
 *
 * Uses Jetpack Navigation with a [NavHostFragment] defined in
 * `activity_main.xml`. The toolbar title updates automatically when the
 * user switches tabs.
 *
 * Owns the one [CardReaderController] (impala-lib reader mode) for every
 * screen it hosts. A fragment that needs the card (registration, load, redeem)
 * calls [awaitCardTap]; its `onTap` runs on the NFC binder thread with the card
 * connected and its `onResult` on the main thread. With no request pending, a
 * tap only reads the identity and is offered to [idleCardTapListener] (the
 * Cards screen offers "Register this card?"). Fragments never register NFC
 * callbacks with the activity themselves.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    lateinit var cardReader: CardReaderController
        private set

    private class PendingTap(
        val onTap: (ImpalaCardSession) -> Any?,
        val onResult: (Result<Any?>) -> Unit
    )

    /** At most one card request at a time; read on the binder thread. */
    @Volatile
    private var pendingTap: PendingTap? = null

    /** Receives the identity of a card tapped while no request is pending (main thread). */
    var idleCardTapListener: ((CardIdentity) -> Unit)? = null

    /**
     * Runs [onTap] with the next tapped card (binder thread, card connected) and
     * delivers its outcome to [onResult] on the main thread. Replaces any
     * request still waiting for a tap.
     */
    @Suppress("UNCHECKED_CAST")
    fun <R> awaitCardTap(onTap: (ImpalaCardSession) -> R, onResult: (Result<R>) -> Unit) {
        pendingTap = PendingTap(onTap, { r -> onResult(r as Result<R>) })
        if (DebugCards.isConfigured()) {
            // Emulator lane (debug builds only): the simulated card "taps" now.
            lifecycleScope.launch(Dispatchers.IO) {
                DebugCards.openSession()?.let { cardReader.debugInjectTap(it) }
            }
        }
    }

    /** Drops a request that is still waiting for a tap. */
    fun cancelCardTap() {
        pendingTap = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        cardReader = CardReaderController(this, aidHex = BuildConfig.CARD_APPLET_AID.ifEmpty { null })

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
        cardReader.enableReaderMode(
            onTap = { session ->
                val request = pendingTap
                if (request != null) {
                    pendingTap = null
                    TapOutcome.Requested(request, runRequest(request, session))
                } else if (idleCardTapListener != null) {
                    TapOutcome.Idle(session.identity)
                } else {
                    TapOutcome.Ignored
                }
            },
            onResult = { result ->
                result.fold(
                    onSuccess = { outcome ->
                        when (outcome) {
                            is TapOutcome.Requested -> outcome.request.onResult(outcome.result)
                            is TapOutcome.Idle -> idleCardTapListener?.invoke(outcome.identity)
                            TapOutcome.Ignored -> Unit
                        }
                    },
                    onFailure = { e ->
                        // The session could not be opened (tag lost, not an
                        // Impala card): hand it to the waiting request, if any.
                        val request = pendingTap
                        if (request != null) {
                            pendingTap = null
                            request.onResult(Result.failure(e))
                        } else {
                            AppLogger.d("NFC", "Card tap not read: ${e.javaClass.simpleName}")
                        }
                    }
                )
            }
        )
    }

    override fun onPause() {
        super.onPause()
        cardReader.disableReaderMode()
    }

    /** Runs a request's onTap, typing card/transport failures as [CardFlowException]. */
    private fun runRequest(request: PendingTap, session: ImpalaCardSession): Result<Any?> =
        try {
            Result.success(request.onTap(session))
        } catch (e: CardFlowException) {
            Result.failure(e)
        } catch (e: BIBOException) {
            Result.failure(CardFlowException(CardError.from(e), e))
        } catch (e: Exception) {
            Result.failure(e)
        }

    private sealed class TapOutcome {
        class Requested(val request: PendingTap, val result: Result<Any?>) : TapOutcome()
        class Idle(val identity: CardIdentity) : TapOutcome()
        object Ignored : TapOutcome()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_options_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_build_info -> {
                showBuildInfoDialog()
                true
            }
            R.id.action_activity_log -> {
                startActivity(Intent(this, LogViewerActivity::class.java))
                true
            }
            R.id.action_nfc_debug -> {
                startActivity(Intent(this, NfcDebugActivity::class.java))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showBuildInfoDialog() {
        val info = buildString {
            appendLine("App: ${getString(R.string.app_name)}")
            appendLine("Version: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            appendLine("Build Type: ${BuildConfig.BUILD_TYPE}")
            appendLine("Application ID: ${BuildConfig.APPLICATION_ID}")
            appendLine("Bridge URL: ${BuildConfig.BRIDGE_BASE_URL}")
            appendLine()
            appendLine("Min SDK: ${android.os.Build.VERSION_CODES.N}")
            appendLine("Device SDK: ${Build.VERSION.SDK_INT}")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
            appendLine("Android: ${Build.VERSION.RELEASE}")
            appendLine()
            appendLine("NFC Available: ${cardReader.isNfcAvailable}")
            appendLine("NFC Enabled: ${cardReader.isNfcEnabled}")
        }

        AppLogger.i("BuildInfo", "Build info viewed")

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.dialog_build_info_title)
            .setMessage(info)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }
}

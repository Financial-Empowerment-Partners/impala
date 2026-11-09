package com.payala.impala.demo.ui.main

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.Menu
import android.view.MenuItem
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavController
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.snackbar.Snackbar
import com.impala.sdk.apdu4j.ApduExchangeHook
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.payala.impala.card.CardReaderController
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.card.ApduTraceLog
import com.payala.impala.demo.card.DebugCards
import com.payala.impala.demo.card.TapProgress
import com.payala.impala.demo.databinding.ActivityMainBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.ui.common.applyEdgeToEdge
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.log.LogViewerActivity
import com.payala.impala.demo.ui.tap.CardReaderUnavailableException
import com.payala.impala.demo.ui.tap.CardTapSheet
import com.payala.impala.demo.ui.tap.SimulatedTapNotStartedException
import com.payala.impala.demo.ui.tap.TapCancelledException
import com.payala.impala.demo.ui.tap.TapFailures
import com.payala.impala.demo.ui.tap.TapAction
import com.payala.impala.demo.ui.tap.TapPrompt
import com.payala.impala.demo.ui.tap.TapUiState
import com.payala.impala.demo.ui.tap.TapViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Main screen with a bottom navigation bar hosting three tabs: Cards (start
 * destination), Transfers, and Settings. The action bar follows the
 * navigation graph (first title "Cards"; Up on nested destinations).
 *
 * Owns the one [CardReaderController] (impala-lib reader mode) for every
 * screen it hosts, and the activity-scoped [tapViewModel] that drives the tap
 * sheet ([CardTapSheet]). A fragment that needs the card (registration, load,
 * redeem) calls [awaitCardTap]; its `onTap` runs on the NFC binder thread
 * with the card connected and its `onResult` on the main thread. With no
 * request pending, a tap only reads the identity and is offered to
 * [idleCardTapListener] (the Cards screen offers "Register this card?").
 * Fragments never register NFC callbacks with the activity themselves.
 *
 * The production controller carries the header-only trace hook: it drives
 * the sheet's step labels and, in debug builds only, the Card Lab's record of
 * recent production taps ([ApduTraceLog]). The controller is never read-only.
 */
class MainActivity : AppCompatActivity() {

    enum class CardAvailability { NFC_READY, NFC_DISABLED, NFC_ABSENT, SIMULATED }

    private lateinit var binding: ActivityMainBinding
    private lateinit var navController: NavController
    private lateinit var appBarConfiguration: AppBarConfiguration
    lateinit var cardReader: CardReaderController
        private set

    /** The tap sheet's state and the pending request (one at a time). */
    val tapViewModel: TapViewModel by viewModels()

    private class PendingTap(
        val prompt: TapPrompt,
        val onTap: (ImpalaCardSession) -> Any?,
        val onResult: (Result<Any?>) -> Unit
    )

    /** The last armed request, for the sheet's Try again (this activity instance only). */
    private var lastRequest: PendingTap? = null

    /** Receives the identity of a card tapped while no request is pending (main thread). */
    var idleCardTapListener: ((CardIdentity) -> Unit)? = null

    /**
     * The flow of the request `onTap` is running on this card I/O thread (set
     * once the request is taken), so the first exchange of a session that has
     * no SELECT before `onTap` (the simulated card, a live default-selection
     * applet) is still labelled with the flow and not `idle`.
     */
    private val runningTap = ThreadLocal<String?>()

    /** Runs on the card I/O thread: header-only exchanges only (no bytes exist in the record). */
    private val traceHook = ApduExchangeHook { exchange ->
        tapViewModel.onExchange(exchange)
        ApduTraceLog.trace(exchange) { traceSource() }
    }

    /** The trace ring's label for a tap: the running or armed request's flow, else `idle`. */
    private fun traceSource(): String =
        runningTap.get() ?: (tapViewModel.peek() as? PendingTap)?.prompt?.logName ?: "idle"

    /** What a card tap can use right now: the simulated card (debug builds), NFC on, NFC off, or no NFC. */
    fun cardAvailability(): CardAvailability = when {
        DebugCards.isConfigured() -> CardAvailability.SIMULATED
        !cardReader.isNfcAvailable -> CardAvailability.NFC_ABSENT
        !cardReader.isNfcEnabled -> CardAvailability.NFC_DISABLED
        else -> CardAvailability.NFC_READY
    }

    /**
     * Runs [onTap] with the next tapped card (binder thread, card connected) and
     * delivers its outcome to [onResult] on the main thread, with the tap sheet
     * showing [prompt]. Replaces any request still waiting for a tap. When no
     * card can be tapped (NFC off or absent), [onResult] gets a
     * [CardReaderUnavailableException] instead of waiting forever.
     */
    @Suppress("UNCHECKED_CAST")
    fun <R> awaitCardTap(prompt: TapPrompt, onTap: (ImpalaCardSession) -> R, onResult: (Result<R>) -> Unit) {
        val request = PendingTap(prompt, onTap) { r -> onResult(r as Result<R>) }
        // A request still parked is replaced: it is told so (a redeem zeroes its PIN).
        (tapViewModel.take() as? PendingTap)?.onResult?.invoke(Result.failure(TapCancelledException()))
        lastRequest = request
        val availability = cardAvailability()
        tapViewModel.arm(prompt, simulated = availability == CardAvailability.SIMULATED, endpoint = DebugCards.endpointText())
        tapViewModel.onRetry = {
            // Only the request whose own non-money sheet failed is re-armed; a follow-up sheet
            // (Cards' "Register this card?") never re-arms an older Sign or Apply request.
            val failed = (tapViewModel.current as? TapUiState.Failed)?.prompt
            val retry = lastRequest?.takeIf { it.prompt === failed && !it.prompt.moneyMoving }
            if (retry != null) awaitCardTap(retry.prompt, retry.onTap, retry.onResult) else tapViewModel.perform(TapAction.CLOSE)
        }
        when (availability) {
            CardAvailability.NFC_DISABLED, CardAvailability.NFC_ABSENT -> {
                tapViewModel.take()
                val e = CardReaderUnavailableException(readerDisabled = availability == CardAvailability.NFC_DISABLED)
                binding.root.post { request.onResult(Result.failure(e)) }
            }
            CardAvailability.NFC_READY -> tapViewModel.offer(request)
            CardAvailability.SIMULATED -> {
                tapViewModel.offer(request)
                injectSimulatedTap(request)
            }
        }
    }

    /** Legacy form: a read prompt with no card named. */
    fun <R> awaitCardTap(onTap: (ImpalaCardSession) -> R, onResult: (Result<R>) -> Unit) =
        awaitCardTap(TapPrompt.Read(null), onTap, onResult)

    /**
     * Drops a request that is still waiting for a tap (its sheet goes away).
     * The request gets a [TapCancelledException] so it can release what it
     * holds; a tap already running is not affected.
     */
    fun cancelCardTap() {
        val dropped = tapViewModel.take() as? PendingTap ?: return
        tapViewModel.dropWaiting()
        dropped.onResult(Result.failure(TapCancelledException()))
    }

    /** A Snackbar anchored above the bottom navigation bar. */
    fun snackbar(text: CharSequence) {
        Snackbar.make(binding.root, text, Snackbar.LENGTH_LONG).setAnchorView(binding.bottomNav).show()
    }

    /**
     * Shows [e] on the tap sheet (when it is up; otherwise as a Snackbar).
     * [hasRecovery]: a money prompt's recovery slot exists, so it offers Resume.
     */
    fun showTapFailure(e: Throwable, hasRecovery: Boolean = false, warning: Boolean = false) {
        if (e is TapCancelledException) return
        val text = TapFailures.describe(this, e)
        if (tapViewModel.isActive) {
            tapViewModel.failed(text.message, text.swHex, warning, hasRecovery, text.readerDisabled)
        } else {
            snackbar(text.message)
        }
    }

    /**
     * Debug lane (the emulator has no NFC): the simulated card "taps" now, in
     * two guarded steps. Opening the session can fail (simulator down): the
     * failure is delivered and the request cleared. Injecting can fail
     * (reader mode off): the session is closed at once, so the one-client
     * simulator is never left holding a dead connection, and the failure is
     * delivered. This coroutine never throws.
     */
    private fun injectSimulatedTap(request: PendingTap) {
        lifecycleScope.launch(Dispatchers.IO) {
            val failure: Throwable? = try {
                val session = DebugCards.openSession(traceHook)
                when {
                    session == null -> SimulatedTapNotStartedException("no simulated card configured")
                    !cardReader.debugInjectTapOrClose(session) -> SimulatedTapNotStartedException("reader mode is off")
                    else -> null
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                e
            }
            if (failure != null) {
                AppLogger.w("NFC", "Simulated tap not started: ${failure.javaClass.simpleName}")
                withContext(Dispatchers.Main) {
                    if (tapViewModel.withdraw(request)) {
                        ApduTraceLog.endTap("not started")
                        request.onResult(Result.failure(failure))
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyEdgeToEdge()
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        cardReader = CardReaderController(
            this,
            aidHex = BuildConfig.CARD_APPLET_AID.ifEmpty { null },
            trace = traceHook
        )

        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        navController = navHostFragment.navController
        appBarConfiguration = AppBarConfiguration(setOf(R.id.nav_cards, R.id.nav_transfers, R.id.nav_settings))
        setupActionBarWithNavController(navController, appBarConfiguration)
        binding.bottomNav.setupWithNavController(navController)

        // The nav host ends where the bottom bar begins, whatever height the
        // bar measures to (it grows by the gesture inset edge to edge).
        binding.bottomNav.addOnLayoutChangeListener { v, _, top, _, bottom, _, oldTop, _, oldBottom ->
            if (bottom - top != oldBottom - oldTop) binding.navHostFragment.updatePadding(bottom = v.height)
        }

        val tap = tapViewModel
        tap.onCancel = { (tap.take() as? PendingTap)?.onResult?.invoke(Result.failure(TapCancelledException())) }
        tap.onOpenNfcSettings = { openNfcSettings() }
        tap.state.observe(this) { CardTapSheet.sync(this, tap) }
    }

    override fun onSupportNavigateUp(): Boolean =
        navController.navigateUp(appBarConfiguration) || super.onSupportNavigateUp()

    override fun onDestroy() {
        tapViewModel.onRetry = null
        tapViewModel.onCancel = null
        tapViewModel.onOpenNfcSettings = null
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        cardReader.enableReaderMode(
            onTap = { session ->
                @Suppress("UNCHECKED_CAST")
                val request = tapViewModel.take() as PendingTap?
                if (request != null) {
                    runningTap.set(request.prompt.logName)
                    try {
                        TapOutcome.Requested(request, tapViewModel.runTap {
                            TapProgress.withSink(tapViewModel::onStep) { runRequest(request, session) }
                        })
                    } finally {
                        runningTap.remove()
                    }
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
                            is TapOutcome.Requested -> {
                                ApduTraceLog.endTap(if (outcome.result.isSuccess) "ok" else outcomeName(outcome.result.exceptionOrNull()))
                                outcome.request.onResult(outcome.result)
                            }
                            is TapOutcome.Idle -> {
                                ApduTraceLog.endTap("idle")
                                idleCardTapListener?.invoke(outcome.identity)
                            }
                            TapOutcome.Ignored -> ApduTraceLog.endTap("ignored")
                        }
                    },
                    onFailure = { e ->
                        // The session could not be opened (tag lost, not an
                        // Impala card): hand it to the waiting request, if any.
                        ApduTraceLog.endTap(outcomeName(e))
                        @Suppress("UNCHECKED_CAST")
                        val request = tapViewModel.take() as PendingTap?
                        if (request != null) {
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

    private fun outcomeName(e: Throwable?): String = when (e) {
        null -> "ok"
        is CardFlowException -> e.error.javaClass.simpleName
        else -> e.javaClass.simpleName
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

    private fun openNfcSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_options_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_build_info -> {
                startActivity(LabIntents.open(this, LabIntents.TAB_DEVICE))
                true
            }
            R.id.action_activity_log -> {
                startActivity(Intent(this, LogViewerActivity::class.java))
                true
            }
            R.id.action_nfc_debug -> {
                startActivity(LabIntents.open(this))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}

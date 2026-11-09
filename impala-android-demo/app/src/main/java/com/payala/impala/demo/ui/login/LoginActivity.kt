package com.payala.impala.demo.ui.login

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.inputmethod.EditorInfo
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.auth.GitHubAuthHelper
import com.payala.impala.demo.auth.GitHubSignInResult
import com.payala.impala.demo.auth.GoogleAuthHelper
import com.payala.impala.demo.auth.GoogleSignInResult
import com.payala.impala.demo.auth.OktaAuthHelper
import com.payala.impala.demo.auth.OktaSignInResult
import com.payala.impala.demo.databinding.ActivityLoginBinding
import com.payala.impala.demo.ui.main.MainActivity
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.payala.impala.card.CardErrorMessages
import com.payala.impala.card.CardReaderController
import com.impala.sdk.apdu4j.ApduExchangeHook
import com.payala.impala.demo.card.ApduTraceLog
import com.payala.impala.demo.card.DebugCards
import com.payala.impala.demo.card.TapProgress
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.ui.common.applyEdgeToEdge
import com.payala.impala.demo.ui.common.padForSystemBars
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.tap.CardReaderUnavailableException
import com.payala.impala.demo.ui.tap.CardTapSheet
import com.payala.impala.demo.ui.tap.SimulatedTapNotStartedException
import com.payala.impala.demo.ui.tap.TapFailures
import com.payala.impala.demo.ui.tap.TapPrompt
import com.payala.impala.demo.ui.tap.TapUiState
import com.payala.impala.demo.ui.tap.TapViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicInteger

/**
 * Launcher activity presenting the authentication methods.
 *
 * On startup, checks [TokenManager.hasValidSession]. If a valid refresh token
 * exists, the user is sent directly to [MainActivity] without seeing the login
 * screen. Otherwise the layout is inflated with:
 * - Username/password form (field errors on the text fields; Go on the
 *   password field signs in)
 * - "Continue with Google" button (Credential Manager)
 * - "Continue with GitHub" button (Custom Chrome Tab OAuth)
 * - "Sign in with Card" button (NFC smartcard via impala-lib patterns)
 * - a quiet "Card Lab" link to the read-only card tools (no session needed)
 *
 * All auth logic is delegated to [LoginViewModel]; this activity only observes
 * [LoginViewModel.loginState] and updates the UI accordingly. Navigation to
 * Main happens in the `Success` observer and never waits for the tap sheet.
 *
 * Card login runs with the tap sheet ([CardTapSheet], driven by [tap]).
 * NFC reader mode ([CardReaderController], impala-lib) is enabled in
 * [onResume]. A tap is acted on only after "Sign in with Card"
 * ([awaitingCardTap]) and only when no other card login is in flight
 * ([LoginViewModel.tryBeginCardLogin]). A failure reaches the sheet and
 * [LoginViewModel.cardTapFailed] only when the user asked for a tap
 * (`wanted = tapClaimed || awaitingCardTap`), so a failure thrown before
 * `onTap` (a foreign card) still shows, and a stray tap while idle is
 * ignored. Cancel while the bridge is being contacted abandons the tap
 * ([LoginViewModel.cardTapAbandoned]); its late result is ignored.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private val viewModel: LoginViewModel by viewModels()
    private val tap: TapViewModel by viewModels()
    private lateinit var googleAuthHelper: GoogleAuthHelper
    private lateinit var gitHubAuthHelper: GitHubAuthHelper
    private lateinit var cardReader: CardReaderController
    private lateinit var oktaAuthHelper: OktaAuthHelper

    /**
     * True when the user has tapped "Sign in with Card" and is waiting for a
     * tap. Read on the NFC binder thread; cleared there when a tap claims it.
     */
    @Volatile
    private var awaitingCardTap = false

    /** Set on the binder thread when a tap claimed the card-login slot; cleared when its result is handled. */
    @Volatile
    private var tapClaimed = false

    /** Bumped by every new card-login attempt and by an abandon; a result of an older attempt is ignored. */
    private val attempt = AtomicInteger(0)

    /**
     * What a claimed tap returns: the attempt it belongs to and the card's
     * signature or why it failed. A failure inside `onTap` is returned, not
     * thrown, so a late one from an abandoned attempt is told apart.
     */
    private class ClaimedTap(val attempt: Int, val outcome: Result<CardLoginTap>)

    /**
     * The card I/O thread's trace hook: the sheet's step labels, and (debug
     * builds only) the Card Lab's record of recent taps, labelled `sign-in`
     * while the user asked for a card login and `idle` otherwise. Header-only
     * exchanges: no bytes exist in the record.
     */
    private val traceHook = ApduExchangeHook { exchange ->
        tap.onExchange(exchange)
        ApduTraceLog.trace(exchange) { if (awaitingCardTap || tapClaimed) TapPrompt.SignIn.logName else "idle" }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Skip login if we already have a valid refresh token
        val tokenManager = (application as ImpalaApp).tokenManager
        if (tokenManager.hasValidSession()) {
            navigateToMain()
            return
        }

        // The header is a dark surface in both modes: light status-bar icons.
        applyEdgeToEdge(lightStatusBarIcons = true)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.loginHeader.padForSystemBars(top = true, bottom = false)
        binding.scrollLogin.padForSystemBars(bottom = true, ime = true)

        googleAuthHelper = GoogleAuthHelper(this)
        gitHubAuthHelper = GitHubAuthHelper(this)
        cardReader = CardReaderController(this, aidHex = BuildConfig.CARD_APPLET_AID.ifEmpty { null }, trace = traceHook)
        oktaAuthHelper = OktaAuthHelper(this)

        // Hide NFC button if device lacks NFC hardware (debug builds keep it
        // when a simulated card is configured; see DebugCards)
        if (!cardReader.isNfcAvailable && !DebugCards.isConfigured()) {
            binding.btnCard.visibility = View.GONE
        }

        // A test network says so on the sign-in screen (the same rule as Settings' network chip).
        binding.chipLoginNetwork.visibility = if (BuildConfig.STELLAR_NETWORK != "pubnet") View.VISIBLE else View.GONE

        // Hide Okta button if not configured
        if (BuildConfig.OKTA_ISSUER_URL.isEmpty()) {
            binding.btnOkta.visibility = View.GONE
        }

        // The read-only Card Lab is reachable before sign-in (public card facts only).
        binding.btnCardLab.visibility = View.VISIBLE
        binding.btnCardLab.setOnClickListener { startActivity(LabIntents.open(this, LabIntents.TAB_INSPECTOR)) }

        tap.onCancel = { abandonCardTap() }
        tap.onRetry = { startCardLogin() }
        tap.onOpenNfcSettings = { openNfcSettings() }
        tap.state.observe(this) { CardTapSheet.sync(this, tap) }

        setupObservers()
        setupClickListeners()
    }

    override fun onDestroy() {
        if (::binding.isInitialized) {
            tap.onCancel = null
            tap.onRetry = null
            tap.onOpenNfcSettings = null
        }
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        if (!::cardReader.isInitialized) return
        val tokenManager = (application as ImpalaApp).tokenManager
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, tokenManager)
        cardReader.enableReaderMode(
            onTap = { session ->
                // Binder thread. Only a tap we asked for, and only one at a time.
                if (!awaitingCardTap || !viewModel.tryBeginCardLogin()) return@enableReaderMode null
                awaitingCardTap = false
                tapClaimed = true
                val mine = attempt.get()
                val outcome: Result<CardLoginTap> = try {
                    Result.success(tap.runTap { TapProgress.withSink(tap::onStep) { viewModel.signInWithCardTap(session, api) } })
                } catch (e: CardFlowException) {
                    Result.failure(e)
                } catch (e: BIBOException) {
                    Result.failure(CardFlowException(CardError.from(e), e))
                } catch (e: Exception) {
                    Result.failure(e)
                }
                ClaimedTap(mine, outcome)
            },
            onResult = { result ->
                result.fold(
                    onSuccess = { claimed ->
                        if (claimed == null) {
                            ApduTraceLog.endTap("ignored")
                            return@fold // not asked for, or another login in flight
                        }
                        if (claimed.attempt != attempt.get()) {
                            // Its slot was released by the abandon; a newer attempt's claim is left alone.
                            ApduTraceLog.endTap("abandoned")
                            AppLogger.d("NFC", "Late result of an abandoned card login ignored")
                            return@fold
                        }
                        ApduTraceLog.endTap(if (claimed.outcome.isSuccess) "ok" else outcomeName(claimed.outcome.exceptionOrNull()))
                        tapClaimed = false
                        claimed.outcome.fold(
                            onSuccess = { signed ->
                                tap.finishing(R.string.tap_finishing_login)
                                viewModel.loginWithCard(api, tokenManager, signed)
                            },
                            onFailure = { e ->
                                showCardFailure(e)
                                viewModel.cardTapFailed(e)
                            }
                        )
                    },
                    onFailure = { e ->
                        // Thrown before onTap claimed anything (the session could not be
                        // opened): it belongs to the attempt waiting for a tap, if any.
                        ApduTraceLog.endTap(outcomeName(e))
                        val wanted = awaitingCardTap
                        awaitingCardTap = false
                        if (wanted) {
                            showCardFailure(e)
                            viewModel.cardTapFailed(e)
                        } else {
                            AppLogger.d("NFC", "Stray card tap ignored: ${e.javaClass.simpleName}")
                        }
                    }
                )
            }
        )
    }

    override fun onPause() {
        super.onPause()
        if (::cardReader.isInitialized) {
            cardReader.disableReaderMode()
        }
    }

    /** "Sign in with Card" (and the sheet's Try again). */
    private fun startCardLogin() {
        hideFieldErrors()
        val simulated = DebugCards.isConfigured()
        attempt.incrementAndGet()
        tapClaimed = false
        tap.arm(TapPrompt.SignIn, simulated = simulated, endpoint = DebugCards.endpointText())
        if (!simulated && !cardReader.isNfcEnabled) {
            awaitingCardTap = false
            showCardFailure(CardReaderUnavailableException(readerDisabled = cardReader.isNfcAvailable))
            return
        }
        awaitingCardTap = true
        if (simulated) injectSimulatedTap()
    }

    /**
     * Debug lane: two guarded steps. Opening the simulated session can fail
     * (simulator down); injecting can fail (reader mode off: the session is
     * closed at once). Either failure reaches the sheet while the user is
     * still waiting for this attempt; the coroutine never throws.
     */
    private fun injectSimulatedTap() {
        val mine = attempt.get()
        lifecycleScope.launch(Dispatchers.IO) {
            val failure: Throwable? = try {
                val session = DebugCards.openSession(trace = traceHook)
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
                AppLogger.w("NFC", "Simulated card tap not started: ${failure.javaClass.simpleName}")
                withContext(Dispatchers.Main) {
                    if (awaitingCardTap && mine == attempt.get()) {
                        ApduTraceLog.endTap("not started")
                        awaitingCardTap = false
                        showCardFailure(failure)
                        viewModel.cardTapFailed(failure)
                    }
                }
            }
        }
    }

    /** The sheet's Cancel: while waiting for a card, or while the bridge is being contacted. */
    private fun abandonCardTap() {
        awaitingCardTap = false
        attempt.incrementAndGet()
        if (tapClaimed) {
            tapClaimed = false
            viewModel.cardTapAbandoned()
        }
    }

    private fun outcomeName(e: Throwable?): String = when (e) {
        null -> "ok"
        is CardFlowException -> e.error.javaClass.simpleName
        else -> e.javaClass.simpleName
    }

    private fun showCardFailure(e: Throwable) {
        val text = TapFailures.describe(this, e)
        tap.failed(text.message, text.swHex, warning = false, hasRecovery = false, readerDisabled = text.readerDisabled)
    }

    private fun setupObservers() {
        viewModel.loginState.observe(this) { state ->
            when (state) {
                is LoginViewModel.LoginState.Loading -> {
                    binding.progressIndicator.visibility = View.VISIBLE
                    setButtonsEnabled(false)
                    binding.tvError.visibility = View.GONE
                }
                is LoginViewModel.LoginState.Success -> {
                    binding.progressIndicator.visibility = View.GONE
                    tap.succeeded(R.string.tap_done_signed_in)
                    navigateToMain()
                }
                is LoginViewModel.LoginState.Error -> {
                    binding.progressIndicator.visibility = View.GONE
                    setButtonsEnabled(true)
                    val message = mapErrorToMessage(state)
                    binding.tvError.text = message
                    binding.tvError.visibility = View.VISIBLE
                    // A card login's bridge half failed: the sheet says so too.
                    if (tap.current is TapUiState.Busy) {
                        val sw = if (BuildConfig.DEBUG) state.cardError?.statusWordHex else null
                        tap.failed(message, sw, warning = false, hasRecovery = false)
                    }
                }
                is LoginViewModel.LoginState.Idle -> {
                    binding.progressIndicator.visibility = View.GONE
                    setButtonsEnabled(true)
                }
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        binding.btnSignIn.isEnabled = enabled
        binding.btnGoogle.isEnabled = enabled
        binding.btnGithub.isEnabled = enabled
        binding.btnCard.isEnabled = enabled
        binding.btnOkta.isEnabled = enabled
    }

    private fun showError(text: CharSequence) {
        binding.tvError.text = text
        binding.tvError.visibility = View.VISIBLE
    }

    private fun hideFieldErrors() {
        binding.tilAccountId.error = null
        binding.tilPassword.error = null
    }

    private fun setupClickListeners() {
        val tokenManager = (application as ImpalaApp).tokenManager
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, tokenManager)

        binding.etAccountId.doAfterTextChanged { binding.tilAccountId.error = null }
        binding.etPassword.doAfterTextChanged { binding.tilPassword.error = null }
        binding.etPassword.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                binding.btnSignIn.performClick()
                true
            } else {
                false
            }
        }

        binding.btnSignIn.setOnClickListener {
            val accountId = binding.etAccountId.text.toString().trim()
            val password = binding.etPassword.text.toString()
            binding.tvError.visibility = View.GONE

            var valid = true
            if (accountId.isEmpty()) {
                binding.tilAccountId.error = getString(R.string.error_empty_username)
                valid = false
            }
            if (password.isEmpty()) {
                binding.tilPassword.error = getString(R.string.error_empty_password)
                valid = false
            } else if (password.length < 8) {
                binding.tilPassword.error = getString(R.string.error_password_short)
                valid = false
            }
            if (!valid) {
                (if (accountId.isEmpty()) binding.etAccountId else binding.etPassword).requestFocus()
                return@setOnClickListener
            }

            viewModel.loginWithPassword(api, tokenManager, accountId, password)
        }

        binding.btnGoogle.setOnClickListener {
            lifecycleScope.launch {
                when (val result = googleAuthHelper.signIn()) {
                    is GoogleSignInResult.Success -> {
                        viewModel.loginWithGoogle(
                            api, tokenManager,
                            result.email, result.idToken, result.displayName
                        )
                    }
                    is GoogleSignInResult.Error -> showError(result.message)
                    is GoogleSignInResult.Cancelled -> { /* no-op */ }
                }
            }
        }

        binding.btnGithub.setOnClickListener {
            gitHubAuthHelper.startSignIn { result ->
                when (result) {
                    is GitHubSignInResult.CodeReceived -> {
                        // The bridge exchanges the code server-side; no
                        // on-device code→token exchange (and no client secret).
                        viewModel.loginWithGitHub(api, tokenManager, result.code)
                    }
                    is GitHubSignInResult.Error -> runOnUiThread { showError(result.message) }
                }
            }
        }

        binding.btnCard.setOnClickListener { startCardLogin() }

        binding.btnOkta.setOnClickListener {
            oktaAuthHelper.startSignIn(
                BuildConfig.OKTA_ISSUER_URL,
                BuildConfig.OKTA_CLIENT_ID
            ) { result ->
                when (result) {
                    is OktaSignInResult.CodeReceived -> {
                        lifecycleScope.launch {
                            val codeVerifier = OktaAuthHelper.pendingCodeVerifier
                            if (codeVerifier == null) {
                                runOnUiThread { showError("Authentication session expired. Please try again.") }
                                return@launch
                            }
                            val accessToken = oktaAuthHelper.exchangeCodeForToken(
                                BuildConfig.OKTA_ISSUER_URL,
                                BuildConfig.OKTA_CLIENT_ID,
                                result.code,
                                codeVerifier
                            )
                            if (accessToken != null) {
                                viewModel.loginWithOkta(
                                    api, tokenManager, accessToken, null
                                )
                            } else {
                                runOnUiThread { showError("Failed to exchange Okta authorization code") }
                            }
                        }
                    }
                    is OktaSignInResult.Error -> runOnUiThread { showError(result.message) }
                }
            }
        }
    }

    private fun mapErrorToMessage(error: LoginViewModel.LoginState.Error): String {
        return when (error.errorType) {
            LoginViewModel.ErrorType.NETWORK -> getString(R.string.error_network)
            LoginViewModel.ErrorType.AUTH_FAILED -> getString(R.string.error_auth_failed)
            LoginViewModel.ErrorType.TOKEN_FAILED -> getString(R.string.error_token_refresh_failed)
            LoginViewModel.ErrorType.SERVER_ERROR -> getString(R.string.error_server)
            LoginViewModel.ErrorType.TIMEOUT -> getString(R.string.error_timeout)
            LoginViewModel.ErrorType.VALIDATION -> error.message
            LoginViewModel.ErrorType.UNKNOWN -> getString(R.string.error_unknown)
            LoginViewModel.ErrorType.CARD -> error.cardError
                ?.let { CardErrorMessages.message(this, it, includeStatusWord = BuildConfig.DEBUG) }
                ?: getString(R.string.error_unknown)
            LoginViewModel.ErrorType.CARD_REJECTED -> getString(R.string.error_card_rejected)
            LoginViewModel.ErrorType.LOCKED_OUT -> getString(R.string.error_card_locked_out)
        }
    }

    private fun openNfcSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
        }
    }

    private fun navigateToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}

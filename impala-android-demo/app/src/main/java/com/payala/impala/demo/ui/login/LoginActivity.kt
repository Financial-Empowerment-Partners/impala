package com.payala.impala.demo.ui.login

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
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
import com.payala.impala.card.CardErrorMessages
import com.payala.impala.card.CardReaderController
import com.payala.impala.demo.card.DebugCards
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Launcher activity presenting four authentication methods.
 *
 * On startup, checks [TokenManager.hasValidSession]. If a valid refresh token
 * exists, the user is sent directly to [MainActivity] without seeing the login
 * screen. Otherwise the layout is inflated with:
 * - Username/password form
 * - "Continue with Google" button (Credential Manager)
 * - "Continue with GitHub" button (Custom Chrome Tab OAuth)
 * - "Sign in with Card" button (NFC smartcard via impala-lib patterns)
 *
 * All auth logic is delegated to [LoginViewModel]; this activity only observes
 * [LoginViewModel.loginState] and updates the UI accordingly.
 *
 * NFC reader mode ([CardReaderController], impala-lib) is enabled in [onResume].
 * A tap is acted on only after "Sign in with Card" ([awaitingCardTap]) and only
 * when no other card login is in flight ([LoginViewModel.tryBeginCardLogin]).
 * On the NFC binder thread, with the card connected,
 * [LoginViewModel.signInWithCardTap] gates on applet version and
 * personalization, fetches the bridge challenge and has the card sign it; the
 * `POST /auth/card` exchange then runs from the main thread.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private val viewModel: LoginViewModel by viewModels()
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Skip login if we already have a valid refresh token
        val tokenManager = (application as ImpalaApp).tokenManager
        if (tokenManager.hasValidSession()) {
            navigateToMain()
            return
        }

        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        googleAuthHelper = GoogleAuthHelper(this)
        gitHubAuthHelper = GitHubAuthHelper(this)
        cardReader = CardReaderController(this, aidHex = BuildConfig.CARD_APPLET_AID.ifEmpty { null })
        oktaAuthHelper = OktaAuthHelper(this)

        // Hide NFC button if device lacks NFC hardware (debug builds keep it
        // when a simulated card is configured; see DebugCards)
        if (!cardReader.isNfcAvailable && !DebugCards.isConfigured()) {
            binding.btnCard.visibility = View.GONE
        }

        // Hide Okta button if not configured
        if (BuildConfig.OKTA_ISSUER_URL.isEmpty()) {
            binding.btnOkta.visibility = View.GONE
        }

        setupObservers()
        setupClickListeners()
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
                viewModel.signInWithCardTap(session, api)
            },
            onResult = { result ->
                result.fold(
                    onSuccess = { tap -> if (tap != null) viewModel.loginWithCard(api, tokenManager, tap) },
                    onFailure = { e -> viewModel.cardTapFailed(e) }
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

    private fun setupObservers() {
        viewModel.loginState.observe(this) { state ->
            when (state) {
                is LoginViewModel.LoginState.Loading -> {
                    binding.progressIndicator.visibility = View.VISIBLE
                    binding.btnSignIn.isEnabled = false
                    binding.btnGoogle.isEnabled = false
                    binding.btnGithub.isEnabled = false
                    binding.btnCard.isEnabled = false
                    binding.btnOkta.isEnabled = false
                    binding.tvError.visibility = View.GONE
                }
                is LoginViewModel.LoginState.Success -> {
                    binding.progressIndicator.visibility = View.GONE
                    navigateToMain()
                }
                is LoginViewModel.LoginState.Error -> {
                    binding.progressIndicator.visibility = View.GONE
                    binding.btnSignIn.isEnabled = true
                    binding.btnGoogle.isEnabled = true
                    binding.btnGithub.isEnabled = true
                    binding.btnCard.isEnabled = true
                    binding.btnOkta.isEnabled = true
                    binding.tvError.text = mapErrorToMessage(state)
                    binding.tvError.visibility = View.VISIBLE
                }
                is LoginViewModel.LoginState.Idle -> {
                    binding.progressIndicator.visibility = View.GONE
                    binding.btnSignIn.isEnabled = true
                    binding.btnGoogle.isEnabled = true
                    binding.btnGithub.isEnabled = true
                    binding.btnCard.isEnabled = true
                    binding.btnOkta.isEnabled = true
                }
            }
        }
    }

    private fun setupClickListeners() {
        val tokenManager = (application as ImpalaApp).tokenManager
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, tokenManager)

        binding.btnSignIn.setOnClickListener {
            val accountId = binding.etAccountId.text.toString().trim()
            val password = binding.etPassword.text.toString()

            if (accountId.isEmpty() || password.isEmpty()) {
                binding.tvError.text = getString(R.string.error_fields_required)
                binding.tvError.visibility = View.VISIBLE
                return@setOnClickListener
            }

            if (password.length < 8) {
                binding.tvError.text = getString(R.string.error_password_short)
                binding.tvError.visibility = View.VISIBLE
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
                    is GoogleSignInResult.Error -> {
                        binding.tvError.text = result.message
                        binding.tvError.visibility = View.VISIBLE
                    }
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
                    is GitHubSignInResult.Error -> {
                        runOnUiThread {
                            binding.tvError.text = result.message
                            binding.tvError.visibility = View.VISIBLE
                        }
                    }
                }
            }
        }

        binding.btnCard.setOnClickListener {
            if (DebugCards.isConfigured()) {
                awaitingCardTap = true
                lifecycleScope.launch(Dispatchers.IO) {
                    DebugCards.openSession()?.let { cardReader.debugInjectTap(it) }
                }
                return@setOnClickListener
            }
            if (!cardReader.isNfcEnabled) {
                binding.tvError.text = getString(R.string.nfc_disabled)
                binding.tvError.visibility = View.VISIBLE
                return@setOnClickListener
            }
            awaitingCardTap = true
            Snackbar.make(binding.root, R.string.nfc_tap_prompt, Snackbar.LENGTH_LONG).show()
        }

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
                                runOnUiThread {
                                    binding.tvError.text = "Authentication session expired. Please try again."
                                    binding.tvError.visibility = View.VISIBLE
                                }
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
                                runOnUiThread {
                                    binding.tvError.text = "Failed to exchange Okta authorization code"
                                    binding.tvError.visibility = View.VISIBLE
                                }
                            }
                        }
                    }
                    is OktaSignInResult.Error -> {
                        runOnUiThread {
                            binding.tvError.text = result.message
                            binding.tvError.visibility = View.VISIBLE
                        }
                    }
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

    private fun navigateToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}

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
import com.payala.impala.demo.auth.NfcCardAuthHelper
import com.payala.impala.demo.auth.NfcCardResult
import com.payala.impala.demo.databinding.ActivityLoginBinding
import com.payala.impala.demo.ui.main.MainActivity
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
 * NFC foreground dispatch is enabled in [onResume] so that tapping an Impala
 * card while this activity is visible triggers [onNewIntent] instead of the
 * system's tag dispatch. The `android:launchMode="singleTop"` attribute in
 * the manifest ensures `onNewIntent` is called on the existing instance.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private val viewModel: LoginViewModel by viewModels()
    private lateinit var googleAuthHelper: GoogleAuthHelper
    private lateinit var gitHubAuthHelper: GitHubAuthHelper
    private lateinit var nfcHelper: NfcCardAuthHelper

    /** True when the user has tapped "Sign in with Card" and is waiting for a tap. */
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
        nfcHelper = NfcCardAuthHelper(this)

        // Hide NFC button if device lacks NFC hardware
        if (!nfcHelper.isNfcAvailable) {
            binding.btnCard.visibility = View.GONE
        }

        setupObservers()
        setupClickListeners()
    }

    override fun onResume() {
        super.onResume()
        if (::nfcHelper.isInitialized) {
            nfcHelper.enableForegroundDispatch()
        }
    }

    override fun onPause() {
        super.onPause()
        if (::nfcHelper.isInitialized) {
            nfcHelper.disableForegroundDispatch()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (!awaitingCardTap) return
        awaitingCardTap = false

        val tokenManager = (application as ImpalaApp).tokenManager
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, tokenManager)

        when (val result = nfcHelper.processTag(intent)) {
            is NfcCardResult.Success -> {
                viewModel.loginWithCard(api, tokenManager, result)
            }
            is NfcCardResult.Error -> {
                binding.tvError.text = result.message
                binding.tvError.visibility = View.VISIBLE
            }
            is NfcCardResult.NfcNotAvailable -> {
                binding.tvError.text = getString(R.string.nfc_not_available)
                binding.tvError.visibility = View.VISIBLE
            }
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
                    binding.tvError.text = mapErrorToMessage(state)
                    binding.tvError.visibility = View.VISIBLE
                }
                is LoginViewModel.LoginState.Idle -> {
                    binding.progressIndicator.visibility = View.GONE
                    binding.btnSignIn.isEnabled = true
                    binding.btnGoogle.isEnabled = true
                    binding.btnGithub.isEnabled = true
                    binding.btnCard.isEnabled = true
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
                        lifecycleScope.launch {
                            val user = gitHubAuthHelper.exchangeCodeForUser(result.code)
                            if (user != null) {
                                viewModel.loginWithGitHub(
                                    api, tokenManager,
                                    user.login, result.code, user.name
                                )
                            } else {
                                binding.tvError.text = "Failed to get GitHub user info"
                                binding.tvError.visibility = View.VISIBLE
                            }
                        }
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
            if (!nfcHelper.isNfcEnabled) {
                binding.tvError.text = getString(R.string.nfc_disabled)
                binding.tvError.visibility = View.VISIBLE
                return@setOnClickListener
            }
            awaitingCardTap = true
            Snackbar.make(binding.root, R.string.nfc_tap_prompt, Snackbar.LENGTH_LONG).show()
        }
    }

    private fun mapErrorToMessage(error: LoginViewModel.LoginState.Error): String {
        return when (error.errorType) {
            LoginViewModel.ErrorType.NETWORK -> getString(R.string.error_network)
            LoginViewModel.ErrorType.AUTH_FAILED -> getString(R.string.error_auth_failed)
            LoginViewModel.ErrorType.TOKEN_FAILED -> getString(R.string.error_token_refresh_failed)
            LoginViewModel.ErrorType.SERVER_ERROR -> getString(R.string.error_server)
            LoginViewModel.ErrorType.VALIDATION -> error.message
            LoginViewModel.ErrorType.UNKNOWN -> getString(R.string.error_unknown)
        }
    }

    private fun navigateToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}

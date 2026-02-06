package com.payala.impala.demo.ui.login

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.auth.GitHubAuthHelper
import com.payala.impala.demo.auth.GitHubSignInResult
import com.payala.impala.demo.auth.GoogleAuthHelper
import com.payala.impala.demo.auth.GoogleSignInResult
import com.payala.impala.demo.databinding.ActivityLoginBinding
import com.payala.impala.demo.ui.main.MainActivity
import kotlinx.coroutines.launch

/**
 * Launcher activity presenting three authentication methods.
 *
 * On startup, checks [TokenManager.hasValidSession]. If a valid refresh token
 * exists, the user is sent directly to [MainActivity] without seeing the login
 * screen. Otherwise the layout is inflated with:
 * - Username/password form
 * - "Continue with Google" button (Credential Manager)
 * - "Continue with GitHub" button (Custom Chrome Tab OAuth)
 *
 * All auth logic is delegated to [LoginViewModel]; this activity only observes
 * [LoginViewModel.loginState] and updates the UI accordingly.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private val viewModel: LoginViewModel by viewModels()
    private lateinit var googleAuthHelper: GoogleAuthHelper
    private lateinit var gitHubAuthHelper: GitHubAuthHelper

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

        setupObservers()
        setupClickListeners()
    }

    private fun setupObservers() {
        viewModel.loginState.observe(this) { state ->
            when (state) {
                is LoginViewModel.LoginState.Loading -> {
                    binding.progressIndicator.visibility = View.VISIBLE
                    binding.btnSignIn.isEnabled = false
                    binding.btnGoogle.isEnabled = false
                    binding.btnGithub.isEnabled = false
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
                    binding.tvError.text = state.message
                    binding.tvError.visibility = View.VISIBLE
                }
                is LoginViewModel.LoginState.Idle -> {
                    binding.progressIndicator.visibility = View.GONE
                    binding.btnSignIn.isEnabled = true
                    binding.btnGoogle.isEnabled = true
                    binding.btnGithub.isEnabled = true
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
    }

    private fun navigateToMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}

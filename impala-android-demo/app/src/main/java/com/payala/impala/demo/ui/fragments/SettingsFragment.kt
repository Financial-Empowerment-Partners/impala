package com.payala.impala.demo.ui.fragments

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.EditText
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.databinding.FragmentSettingsBinding
import com.payala.impala.demo.model.EnrollMfaRequest
import com.payala.impala.demo.ui.login.LoginActivity
import kotlinx.coroutines.launch

/**
 * Settings screen showing account info, MFA status, bridge version, and a logout button.
 *
 * Account data comes from [TokenManager] (local). MFA status and version info
 * are fetched from the bridge API on view creation. The logout button clears all
 * stored tokens and navigates back to [LoginActivity].
 */
class SettingsFragment : Fragment(R.layout.fragment_settings) {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentSettingsBinding.bind(view)

        val app = requireActivity().application as ImpalaApp
        val tokenManager = app.tokenManager

        // Display account info
        val accountId = tokenManager.getAccountId() ?: getString(R.string.not_available)
        val displayName = tokenManager.getDisplayName()
        val authProvider = tokenManager.getAuthProvider() ?: "password"

        binding.tvAccountName.text = displayName ?: accountId
        binding.tvPayalaId.text = accountId

        // Set server URL
        binding.etServerUrl.setText(BuildConfig.BRIDGE_BASE_URL)

        // Fetch version info
        loadVersionInfo()

        // Load MFA status
        loadMfaStatus(accountId)

        binding.btnManageMfa.setOnClickListener {
            showMfaEnrollmentDialog(accountId)
        }

        binding.btnLogout.setOnClickListener {
            tokenManager.clearAll()
            ApiClient.reset()
            val intent = Intent(requireContext(), LoginActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            }
            startActivity(intent)
        }
    }

    private fun showMfaEnrollmentDialog(accountId: String) {
        val options = arrayOf("TOTP (Authenticator App)", "SMS")
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.dialog_mfa_title)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> enrollTotp(accountId)
                    1 -> promptSmsEnrollment(accountId)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun enrollTotp(accountId: String) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val response = api.enrollMfa(
                    EnrollMfaRequest(
                        account_id = accountId,
                        mfa_type = "totp"
                    )
                )
                if (response.success) {
                    Snackbar.make(requireView(), R.string.mfa_enrolled_totp, Snackbar.LENGTH_SHORT).show()
                    loadMfaStatus(accountId)
                } else {
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Snackbar.make(
                    requireView(),
                    "${getString(R.string.mfa_enrollment_failed)}: ${e.message}",
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun promptSmsEnrollment(accountId: String) {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_sms_enrollment, null)
        val etPhone = dialogView.findViewById<EditText>(R.id.etPhoneNumber)

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.dialog_sms_title)
            .setView(dialogView)
            .setPositiveButton(R.string.dialog_enroll) { _, _ ->
                val phone = etPhone.text.toString().trim()
                if (phone.isEmpty()) {
                    Snackbar.make(requireView(), R.string.error_phone_required, Snackbar.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                enrollSms(accountId, phone)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun enrollSms(accountId: String, phoneNumber: String) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val response = api.enrollMfa(
                    EnrollMfaRequest(
                        account_id = accountId,
                        mfa_type = "sms",
                        phone_number = phoneNumber
                    )
                )
                if (response.success) {
                    Snackbar.make(requireView(), R.string.mfa_enrolled_sms, Snackbar.LENGTH_SHORT).show()
                    loadMfaStatus(accountId)
                } else {
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Snackbar.make(
                    requireView(),
                    "${getString(R.string.mfa_enrollment_failed)}: ${e.message}",
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun loadVersionInfo() {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val version = api.getVersion()
                _binding?.tvVersion?.text = "${version.name} v${version.version}\n" +
                    "Built: ${version.build_date}\n" +
                    "Schema: ${version.schema_version ?: "N/A"}"
            } catch (_: Exception) {
                _binding?.tvVersion?.text = "Impala Demo v${BuildConfig.VERSION_NAME}\n(Bridge offline)"
            }
        }
    }

    private fun loadMfaStatus(accountId: String) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val enrollments = api.getMfa(accountId)
                if (enrollments.isNotEmpty()) {
                    val types = enrollments
                        .filter { it.enabled }
                        .joinToString(", ") { it.mfa_type.uppercase() }
                    _binding?.tvMfaStatus?.text = if (types.isNotEmpty()) {
                        "Enrolled: $types"
                    } else {
                        getString(R.string.mfa_not_enrolled)
                    }
                } else {
                    _binding?.tvMfaStatus?.text = getString(R.string.mfa_not_enrolled)
                }
            } catch (_: Exception) {
                _binding?.tvMfaStatus?.text = getString(R.string.mfa_not_enrolled)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}

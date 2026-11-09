package com.payala.impala.demo.ui.fragments

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.EditText
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.databinding.FragmentSettingsBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.EnrollMfaRequest
import com.payala.impala.demo.ui.common.Identifiers
import com.payala.impala.demo.ui.login.LoginActivity
import kotlinx.coroutines.launch

/**
 * Settings screen showing account info, MFA status, bridge version, and a logout button.
 *
 * Account data comes from [TokenManager] (local): the account id is shown once,
 * under an avatar that carries the display name's initial (a person glyph when
 * there is none). The bridge URL is a read-only row with the Stellar network
 * chip: it is fixed at build time. MFA status and version info are fetched from
 * the bridge API on view creation. Log Out asks for confirmation, then clears
 * all stored tokens and navigates back to [LoginActivity].
 */
class SettingsFragment : Fragment(R.layout.fragment_settings) {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentSettingsBinding.bind(view)

        val app = requireActivity().application as ImpalaApp
        val tokenManager = app.tokenManager

        // Account: the id once; the display name (when known) above it.
        val accountId = tokenManager.getAccountId() ?: getString(R.string.not_available)
        val displayName = tokenManager.getDisplayName()?.trim()?.takeIf { it.isNotEmpty() }
        // Identifiers wrap only at their separators; long-press copies the value itself.
        binding.tvPayalaId.text = Identifiers.breakable(accountId)
        tokenManager.getAccountId()?.let { id -> copyOnLongPress(binding.tvPayalaId, getString(R.string.label_payala_id), id) }
        binding.tvAccountName.text = displayName
        binding.tvAccountName.visibility = if (displayName != null) View.VISIBLE else View.GONE
        val initial = displayName?.firstOrNull { it.isLetterOrDigit() }?.uppercaseChar()
        binding.tvAvatarInitial.text = initial?.toString()
        binding.tvAvatarInitial.visibility = if (initial != null) View.VISIBLE else View.GONE
        binding.ivAvatarGlyph.visibility = if (initial != null) View.GONE else View.VISIBLE

        // Server: read-only (fixed at build time), with the Stellar network.
        binding.tvServerUrl.text = Identifiers.breakable(BuildConfig.BRIDGE_BASE_URL)
        copyOnLongPress(binding.tvServerUrl, getString(R.string.hint_server_url), BuildConfig.BRIDGE_BASE_URL)
        bindNetworkChip()
        binding.tvAppVersion.text =
            getString(R.string.settings_app_version, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE)

        // Fetch version info
        loadVersionInfo()

        // Load MFA status
        loadMfaStatus(accountId)

        binding.btnManageMfa.setOnClickListener {
            showMfaEnrollmentDialog(accountId)
        }

        // Notification preferences
        loadNotificationStatus()
        binding.btnManageNotifications.setOnClickListener {
            findNavController().navigate(R.id.action_settings_to_notifications)
        }

        binding.btnLogout.setOnClickListener {
            val dialog = MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.settings_logout_confirm_title)
                .setMessage(R.string.settings_logout_confirm_message)
                .setPositiveButton(R.string.btn_logout) { _, _ -> logOut() }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
            // Destructive, like the Log Out button that opened it: the confirm action reads in the error colour.
            dialog.getButton(DialogInterface.BUTTON_POSITIVE)?.let {
                it.setTextColor(MaterialColors.getColor(it, androidx.appcompat.R.attr.colorError))
            }
        }
    }

    /** Long-press copies [value] (never the displayed text, which carries break points) to the clipboard. */
    private fun copyOnLongPress(view: View, label: String, value: String) {
        view.setOnLongClickListener {
            val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
            // Android 13+ shows its own copy confirmation.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                Snackbar.make(requireView(), getString(R.string.lab_copied, label), Snackbar.LENGTH_SHORT).show()
            }
            true
        }
    }

    private fun logOut() {
        val app = requireActivity().application as ImpalaApp
        AppLogger.i("Settings", "User logged out")
        app.tokenManager.clearAll()
        ApiClient.reset()
        val intent = Intent(requireContext(), LoginActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        startActivity(intent)
    }

    /** The network chip: testnet in the warning family, the public network in the success family. */
    private fun bindNetworkChip() {
        val chip = binding.chipNetwork
        val testnet = BuildConfig.STELLAR_NETWORK != "pubnet"
        chip.text = getString(if (testnet) R.string.settings_network_testnet else R.string.settings_network_pubnet)
        val container = if (testnet) R.attr.colorStatusWarningContainer else R.attr.colorStatusSuccessContainer
        val onContainer = if (testnet) R.attr.colorOnStatusWarningContainer else R.attr.colorOnStatusSuccessContainer
        chip.chipBackgroundColor = android.content.res.ColorStateList.valueOf(MaterialColors.getColor(chip, container))
        chip.setTextColor(MaterialColors.getColor(chip, onContainer))
    }

    private fun showMfaEnrollmentDialog(accountId: String) {
        val options = arrayOf(getString(R.string.settings_mfa_totp), getString(R.string.settings_mfa_sms))
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
                    AppLogger.i("MFA", "TOTP enrollment successful")
                    Snackbar.make(requireView(), R.string.mfa_enrolled_totp, Snackbar.LENGTH_SHORT).show()
                    loadMfaStatus(accountId)
                } else {
                    AppLogger.w("MFA", "TOTP enrollment rejected: ${response.message}")
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                AppLogger.e("MFA", "TOTP enrollment failed: ${e.message}")
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
                    AppLogger.i("MFA", "SMS enrollment successful")
                    Snackbar.make(requireView(), R.string.mfa_enrolled_sms, Snackbar.LENGTH_SHORT).show()
                    loadMfaStatus(accountId)
                } else {
                    AppLogger.w("MFA", "SMS enrollment rejected: ${response.message}")
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                AppLogger.e("MFA", "SMS enrollment failed: ${e.message}")
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
                if (!isAdded) return@launch
                _binding?.tvVersion?.text = getString(
                    R.string.settings_bridge_version,
                    version.name, version.version, version.build_date,
                    version.schema_version ?: getString(R.string.not_available)
                )
            } catch (_: Exception) {
                if (!isAdded) return@launch
                _binding?.tvVersion?.text = getString(R.string.settings_bridge_offline)
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
                    if (!isAdded) return@launch
                    _binding?.tvMfaStatus?.text = if (types.isNotEmpty()) {
                        getString(R.string.settings_mfa_enrolled, types)
                    } else {
                        getString(R.string.mfa_not_enrolled)
                    }
                } else if (isAdded) {
                    _binding?.tvMfaStatus?.text = getString(R.string.mfa_not_enrolled)
                }
            } catch (_: Exception) {
                if (isAdded) _binding?.tvMfaStatus?.text = getString(R.string.mfa_not_enrolled)
            }
        }
    }

    private fun loadNotificationStatus() {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val subs = api.listSubscriptions().data
                val active = subs.count { it.enabled }
                if (!isAdded) return@launch
                _binding?.tvNotificationStatus?.text = if (subs.isEmpty()) {
                    getString(R.string.settings_notifications_none)
                } else {
                    resources.getQuantityString(R.plurals.settings_notifications_active, active, active)
                }
            } catch (_: Exception) {
                if (isAdded) _binding?.tvNotificationStatus?.text = getString(R.string.settings_notifications_unavailable)
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}

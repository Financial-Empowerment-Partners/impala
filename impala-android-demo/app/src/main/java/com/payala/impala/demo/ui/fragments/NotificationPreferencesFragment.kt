package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.databinding.FragmentNotificationPreferencesBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.CreateSubscriptionRequest
import com.payala.impala.demo.model.SubscriptionListItem
import com.payala.impala.demo.model.UpdateSubscriptionRequest
import kotlinx.coroutines.launch

/**
 * Fragment for managing notification event subscriptions.
 *
 * Displays a list of (event_type, medium) subscriptions with toggle switches
 * for enable/disable and a delete button. Users can add new subscriptions by
 * selecting an event type and delivery medium.
 */
class NotificationPreferencesFragment :
    Fragment(R.layout.fragment_notification_preferences) {

    private var _binding: FragmentNotificationPreferencesBinding? = null
    private val binding get() = _binding!!
    private val subscriptions = mutableListOf<SubscriptionListItem>()
    private lateinit var adapter: SubscriptionAdapter

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentNotificationPreferencesBinding.bind(view)

        adapter = SubscriptionAdapter(
            subscriptions,
            onToggle = { item, enabled -> updateSubscription(item.id, enabled) },
            onDelete = { item -> deleteSubscription(item.id) }
        )
        binding.rvSubscriptions.layoutManager = LinearLayoutManager(requireContext())
        binding.rvSubscriptions.adapter = adapter

        binding.btnAddSubscription.setOnClickListener { showAddDialog() }

        loadSubscriptions()
    }

    private fun loadSubscriptions() {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val items = api.listSubscriptions()
                subscriptions.clear()
                subscriptions.addAll(items)
                adapter.notifyDataSetChanged()
                updateEmptyState()
            } catch (e: Exception) {
                AppLogger.e("NotifPref", "Failed to load subscriptions: ${e.message}")
                Snackbar.make(requireView(), "Failed to load subscriptions", Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    private fun updateSubscription(id: Int, enabled: Boolean) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                api.updateSubscription(id, UpdateSubscriptionRequest(enabled = enabled))
            } catch (e: Exception) {
                AppLogger.e("NotifPref", "Failed to update subscription: ${e.message}")
                Snackbar.make(requireView(), "Failed to update", Snackbar.LENGTH_SHORT).show()
                loadSubscriptions() // Reload to reset UI
            }
        }
    }

    private fun deleteSubscription(id: Int) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                api.deleteSubscription(id)
                loadSubscriptions()
            } catch (e: Exception) {
                AppLogger.e("NotifPref", "Failed to delete subscription: ${e.message}")
                Snackbar.make(requireView(), "Failed to delete", Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    private fun showAddDialog() {
        val eventTypes = arrayOf(
            "Login Success" to "login_success",
            "Login Failure" to "login_failure",
            "Password Change" to "password_change",
            "Incoming Transfer" to "transfer_incoming",
            "Outgoing Transfer" to "transfer_outgoing",
            "Profile Updated" to "profile_updated",
        )
        val mediums = arrayOf(
            "Push Notification" to "mobile_push",
            "SMS" to "sms",
            "Email" to "email",
            "Webhook" to "webhook",
        )

        var selectedEvent = 0
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Select Event Type")
            .setSingleChoiceItems(eventTypes.map { it.first }.toTypedArray(), 0) { _, which ->
                selectedEvent = which
            }
            .setPositiveButton("Next") { _, _ ->
                // Second dialog: select medium
                var selectedMedium = 0
                MaterialAlertDialogBuilder(requireContext())
                    .setTitle("Select Delivery Channel")
                    .setSingleChoiceItems(mediums.map { it.first }.toTypedArray(), 0) { _, which ->
                        selectedMedium = which
                    }
                    .setPositiveButton("Subscribe") { _, _ ->
                        createSubscription(
                            eventTypes[selectedEvent].second,
                            mediums[selectedMedium].second
                        )
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun createSubscription(eventType: String, medium: String) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val response = api.createSubscription(
                    CreateSubscriptionRequest(event_type = eventType, medium = medium)
                )
                if (response.success) {
                    Snackbar.make(requireView(), "Subscription added", Snackbar.LENGTH_SHORT).show()
                    loadSubscriptions()
                } else {
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                AppLogger.e("NotifPref", "Failed to create subscription: ${e.message}")
                Snackbar.make(requireView(), "Failed to create subscription", Snackbar.LENGTH_SHORT).show()
            }
        }
    }

    private fun updateEmptyState() {
        binding.tvEmpty.visibility = if (subscriptions.isEmpty()) View.VISIBLE else View.GONE
        binding.rvSubscriptions.visibility = if (subscriptions.isEmpty()) View.GONE else View.VISIBLE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    // ── RecyclerView Adapter ──────────────────────────────────────────

    private class SubscriptionAdapter(
        private val items: List<SubscriptionListItem>,
        private val onToggle: (SubscriptionListItem, Boolean) -> Unit,
        private val onDelete: (SubscriptionListItem) -> Unit,
    ) : RecyclerView.Adapter<SubscriptionAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvEventType: TextView = view.findViewById(R.id.tvEventType)
            val tvMedium: TextView = view.findViewById(R.id.tvMedium)
            val switchEnabled: MaterialSwitch = view.findViewById(R.id.switchEnabled)
            val btnDelete: ImageButton = view.findViewById(R.id.btnDelete)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = android.view.LayoutInflater.from(parent.context)
                .inflate(R.layout.item_subscription, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvEventType.text = formatEventType(item.event_type)
            holder.tvMedium.text = formatMedium(item.medium)

            holder.switchEnabled.setOnCheckedChangeListener(null)
            holder.switchEnabled.isChecked = item.enabled
            holder.switchEnabled.setOnCheckedChangeListener { _, isChecked ->
                onToggle(item, isChecked)
            }

            holder.btnDelete.setOnClickListener { onDelete(item) }
        }

        override fun getItemCount() = items.size

        private fun formatEventType(type: String): String = when (type) {
            "login_success" -> "Login Success"
            "login_failure" -> "Login Failure"
            "password_change" -> "Password Change"
            "transfer_incoming" -> "Incoming Transfer"
            "transfer_outgoing" -> "Outgoing Transfer"
            "profile_updated" -> "Profile Updated"
            else -> type
        }

        private fun formatMedium(medium: String): String = when (medium) {
            "mobile_push" -> "Push Notification"
            "sms" -> "SMS"
            "email" -> "Email"
            "webhook" -> "Webhook"
            else -> medium
        }
    }
}

package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.databinding.FragmentTransfersBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.CreateTransactionRequest
import kotlinx.coroutines.launch
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

/**
 * Displays recent Stellar/Payala transfers in a [RecyclerView].
 *
 * Each item shows the transaction ID, source account, amount, timestamp, and a
 * status chip (Confirmed / Pending). The FAB opens a dialog to create a new
 * transaction via the bridge's `POST /transaction` endpoint. Transactions are
 * maintained locally (the bridge has no GET /transaction list endpoint).
 */
class TransfersFragment : Fragment(R.layout.fragment_transfers) {

    private var _binding: FragmentTransfersBinding? = null
    private val binding get() = _binding!!

    /** Represents a single transfer displayed in the list. */
    data class TransferItem(
        val txId: String,
        val sourceAccount: String,
        val amount: String,
        val timestamp: String,
        val status: String
    )

    private val transfers = mutableListOf<TransferItem>()
    private lateinit var adapter: TransfersAdapter

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentTransfersBinding.bind(view)

        adapter = TransfersAdapter(transfers)
        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter
        updateEmptyState()

        binding.fabNewTransfer.setOnClickListener {
            showNewTransferDialog()
        }
    }

    private fun showNewTransferDialog() {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_new_transfer, null)

        val etSourceAccount = dialogView.findViewById<EditText>(R.id.etSourceAccount)
        val etAmount = dialogView.findViewById<EditText>(R.id.etAmount)
        val etMemo = dialogView.findViewById<EditText>(R.id.etMemo)
        val etCurrency = dialogView.findViewById<EditText>(R.id.etCurrency)

        // Pre-fill source account from token manager
        val app = requireActivity().application as ImpalaApp
        val accountId = app.tokenManager.getAccountId()
        if (accountId != null) {
            etSourceAccount.setText(accountId)
        }

        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.dialog_new_transfer_title)
            .setView(dialogView)
            .setPositiveButton(R.string.dialog_submit) { _, _ ->
                val sourceAccount = etSourceAccount.text.toString().trim()
                val amount = etAmount.text.toString().trim()
                val memo = etMemo.text.toString().trim()
                val currency = etCurrency.text.toString().trim().ifEmpty { "XLM" }

                if (sourceAccount.isEmpty() || amount.isEmpty()) {
                    Snackbar.make(requireView(), R.string.error_fields_required, Snackbar.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                createTransaction(sourceAccount, amount, memo, currency)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun createTransaction(sourceAccount: String, amount: String, memo: String, currency: String) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val response = api.createTransaction(
                    CreateTransactionRequest(
                        source_account = sourceAccount,
                        memo = memo.ifEmpty { null },
                        payala_currency = currency
                    )
                )
                if (response.success) {
                    AppLogger.i("Transfer", "Transaction created: ${response.btxid} ($amount $currency)")
                    val timestamp = LocalDateTime.now()
                        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
                    transfers.add(
                        0,
                        TransferItem(
                            txId = response.btxid ?: "pending",
                            sourceAccount = sourceAccount,
                            amount = "$amount $currency",
                            timestamp = timestamp,
                            status = "Pending"
                        )
                    )
                    adapter.notifyItemInserted(0)
                    binding.recyclerView.scrollToPosition(0)
                    updateEmptyState()
                    Snackbar.make(requireView(), R.string.transfer_created, Snackbar.LENGTH_SHORT).show()
                } else {
                    AppLogger.w("Transfer", "Transaction rejected: ${response.message}")
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                AppLogger.e("Transfer", "Transaction failed: ${e.message}")
                Snackbar.make(
                    requireView(),
                    "${getString(R.string.transfer_failed)}: ${e.message}",
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun updateEmptyState() {
        if (transfers.isEmpty()) {
            binding.emptyState.visibility = View.VISIBLE
            binding.recyclerView.visibility = View.GONE
        } else {
            binding.emptyState.visibility = View.GONE
            binding.recyclerView.visibility = View.VISIBLE
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private class TransfersAdapter(
        private val items: List<TransferItem>
    ) : RecyclerView.Adapter<TransfersAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvTxId: TextView = view.findViewById(R.id.tvTxId)
            val tvSourceAccount: TextView = view.findViewById(R.id.tvSourceAccount)
            val tvAmount: TextView = view.findViewById(R.id.tvAmount)
            val tvTimestamp: TextView = view.findViewById(R.id.tvTimestamp)
            val chipStatus: Chip = view.findViewById(R.id.chipStatus)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_transfer, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val transfer = items[position]
            holder.tvTxId.text = transfer.txId
            holder.tvSourceAccount.text = transfer.sourceAccount
            holder.tvAmount.text = transfer.amount
            holder.tvTimestamp.text = transfer.timestamp
            holder.chipStatus.text = transfer.status
        }

        override fun getItemCount() = items.size
    }
}

package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.FragmentTransfersBinding

/**
 * Displays recent Stellar/Payala transfers in a [RecyclerView].
 *
 * Each item shows the transaction ID, source account, amount, timestamp, and a
 * status chip (Confirmed / Pending). The FAB stubs out the "new transfer" flow.
 * Currently uses placeholder data.
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

    // Placeholder data for the demo
    private val transfers = listOf(
        TransferItem(
            "a3f1b2c4-...-d8e9",
            "GBXYZ...MNOP",
            "100.00 XLM",
            "2025-06-15 14:30",
            "Confirmed"
        ),
        TransferItem(
            "f7e2d1a3-...-c6b5",
            "GABCD...EFGH",
            "50.00 XLM",
            "2025-06-14 09:15",
            "Pending"
        ),
        TransferItem(
            "b8c3a4f5-...-e1d2",
            "GKLMN...PQRS",
            "250.00 XLM",
            "2025-06-13 18:45",
            "Confirmed"
        )
    )

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentTransfersBinding.bind(view)

        if (transfers.isEmpty()) {
            binding.emptyState.visibility = View.VISIBLE
            binding.recyclerView.visibility = View.GONE
        } else {
            binding.emptyState.visibility = View.GONE
            binding.recyclerView.visibility = View.VISIBLE
        }

        val adapter = TransfersAdapter(transfers)
        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter

        binding.fabNewTransfer.setOnClickListener {
            Snackbar.make(view, "New transfer flow (demo)", Snackbar.LENGTH_SHORT).show()
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

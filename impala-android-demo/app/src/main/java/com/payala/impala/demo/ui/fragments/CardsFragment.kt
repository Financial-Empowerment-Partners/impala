package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.FragmentCardsBinding

/**
 * Displays registered smartcards in a [RecyclerView].
 *
 * Each card shows its ID, EC public-key fingerprint, and registration date.
 * A delete button triggers a confirmation dialog. The FAB stubs out NFC card
 * registration. Currently uses placeholder data.
 */
class CardsFragment : Fragment(R.layout.fragment_cards) {

    private var _binding: FragmentCardsBinding? = null
    private val binding get() = _binding!!

    /** Represents a registered Impala smartcard. */
    data class CardItem(
        val cardId: String,
        val ecPubkeyFingerprint: String,
        val registeredDate: String
    )

    // Placeholder data for the demo
    private val cards = mutableListOf(
        CardItem("CARD-001", "04:A2:3B:C7:...:F1", "2025-01-15"),
        CardItem("CARD-002", "04:B7:1C:D8:...:E3", "2025-03-22"),
        CardItem("CARD-003", "04:F9:4E:A1:...:B6", "2025-06-10")
    )

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentCardsBinding.bind(view)

        val adapter = CardsAdapter(cards) { card, position ->
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.dialog_delete_card_title)
                .setMessage(getString(R.string.dialog_delete_card_message, card.cardId))
                .setPositiveButton("Delete") { _, _ ->
                    cards.removeAt(position)
                    binding.recyclerView.adapter?.notifyItemRemoved(position)
                    updateEmptyState()
                    Snackbar.make(view, "Card ${card.cardId} deleted", Snackbar.LENGTH_SHORT).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter
        updateEmptyState()

        binding.fabRegisterCard.setOnClickListener {
            Snackbar.make(view, "Tap an NFC card to register", Snackbar.LENGTH_LONG).show()
        }
    }

    private fun updateEmptyState() {
        if (cards.isEmpty()) {
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

    private class CardsAdapter(
        private val items: List<CardItem>,
        private val onDelete: (CardItem, Int) -> Unit
    ) : RecyclerView.Adapter<CardsAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvCardId: TextView = view.findViewById(R.id.tvCardId)
            val tvPubkeyFingerprint: TextView = view.findViewById(R.id.tvPubkeyFingerprint)
            val tvDate: TextView = view.findViewById(R.id.tvDate)
            val btnDelete: ImageButton = view.findViewById(R.id.btnDelete)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_card, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val card = items[position]
            holder.tvCardId.text = card.cardId
            holder.tvPubkeyFingerprint.text = card.ecPubkeyFingerprint
            holder.tvDate.text = card.registeredDate
            holder.btnDelete.setOnClickListener {
                onDelete(card, position)
            }
        }

        override fun getItemCount() = items.size
    }
}

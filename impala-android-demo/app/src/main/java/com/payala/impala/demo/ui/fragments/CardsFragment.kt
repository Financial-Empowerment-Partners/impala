package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.auth.NfcCardResult
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.databinding.FragmentCardsBinding
import com.payala.impala.demo.model.CreateCardRequest
import com.payala.impala.demo.model.DeleteCardRequest
import com.payala.impala.demo.ui.main.MainActivity
import kotlinx.coroutines.launch
import java.time.LocalDate

/**
 * Displays registered smartcards in a [RecyclerView].
 *
 * Each card shows its ID, EC public-key fingerprint, and registration date.
 * A delete button triggers a confirmation dialog that calls `DELETE /card`
 * on the bridge API. The FAB initiates NFC card registration via the
 * bridge's `POST /card` endpoint using the card's public keys read over NFC.
 *
 * Card data is maintained locally (the bridge has no GET /card list endpoint).
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

    private val cards = mutableListOf<CardItem>()
    private lateinit var adapter: CardsAdapter

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentCardsBinding.bind(view)

        adapter = CardsAdapter(cards) { card, position ->
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.dialog_delete_card_title)
                .setMessage(getString(R.string.dialog_delete_card_message, card.cardId))
                .setPositiveButton("Delete") { _, _ ->
                    deleteCard(card, position)
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter
        updateEmptyState()

        binding.fabRegisterCard.setOnClickListener {
            val mainActivity = requireActivity() as MainActivity
            if (!mainActivity.nfcHelper.isNfcEnabled) {
                Snackbar.make(view, R.string.nfc_disabled, Snackbar.LENGTH_LONG).show()
                return@setOnClickListener
            }

            Snackbar.make(view, R.string.nfc_tap_prompt, Snackbar.LENGTH_LONG).show()
            mainActivity.nfcCallback = { result ->
                mainActivity.nfcCallback = null
                when (result) {
                    is NfcCardResult.Success -> registerCard(result)
                    is NfcCardResult.Error ->
                        Snackbar.make(view, result.message, Snackbar.LENGTH_SHORT).show()
                    is NfcCardResult.NfcNotAvailable ->
                        Snackbar.make(view, R.string.nfc_not_available, Snackbar.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun registerCard(result: NfcCardResult.Success) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)
        val accountId = app.tokenManager.getAccountId() ?: return

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val ecHex = result.ecPubKey.joinToString("") { "%02x".format(it) }
                val rsaHex = result.rsaPubKey.joinToString("") { "%02x".format(it) }
                val response = api.createCard(
                    CreateCardRequest(
                        account_id = accountId,
                        card_id = result.user.cardId,
                        ec_pubkey = ecHex,
                        rsa_pubkey = rsaHex
                    )
                )
                if (response.success) {
                    AppLogger.i("Cards", "Card registered: ${result.user.cardId}")
                    val fingerprint = ecHex.take(20).chunked(2).joinToString(":")
                    cards.add(
                        CardItem(
                            result.user.cardId,
                            fingerprint,
                            LocalDate.now().toString()
                        )
                    )
                    adapter.notifyItemInserted(cards.size - 1)
                    updateEmptyState()
                    Snackbar.make(requireView(), R.string.card_registered, Snackbar.LENGTH_SHORT).show()
                } else {
                    AppLogger.w("Cards", "Card registration rejected: ${response.message}")
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                AppLogger.e("Cards", "Card registration failed: ${e.message}")
                Snackbar.make(
                    requireView(),
                    "${getString(R.string.card_registration_failed)}: ${e.message}",
                    Snackbar.LENGTH_SHORT
                ).show()
            }
        }
    }

    private fun deleteCard(card: CardItem, position: Int) {
        val app = requireActivity().application as ImpalaApp
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val response = api.deleteCard(DeleteCardRequest(card.cardId))
                if (response.success) {
                    AppLogger.i("Cards", "Card deleted: ${card.cardId}")
                    cards.removeAt(position)
                    adapter.notifyItemRemoved(position)
                    updateEmptyState()
                    Snackbar.make(requireView(), "Card ${card.cardId} deleted", Snackbar.LENGTH_SHORT).show()
                } else {
                    AppLogger.w("Cards", "Card deletion rejected: ${response.message}")
                    Snackbar.make(requireView(), response.message, Snackbar.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                AppLogger.e("Cards", "Card deletion failed: ${e.message}")
                Snackbar.make(requireView(), "Delete failed: ${e.message}", Snackbar.LENGTH_SHORT).show()
            }
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
        // Clear NFC callback when fragment is destroyed
        (activity as? MainActivity)?.nfcCallback = null
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

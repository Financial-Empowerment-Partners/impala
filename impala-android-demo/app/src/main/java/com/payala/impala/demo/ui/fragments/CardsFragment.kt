package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.payala.impala.card.CardErrorMessages
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.databinding.FragmentCardsBinding
import com.payala.impala.demo.ui.cards.CardsViewModel
import com.payala.impala.demo.ui.cards.CardsViewModel.Event
import com.payala.impala.demo.ui.cards.CardsViewModel.Refusal
import com.payala.impala.demo.ui.main.MainActivity

/**
 * Registered smartcards of the signed-in account.
 *
 * The list is this device's local record ([CardStore], per account, survives
 * logout); the bridge has no card-list endpoint. The FAB registers a card:
 * the card is read through the activity's reader mode and checked
 * ([CardsViewModel.checkRegistrable]) before `POST /card`. Tapping a card on
 * this screen without pressing the FAB offers to register it.
 */
class CardsFragment : Fragment(R.layout.fragment_cards) {

    private var _binding: FragmentCardsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: CardsViewModel by viewModels()

    private lateinit var adapter: CardsAdapter
    private lateinit var store: CardStore

    private val app get() = requireActivity().application as ImpalaApp
    private val api get() = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentCardsBinding.bind(view)
        store = CardStore(requireContext())

        adapter = CardsAdapter(getString(R.string.card_local_record)) { card ->
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.dialog_delete_card_title)
                .setMessage(getString(R.string.dialog_delete_card_message, card.cardId))
                .setPositiveButton("Delete") { _, _ ->
                    val accountId = app.tokenManager.getAccountId() ?: return@setPositiveButton
                    viewModel.delete(api, store, accountId, card.cardId)
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter

        viewModel.cards.observe(viewLifecycleOwner) { cards ->
            adapter.submit(cards)
            binding.emptyState.visibility = if (cards.isEmpty()) View.VISIBLE else View.GONE
            binding.recyclerView.visibility = if (cards.isEmpty()) View.GONE else View.VISIBLE
        }
        viewModel.events.observe(viewLifecycleOwner) { event ->
            if (event != null) {
                Snackbar.make(view, describe(event), Snackbar.LENGTH_LONG).show()
                viewModel.eventHandled()
            }
        }
        viewModel.load(store, app.tokenManager.getAccountId())

        binding.fabRegisterCard.setOnClickListener {
            val main = requireActivity() as MainActivity
            if (!main.cardReader.isNfcEnabled) {
                Snackbar.make(view, R.string.nfc_disabled, Snackbar.LENGTH_LONG).show()
                return@setOnClickListener
            }
            Snackbar.make(view, R.string.nfc_tap_prompt, Snackbar.LENGTH_LONG).show()
            main.awaitCardTap(
                onTap = { session -> session.identity },
                onResult = { result ->
                    if (_binding == null) return@awaitCardTap
                    result.fold(
                        onSuccess = { identity -> register(identity) },
                        onFailure = { e -> Snackbar.make(view, failureMessage(e), Snackbar.LENGTH_LONG).show() }
                    )
                }
            )
        }
    }

    override fun onResume() {
        super.onResume()
        (activity as? MainActivity)?.idleCardTapListener = { identity -> offerRegistration(identity) }
    }

    override fun onPause() {
        super.onPause()
        (activity as? MainActivity)?.idleCardTapListener = null
    }

    private fun register(identity: CardIdentity) {
        viewModel.register(api, store, app.tokenManager.getAccountId(), identity)
    }

    private fun offerRegistration(identity: CardIdentity) {
        val accountId = app.tokenManager.getAccountId() ?: return
        if (store.find(accountId, identity.wireCardId) != null) return
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.card_offer_register)
            .setMessage(identity.wireCardId)
            .setPositiveButton(R.string.btn_register_card) { _, _ -> register(identity) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun failureMessage(e: Throwable): String =
        if (e is CardFlowException) CardErrorMessages.message(requireContext(), e.error, BuildConfig.DEBUG)
        else "${getString(R.string.card_registration_failed)}: ${e.message ?: e.javaClass.simpleName}"

    private fun describe(event: Event): String = when (event) {
        is Event.Registered -> getString(R.string.card_registered)
        is Event.Refused -> when (event.refusal) {
            Refusal.WRONG_VERSION -> getString(R.string.card_refused_wrong_version, event.detail)
            Refusal.NOT_PERSONALIZED -> getString(R.string.card_refused_not_personalized)
            Refusal.ACCOUNT_MISMATCH -> getString(R.string.card_refused_account_mismatch)
            Refusal.NO_SESSION -> getString(R.string.card_refused_no_session)
        }
        is Event.BridgeRefused -> event.message
        is Event.Failed -> "${getString(R.string.card_registration_failed)}: ${event.message}"
        is Event.Deleted -> "Card ${event.cardId} deleted"
        is Event.DeleteFailed -> "Delete failed: ${event.message}"
    }

    override fun onDestroyView() {
        super.onDestroyView()
        (activity as? MainActivity)?.cancelCardTap()
        _binding = null
    }

    private class CardsAdapter(
        private val localLabel: String,
        private val onDelete: (StoredCard) -> Unit
    ) : RecyclerView.Adapter<CardsAdapter.ViewHolder>() {
        private var items: List<StoredCard> = emptyList()

        fun submit(cards: List<StoredCard>) {
            items = cards
            @Suppress("NotifyDataSetChanged")
            notifyDataSetChanged()
        }

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvCardId: TextView = view.findViewById(R.id.tvCardId)
            val tvPubkeyFingerprint: TextView = view.findViewById(R.id.tvPubkeyFingerprint)
            val tvDate: TextView = view.findViewById(R.id.tvDate)
            val btnDelete: ImageButton = view.findViewById(R.id.btnDelete)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
            ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_card, parent, false))

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val card = items[position]
            val ctx = holder.itemView.context
            holder.tvCardId.text = card.cardId
            holder.tvPubkeyFingerprint.text = card.pubkeyFingerprint
            holder.tvDate.text = listOf(
                card.registeredAt.take(10),
                ctx.getString(R.string.card_state_issued, card.appletVersion, card.currency),
                localLabel
            ).joinToString(" · ")
            holder.btnDelete.setOnClickListener { onDelete(card) }
        }

        override fun getItemCount() = items.size
    }
}

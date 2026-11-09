package com.payala.impala.demo.ui.fragments

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.widget.PopupMenu
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.impala.sdk.flows.CardIdentity
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.databinding.FragmentCardsBinding
import com.payala.impala.demo.ui.cards.CardPresentation
import com.payala.impala.demo.ui.cards.CardsViewModel
import com.payala.impala.demo.ui.cards.CardsViewModel.Event
import com.payala.impala.demo.ui.cards.CardsViewModel.IssuerState
import com.payala.impala.demo.ui.cards.CardsViewModel.ProgramMismatchPolicy
import com.payala.impala.demo.ui.cards.CardsViewModel.Refusal
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.main.MainActivity
import com.payala.impala.demo.ui.tap.TapPrompt

/**
 * Registered smartcards of the signed-in account, as card faces.
 *
 * The list is this device's local record ([CardStore], per account, survives
 * logout); the bridge has no card-list endpoint. The FAB registers a card:
 * the card is read through the activity's reader mode with the tap sheet
 * (simulated card, NFC on, or a Failed sheet explaining why not), checked
 * ([CardsViewModel.checkRegistrable] and the program check) and posted; the
 * sheet says Done only after `POST /card` succeeded. Tapping a card on this
 * screen without pressing the FAB offers to register it.
 */
class CardsFragment : Fragment(R.layout.fragment_cards) {

    private var _binding: FragmentCardsBinding? = null
    private val binding get() = _binding!!
    private val viewModel: CardsViewModel by viewModels()

    private lateinit var adapter: CardsAdapter
    private lateinit var store: CardStore

    private val app get() = requireActivity().application as ImpalaApp
    private val api get() = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)
    private val main get() = activity as? MainActivity

    /** Program-mismatch rule at registration: live refuses, testnet warns (test-issuer login cards stay usable). */
    private val policy: ProgramMismatchPolicy
        get() = if (BuildConfig.FLAVOR == "live") ProgramMismatchPolicy.REFUSE else ProgramMismatchPolicy.WARN

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentCardsBinding.bind(view)
        store = CardStore(requireContext())

        adapter = CardsAdapter(::onCardMenu)
        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter

        viewModel.cards.observe(viewLifecycleOwner) { cards ->
            adapter.submitList(cards)
            binding.emptyState.visibility = if (cards.isEmpty()) View.VISIBLE else View.GONE
            binding.recyclerView.visibility = if (cards.isEmpty()) View.GONE else View.VISIBLE
        }
        viewModel.issuer.observe(viewLifecycleOwner) { issuer ->
            adapter.bridgeProgramIdHex = (issuer as? IssuerState.Known)?.programIdHex
        }
        viewModel.events.observe(viewLifecycleOwner) { event ->
            if (event != null) {
                handle(event)
                viewModel.eventHandled()
            }
        }
        viewModel.load(store, app.tokenManager.getAccountId())
        viewModel.loadIssuer(api)

        binding.fabRegisterCard.setOnClickListener { registerWithTap() }
    }

    override fun onResume() {
        super.onResume()
        main?.idleCardTapListener = { identity -> offerRegistration(identity) }
    }

    override fun onPause() {
        super.onPause()
        main?.idleCardTapListener = null
    }

    private fun registerWithTap() {
        val host = main ?: return
        host.awaitCardTap(
            TapPrompt.Register,
            onTap = { session -> session.identity },
            onResult = { result ->
                // The view may be gone (rotation): nothing was registered; the user taps again.
                if (!isAdded || _binding == null) {
                    host.tapViewModel.hide()
                    return@awaitCardTap
                }
                result.fold(
                    onSuccess = { identity ->
                        host.tapViewModel.finishing(R.string.tap_finishing_register)
                        register(identity)
                    },
                    onFailure = { e -> host.showTapFailure(e) }
                )
            }
        )
    }

    private fun register(identity: CardIdentity, acknowledged: Boolean = false) {
        viewModel.register(api, store, app.tokenManager.getAccountId(), identity, policy, acknowledged)
    }

    /** A follow-up registration with no tap before it: the sheet shows Finishing, then the outcome. */
    private fun registerWithSheet(identity: CardIdentity, acknowledged: Boolean) {
        main?.tapViewModel?.followUp(TapPrompt.Register, R.string.tap_finishing_register)
        register(identity, acknowledged)
    }

    private fun offerRegistration(identity: CardIdentity) {
        if (!isAdded || _binding == null) return
        val accountId = app.tokenManager.getAccountId() ?: return
        if (store.find(accountId, identity.wireCardId) != null) return
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.card_offer_register)
            .setMessage(CardPresentation.groupedId(identity.wireCardId))
            .setPositiveButton(R.string.btn_register_card) { _, _ -> registerWithSheet(identity, acknowledged = false) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun handle(event: Event) {
        val tap = main?.tapViewModel
        fun outcome(message: String) {
            if (tap != null && tap.isActive) tap.failed(message, null, warning = false, hasRecovery = false)
            else main?.snackbar(message)
        }
        when (event) {
            is Event.Registered -> {
                if (tap != null && tap.isActive) tap.succeeded(R.string.tap_done_registered)
                else main?.snackbar(getString(R.string.card_registered))
            }
            is Event.Refused -> outcome(refusalMessage(event))
            is Event.BridgeRefused -> outcome(event.message)
            is Event.Failed -> outcome("${getString(R.string.card_registration_failed)}: ${event.message}")
            is Event.ProgramMismatch -> {
                tap?.hide()
                MaterialAlertDialogBuilder(requireContext())
                    .setTitle(R.string.cards_mismatch_title)
                    .setMessage(getString(R.string.cards_mismatch_message, event.bridgeProgramIdHex))
                    .setPositiveButton(R.string.cards_mismatch_register) { _, _ -> registerWithSheet(event.identity, acknowledged = true) }
                    .setNegativeButton(android.R.string.cancel) { _, _ -> nothingRegistered() }
                    .setOnCancelListener { nothingRegistered() }
                    .show()
            }
            is Event.IssuerUnknown -> {
                if (event.canAcknowledge) {
                    tap?.hide()
                    MaterialAlertDialogBuilder(requireContext())
                        .setTitle(R.string.cards_issuer_unknown_title)
                        .setMessage(R.string.cards_issuer_unknown_message)
                        .setPositiveButton(R.string.cards_mismatch_register) { _, _ -> registerWithSheet(event.identity, acknowledged = true) }
                        .setNegativeButton(android.R.string.cancel) { _, _ -> nothingRegistered() }
                        .setOnCancelListener { nothingRegistered() }
                        .show()
                } else {
                    outcome(getString(R.string.cards_issuer_unknown_refused))
                }
            }
            is Event.Deleted -> main?.snackbar(getString(R.string.cards_removed, event.cardId.takeLast(4)))
            is Event.DeleteFailed -> main?.snackbar(getString(R.string.cards_remove_failed, event.message))
        }
    }

    /** "Register anyway?" was declined: the sheet is already gone, so say that nothing changed. */
    private fun nothingRegistered() {
        if (!isAdded || _binding == null) return
        main?.snackbar(getString(R.string.cards_not_registered))
    }

    private fun refusalMessage(event: Event.Refused): String = when (event.refusal) {
        Refusal.WRONG_VERSION -> getString(R.string.card_refused_wrong_version, event.detail)
        Refusal.NOT_PERSONALIZED -> getString(R.string.card_refused_not_personalized)
        Refusal.ACCOUNT_MISMATCH -> getString(R.string.card_refused_account_mismatch)
        Refusal.NO_SESSION -> getString(R.string.card_refused_no_session)
        Refusal.WRONG_PROGRAM -> getString(R.string.card_refused_wrong_program)
    }

    private fun onCardMenu(card: StoredCard, anchor: View) {
        val popup = PopupMenu(requireContext(), anchor)
        popup.inflate(R.menu.card_item_menu)
        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_copy_card_id -> { copyId(card.cardId); true }
                R.id.action_inspect_card -> {
                    startActivity(LabIntents.open(requireContext(), LabIntents.TAB_DOCTOR, card.cardId))
                    true
                }
                R.id.action_remove_card -> { confirmRemove(card); true }
                else -> false
            }
        }
        popup.show()
    }

    private fun copyId(cardId: String) {
        val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(getString(R.string.cards_clip_label), cardId))
        // Android 13+ shows its own copy confirmation.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) main?.snackbar(getString(R.string.cards_id_copied))
    }

    private fun confirmRemove(card: StoredCard) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.dialog_delete_card_title)
            .setMessage(getString(R.string.dialog_delete_card_message, card.cardId))
            .setPositiveButton(R.string.cards_remove_confirm) { _, _ ->
                val accountId = app.tokenManager.getAccountId() ?: return@setPositiveButton
                viewModel.delete(api, store, accountId, card.cardId)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        main?.cancelCardTap()
        _binding = null
    }

    private class CardsAdapter(
        private val onMenu: (StoredCard, View) -> Unit
    ) : ListAdapter<StoredCard, CardsAdapter.ViewHolder>(DIFF) {

        var bridgeProgramIdHex: String? = null
            set(value) {
                if (field == value) return
                field = value
                @Suppress("NotifyDataSetChanged")
                notifyDataSetChanged()
            }

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val btnOverflow: ImageButton = view.findViewById(R.id.btnOverflow)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder =
            ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_card, parent, false))

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val card = getItem(position)
            CardFaceBinder.bind(holder.itemView, card, bridgeProgramIdHex)
            holder.btnOverflow.setOnClickListener { onMenu(card, it) }
        }

        companion object {
            val DIFF = object : DiffUtil.ItemCallback<StoredCard>() {
                override fun areItemsTheSame(a: StoredCard, b: StoredCard) = a.cardId == b.cardId
                override fun areContentsTheSame(a: StoredCard, b: StoredCard) = a == b
            }
        }
    }
}

/** Binds one card face ([R.layout.item_card]): identifiers only, never the holder name or balance. */
internal object CardFaceBinder {
    fun bind(view: View, card: StoredCard, bridgeProgramIdHex: String?) {
        val ctx = view.context
        val face = CardPresentation.face(card, bridgeProgramIdHex)
        view.findViewById<TextView>(R.id.tvCardId).text = face.groupedId
        view.findViewById<TextView>(R.id.tvCardLine).text =
            ctx.getString(R.string.cards_face_line, face.appletVersion, face.currency, face.registeredDate)
        view.findViewById<View>(R.id.chipRegistered).visibility =
            if (face.chip == CardPresentation.Chip.REGISTERED) View.VISIBLE else View.GONE
        view.findViewById<View>(R.id.chipMismatch).visibility =
            if (face.chip == CardPresentation.Chip.PROGRAM_MISMATCH) View.VISIBLE else View.GONE
        view.contentDescription = ctx.getString(R.string.cards_face_description, card.cardId)
        view.findViewById<View>(R.id.btnOverflow).contentDescription = ctx.getString(R.string.cards_more_actions, face.last4)
    }
}

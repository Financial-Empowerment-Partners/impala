package com.payala.impala.demo.ui.fragments

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.impala.sdk.flows.CardFlowException
import com.payala.impala.card.CardErrorMessages
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.databinding.FragmentTransfersBinding
import com.payala.impala.demo.transfer.IssuanceController
import com.payala.impala.demo.transfer.Money
import com.payala.impala.demo.transfer.PendingCredit
import com.payala.impala.demo.transfer.PendingRedemption
import com.payala.impala.demo.transfer.PendingTransferStore
import com.payala.impala.demo.transfer.RedemptionController
import com.payala.impala.demo.transfer.RedemptionRefused
import com.payala.impala.demo.ui.main.MainActivity
import com.payala.impala.demo.ui.transfer.TransfersViewModel
import com.payala.impala.demo.ui.transfer.TransfersViewModel.Event

/**
 * Card transfers: **Redeem from card** (the holder authorizes, with the card
 * PIN, a transfer of stored value back to their custodial Stellar account) and
 * **Load card** (a bridge-signed credit funded from the custodial account).
 * Amounts are integer card minor units. The bridge's `POST /transaction`
 * (which records external transactions) is not a transfer and is not offered.
 */
class TransfersFragment : Fragment(R.layout.fragment_transfers) {

    private var _binding: FragmentTransfersBinding? = null
    private val binding get() = _binding!!
    private val viewModel: TransfersViewModel by viewModels()
    private lateinit var adapter: TransferAdapter

    private val app get() = requireActivity().application as ImpalaApp
    private val main get() = requireActivity() as MainActivity

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _binding = FragmentTransfersBinding.bind(view)
        val api = ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, app.tokenManager)
        val store = PendingTransferStore(requireContext())
        viewModel.bind(RedemptionController(api, store), IssuanceController(api, store), store)

        adapter = TransferAdapter()
        binding.recyclerView.layoutManager = LinearLayoutManager(requireContext())
        binding.recyclerView.adapter = adapter
        viewModel.rows.observe(viewLifecycleOwner) { rows ->
            adapter.submit(rows)
            val empty = rows.redemptions.isEmpty() && rows.credits.isEmpty()
            binding.emptyState.visibility = if (empty) View.VISIBLE else View.GONE
            binding.recyclerView.visibility = if (empty) View.GONE else View.VISIBLE
        }
        viewModel.events.observe(viewLifecycleOwner) { event ->
            if (event != null) {
                handle(event)
                viewModel.eventHandled()
            }
        }
        binding.fabNewTransfer.setOnClickListener { chooseAction() }
    }

    private fun chooseAction() {
        val items = arrayOf(getString(R.string.transfer_action_redeem), getString(R.string.transfer_action_load))
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_choose_action)
            .setItems(items) { _, which -> chooseCard { card -> if (which == 0) redeemDialog(card) else loadDialog(card) } }
            .show()
    }

    private fun chooseCard(then: (StoredCard) -> Unit) {
        val accountId = app.tokenManager.getAccountId() ?: return
        val cards = CardStore(requireContext()).list(accountId)
        if (cards.isEmpty()) {
            snack(getString(R.string.transfer_no_cards))
            return
        }
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_choose_card)
            .setItems(cards.map { "${it.cardId} · ${it.currency}" }.toTypedArray()) { _, i -> then(cards[i]) }
            .show()
    }

    // ── Redeem ──────────────────────────────────────────────────────────

    private fun redeemDialog(card: StoredCard) {
        if (viewModel.redemptions.needsRecovery(card.cardId)) {
            offerResume(card)
            return
        }
        val form = amountForm(card, withPin = true)
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_action_redeem)
            .setView(form.root)
            .setPositiveButton(R.string.dialog_submit) { _, _ ->
                val amount = Money.parseCardAmount(form.amount.text?.toString().orEmpty())
                val pin = form.takePin()
                when {
                    amount == null -> { pin.fill('\u0000'); snack(getString(R.string.transfer_amount_invalid)) }
                    pin.size != 4 -> { pin.fill('\u0000'); snack(getString(R.string.transfer_pin_invalid)) }
                    pin.all { it == '0' } -> { pin.fill('\u0000'); snack(getString(R.string.transfer_pin_less_refused)) }
                    else -> viewModel.prepareRedemption(card.cardId) { prepared ->
                        snack(getString(R.string.transfer_tap_to_sign))
                        main.awaitCardTap(
                            onTap = { session -> viewModel.redemptions.signOnCard(session, prepared, card, amount, pin) },
                            onResult = { result ->
                                result.fold(
                                    onSuccess = { submit(card) },
                                    onFailure = { e -> pin.fill('\u0000'); cardFailure(e) }
                                )
                            }
                        )
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> form.takePin().fill('\u0000') }
            .show()
    }

    private fun offerResume(card: StoredCard) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_resume_offer)
            .setMessage(R.string.transfer_resume_message)
            .setPositiveButton(R.string.transfer_resume_offer) { _, _ ->
                snack(getString(R.string.transfer_tap_to_read))
                main.awaitCardTap(
                    onTap = { session -> viewModel.redemptions.recoverOnCard(session, card.cardId) },
                    onResult = { result ->
                        result.fold(
                            onSuccess = { recovered -> if (recovered != null) submit(card) else viewModel.refresh() },
                            onFailure = { e -> cardFailure(e) }
                        )
                    }
                )
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun submit(card: StoredCard) {
        val accountId = app.tokenManager.getAccountId() ?: return
        viewModel.refresh()
        viewModel.submitAndTrack(accountId, card.cardId)
    }

    // ── Load ────────────────────────────────────────────────────────────

    private fun loadDialog(card: StoredCard) {
        val form = amountForm(card, withPin = false)
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_action_load)
            .setView(form.root)
            .setPositiveButton(R.string.dialog_submit) { _, _ ->
                val amount = Money.parseCardAmount(form.amount.text?.toString().orEmpty())
                if (amount == null) {
                    snack(getString(R.string.transfer_amount_invalid))
                    return@setPositiveButton
                }
                val accountId = app.tokenManager.getAccountId() ?: return@setPositiveButton
                snack(getString(R.string.transfer_tap_to_read))
                main.awaitCardTap(
                    onTap = { session ->
                        val identity = session.identity.requirePersonalized()
                        require(identity.wireCardId == card.cardId) { getString(R.string.transfer_card_mismatch, identity.wireCardId) }
                        viewModel.issuances.observeReceiveCounter(session)
                    },
                    onResult = { result ->
                        result.fold(
                            onSuccess = { observed -> viewModel.createIssuance(accountId, card.cardId, amount, observed) },
                            onFailure = { e -> cardFailure(e) }
                        )
                    }
                )
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun fundDialog(credit: PendingCredit) {
        val accountId = app.tokenManager.getAccountId() ?: return
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_fund_title)
            .setMessage(getString(R.string.transfer_fund_message, credit.fundingAmount, "XLM", credit.fundingDestination, credit.fundingMemo))
            .setPositiveButton(R.string.transfer_fund_button) { _, _ ->
                viewModel.fund(accountId, credit.issuanceId, newAttempt = credit.fundingStatus == "rejected")
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun applyDialog(credit: PendingCredit) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_apply_button)
            .setMessage(getString(R.string.transfer_tap_to_apply))
            .setPositiveButton(R.string.transfer_apply_button) { _, _ ->
                main.awaitCardTap(
                    onTap = { session -> viewModel.issuances.applyOnCard(session, credit.issuanceId) },
                    onResult = { result ->
                        result.fold(
                            onSuccess = { applied ->
                                when (applied.ackStatusWord) {
                                    IssuanceController.EXCEPTION_SW -> snack(getString(R.string.transfer_credit_exception))
                                    "9000" -> viewModel.ack(applied.issuanceId)
                                    else -> {
                                        snack(getString(R.string.transfer_card_refused_credit, applied.ackStatusWord))
                                        viewModel.ack(applied.issuanceId)
                                    }
                                }
                            },
                            onFailure = { e -> cardFailure(e) }
                        )
                    }
                )
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ── Shared ──────────────────────────────────────────────────────────

    private class AmountForm(val root: View, val amount: TextInputEditText, val pin: TextInputEditText) {
        /** Copies the PIN out of the field as a CharArray and clears the field. */
        fun takePin(): CharArray {
            val e = pin.text ?: return CharArray(0)
            val out = CharArray(e.length)
            android.text.TextUtils.getChars(e, 0, e.length, out, 0)
            e.clear()
            return out
        }
    }

    private fun amountForm(card: StoredCard, withPin: Boolean): AmountForm {
        val root = layoutInflater.inflate(R.layout.dialog_card_amount, null)
        val amount = root.findViewById<TextInputEditText>(R.id.etAmount)
        val pin = root.findViewById<TextInputEditText>(R.id.etPin)
        val decimal = root.findViewById<TextView>(R.id.tvAmountDecimal)
        root.findViewById<TextView>(R.id.tvCard).text = "${card.cardId} · ${card.currency}"
        root.findViewById<View>(R.id.tilPin).visibility = if (withPin) View.VISIBLE else View.GONE
        amount.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val v = Money.parseCardAmount(s?.toString().orEmpty())
                // Display only; XLM cards use scale 7 (OD-5).
                decimal.text = if (v == null) "" else getString(R.string.transfer_amount_decimal, Money.format(v, 7), card.currency)
            }
        })
        return AmountForm(root, amount, pin)
    }

    private fun handle(event: Event) {
        when (event) {
            is Event.Message -> snack(
                when {
                    event.text == "fund:ambiguous" -> getString(R.string.transfer_fund_ambiguous)
                    event.text == "fund:rejected" -> getString(R.string.transfer_fund_rejected)
                    event.text == "redemption:frozen" -> getString(R.string.transfer_frozen)
                    event.text.startsWith("redemption:") -> getString(R.string.transfer_done_redeem, event.text.substringAfter(':'))
                    else -> getString(R.string.transfer_done_load, event.text.substringAfter(':'))
                }
            )
            is Event.Refused -> snack(
                when (event.refusal) {
                    RedemptionRefused.Refusal.ISSUER_UNCONFIGURED -> getString(R.string.transfer_issuer_unconfigured)
                    RedemptionRefused.Refusal.CARD_NOT_CERTIFIED -> getString(R.string.transfer_card_not_certified)
                    RedemptionRefused.Refusal.FROZEN_PENDING -> getString(R.string.transfer_frozen)
                    RedemptionRefused.Refusal.PENDING_EXISTS -> getString(R.string.transfer_pending_exists)
                    RedemptionRefused.Refusal.AMOUNT_INVALID -> getString(R.string.transfer_amount_invalid)
                    RedemptionRefused.Refusal.PIN_INVALID -> getString(R.string.transfer_pin_invalid)
                    RedemptionRefused.Refusal.PIN_LESS_REFUSED -> getString(R.string.transfer_pin_less_refused)
                    else -> event.detail ?: event.refusal.name
                }
            )
            is Event.IssuanceFailed -> snack(event.message ?: event.code)
            is Event.FundingNeeded -> fundDialog(event.credit)
            is Event.ReadyToApply -> applyDialog(event.credit)
            is Event.Failed -> snack(event.message)
        }
    }

    private fun cardFailure(e: Throwable) {
        if (e is CardFlowException) snack(CardErrorMessages.message(requireContext(), e.error, BuildConfig.DEBUG))
        else viewModel.failed(e)
    }

    private fun snack(text: String) {
        _binding?.let { Snackbar.make(it.root, text, Snackbar.LENGTH_LONG).show() }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        (activity as? MainActivity)?.cancelCardTap()
        _binding = null
    }

    private inner class TransferAdapter : RecyclerView.Adapter<TransferAdapter.ViewHolder>() {
        private var items: List<Any> = emptyList()

        fun submit(rows: TransfersViewModel.Rows) {
            items = rows.redemptions + rows.credits
            @Suppress("NotifyDataSetChanged")
            notifyDataSetChanged()
        }

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvTxId: TextView = view.findViewById(R.id.tvTxId)
            val tvSource: TextView = view.findViewById(R.id.tvSourceAccount)
            val tvAmount: TextView = view.findViewById(R.id.tvAmount)
            val tvTimestamp: TextView = view.findViewById(R.id.tvTimestamp)
            val chip: Chip = view.findViewById(R.id.chipStatus)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_transfer, parent, false))

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            when (val item = items[position]) {
                is PendingRedemption -> {
                    holder.tvTxId.text = item.redemptionId ?: getString(R.string.transfer_action_redeem)
                    holder.tvSource.text = item.cardId
                    holder.tvAmount.text = "-${item.amount}"
                    holder.tvTimestamp.text = when {
                        item.isFrozen -> getString(R.string.transfer_frozen)
                        item.state == PendingRedemption.STATE_REFUSED -> getString(R.string.transfer_refused_needs_operator, item.reason)
                        item.btxid != null -> "btxid ${item.btxid}"
                        else -> item.reason.orEmpty()
                    }
                    holder.chip.text = item.state
                    holder.itemView.setOnClickListener {
                        val accountId = app.tokenManager.getAccountId() ?: return@setOnClickListener
                        if (!item.isTerminal && item.tuple != null) viewModel.submitAndTrack(accountId, item.cardId)
                    }
                }
                is PendingCredit -> {
                    holder.tvTxId.text = item.issuanceRef ?: item.issuanceId
                    holder.tvSource.text = item.cardId
                    holder.tvAmount.text = "+${item.cardAmount}"
                    holder.tvTimestamp.text = listOfNotNull("funding ${item.fundingStatus}", item.ackStatusWord?.let { "SW $it" }).joinToString(" · ")
                    holder.chip.text = item.state
                    holder.itemView.setOnClickListener {
                        when {
                            item.state == "awaiting_funds" && item.fundingStatus in setOf("none", "rejected") -> fundDialog(item)
                            item.signableHex != null && item.ackStatusWord == null -> applyDialog(item)
                            item.ackStatusWord != null && !item.acked && item.ackStatusWord != IssuanceController.EXCEPTION_SW -> viewModel.ack(item.issuanceId)
                        }
                    }
                }
            }
        }

        override fun getItemCount() = items.size
    }
}

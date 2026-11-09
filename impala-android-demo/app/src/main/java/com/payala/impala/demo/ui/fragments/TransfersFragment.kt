package com.payala.impala.demo.ui.fragments

import android.content.res.ColorStateList
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.Chip
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.R
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.databinding.FragmentTransfersBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.transfer.IssuanceController
import com.payala.impala.demo.transfer.IssuanceRefused
import com.payala.impala.demo.transfer.Money
import com.payala.impala.demo.transfer.PendingCredit
import com.payala.impala.demo.transfer.PendingRedemption
import com.payala.impala.demo.transfer.PendingTransferStore
import com.payala.impala.demo.transfer.RedemptionController
import com.payala.impala.demo.transfer.RedemptionRefused
import com.payala.impala.demo.ui.main.MainActivity
import com.payala.impala.demo.ui.tap.TapPrompt
import com.payala.impala.demo.ui.tap.TapUiState
import com.payala.impala.demo.ui.tap.TapViewModel
import com.payala.impala.demo.ui.transfer.TransferPresentation
import com.payala.impala.demo.ui.transfer.TransferPresentation.RowAction
import com.payala.impala.demo.ui.transfer.TransferPresentation.Tone
import com.payala.impala.demo.ui.transfer.TransfersViewModel
import com.payala.impala.demo.ui.transfer.TransfersViewModel.Event
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import retrofit2.HttpException
import java.text.DateFormat
import java.util.Date

/**
 * Card transfers: **Redeem from card** (the holder authorizes, with the card
 * PIN, a transfer of stored value back to their custodial Stellar account) and
 * **Load card** (a bridge-signed credit funded from the custodial account).
 * Amounts are integer card minor units, shown with [Money.format] only. The
 * bridge's `POST /transaction` (which records external transactions) is not a
 * transfer and is not offered.
 *
 * Every card step runs through the tap sheet (MainActivity.awaitCardTap):
 * Done appears only after the real outcome (the submit for a redemption, the
 * ack for a credit). Money prompts never offer "Try again"; a failure offers
 * Resume only when a recovery slot exists, and Resume routes into the
 * existing recovery paths (recover the tuple from the card; re-present the
 * persisted credit), which never re-sign. Ambiguous and stranded outcomes are
 * persistent row banners ([TransferPresentation]), not Snackbars.
 *
 * Result callbacks check `isAdded` and the binding first: a signed tuple whose
 * result arrives after the view is gone stays "Ready to send" on its row
 * (never lost, never submitted twice).
 */
class TransfersFragment : Fragment(R.layout.fragment_transfers) {

    private var _binding: FragmentTransfersBinding? = null
    private val binding get() = _binding!!
    private val viewModel: TransfersViewModel by viewModels()
    private lateinit var adapter: TransferAdapter

    private val app get() = requireActivity().application as ImpalaApp
    private val main get() = activity as? MainActivity
    private val alive get() = isAdded && _binding != null

    /** GET /card-issuer: false = no card issuer on this bridge (banner, FAB explains); null = not known. */
    private var issuerConfigured: Boolean? = null

    /**
     * What the tap sheet's Finishing waits for (this view only). [sheet] is the
     * prompt of the sheet that waits; once that sheet is closed or replaced, the
     * outcome is never shown on a newer one (its row carries it).
     */
    private sealed class Watch(val sheet: TapPrompt?) {
        class Submit(val cardId: String, sheet: TapPrompt?) : Watch(sheet)
        class Ack(val issuanceId: String, sheet: TapPrompt?) : Watch(sheet)
        class Issuance(val cardId: String, sheet: TapPrompt?) : Watch(sheet)
    }

    private var watch: Watch? = null

    /** The prompt of the Busy sheet now up, if any. */
    private fun busyPrompt(): TapPrompt? = (main?.tapViewModel?.current as? TapUiState.Busy)?.prompt

    /** The tap view model, only while [w]'s own sheet is still the one up. */
    private fun sheetFor(w: Watch): TapViewModel? =
        main?.tapViewModel?.takeIf { w.sheet != null && busyPrompt() === w.sheet }

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
            adapter.show(rows, currencies())
            val empty = rows.redemptions.isEmpty() && rows.credits.isEmpty()
            binding.emptyState.visibility = if (empty) View.VISIBLE else View.GONE
            binding.recyclerView.visibility = if (empty) View.GONE else View.VISIBLE
            evaluateSubmitWatch(rows)
        }
        viewModel.events.observe(viewLifecycleOwner) { event ->
            if (event != null) {
                handle(event)
                viewModel.eventHandled()
            }
        }
        binding.fabNewTransfer.setOnClickListener { onNewTransfer() }
        checkIssuer(api)
    }

    // ── Issuer banner ───────────────────────────────────────────────────

    private fun checkIssuer(api: BridgeApiService) {
        viewLifecycleOwner.lifecycleScope.launch {
            val configured: Boolean? = try {
                api.cardIssuer().isConfigured
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                if (e.code() == 404) false else null
            } catch (e: Exception) {
                null
            }
            issuerConfigured = configured
            _binding?.bannerIssuer?.visibility = if (configured == false) View.VISIBLE else View.GONE
        }
    }

    private fun onNewTransfer() {
        if (issuerConfigured == false) {
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.transfers_offline_disabled_title)
                .setMessage(R.string.transfers_offline_disabled_body)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }
        chooseAction()
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
            .setItems(cards.map { "····${it.cardId.takeLast(4)} · ${it.currency}" }.toTypedArray()) { _, i -> then(cards[i]) }
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
                    else -> viewModel.prepareRedemption(card.cardId, orElse = { pin.fill('\u0000') }) { prepared ->
                        if (!alive) {
                            pin.fill('\u0000')
                            return@prepareRedemption
                        }
                        signOnCard(card, prepared, amount, pin)
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> form.takePin().fill('\u0000') }
            .show()
    }

    private fun signOnCard(card: StoredCard, prepared: RedemptionController.Prepared, amount: Long, pin: CharArray) {
        val host = main ?: run { pin.fill('\u0000'); return }
        val tap = host.tapViewModel
        val redemptions = viewModel.redemptions
        tap.onResume = { recoverFromCard(card) }
        host.awaitCardTap(
            TapPrompt.Sign(TapPrompt.suffixOf(card.cardId)),
            onTap = { session -> redemptions.signOnCard(session, prepared, card, amount, pin) },
            onResult = { result ->
                pin.fill('\u0000')
                if (!alive) {
                    // A signed tuple stays "Ready to send" on its row; it is never submitted from here.
                    if (result.isSuccess) AppLogger.i("Transfers", "Signed result arrived after the screen closed; left ready to send")
                    tap.hide()
                    return@awaitCardTap
                }
                result.fold(
                    onSuccess = { startSubmit(card.cardId) },
                    onFailure = { e -> moneyFailure(e, hasRecovery = redemptions.needsRecovery(card.cardId)) }
                )
            }
        )
    }

    /** Resume: rebuild a tuple the app lost from the card (GET_LAST_TRANSFER); never re-signs. */
    private fun recoverFromCard(card: StoredCard) {
        val host = main ?: return
        val tap = host.tapViewModel
        val redemptions = viewModel.redemptions
        host.awaitCardTap(
            TapPrompt.Read(TapPrompt.suffixOf(card.cardId)),
            onTap = { session -> redemptions.recoverOnCard(session, card.cardId) },
            onResult = { result ->
                if (!alive) {
                    tap.hide()
                    return@awaitCardTap
                }
                result.fold(
                    onSuccess = { recovered ->
                        if (recovered != null) {
                            startSubmit(card.cardId)
                        } else {
                            tap.finishing(R.string.tap_finishing_check)
                            tap.succeeded(R.string.tap_done_nothing_signed)
                            viewModel.refresh()
                        }
                    },
                    onFailure = { e -> host.showTapFailure(e) }
                )
            }
        )
    }

    private fun offerResume(card: StoredCard) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_resume_offer)
            .setMessage(R.string.transfer_resume_message)
            .setPositiveButton(R.string.transfer_resume_offer) { _, _ -> recoverFromCard(card) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** The card signed (or the tuple was recovered): submit, with the sheet waiting for the bridge's answer. */
    private fun startSubmit(cardId: String) {
        val accountId = app.tokenManager.getAccountId() ?: return
        val tap = main?.tapViewModel
        if (tap != null && tap.isActive) tap.finishing(R.string.tap_finishing_send)
        watch = Watch.Submit(cardId, busyPrompt())
        viewModel.refresh()
        viewModel.submitAndTrack(accountId, cardId)
    }

    /** A row's Send: the stored tuple is posted again, byte-identical (the bridge dedupes). */
    private fun sendFromRow(cardId: String) {
        main?.tapViewModel?.followUp(TapPrompt.Sign(TapPrompt.suffixOf(cardId)), R.string.tap_finishing_send)
        startSubmit(cardId)
    }

    private fun evaluateSubmitWatch(rows: TransfersViewModel.Rows) {
        val w = watch as? Watch.Submit ?: return
        val current = rows.redemptions.filter { it.cardId == w.cardId }.maxByOrNull { it.createdAt }
        val outcome = TransferPresentation.submitOutcome(current) ?: return
        watch = null
        val tap = sheetFor(w) ?: return
        when (outcome) {
            TransferPresentation.SubmitOutcome.ACCEPTED -> tap.succeeded(R.string.tap_done_sent)
            TransferPresentation.SubmitOutcome.REFUSED -> tap.failed(
                getString(R.string.transfer_refused_needs_operator, current?.reason.orEmpty()), null, warning = false, hasRecovery = false
            )
            TransferPresentation.SubmitOutcome.AMBIGUOUS -> tap.failed(getString(R.string.transfer_frozen), null, warning = true, hasRecovery = false)
        }
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
                readCounter(card, accountId, amount)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun readCounter(card: StoredCard, accountId: String, amount: Long) {
        val host = main ?: return
        val tap = host.tapViewModel
        val issuances = viewModel.issuances
        val mismatch = getString(R.string.transfer_card_mismatch, card.cardId)
        host.awaitCardTap(
            TapPrompt.Read(TapPrompt.suffixOf(card.cardId)),
            onTap = { session ->
                val identity = session.identity.requirePersonalized()
                require(identity.wireCardId == card.cardId) { mismatch }
                issuances.observeReceiveCounter(session)
            },
            onResult = { result ->
                if (!alive) {
                    tap.hide()
                    return@awaitCardTap
                }
                result.fold(
                    onSuccess = { observed ->
                        tap.finishing(R.string.tap_finishing_load)
                        watch = Watch.Issuance(card.cardId, busyPrompt())
                        viewModel.createIssuance(accountId, card.cardId, amount, observed)
                    },
                    onFailure = { e -> host.showTapFailure(e) }
                )
            }
        )
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

    /** "Apply to card": the confirm arms the sheet, which names the expected card. */
    private fun applyDialog(credit: PendingCredit) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.transfer_apply_button)
            .setMessage(getString(R.string.tap_hint_waiting_card, TapPrompt.suffixOf(credit.cardId)))
            .setPositiveButton(R.string.transfer_apply_button) { _, _ -> applyOnCard(credit.issuanceId, credit.cardId) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Applies the persisted credit. Re-presenting it (Resume after a torn
     * apply) is safe: the card's receive state decides whether it already
     * applied, and nothing is ever re-issued.
     */
    private fun applyOnCard(issuanceId: String, cardId: String) {
        val host = main ?: return
        val tap = host.tapViewModel
        val issuances = viewModel.issuances
        tap.onResume = { applyOnCard(issuanceId, cardId) }
        host.awaitCardTap(
            TapPrompt.Apply(TapPrompt.suffixOf(cardId)),
            onTap = { session -> issuances.applyOnCard(session, issuanceId) },
            onResult = { result ->
                if (!alive) {
                    tap.hide()
                    return@awaitCardTap
                }
                result.fold(
                    onSuccess = { applied ->
                        viewModel.refresh()
                        when (applied.ackStatusWord) {
                            IssuanceController.EXCEPTION_SW ->
                                tap.failed(getString(R.string.transfer_credit_exception), null, warning = false, hasRecovery = false)
                            "9000" -> {
                                tap.finishing(R.string.tap_finishing_ack)
                                watch = Watch.Ack(applied.issuanceId, busyPrompt())
                                viewModel.ack(applied.issuanceId)
                            }
                            else -> {
                                tap.failed(
                                    getString(R.string.transfer_card_refused_credit, applied.ackStatusWord),
                                    if (BuildConfig.DEBUG) applied.ackStatusWord else null,
                                    warning = false, hasRecovery = false
                                )
                                viewModel.ack(applied.issuanceId)
                            }
                        }
                    },
                    // Nothing decided (tag lost, wrong card): the persisted credit can be presented again.
                    onFailure = { e -> moneyFailure(e, hasRecovery = true) }
                )
            }
        )
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

    /** A money prompt failed: the sheet offers Resume only when [hasRecovery], never Try again. */
    private fun moneyFailure(e: Throwable, hasRecovery: Boolean) {
        val host = main ?: return
        viewModel.refresh()
        val refusal = refusalText(e)
        if (refusal != null) {
            if (host.tapViewModel.isActive) host.tapViewModel.failed(refusal, null, warning = false, hasRecovery = hasRecovery)
            else snack(refusal)
        } else {
            host.showTapFailure(e, hasRecovery = hasRecovery)
        }
    }

    private fun refusalText(e: Throwable): String? = when (e) {
        is RedemptionRefused -> refusalMessage(e.refusal, e.message)
        is IssuanceRefused -> e.message ?: e.code
        else -> null
    }

    private fun refusalMessage(refusal: RedemptionRefused.Refusal, detail: String?): String = when (refusal) {
        RedemptionRefused.Refusal.ISSUER_UNCONFIGURED -> getString(R.string.transfer_issuer_unconfigured)
        RedemptionRefused.Refusal.CARD_NOT_CERTIFIED -> getString(R.string.transfer_card_not_certified)
        RedemptionRefused.Refusal.FROZEN_PENDING -> getString(R.string.transfer_frozen)
        RedemptionRefused.Refusal.PENDING_EXISTS -> getString(R.string.transfer_pending_exists)
        RedemptionRefused.Refusal.AMOUNT_INVALID -> getString(R.string.transfer_amount_invalid)
        RedemptionRefused.Refusal.PIN_INVALID -> getString(R.string.transfer_pin_invalid)
        RedemptionRefused.Refusal.PIN_LESS_REFUSED -> getString(R.string.transfer_pin_less_refused)
        else -> detail ?: refusal.name
    }

    private fun handle(event: Event) {
        val w = watch
        val tap = w?.let(::sheetFor)
        when (event) {
            is Event.Message -> when {
                // Persistent row banners carry these; no Snackbar that disappears.
                event.text == "fund:ambiguous" || event.text == "redemption:frozen" -> Unit
                event.text == "fund:rejected" -> snack(getString(R.string.transfer_fund_rejected))
                event.text.startsWith("redemption:") -> snack(getString(R.string.transfer_done_redeem, event.text.substringAfter(':')))
                event.text.startsWith("load:") && w is Watch.Ack -> {
                    watch = null
                    if (tap != null) tap.succeeded(R.string.tap_done_loaded)
                    else snack(getString(R.string.transfer_done_load, event.text.substringAfter(':')))
                }
                else -> snack(getString(R.string.transfer_done_load, event.text.substringAfter(':')))
            }
            is Event.Refused -> failOrSnack(refusalMessage(event.refusal, event.detail))
            is Event.IssuanceFailed -> failOrSnack(event.message ?: event.code)
            is Event.FundingNeeded -> {
                if (w is Watch.Issuance) {
                    watch = null
                    tap?.succeeded(R.string.tap_done_load_created)
                }
                fundDialog(event.credit)
            }
            is Event.ReadyToApply -> applyDialog(event.credit)
            is Event.Failed -> failOrSnack(event.message)
        }
    }

    /** A flow step failed: on the sheet when it is waiting for this outcome, else a Snackbar. */
    private fun failOrSnack(message: String) {
        val tap = watch?.let(::sheetFor)
        watch = null
        if (tap != null) tap.failed(message, null, warning = false, hasRecovery = false) else snack(message)
    }

    private fun snack(text: String) {
        if (_binding == null) return
        main?.snackbar(text)
    }

    private fun currencies(): Map<String, String> {
        val accountId = app.tokenManager.getAccountId() ?: return emptyMap()
        return CardStore(requireContext()).list(accountId).associate { it.cardId to it.currency }
    }

    // ── Row actions and details ─────────────────────────────────────────

    private fun onRowAction(item: Any) {
        when (item) {
            is PendingRedemption -> {
                val row = TransferPresentation.redemption(item)
                if (row.action == RowAction.SEND && item.tuple != null && !item.isTerminal) sendFromRow(item.cardId)
                else details(item)
            }
            is PendingCredit -> {
                val row = TransferPresentation.credit(item)
                when (row.action) {
                    RowAction.FUND -> fundDialog(item)
                    RowAction.APPLY -> applyDialog(item)
                    else -> details(item)
                }
            }
        }
    }

    private fun details(item: Any) {
        val lines = ArrayList<String>()
        val builder = MaterialAlertDialogBuilder(requireContext()).setTitle(R.string.transfer_details_title)
        when (item) {
            is PendingRedemption -> {
                lines += getString(R.string.transfer_details_card, item.cardId)
                lines += getString(R.string.transfer_details_status, item.state)
                item.redemptionId?.let { lines += getString(R.string.transfer_details_redemption, it) }
                item.btxid?.let { lines += getString(R.string.transfer_details_btxid, it) }
                item.reason?.let { lines += getString(R.string.transfer_details_reason, it) }
                when {
                    // Re-checks the bridge with the stored tuple; never signs.
                    !item.isTerminal && item.tuple != null -> builder.setPositiveButton(R.string.transfer_details_check_status) { _, _ ->
                        val accountId = app.tokenManager.getAccountId() ?: return@setPositiveButton
                        viewModel.submitAndTrack(accountId, item.cardId)
                    }
                    viewModel.redemptions.needsRecovery(item.cardId) -> builder.setPositiveButton(R.string.tap_action_resume) { _, _ ->
                        val card = storedCard(item.cardId) ?: return@setPositiveButton
                        recoverFromCard(card)
                    }
                }
            }
            is PendingCredit -> {
                lines += getString(R.string.transfer_details_card, item.cardId)
                lines += getString(R.string.transfer_details_status, item.state)
                lines += getString(R.string.transfer_details_issuance, item.issuanceRef ?: item.issuanceId)
                lines += getString(R.string.transfer_details_funding, item.fundingStatus)
                item.ackStatusWord?.let { lines += getString(R.string.transfer_details_sw, it) }
                val sw = item.ackStatusWord
                if (sw != null && !item.acked && sw != IssuanceController.EXCEPTION_SW) {
                    builder.setPositiveButton(R.string.transfer_details_report) { _, _ -> viewModel.ack(item.issuanceId) }
                }
            }
        }
        builder.setMessage(lines.joinToString("\n")).setNegativeButton(R.string.tap_action_close, null).show()
    }

    private fun storedCard(cardId: String): StoredCard? {
        val accountId = app.tokenManager.getAccountId() ?: return null
        return CardStore(requireContext()).find(accountId, cardId)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        main?.let { host ->
            host.cancelCardTap()
            host.tapViewModel.onResume = null
        }
        watch = null
        _binding = null
    }

    // ── List ────────────────────────────────────────────────────────────

    private class Item(val source: Any, val row: TransferPresentation.TransferRow)

    private inner class TransferAdapter : ListAdapter<Item, TransferAdapter.ViewHolder>(DIFF) {
        private var currency: Map<String, String> = emptyMap()

        fun show(rows: TransfersViewModel.Rows, currencies: Map<String, String>) {
            currency = currencies
            val items = rows.redemptions.map { Item(it, TransferPresentation.redemption(it)) } +
                rows.credits.map { Item(it, TransferPresentation.credit(it)) }
            submitList(items.sortedByDescending { it.row.createdAt })
        }

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val btnAction: MaterialButton = view.findViewById(R.id.btnAction)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            ViewHolder(LayoutInflater.from(parent.context).inflate(R.layout.item_transfer, parent, false))

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = getItem(position)
            val sourceId = when (val s = item.source) {
                is PendingRedemption -> s.redemptionId ?: s.cardId
                is PendingCredit -> s.issuanceRef ?: s.issuanceId
                else -> item.row.cardId
            }
            TransferRowBinder.bind(holder.itemView, item.row, sourceId, currency[item.row.cardId])
            holder.btnAction.setOnClickListener { if (alive) onRowAction(item.source) }
            holder.itemView.setOnClickListener { if (alive) details(item.source) }
        }
    }

    private companion object {
        val DIFF = object : DiffUtil.ItemCallback<Item>() {
            override fun areItemsTheSame(a: Item, b: Item) = a.row.key == b.row.key
            override fun areContentsTheSame(a: Item, b: Item) = a.source == b.source
        }
    }
}

/**
 * Binds one Transfers row ([R.layout.item_transfer]) from its presentation;
 * colours come from theme attributes only. Listeners are the caller's.
 */
internal object TransferRowBinder {
    private val dateFormat: DateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)

    fun bind(view: View, row: TransferPresentation.TransferRow, sourceId: String, currency: String?) {
        val ctx = view.context
        val tvTxId: TextView = view.findViewById(R.id.tvTxId)
        val tvSource: TextView = view.findViewById(R.id.tvSourceAccount)
        val tvAmount: TextView = view.findViewById(R.id.tvAmount)
        val tvTimestamp: TextView = view.findViewById(R.id.tvTimestamp)
        val chip: Chip = view.findViewById(R.id.chipStatus)
        val bannerCard: MaterialCardView = view.findViewById(R.id.banner)
        val ivBanner: ImageView = view.findViewById(R.id.ivBanner)
        val tvBanner: TextView = view.findViewById(R.id.tvBanner)
        val btnAction: MaterialButton = view.findViewById(R.id.btnAction)

        tvTxId.text = ctx.getString(
            if (row.kind == TransferPresentation.Kind.REDEEM) R.string.transfer_row_title_redeem else R.string.transfer_row_title_load,
            row.cardLast4
        )
        tvAmount.text = if (currency.isNullOrEmpty()) row.amountText else ctx.getString(R.string.transfer_row_amount, row.amountText, currency)
        tvSource.text = sourceId
        tvTimestamp.visibility = if (row.createdAt > 0) View.VISIBLE else View.GONE
        tvTimestamp.text = if (row.createdAt > 0) dateFormat.format(Date(row.createdAt)) else ""
        chip.text = if (row.labelArg != null) ctx.getString(row.label, row.labelArg) else ctx.getString(row.label)
        tintChip(chip, row.tone)

        val banner = row.banner
        bannerCard.visibility = if (banner == null) View.GONE else View.VISIBLE
        if (banner != null) {
            tvBanner.text = if (banner.arg != null) ctx.getString(banner.textRes, banner.arg) else ctx.getString(banner.textRes)
            val (bg, fg) = containerPair(banner.tone)
            bannerCard.setCardBackgroundColor(MaterialColors.getColor(bannerCard, bg))
            val fgColor = MaterialColors.getColor(bannerCard, fg)
            tvBanner.setTextColor(fgColor)
            ivBanner.setImageResource(if (banner.tone == Tone.DANGER) R.drawable.ic_error else R.drawable.ic_warning)
            ivBanner.imageTintList = ColorStateList.valueOf(fgColor)
        }

        val label = when (row.action) {
            RowAction.NONE -> null
            RowAction.SEND -> R.string.transfer_row_action_send
            RowAction.FUND -> R.string.transfer_row_action_fund
            RowAction.APPLY -> R.string.transfer_row_action_apply
            RowAction.DETAILS -> R.string.transfer_row_action_details
        }
        btnAction.visibility = if (label == null) View.GONE else View.VISIBLE
        if (label != null) btnAction.setText(label)
    }

    private fun tintChip(chip: Chip, tone: Tone) {
        val outlined = tone == Tone.PENDING
        val bg: Int? = if (outlined) null else containerPair(tone).first
        val fg = if (outlined) com.google.android.material.R.attr.colorTertiary else containerPair(tone).second
        chip.chipBackgroundColor = ColorStateList.valueOf(
            if (bg == null) android.graphics.Color.TRANSPARENT else MaterialColors.getColor(chip, bg)
        )
        val fgColor = MaterialColors.getColor(chip, fg)
        chip.setTextColor(fgColor)
        chip.chipStrokeWidth = if (outlined) chip.resources.displayMetrics.density else 0f
        chip.chipStrokeColor = ColorStateList.valueOf(fgColor)
    }

    /** Container / on-container theme attributes per tone. */
    private fun containerPair(tone: Tone): Pair<Int, Int> = when (tone) {
        Tone.SUCCESS -> R.attr.colorStatusSuccessContainer to R.attr.colorOnStatusSuccessContainer
        Tone.WARNING -> R.attr.colorStatusWarningContainer to R.attr.colorOnStatusWarningContainer
        Tone.DANGER -> com.google.android.material.R.attr.colorErrorContainer to com.google.android.material.R.attr.colorOnErrorContainer
        Tone.PENDING -> com.google.android.material.R.attr.colorTertiaryContainer to com.google.android.material.R.attr.colorOnTertiaryContainer
        Tone.NEUTRAL -> com.google.android.material.R.attr.colorSurfaceContainerHighest to com.google.android.material.R.attr.colorOnSurfaceVariant
    }
}

package com.payala.impala.demo.ui.transfer

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.transfer.IssuanceController
import com.payala.impala.demo.transfer.IssuanceRefused
import com.payala.impala.demo.transfer.PendingCredit
import com.payala.impala.demo.transfer.PendingRedemption
import com.payala.impala.demo.transfer.PendingTransferStore
import com.payala.impala.demo.transfer.RedemptionController
import com.payala.impala.demo.transfer.RedemptionRefused
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * Drives the two card transfer flows for the Transfers screen. The card steps
 * (sign, read counter, apply credit) run in the activity's reader mode
 * (`MainActivity.awaitCardTap`); everything else is here.
 */
class TransfersViewModel : ViewModel() {

    sealed class Event {
        data class Message(val text: String) : Event()
        data class Refused(val refusal: RedemptionRefused.Refusal, val detail: String?) : Event()
        data class IssuanceFailed(val code: String, val message: String?) : Event()
        /** The issuance exists; show the funding instructions and a Fund button. */
        data class FundingNeeded(val credit: PendingCredit) : Event()
        /** Funded: offer "Apply to card". */
        data class ReadyToApply(val credit: PendingCredit) : Event()
        data class Failed(val message: String) : Event()
    }

    data class Rows(val redemptions: List<PendingRedemption>, val credits: List<PendingCredit>)

    private val _rows = MutableLiveData(Rows(emptyList(), emptyList()))
    val rows: LiveData<Rows> = _rows
    private val _events = MutableLiveData<Event?>()
    val events: LiveData<Event?> = _events

    lateinit var redemptions: RedemptionController
        private set
    lateinit var issuances: IssuanceController
        private set
    private lateinit var store: PendingTransferStore

    fun bind(redemption: RedemptionController, issuance: IssuanceController, pending: PendingTransferStore) {
        if (::store.isInitialized) return
        redemptions = redemption
        issuances = issuance
        store = pending
        refresh()
    }

    fun refresh() {
        _rows.value = Rows(store.redemptions() + store.history(), store.credits())
    }

    fun eventHandled() {
        _events.value = null
    }

    private fun launchFlow(block: suspend () -> Unit) {
        viewModelScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: RedemptionRefused) {
                _events.value = Event.Refused(e.refusal, e.message)
            } catch (e: IssuanceRefused) {
                _events.value = Event.IssuanceFailed(e.code, e.message)
            } catch (e: Exception) {
                AppLogger.w("Transfers", "Transfer step failed: ${e.javaClass.simpleName}")
                _events.value = Event.Failed(e.message ?: e.javaClass.simpleName)
            } finally {
                refresh()
            }
        }
    }

    /** Prepare a redemption before asking for a tap; [then] runs on success. */
    fun prepareRedemption(cardId: String, then: (RedemptionController.Prepared) -> Unit) = launchFlow {
        then(redemptions.prepare(cardId))
    }

    /** After the card signed (or the tuple was recovered): submit and track until terminal. */
    fun submitAndTrack(accountId: String, cardId: String) = launchFlow {
        val submitted = redemptions.submit(accountId, cardId)
        refresh()
        val tracked = redemptions.track(submitted.cardId)
        if (tracked.isTerminal) store.archiveRedemption(cardId)
        _events.value = Event.Message("redemption:${tracked.state}")
    }

    fun createIssuance(accountId: String, cardId: String, amount: Long, observedCounter: Int) = launchFlow {
        _events.value = Event.FundingNeeded(issuances.create(accountId, cardId, amount, observedCounter))
    }

    fun fund(accountId: String, issuanceId: String, newAttempt: Boolean = false) = launchFlow {
        var credit = issuances.fund(accountId, issuanceId, newAttempt)
        if (credit.fundingStatus == "submitted") credit = issuances.awaitFundingIntent(issuanceId)
        when (credit.fundingStatus) {
            "ambiguous" -> _events.value = Event.Message("fund:ambiguous")
            "rejected" -> _events.value = Event.Message("fund:rejected")
            "settled" -> {
                credit = issuances.awaitFunded(issuanceId)
                if (credit.state in setOf("funded", "issued", "acked")) {
                    _events.value = Event.ReadyToApply(issuances.fetchCredit(issuanceId))
                } else {
                    _events.value = Event.Message("load:${credit.state}")
                }
            }
            else -> _events.value = Event.Message("fund:${credit.fundingStatus}")
        }
    }

    /** After the card applied (or refused) the credit: ack the status word. */
    fun ack(issuanceId: String) = launchFlow {
        val credit = issuances.ack(issuanceId)
        _events.value = Event.Message("load:${credit.ackStatusWord}")
    }

    fun failed(e: Throwable) {
        _events.value = when (e) {
            is RedemptionRefused -> Event.Refused(e.refusal, e.message)
            is IssuanceRefused -> Event.IssuanceFailed(e.code, e.message)
            else -> Event.Failed(e.message ?: e.javaClass.simpleName)
        }
        refresh()
    }
}

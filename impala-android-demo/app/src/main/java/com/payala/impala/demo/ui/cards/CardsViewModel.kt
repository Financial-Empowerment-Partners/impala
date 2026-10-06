package com.payala.impala.demo.ui.cards

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.UuidBytes
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.api.BridgeErrors
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.CreateCardRequest
import com.payala.impala.demo.model.DeleteCardRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import retrofit2.HttpException

/**
 * Cards screen state: the locally recorded cards of the signed-in account,
 * registration (`POST /card`) and deletion (`DELETE /card`).
 *
 * Registration is refused client-side, before anything is sent, when the card
 * cannot work for this account: an applet older than 0.2, a card that is not
 * personalized, or a card issued to a different account than the session's
 * (the bridge would accept the row, but `POST /auth/card` would then fail with
 * a generic 401 forever, because the card signs with its on-card account).
 */
class CardsViewModel : ViewModel() {

    enum class Refusal { WRONG_VERSION, NOT_PERSONALIZED, ACCOUNT_MISMATCH, NO_SESSION }

    sealed class Event {
        data class Registered(val card: StoredCard) : Event()
        data class Refused(val refusal: Refusal, val detail: String = "") : Event()
        /** The bridge refused; [message] is shown verbatim. */
        data class BridgeRefused(val message: String) : Event()
        data class Failed(val message: String) : Event()
        data class Deleted(val cardId: String) : Event()
        data class DeleteFailed(val cardId: String, val message: String) : Event()
    }

    private val _cards = MutableLiveData<List<StoredCard>>(emptyList())
    val cards: LiveData<List<StoredCard>> = _cards

    private val _events = MutableLiveData<Event?>()
    val events: LiveData<Event?> = _events

    fun load(store: CardStore, accountId: String?) {
        _cards.value = if (accountId == null) emptyList() else store.list(accountId)
    }

    fun register(api: BridgeApiService, store: CardStore, sessionAccountId: String?, identity: CardIdentity) {
        val refusal = checkRegistrable(identity, sessionAccountId)
        if (refusal != null) {
            AppLogger.w("Cards", "Registration refused client-side: $refusal")
            _events.value = Event.Refused(refusal, if (refusal == Refusal.WRONG_VERSION) identity.versionString else "")
            return
        }
        val accountId = sessionAccountId!!
        viewModelScope.launch {
            try {
                val response = api.createCard(
                    CreateCardRequest(account_id = accountId, card_id = identity.wireCardId, ec_pubkey = identity.pubKeyHex)
                )
                if (response.success) {
                    val card = StoredCard.from(identity)
                    store.save(accountId, card)
                    _cards.value = store.list(accountId)
                    AppLogger.i("Cards", "Card registered: ${identity.wireCardId}")
                    _events.value = Event.Registered(card)
                } else {
                    _events.value = Event.BridgeRefused(response.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                val message = BridgeErrors.parse(e)?.message ?: "HTTP ${e.code()}"
                AppLogger.w("Cards", "Card registration refused by the bridge: HTTP ${e.code()}")
                _events.value = if (e.code() == 400 || e.code() == 409) Event.BridgeRefused(message) else Event.Failed(message)
            } catch (e: Exception) {
                AppLogger.e("Cards", "Card registration failed: ${e.javaClass.simpleName}")
                _events.value = Event.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    /** Removes the local record only after the bridge confirms the delete. */
    fun delete(api: BridgeApiService, store: CardStore, accountId: String, cardId: String) {
        viewModelScope.launch {
            try {
                val response = api.deleteCard(DeleteCardRequest(cardId))
                if (response.success) {
                    store.remove(accountId, cardId)
                    _cards.value = store.list(accountId)
                    _events.value = Event.Deleted(cardId)
                } else {
                    _events.value = Event.DeleteFailed(cardId, response.message)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                _events.value = Event.DeleteFailed(cardId, BridgeErrors.parse(e)?.message ?: "HTTP ${e.code()}")
            } catch (e: Exception) {
                _events.value = Event.DeleteFailed(cardId, e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun eventHandled() {
        _events.value = null
    }

    companion object {
        /** Why [identity] cannot be registered for [sessionAccountId], or null when it can. */
        fun checkRegistrable(identity: CardIdentity, sessionAccountId: String?): Refusal? {
            if (identity.version.major.toInt() == 0 && identity.version.minor < 2) return Refusal.WRONG_VERSION
            if (!identity.isPersonalized) return Refusal.NOT_PERSONALIZED
            if (sessionAccountId.isNullOrBlank()) return Refusal.NO_SESSION
            if (!UuidBytes.same(identity.accountUuid, sessionAccountId)) return Refusal.ACCOUNT_MISMATCH
            return null
        }
    }
}

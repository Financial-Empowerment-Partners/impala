package com.payala.impala.demo.ui.cards

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.StellarCardKey
import com.payala.impala.card.CardStellarKeys
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.api.BridgeErrors
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.CreateCardRequest
import com.payala.impala.demo.model.DeleteCardRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import retrofit2.HttpException

/**
 * Cards screen state: the locally recorded cards of the signed-in account,
 * the bridge's card program ([issuer], from the public `GET /card-issuer`),
 * registration (`POST /card`) and deletion (`DELETE /card`).
 *
 * Registration is refused client-side, before anything is sent, when the card
 * cannot work for this account: an applet older than 0.2, a card that is not
 * personalized, or a card issued to a different account than the session's
 * (the bridge would accept the row, but `POST /auth/card` would then fail with
 * a generic 401 forever, because the card signs with its on-card account).
 *
 * A card issued by a different program than the bridge's (a `--test-issuer`
 * card, say) can sign in but can never load or redeem. What happens is the
 * caller's [ProgramMismatchPolicy], passed explicitly so the rule does not
 * depend on the build flavour: [ProgramMismatchPolicy.WARN] asks first
 * ([Event.ProgramMismatch], then `register(…, acknowledged = true)`),
 * [ProgramMismatchPolicy.REFUSE] refuses ([Refusal.WRONG_PROGRAM]). When the
 * program cannot be checked (the issuer endpoint is unreachable), WARN asks
 * ([Event.IssuerUnknown]) and REFUSE refuses the same way (fail closed).
 *
 * A card with a Stellar key (applet 0.3) is registered with it, so it can sign
 * in with SEP-10: the address and the card's two cross-signatures go in the
 * same `POST /card`. They are checked here first, and left out (the card then
 * registers for the legacy sign-in only) when they do not verify for this
 * card and account; the bridge makes the decision that counts.
 */
class CardsViewModel : ViewModel() {

    enum class Refusal { WRONG_VERSION, NOT_PERSONALIZED, ACCOUNT_MISMATCH, NO_SESSION, WRONG_PROGRAM }

    /** What to do when the card's program differs from the bridge's. */
    enum class ProgramMismatchPolicy { WARN, REFUSE }

    /** The bridge's card program, as far as this screen knows. */
    sealed class IssuerState {
        /** Not fetched yet. */
        object Unknown : IssuerState()
        /** `configured: false`, or the endpoint does not exist (404): the bridge has no card program. */
        object Unconfigured : IssuerState()
        /** The bridge's program id and issuer public key (public values). */
        class Known(val programIdHex: String?, val publicKeyHex: String?) : IssuerState()
        /** The endpoint could not be reached (network, 5xx): nothing can be concluded. */
        object Unreachable : IssuerState()
    }

    sealed class Event {
        data class Registered(val card: StoredCard) : Event()
        data class Refused(val refusal: Refusal, val detail: String = "") : Event()
        /** The bridge refused; [message] is shown verbatim. */
        data class BridgeRefused(val message: String) : Event()
        data class Failed(val message: String) : Event()
        data class Deleted(val cardId: String) : Event()
        data class DeleteFailed(val cardId: String, val message: String) : Event()
        /** WARN policy: the card's program differs from the bridge's; nothing was posted. Confirm with `acknowledged = true`. */
        class ProgramMismatch(val identity: CardIdentity, val bridgeProgramIdHex: String) : Event()
        /** The bridge's program could not be checked; nothing was posted. [canAcknowledge] under the WARN policy only. */
        class IssuerUnknown(val identity: CardIdentity, val canAcknowledge: Boolean) : Event()
    }

    private val _cards = MutableLiveData<List<StoredCard>>(emptyList())
    val cards: LiveData<List<StoredCard>> = _cards

    private val _events = MutableLiveData<Event?>()
    val events: LiveData<Event?> = _events

    private val _issuer = MutableLiveData<IssuerState>(IssuerState.Unknown)
    val issuer: LiveData<IssuerState> = _issuer

    private var issuerFetch: Deferred<IssuerState>? = null

    fun load(store: CardStore, accountId: String?) {
        _cards.value = if (accountId == null) emptyList() else store.list(accountId)
    }

    /** Starts the issuer fetch unless one is known or running (an Unreachable result is retried). */
    fun loadIssuer(api: BridgeApiService) {
        viewModelScope.launch { awaitIssuer(api) }
    }

    /** The issuer state, fetching it first when it is Unknown or Unreachable. Concurrent callers share one fetch. */
    suspend fun awaitIssuer(api: BridgeApiService): IssuerState {
        val known = _issuer.value
        if (known is IssuerState.Known || known is IssuerState.Unconfigured) return known
        val fetch = issuerFetch?.takeIf { it.isActive } ?: viewModelScope.async { fetchIssuer(api) }.also { issuerFetch = it }
        val state = fetch.await()
        _issuer.value = state
        return state
    }

    private suspend fun fetchIssuer(api: BridgeApiService): IssuerState = try {
        val info = api.cardIssuer()
        if (info.configured == false || info.public_key_hex.isNullOrBlank()) IssuerState.Unconfigured
        else IssuerState.Known(info.program_id_hex?.takeIf { it.isNotBlank() }, info.public_key_hex)
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == 404) IssuerState.Unconfigured else IssuerState.Unreachable.also {
            AppLogger.w("Cards", "Card issuer unreachable: HTTP ${e.code()}")
        }
    } catch (e: Exception) {
        AppLogger.w("Cards", "Card issuer unreachable: ${e.javaClass.simpleName}")
        IssuerState.Unreachable
    }

    /**
     * Registers [identity] for [sessionAccountId] after the client-side checks
     * and the program check (which awaits the issuer fetch). [acknowledged]:
     * the user confirmed "Register anyway?" (honoured under WARN only).
     */
    fun register(
        api: BridgeApiService,
        store: CardStore,
        sessionAccountId: String?,
        identity: CardIdentity,
        programMismatchPolicy: ProgramMismatchPolicy,
        acknowledged: Boolean = false,
        stellarKey: StellarCardKey? = null
    ) {
        val refusal = checkRegistrable(identity, sessionAccountId)
        if (refusal != null) {
            AppLogger.w("Cards", "Registration refused client-side: $refusal")
            _events.value = Event.Refused(refusal, if (refusal == Refusal.WRONG_VERSION) identity.versionString else "")
            return
        }
        val accountId = sessionAccountId!!
        viewModelScope.launch {
            val warn = programMismatchPolicy == ProgramMismatchPolicy.WARN
            when (val issuer = awaitIssuer(api)) {
                is IssuerState.Known -> {
                    val bridgeProgram = issuer.programIdHex
                    if (bridgeProgram != null && !sameProgram(identity.programIdHex, bridgeProgram)) {
                        when {
                            !warn -> {
                                AppLogger.w("Cards", "Registration refused: card program differs from the bridge's")
                                _events.value = Event.Refused(Refusal.WRONG_PROGRAM)
                                return@launch
                            }
                            !acknowledged -> {
                                _events.value = Event.ProgramMismatch(identity, bridgeProgram)
                                return@launch
                            }
                            else -> AppLogger.i("Cards", "Registering a card of another program (acknowledged)")
                        }
                    }
                }
                IssuerState.Unreachable, IssuerState.Unknown -> {
                    if (!warn || !acknowledged) {
                        _events.value = Event.IssuerUnknown(identity, canAcknowledge = warn)
                        return@launch
                    }
                }
                IssuerState.Unconfigured -> Unit
            }
            post(api, store, accountId, identity, stellarKey)
        }
    }

    /**
     * The registration request for [identity]: with the three Stellar fields
     * when [stellarKey] is bound and both cross-signatures verify for this
     * card, without them otherwise.
     */
    internal fun registrationRequest(accountId: String, identity: CardIdentity, stellarKey: StellarCardKey?): CreateCardRequest {
        val plain = CreateCardRequest(account_id = accountId, card_id = identity.wireCardId, ec_pubkey = identity.pubKeyHex)
        if (stellarKey == null || !stellarKey.isBound) return plain
        val verifies = CardStellarKeys.bindingVerifies(identity.pubKey, identity.accountId, identity.cardId, stellarKey) &&
            CardStellarKeys.proofVerifies(identity.pubKey, identity.accountId, identity.cardId, stellarKey)
        if (!verifies) {
            AppLogger.w("Cards", "The card's Stellar key signatures do not verify; registering for the legacy sign-in only")
            return plain
        }
        return plain.copy(
            stellar_address = stellarKey.address,
            stellar_binding_sig = Hex.encode(stellarKey.bindingSignature!!),
            stellar_proof_sig = Hex.encode(stellarKey.proofSignature!!)
        )
    }

    private suspend fun post(
        api: BridgeApiService, store: CardStore, accountId: String, identity: CardIdentity, stellarKey: StellarCardKey?
    ) {
        try {
            val response = api.createCard(registrationRequest(accountId, identity, stellarKey))
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

        /** Program ids compare as hex, ignoring case. */
        fun sameProgram(a: String, b: String): Boolean = a.equals(b, ignoreCase = true)
    }
}

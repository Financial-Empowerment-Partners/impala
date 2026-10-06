package com.payala.impala.demo.transfer

import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.RedemptionFlow
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.TransferProtocol
import com.payala.impala.card.CardTransfers
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.api.BridgeErrors
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.CardIssuerResponse
import com.payala.impala.demo.model.RedemptionRequest
import kotlinx.coroutines.delay
import java.io.IOException

/** A redemption the app refuses before (or instead of) asking the card to sign. */
class RedemptionRefused(val refusal: Refusal, detail: String = "") : Exception(refusal.name + (if (detail.isEmpty()) "" else ": $detail")) {
    enum class Refusal {
        ISSUER_UNCONFIGURED, CARD_NOT_CERTIFIED, AMOUNT_INVALID, PIN_INVALID, PIN_LESS_REFUSED,
        CARD_MISMATCH, FROZEN_PENDING, PENDING_EXISTS, NOTHING_TO_SUBMIT
    }
}

/**
 * Card → bridge redemption (stored value back to the owner's custodial
 * Stellar account): prepare → tap/sign → submit → track.
 *
 * Never re-sign. The signable is persisted before SIGN_TRANSFER_V2 and the
 * tuple right after; every retry re-posts the stored bytes. A tuple lost to a
 * crash is rebuilt from the card (GET_LAST_TRANSFER), never re-signed.
 */
class RedemptionController(
    private val api: BridgeApiService,
    private val store: PendingTransferStore,
    private val clock: () -> Long = System::currentTimeMillis
) {
    /** What the tap needs from the bridge, fetched before the user is asked to tap. */
    data class Prepared(
        val cardId: String,
        val redemptionUuid: ByteArray,
        val lastRedeemedCounter: Int,
        val programIdHex: String?
    )

    private var issuer: CardIssuerResponse? = null

    /** `GET /card-issuer` (cached for this controller's session) + `GET /offline/cards/{id}`. */
    suspend fun prepare(cardId: String): Prepared {
        store.redemption(cardId)?.let { pending ->
            if (pending.isFrozen) throw RedemptionRefused(RedemptionRefused.Refusal.FROZEN_PENDING)
            if (!pending.isTerminal) throw RedemptionRefused(RedemptionRefused.Refusal.PENDING_EXISTS)
        }
        val info = issuer ?: api.cardIssuer().also { issuer = it }
        if (!info.isConfigured) throw RedemptionRefused(RedemptionRefused.Refusal.ISSUER_UNCONFIGURED)
        val card = api.offlineCard(cardId)
        if (!card.certified) throw RedemptionRefused(RedemptionRefused.Refusal.CARD_NOT_CERTIFIED)
        return Prepared(cardId, UuidBytes.parse(info.redemption_uuid!!), card.last_redeemed_counter, info.program_id_hex)
    }

    /**
     * Binder thread, card connected. Checks the card is the one prepared and
     * matches its stored record, composes the signable
     * (`recipient = redemption_uuid`, `counter = last_redeemed + 1`,
     * `sendSequence = max(previous + 1, now)`), persists it, has the card sign
     * with the user PIN, and persists the tuple. [pin] is zeroed in all cases.
     */
    fun signOnCard(session: ImpalaCardSession, prepared: Prepared, stored: StoredCard?, amount: Long, pin: CharArray): PendingRedemption {
        try {
            if (amount !in 1..Money.MAX_CARD_AMOUNT) throw RedemptionRefused(RedemptionRefused.Refusal.AMOUNT_INVALID)
            if (pin.size != 4 || pin.any { it !in '0'..'9' }) throw RedemptionRefused(RedemptionRefused.Refusal.PIN_INVALID)
            // "0000" asks the card for a PIN-less transfer: that is a card policy, never a user choice here.
            if (pin.all { it == '0' }) throw RedemptionRefused(RedemptionRefused.Refusal.PIN_LESS_REFUSED)

            val identity = session.identity.requirePersonalized()
            if (identity.wireCardId != prepared.cardId) throw RedemptionRefused(RedemptionRefused.Refusal.CARD_MISMATCH, "tapped ${identity.wireCardId}")
            if (prepared.programIdHex != null && !identity.programIdHex.equals(prepared.programIdHex, ignoreCase = true)) {
                throw RedemptionRefused(RedemptionRefused.Refusal.CARD_MISMATCH, "card program differs from the bridge's")
            }
            if (stored != null && (stored.programIdHex != identity.programIdHex || stored.currency != StoredCard.currencyText(identity.currency))) {
                throw RedemptionRefused(RedemptionRefused.Refusal.CARD_MISMATCH, "card differs from its registered record")
            }
            store.redemption(prepared.cardId)?.let { if (!it.isTerminal) throw RedemptionRefused(RedemptionRefused.Refusal.PENDING_EXISTS) }

            val previous = CardTransfers.previousSendSequence(session)
            val sequence = TransferProtocol.nextSendSequence(previous, clock())
            val signable = RedemptionFlow.compose(
                identity, prepared.redemptionUuid, amount.toUInt(), sequence, prepared.lastRedeemedCounter + 1, previous
            )
            val slot = PendingRedemption(prepared.cardId, Hex.encode(signable.encode()), amount = amount, createdAt = clock())
            store.saveRedemption(slot) // on disk before the card debits
            val tuple = CardTransfers.redeem(session, pin, signable)
            val signed = slot.copy(tuple = tuple, state = PendingRedemption.STATE_SIGNED)
            store.saveRedemption(signed)
            AppLogger.i("Redeem", "Card ${prepared.cardId} signed a redemption")
            return signed
        } finally {
            pin.fill('\u0000')
        }
    }

    /**
     * Binder thread: a slot was written but its tuple was not (the app died
     * mid-sign). If the card's last signed transfer is that signable, rebuild
     * the tuple from GET_LAST_TRANSFER ("Resume pending transfer"); if the card
     * never signed it, the slot is dropped (nothing was debited).
     */
    fun recoverOnCard(session: ImpalaCardSession, cardId: String): PendingRedemption? {
        val pending = store.redemption(cardId) ?: return null
        if (pending.tuple != null) return pending
        val last = CardTransfers.recoverLastSigned(session)
        return if (last != null && last.signableHex.equals(pending.signableHex, ignoreCase = true)) {
            pending.copy(tuple = last, state = PendingRedemption.STATE_SIGNED).also { store.saveRedemption(it) }
        } else {
            AppLogger.i("Redeem", "Pending slot for $cardId was never signed by the card; discarding it")
            store.archiveRedemption(cardId)
            null
        }
    }

    /** True when a slot exists whose tuple was never persisted (offer "Resume pending transfer" on the next tap). */
    fun needsRecovery(cardId: String): Boolean = store.redemption(cardId)?.let { it.tuple == null && !it.isTerminal } == true

    /**
     * Posts the stored tuple — byte-identical on every attempt. 202 (new or
     * replay) records the id; 409 `counter_consumed` / `duplicate_debit_proof`
     * mean the bridge already holds this debit (terminal success from the
     * app's view); any other 4xx is a refusal of a debit the card already
     * made: retained and shown as "needs operator", never re-signed. Network
     * failures and 5xx leave the slot as is for a retry.
     */
    suspend fun submit(accountId: String, cardId: String): PendingRedemption {
        val pending = store.redemption(cardId) ?: throw RedemptionRefused(RedemptionRefused.Refusal.NOTHING_TO_SUBMIT)
        val tuple = pending.tuple ?: throw RedemptionRefused(RedemptionRefused.Refusal.NOTHING_TO_SUBMIT, "tuple not recovered yet")
        if (pending.redemptionId != null || pending.isTerminal) return pending
        val request = RedemptionRequest(
            payala_account_id = accountId,
            card_id = cardId,
            signable_hex = tuple.signableHex,
            signature_der_hex = tuple.signatureDerHex,
            card_pubkey_hex = tuple.cardPubkeyHex,
            card_cert_hex = tuple.cardCertHex
        )
        val response = api.createRedemption(request) // IOException propagates: retry later with the same bytes
        val updated = when {
            response.isSuccessful -> {
                val body = response.body() ?: throw IOException("empty redemption response")
                pending.copy(redemptionId = body.redemption_id, state = body.state)
            }
            response.code() == 409 -> {
                val err = BridgeErrors.parse(response.errorBody()?.string() ?: "")
                when (err?.code) {
                    "counter_consumed", "duplicate_debit_proof" ->
                        pending.copy(state = PendingRedemption.STATE_SUBMITTED, reason = err.code)
                    else -> pending.copy(state = PendingRedemption.STATE_REFUSED, reason = err?.code ?: "http_409")
                }
            }
            response.code() in 400..499 -> {
                val err = BridgeErrors.parse(response.errorBody()?.string() ?: "")
                pending.copy(state = PendingRedemption.STATE_REFUSED, reason = err?.code ?: "http_${response.code()}")
            }
            else -> throw IOException("bridge answered HTTP ${response.code()}; retry with the same tuple")
        }
        store.saveRedemption(updated)
        return updated
    }

    /**
     * Polls `GET /offline/redemptions/{id}` every [intervalMs] until a terminal
     * state or [maxMs]. `frozen` (ambiguous payout) keeps polling: it is shown
     * as "outcome unknown — do not repeat" and blocks new redemptions.
     */
    suspend fun track(cardId: String, intervalMs: Long = 5_000, maxMs: Long = 360_000): PendingRedemption {
        var current = store.redemption(cardId) ?: throw RedemptionRefused(RedemptionRefused.Refusal.NOTHING_TO_SUBMIT)
        val id = current.redemptionId ?: return current
        var waited = 0L
        while (!current.isTerminal && waited <= maxMs) {
            val status = api.redemptionStatus(id)
            current = current.copy(state = status.state, reason = status.reason ?: current.reason, btxid = status.btxid ?: current.btxid)
            store.saveRedemption(current)
            if (current.isTerminal) break
            delay(intervalMs)
            waited += intervalMs
        }
        return current
    }
}

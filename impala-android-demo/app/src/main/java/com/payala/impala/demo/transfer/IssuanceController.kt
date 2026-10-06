package com.payala.impala.demo.transfer

import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.Hex
import com.impala.sdk.models.TransferProtocol
import com.payala.impala.card.CardTransfers
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.api.BridgeErrors
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.IssuanceAckRequest
import com.payala.impala.demo.model.IssuanceRequest
import com.payala.impala.demo.model.SignSubmitRequest
import kotlinx.coroutines.delay
import java.io.IOException

/** A load the app refuses or cannot continue. */
class IssuanceRefused(val code: String, message: String = code) : Exception(message)

/**
 * Bridge → card load: create the issuance (with the card's observed receive
 * counter), fund it from the owner's custodial account with exactly the
 * bridge's parameters, wait for `funded`, fetch the signed credit (persisted
 * before the tap), apply it on the card, ack the status word.
 */
class IssuanceController(
    private val api: BridgeApiService,
    private val store: PendingTransferStore,
    private val clock: () -> Long = System::currentTimeMillis
) {
    /** Binder thread: the card's last accepted receive counter, read at the tap that starts the load. */
    fun observeReceiveCounter(session: ImpalaCardSession): Int {
        session.identity.requirePersonalized()
        return session.sdk.getReceiveState().counter
    }

    suspend fun create(accountId: String, cardId: String, cardAmount: Long, observedReceiveCounter: Int): PendingCredit {
        if (cardAmount !in 1..Money.MAX_CARD_AMOUNT) throw IssuanceRefused("amount_invalid")
        val response = api.createIssuance(IssuanceRequest(accountId, cardId, cardAmount, observedReceiveCounter))
        if (!response.isSuccessful) {
            val err = BridgeErrors.parse(response.errorBody()?.string() ?: "")
            throw IssuanceRefused(err?.code ?: "http_${response.code()}", err?.message ?: "HTTP ${response.code()}")
        }
        val body = response.body() ?: throw IOException("empty issuance response")
        val funding = body.funding ?: throw IssuanceRefused("no_funding_instructions")
        if (funding.asset != "XLM") throw IssuanceRefused("unsupported_asset", "funding asset ${funding.asset} is not supported by the custodial sign path")
        val credit = PendingCredit(
            issuanceId = body.issuance_id,
            cardId = cardId,
            cardAmount = cardAmount,
            issuanceRef = body.issuance_ref,
            fundingDestination = funding.destination,
            fundingAmount = funding.amount,
            fundingMemo = funding.memo,
            fundingKey = funding.idempotency_key,
            state = body.state,
            createdAt = clock()
        )
        store.saveCredit(credit)
        return credit
    }

    /**
     * `POST /managed-account/sign` with the bridge's destination, amount,
     * memo and idempotency key, verbatim. Outcome contract: 200 settled;
     * 202 `ambiguous` = outcome unknown, only ever replayed with the SAME key;
     * 202 `submitted`/`prepared` = poll the intent; 400 `payment_rejected` = a
     * definite failure, so the next attempt may use a NEW key; 503 = retryable
     * with the same key.
     */
    suspend fun fund(accountId: String, issuanceId: String, newAttemptAfterRejection: Boolean = false): PendingCredit {
        var credit = store.credit(issuanceId) ?: throw IssuanceRefused("unknown_issuance")
        if (credit.fundingStatus == "settled") return credit
        if (newAttemptAfterRejection) {
            if (credit.fundingStatus != "rejected") throw IssuanceRefused("not_rejected", "a new funding key is only allowed after a definite rejection")
            val attempt = credit.fundingAttempt + 1
            credit = credit.copy(fundingAttempt = attempt, fundingKey = "${credit.issuanceRef}:$attempt", fundingStatus = "none")
            store.saveCredit(credit)
        }
        val request = SignSubmitRequest(
            payala_account_id = accountId,
            destination = credit.fundingDestination!!,
            amount = credit.fundingAmount!!,
            memo = credit.fundingMemo,
            idempotency_key = credit.fundingKey
        )
        val response = api.signAndSubmit(request)
        val body = response.body()
        val status = when {
            response.code() == 200 && body?.status in setOf(null, "settled") && body?.success != false -> "settled"
            response.code() == 202 && body?.status == "ambiguous" -> "ambiguous"
            response.code() == 202 -> "submitted"
            response.code() == 400 && BridgeErrors.parse(response.errorBody()?.string() ?: "")?.code == "payment_rejected" -> "rejected"
            response.code() == 503 -> throw IOException("custodial signing is paused or unconfigured (503); retry later with the same key")
            else -> {
                val err = BridgeErrors.parse(response.errorBody()?.string() ?: "")
                throw IssuanceRefused(err?.code ?: "http_${response.code()}", err?.message ?: "HTTP ${response.code()}")
            }
        }
        credit = credit.copy(fundingStatus = status, fundingIntentId = body?.intent_id ?: credit.fundingIntentId)
        store.saveCredit(credit)
        return credit
    }

    /** Polls the funding intent (202 submitted) until it settles or is rejected. */
    suspend fun awaitFundingIntent(issuanceId: String, intervalMs: Long = 5_000, maxMs: Long = 330_000): PendingCredit {
        var credit = store.credit(issuanceId) ?: throw IssuanceRefused("unknown_issuance")
        val intentId = credit.fundingIntentId ?: return credit
        var waited = 0L
        while (credit.fundingStatus == "submitted" && waited <= maxMs) {
            val intent = api.custodialIntent(intentId)
            val s = when (intent.status) {
                "settled" -> "settled"
                "rejected" -> "rejected"
                "ambiguous" -> "ambiguous"
                else -> "submitted"
            }
            credit = credit.copy(fundingStatus = s)
            store.saveCredit(credit)
            if (s != "submitted") break
            delay(intervalMs)
            waited += intervalMs
        }
        return credit
    }

    /** Polls `GET /offline/issuances/{id}` until the bridge has matched the deposit (funded or later) or it expired. */
    suspend fun awaitFunded(issuanceId: String, intervalMs: Long = 5_000, maxMs: Long = 600_000): PendingCredit {
        var credit = store.credit(issuanceId) ?: throw IssuanceRefused("unknown_issuance")
        var waited = 0L
        while (credit.state == "awaiting_funds" && waited <= maxMs) {
            val row = api.issuance(issuanceId)
            credit = credit.copy(state = row.state)
            store.saveCredit(credit)
            if (row.state != "awaiting_funds") break
            delay(intervalMs)
            waited += intervalMs
        }
        return credit
    }

    /** `GET /offline/issuances/{id}/credit`, persisted before any tap (identical bytes on every replay). */
    suspend fun fetchCredit(issuanceId: String): PendingCredit {
        var credit = store.credit(issuanceId) ?: throw IssuanceRefused("unknown_issuance")
        if (credit.signableHex != null && credit.tailHex != null) return credit
        val response = api.issuanceCredit(issuanceId)
        if (!response.isSuccessful) {
            val err = BridgeErrors.parse(response.errorBody()?.string() ?: "")
            throw IssuanceRefused(err?.code ?: "http_${response.code()}", err?.message ?: "HTTP ${response.code()}")
        }
        val body = response.body() ?: throw IOException("empty credit response")
        require(body.signable_hex.length == 120 && body.tail_hex.length == 418) { "malformed credit from the bridge" }
        credit = credit.copy(state = body.state, counter = body.counter, signableHex = body.signable_hex.lowercase(), tailHex = body.tail_hex.lowercase())
        store.saveCredit(credit)
        return credit
    }

    /** What the card's receive state says about a persisted credit (docs/transfer-protocol.md §6.4). */
    enum class TornVerdict { ALREADY_APPLIED, PRESENT, EXCEPTION }

    fun tornVerdict(counter: Int, digestHex: String, creditCounter: Int, creditTransferIdHex: String): TornVerdict = when {
        digestHex.equals(creditTransferIdHex, ignoreCase = true) -> TornVerdict.ALREADY_APPLIED
        counter < creditCounter -> TornVerdict.PRESENT
        else -> TornVerdict.EXCEPTION
    }

    /**
     * Binder thread: decide from GET_RECEIVE_STATE, then apply if (and only
     * if) the card has not committed this credit and nothing else landed on
     * its counter. Records the ack status word ("9000" applied or already
     * applied; the card's SW on refusal) or [EXCEPTION_SW] when another credit
     * holds the counter — never auto-credited, never acked, operator resolution.
     */
    fun applyOnCard(session: ImpalaCardSession, issuanceId: String): PendingCredit {
        var credit = store.credit(issuanceId) ?: throw IssuanceRefused("unknown_issuance")
        val signable = Hex.decode(credit.signableHex ?: throw IssuanceRefused("credit_not_fetched"), 60)
        val tail = Hex.decode(credit.tailHex!!, 209)
        val identity = session.identity.requirePersonalized()
        if (identity.wireCardId != credit.cardId) throw IssuanceRefused("card_mismatch", "this credit is for card ${credit.cardId}")
        val transferId = TransferProtocol.transferId(identity.programId, signable).hex()
        val receive = session.sdk.getReceiveState()
        val sw = when (tornVerdict(receive.counter, receive.lastDigest.hex(), credit.counter ?: Int.MAX_VALUE, transferId)) {
            TornVerdict.ALREADY_APPLIED -> "9000"
            TornVerdict.EXCEPTION -> EXCEPTION_SW
            TornVerdict.PRESENT -> try {
                CardTransfers.applyCredit(session, signable, tail)
            } catch (e: CardFlowException) {
                throw e // tag lost etc.: nothing decided, re-present on the next tap
            }
        }
        credit = credit.copy(
            ackStatusWord = sw,
            state = when (sw) {
                "9000" -> "applied"
                EXCEPTION_SW -> "exception"
                else -> "card_refused"
            }
        )
        store.saveCredit(credit)
        AppLogger.i("Load", "Credit for issuance $issuanceId on card ${credit.cardId}: $sw")
        return credit
    }

    /** `POST /offline/issuances/{id}/ack {applied, status_word}` (client-asserted; informational to the bridge). */
    suspend fun ack(issuanceId: String): PendingCredit {
        var credit = store.credit(issuanceId) ?: throw IssuanceRefused("unknown_issuance")
        val sw = credit.ackStatusWord ?: throw IssuanceRefused("not_applied_yet")
        if (credit.acked) return credit
        // Another credit holds the counter: there is no card status word to
        // report, and nothing here may suggest re-issuing. Operator resolution
        // (bridge write-off procedure) decides; the issuance stays `issued`.
        if (sw == EXCEPTION_SW) throw IssuanceRefused("exception_needs_operator", "another credit landed on this card's counter; contact the operator")
        val response = api.ackIssuance(issuanceId, IssuanceAckRequest(applied = sw == "9000", status_word = sw))
        if (!response.isSuccessful && response.code() >= 500) throw IOException("ack failed with HTTP ${response.code()}; retry")
        credit = credit.copy(acked = true, state = response.body()?.state ?: credit.state)
        store.saveCredit(credit)
        return credit
    }

    companion object {
        /** Local marker when another credit occupies the counter; never sent to the bridge. */
        const val EXCEPTION_SW = "EXCP"
    }
}

package com.payala.impala.demo.transfer

import android.content.Context
import android.content.SharedPreferences
import com.impala.sdk.flows.RedemptionTuple
import org.json.JSONArray
import org.json.JSONObject

/**
 * A card → bridge redemption from the app's side. The slot is written
 * **before** the card signs (signable only) and again with the full tuple
 * right after, so a crash can always be resolved without re-signing: either
 * the tuple is here, or it is on the card (GET_LAST_TRANSFER), or the card
 * never signed this signable.
 */
data class PendingRedemption(
    val cardId: String,
    val signableHex: String,
    val tuple: RedemptionTuple? = null,
    val redemptionId: String? = null,
    /** accepted | paying | frozen | paid | failed | cancelled, or local: signing | signed | submitted | refused */
    val state: String = STATE_SIGNING,
    val reason: String? = null,
    val btxid: String? = null,
    val amount: Long = 0,
    val createdAt: Long = 0
) {
    val isTerminal: Boolean get() = state in TERMINAL
    /** Ambiguous payout: "outcome unknown — do not repeat"; blocks new redemptions from this card. */
    val isFrozen: Boolean get() = state == "frozen"

    fun toJson(): JSONObject = JSONObject().apply {
        put("card_id", cardId); put("signable_hex", signableHex); put("state", state); put("amount", amount); put("created_at", createdAt)
        redemptionId?.let { put("redemption_id", it) }
        reason?.let { put("reason", it) }
        btxid?.let { put("btxid", it) }
        tuple?.let {
            put("tuple", JSONObject().put("signable_hex", it.signableHex).put("signature_der_hex", it.signatureDerHex)
                .put("card_pubkey_hex", it.cardPubkeyHex).put("card_cert_hex", it.cardCertHex))
        }
    }

    companion object {
        const val STATE_SIGNING = "signing"
        const val STATE_SIGNED = "signed"
        /** Accepted earlier (202 replay / 409 counter_consumed) but this device never learned the id. */
        const val STATE_SUBMITTED = "submitted"
        /** The bridge refused the tuple: the card was debited, the value is stranded (not lost) — needs an operator. */
        const val STATE_REFUSED = "refused"
        val TERMINAL = setOf("paid", "failed", "cancelled", STATE_REFUSED, STATE_SUBMITTED)

        fun fromJson(o: JSONObject) = PendingRedemption(
            cardId = o.getString("card_id"),
            signableHex = o.getString("signable_hex"),
            tuple = o.optJSONObject("tuple")?.let {
                RedemptionTuple(it.getString("signable_hex"), it.getString("signature_der_hex"), it.getString("card_pubkey_hex"), it.getString("card_cert_hex"))
            },
            redemptionId = o.optString("redemption_id").ifEmpty { null },
            state = o.optString("state", STATE_SIGNING),
            reason = o.optString("reason").ifEmpty { null },
            btxid = o.optString("btxid").ifEmpty { null },
            amount = o.optLong("amount"),
            createdAt = o.optLong("created_at")
        )
    }
}

/**
 * A bridge → card load (issuance). The signed credit is persisted before the
 * card is tapped, so it can be re-presented after a torn apply; the card's own
 * GET_RECEIVE_STATE decides what happened.
 */
data class PendingCredit(
    val issuanceId: String,
    val cardId: String,
    val cardAmount: Long,
    val issuanceRef: String? = null,
    /** Funding parameters exactly as the bridge gave them. */
    val fundingDestination: String? = null,
    val fundingAmount: String? = null,
    val fundingMemo: String? = null,
    /** The idempotency key of the current funding attempt (the bridge's on the first; a new one only after a definite rejection). */
    val fundingKey: String? = null,
    val fundingAttempt: Int = 1,
    /** none | submitted | ambiguous | settled | rejected */
    val fundingStatus: String = "none",
    val fundingIntentId: String? = null,
    /** awaiting_funds | funded | issued | acked | expired | reversed (bridge), or local applied | card_refused | exception */
    val state: String = "awaiting_funds",
    val counter: Int? = null,
    val signableHex: String? = null,
    val tailHex: String? = null,
    val ackStatusWord: String? = null,
    val acked: Boolean = false,
    val createdAt: Long = 0
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("issuance_id", issuanceId); put("card_id", cardId); put("card_amount", cardAmount)
        put("funding_attempt", fundingAttempt); put("funding_status", fundingStatus); put("state", state)
        put("acked", acked); put("created_at", createdAt)
        issuanceRef?.let { put("issuance_ref", it) }
        fundingDestination?.let { put("funding_destination", it) }
        fundingAmount?.let { put("funding_amount", it) }
        fundingMemo?.let { put("funding_memo", it) }
        fundingKey?.let { put("funding_key", it) }
        fundingIntentId?.let { put("funding_intent_id", it) }
        counter?.let { put("counter", it) }
        signableHex?.let { put("signable_hex", it) }
        tailHex?.let { put("tail_hex", it) }
        ackStatusWord?.let { put("ack_status_word", it) }
    }

    companion object {
        fun fromJson(o: JSONObject) = PendingCredit(
            issuanceId = o.getString("issuance_id"),
            cardId = o.getString("card_id"),
            cardAmount = o.optLong("card_amount"),
            issuanceRef = o.optString("issuance_ref").ifEmpty { null },
            fundingDestination = o.optString("funding_destination").ifEmpty { null },
            fundingAmount = o.optString("funding_amount").ifEmpty { null },
            fundingMemo = o.optString("funding_memo").ifEmpty { null },
            fundingKey = o.optString("funding_key").ifEmpty { null },
            fundingAttempt = o.optInt("funding_attempt", 1),
            fundingStatus = o.optString("funding_status", "none"),
            fundingIntentId = o.optString("funding_intent_id").ifEmpty { null },
            state = o.optString("state", "awaiting_funds"),
            counter = if (o.has("counter")) o.getInt("counter") else null,
            signableHex = o.optString("signable_hex").ifEmpty { null },
            tailHex = o.optString("tail_hex").ifEmpty { null },
            ackStatusWord = o.optString("ack_status_word").ifEmpty { null },
            acked = o.optBoolean("acked"),
            createdAt = o.optLong("created_at")
        )
    }
}

/**
 * Durable, synchronous (`commit()`) storage for in-flight card transfers: the
 * write must be on disk before the card is asked to sign. One open redemption
 * per card; credits keyed by issuance id. Not cleared on logout.
 */
class PendingTransferStore internal constructor(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(context.getSharedPreferences(FILE, Context.MODE_PRIVATE))

    fun redemption(cardId: String): PendingRedemption? =
        prefs.getString(redemptionKey(cardId), null)?.let { runCatching { PendingRedemption.fromJson(JSONObject(it)) }.getOrNull() }

    /** Persists synchronously; throws if the write did not reach disk (never sign without it). */
    fun saveRedemption(r: PendingRedemption) {
        check(prefs.edit().putString(redemptionKey(r.cardId), r.toJson().toString()).commit()) { "pending redemption was not persisted" }
    }

    fun redemptions(): List<PendingRedemption> = prefs.all.keys.filter { it.startsWith(REDEMPTION_PREFIX) }
        .mapNotNull { k -> prefs.getString(k, null)?.let { runCatching { PendingRedemption.fromJson(JSONObject(it)) }.getOrNull() } }
        .sortedByDescending { it.createdAt }

    /** Moves a finished redemption to history so the card can redeem again. */
    fun archiveRedemption(cardId: String) {
        val r = redemption(cardId) ?: return
        val history = JSONArray(prefs.getString(HISTORY, "[]"))
        history.put(r.toJson())
        check(prefs.edit().putString(HISTORY, history.toString()).remove(redemptionKey(cardId)).commit())
    }

    fun history(): List<PendingRedemption> {
        val arr = runCatching { JSONArray(prefs.getString(HISTORY, "[]")) }.getOrDefault(JSONArray())
        return (0 until arr.length()).map { PendingRedemption.fromJson(arr.getJSONObject(it)) }.sortedByDescending { it.createdAt }
    }

    fun credit(issuanceId: String): PendingCredit? =
        prefs.getString(CREDIT_PREFIX + issuanceId, null)?.let { runCatching { PendingCredit.fromJson(JSONObject(it)) }.getOrNull() }

    fun saveCredit(c: PendingCredit) {
        check(prefs.edit().putString(CREDIT_PREFIX + c.issuanceId, c.toJson().toString()).commit()) { "pending credit was not persisted" }
    }

    fun credits(): List<PendingCredit> = prefs.all.keys.filter { it.startsWith(CREDIT_PREFIX) }
        .mapNotNull { k -> prefs.getString(k, null)?.let { runCatching { PendingCredit.fromJson(JSONObject(it)) }.getOrNull() } }
        .sortedByDescending { it.createdAt }

    companion object {
        private const val FILE = "impala_pending_transfers"
        private const val REDEMPTION_PREFIX = "redemption."
        private const val CREDIT_PREFIX = "credit."
        private const val HISTORY = "redemption_history"
        private fun redemptionKey(cardId: String) = REDEMPTION_PREFIX + cardId
    }
}

package com.payala.impala.demo.card

import android.content.Context
import android.content.SharedPreferences
import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.UuidBytes
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

/**
 * A card registered with the bridge from this device. Display data only:
 * nothing here is secret (the pubkey is stored as a fingerprint).
 */
data class StoredCard(
    /** `card_id` wire form, 32 lowercase hex. */
    val cardId: String,
    /** Lowercase dashed account UUID the card was issued to. */
    val accountUuid: String,
    val pubkeyFingerprint: String,
    val programIdHex: String,
    /** The 4-byte currency tag as text ("XLM", "USDC", "UST0"). */
    val currency: String,
    val appletVersion: String,
    /** ISO-8601 instant of the bridge's successful `POST /card`. */
    val registeredAt: String
) {
    fun toJson(): JSONObject = JSONObject()
        .put("card_id", cardId).put("account_uuid", accountUuid).put("pubkey_fingerprint", pubkeyFingerprint)
        .put("program_id_hex", programIdHex).put("currency", currency).put("applet_version", appletVersion)
        .put("registered_at", registeredAt)

    companion object {
        fun fromJson(o: JSONObject) = StoredCard(
            o.getString("card_id"), o.getString("account_uuid"), o.getString("pubkey_fingerprint"),
            o.optString("program_id_hex"), o.optString("currency"), o.optString("applet_version"),
            o.optString("registered_at")
        )

        /** First 10 bytes of the 130-hex pubkey (after the 04 prefix), colon-separated. */
        fun fingerprint(pubKeyHex: String): String = pubKeyHex.drop(2).take(20).chunked(2).joinToString(":")

        /** The currency tag as display text, trailing NULs dropped ("XLM\u0000" -> "XLM"). */
        fun currencyText(tag: ByteArray): String = tag.decodeToString().trimEnd('\u0000')

        fun from(identity: CardIdentity, now: Instant = Instant.now()) = StoredCard(
            cardId = identity.wireCardId,
            accountUuid = identity.accountUuid,
            pubkeyFingerprint = fingerprint(identity.pubKeyHex),
            programIdHex = identity.programIdHex,
            currency = currencyText(identity.currency),
            appletVersion = identity.versionString,
            registeredAt = now.toString()
        )
    }
}

/**
 * Per-account list of registered cards, kept in its own preferences file so it
 * survives logout (`TokenManager.clearAll`). The bridge has no card-list
 * endpoint, so this is the app's local record of what it registered.
 */
class CardStore internal constructor(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(context.getSharedPreferences(FILE, Context.MODE_PRIVATE))

    fun list(accountId: String): List<StoredCard> {
        val raw = prefs.getString(key(accountId), null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { StoredCard.fromJson(arr.getJSONObject(it)) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Adds or replaces (by card id) a card under [accountId]. */
    fun save(accountId: String, card: StoredCard) {
        write(accountId, list(accountId).filterNot { it.cardId == card.cardId } + card)
    }

    fun remove(accountId: String, cardId: String) {
        write(accountId, list(accountId).filterNot { it.cardId == cardId })
    }

    fun find(accountId: String, cardId: String): StoredCard? = list(accountId).firstOrNull { it.cardId == cardId }

    private fun write(accountId: String, cards: List<StoredCard>) {
        val arr = JSONArray()
        cards.forEach { arr.put(it.toJson()) }
        prefs.edit().putString(key(accountId), arr.toString()).apply()
    }

    companion object {
        private const val FILE = "impala_cards"

        /** Accounts are keyed by their canonical UUID bytes when they are UUIDs, so dashed and bare forms share a list. */
        internal fun key(accountId: String): String =
            "cards." + (runCatching { UuidBytes.format(UuidBytes.parse(accountId)) }.getOrDefault(accountId.lowercase()))
    }
}

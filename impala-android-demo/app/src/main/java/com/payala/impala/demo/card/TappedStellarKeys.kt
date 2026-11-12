package com.payala.impala.demo.card

import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.models.StellarCardKey
import com.payala.impala.card.CardAuthenticator
import com.payala.impala.card.ImpalaCardSession

/**
 * The Stellar keys of cards tapped in this process, by wire card id. A card's
 * Stellar key and its two cross-signatures are read in the tap that reads its
 * identity (one more read-only command) and sent with the registration that
 * follows, which may happen after the card has left the field ("Register this
 * card?"). Public values only: a public key and two signatures.
 */
object TappedStellarKeys {
    private const val MAX_ENTRIES = 8
    private val keys = LinkedHashMap<String, StellarCardKey>()

    /**
     * Reads the Stellar key of a card that advertises one, inside its tap, and
     * returns [identity] unchanged. A card without one is forgotten. A failed
     * read fails the tap: registering the card without its key would leave it
     * on the legacy sign-in for good.
     *
     * @throws com.impala.sdk.flows.CardFlowException when the read fails
     */
    fun readDuringTap(session: ImpalaCardSession, identity: CardIdentity): CardIdentity {
        val key = if (identity.hasStellarKey) CardAuthenticator.stellarKey(session) else null
        synchronized(keys) {
            keys.remove(identity.wireCardId)
            if (key != null) {
                keys[identity.wireCardId] = key
                while (keys.size > MAX_ENTRIES) keys.remove(keys.keys.first())
            }
        }
        return identity
    }

    /** The key read in this card's last tap, or null (no Stellar key, or not tapped in this process). */
    fun forCard(wireCardId: String): StellarCardKey? = synchronized(keys) { keys[wireCardId] }

    fun clear() = synchronized(keys) { keys.clear() }
}

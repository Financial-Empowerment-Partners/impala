package com.payala.impala.card

import android.util.Log
import com.impala.sdk.flows.CardIdentity
import java.util.concurrent.atomic.AtomicReference

/** A card tapped while the app was not in reader mode (system NFC dispatch). */
class CardTapEvent(val identity: CardIdentity)

/** Receives [CardTapEvent]s from [com.payala.impala.NfcContactActivity] on the main thread. */
fun interface CardTapListener {
    fun onCardTapped(event: CardTapEvent)
}

/**
 * Static registry for the single [CardTapListener] (same pattern as
 * `ImpalaNdefHandler`). System dispatch only ever reads the identity; it never
 * sends a state-changing command.
 */
object ImpalaCardTapHandler {
    private const val TAG = "ImpalaCardTap"
    private val listenerRef = AtomicReference<CardTapListener?>()

    @JvmStatic
    fun setCardTapListener(listener: CardTapListener?) = listenerRef.set(listener)

    @JvmStatic
    fun getCardTapListener(): CardTapListener? = listenerRef.get()

    /**
     * Reads [session]'s identity (non-mutating INS only) and returns the event
     * for delivery, or null when nobody is listening or the read failed.
     */
    @JvmStatic
    fun readTap(session: ImpalaCardSession): CardTapEvent? {
        if (listenerRef.get() == null) {
            Log.d(TAG, "Card tapped with no CardTapListener registered")
            return null
        }
        return try {
            CardTapEvent(session.identity)
        } catch (e: Exception) {
            Log.d(TAG, "Card tap identity read failed: ${e.javaClass.simpleName}")
            null
        }
    }

    @JvmStatic
    fun deliver(event: CardTapEvent) {
        val l = listenerRef.get() ?: return
        try {
            l.onCardTapped(event)
        } catch (e: Exception) {
            Log.e(TAG, "CardTapListener threw ${e.javaClass.simpleName}")
        }
    }
}

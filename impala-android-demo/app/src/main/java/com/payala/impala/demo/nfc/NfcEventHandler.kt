package com.payala.impala.demo.nfc

import android.nfc.NdefMessage

/**
 * Singleton event dispatcher for NFC events, mirroring the impala-lib
 * [ImpalaNdefHandler] listener pattern.
 *
 * The application registers listeners early (e.g. in `Application.onCreate`)
 * and background NFC processing dispatches results here. Supports two event
 * types: APDU card read results and NDEF message discovery.
 *
 * Thread-safe: listeners are volatile and callbacks are invoked on the
 * calling thread (typically the service's background handler thread).
 */
object NfcEventHandler {

    /**
     * Callback for IsoDep APDU card events (smartcard taps).
     * Invoked when the background watcher successfully reads a card or
     * encounters an error.
     */
    interface ApduEventListener {
        /** Called when a card is successfully read in the background. */
        fun onCardRead(user: CardUser, ecPubKey: ByteArray, tagId: ByteArray?)

        /** Called when card APDU processing fails. */
        fun onCardError(message: String)
    }

    /**
     * Callback for NDEF message events (data tags).
     * Mirrors impala-lib's `ImpalaNdefHandler.NdefListener`.
     */
    interface NdefEventListener {
        /** Called when NDEF messages are read from a tag. */
        fun onNdefReceived(messages: Array<NdefMessage>)
    }

    @Volatile
    private var apduListener: ApduEventListener? = null

    @Volatile
    private var ndefListener: NdefEventListener? = null

    /** Register a listener for IsoDep APDU card events. Replaces any previous listener. */
    fun setApduEventListener(listener: ApduEventListener?) {
        apduListener = listener
    }

    /** Register a listener for NDEF message events. Replaces any previous listener. */
    fun setNdefEventListener(listener: NdefEventListener?) {
        ndefListener = listener
    }

    /** Dispatch a successful card read to the registered APDU listener. */
    fun dispatchCardRead(user: CardUser, ecPubKey: ByteArray, tagId: ByteArray?) {
        apduListener?.onCardRead(user, ecPubKey, tagId)
    }

    /** Dispatch a card error to the registered APDU listener. */
    fun dispatchCardError(message: String) {
        apduListener?.onCardError(message)
    }

    /** Dispatch NDEF messages to the registered NDEF listener. */
    fun dispatchNdef(messages: Array<NdefMessage>) {
        ndefListener?.onNdefReceived(messages)
    }
}

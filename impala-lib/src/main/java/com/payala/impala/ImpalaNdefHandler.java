package com.payala.impala;

import android.content.Context;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;

/**
 * Singleton-style handler that dispatches NFC NDEF messages to a registered listener.
 *
 * <p>The application should register an {@link NdefListener} early in its lifecycle
 * so that NDEF messages discovered by {@link NdefDispatchActivity} are not silently dropped.
 *
 * <p>Usage:
 * <pre>
 *   ImpalaNdefHandler.setNdefListener(messages -> {
 *       for (NdefMessage msg : messages) {
 *           // process NDEF records
 *       }
 *   });
 * </pre>
 */
public class ImpalaNdefHandler {

    /**
     * Callback interface for receiving NFC NDEF messages.
     */
    public interface NdefListener {
        /**
         * Called when one or more NDEF messages are read from an NFC tag.
         *
         * @param messages array of NDEF messages discovered on the tag
         */
        void onNdefReceived(NdefMessage[] messages);
    }

    private static volatile NdefListener listener;

    /**
     * Register a listener to receive NDEF messages. Only one listener
     * is supported at a time; setting a new listener replaces the previous one.
     */
    public static void setNdefListener(NdefListener l) {
        listener = l;
    }

    /**
     * Dispatch NDEF messages to the registered listener, if any.
     * Called internally by {@link NdefDispatchActivity}.
     */
    public static void handle_nfc_ndef(Context context, NdefMessage[] messages) {
        if (listener != null) {
            listener.onNdefReceived(messages);
        }
    }
}

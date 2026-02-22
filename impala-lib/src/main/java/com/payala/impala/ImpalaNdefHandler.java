package com.payala.impala;

import android.content.Context;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.util.Log;

import java.util.concurrent.atomic.AtomicReference;

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

    private static final String TAG = "ImpalaNdefHandler";

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

    private static final AtomicReference<NdefListener> listenerRef = new AtomicReference<>();

    /**
     * Register a listener to receive NDEF messages. Only one listener
     * is supported at a time; setting a new listener replaces the previous one.
     */
    public static void setNdefListener(NdefListener l) {
        listenerRef.set(l);
    }

    /**
     * Returns the currently registered listener, or null if none.
     */
    public static NdefListener getNdefListener() {
        return listenerRef.get();
    }

    /**
     * Dispatch NDEF messages to the registered listener, if any.
     * Called internally by {@link NdefDispatchActivity}.
     */
    public static void handle_nfc_ndef(Context context, NdefMessage[] messages) {
        NdefListener l = listenerRef.get();
        if (l != null) {
            try {
                l.onNdefReceived(messages);
            } catch (Exception e) {
                Log.e(TAG, "NDEF callback error: " + e.getMessage());
            }
        } else {
            Log.w(TAG, "No NDEF listener registered");
        }
    }
}

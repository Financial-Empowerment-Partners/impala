package com.payala.impala;

import android.content.Context;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;

public class ImpalaNdefHandler {

    public interface NdefListener {
        void onNdefReceived(NdefMessage[] messages);
    }

    private static NdefListener listener;

    public static void setNdefListener(NdefListener l) {
        listener = l;
    }

    public static void handle_nfc_ndef(Context context, NdefMessage[] messages) {
        if (listener != null) {
            listener.onNdefReceived(messages);
        }
    }
}

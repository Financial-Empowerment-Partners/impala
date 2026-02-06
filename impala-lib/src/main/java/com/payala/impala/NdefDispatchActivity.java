package com.payala.impala;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.os.Parcelable;

/**
 * Transient activity that handles NFC NDEF tag discovery events.
 *
 * <p>Declared in AndroidManifest.xml with an intent filter for
 * {@code ACTION_NDEF_DISCOVERED} and all MIME types. When Android discovers
 * an NDEF tag, this activity extracts the messages and delegates them to
 * {@link ImpalaNdefHandler#handle_nfc_ndef}, then immediately finishes.
 *
 * <p>Uses {@code Theme.NoDisplay} so no UI is shown to the user.
 */
public class NdefDispatchActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        handleIntent(getIntent());
        finish();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
        finish();
    }

    /**
     * Extract NDEF messages from the discovery intent and forward them
     * to the registered NDEF handler.
     */
    private void handleIntent(Intent intent) {
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(intent.getAction())) {
            Parcelable[] rawMessages = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
            if (rawMessages != null && rawMessages.length > 0) {
                NdefMessage[] messages = new NdefMessage[rawMessages.length];
                for (int i = 0; i < rawMessages.length; i++) {
                    messages[i] = (NdefMessage) rawMessages[i];
                }
                ImpalaNdefHandler.handle_nfc_ndef(this, messages);
            }
        }
    }
}

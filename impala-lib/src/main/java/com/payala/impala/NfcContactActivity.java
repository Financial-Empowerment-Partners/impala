package com.payala.impala;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;

import com.impala.sdk.ImpalaSDK;
import com.impala.sdk.apdu4j.CommandAPDU;

/**
 * Handles NFC IsoDep (contact/contactless smartcard) tag discovery.
 * Reads the APDU payload from the tag and passes it to the ImpalaSDK tx method.
 */
public class NfcContactActivity extends Activity {

    private static final String TAG = "NfcContactActivity";

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

    private void handleIntent(Intent intent) {
        String action = intent.getAction();
        if (!NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
            return;
        }

        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag == null) {
            Log.w(TAG, "No tag in intent");
            return;
        }

        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            Log.w(TAG, "Tag does not support IsoDep");
            return;
        }

        try {
            isoDep.connect();

            IsoDepBibo bibo = new IsoDepBibo(isoDep);
            ImpalaSDK sdk = new ImpalaSDK(bibo);

            byte[] tagId = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
            if (tagId == null) {
                tagId = tag.getId();
            }

            CommandAPDU cmd = new CommandAPDU(tagId);
            sdk.tx(cmd);

            Log.i(TAG, "APDU transmitted to ImpalaSDK via NFC contact");
        } catch (Exception e) {
            Log.e(TAG, "Error processing NFC contact", e);
        } finally {
            try {
                isoDep.close();
            } catch (Exception ignored) {
            }
        }
    }
}

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
 * Transient activity that handles NFC IsoDep (ISO 14443-4) tag discovery.
 *
 * <p>When Android detects an IsoDep-compatible smartcard (e.g. an Impala JavaCard),
 * this activity:
 * <ol>
 *   <li>Connects to the card via {@link IsoDep}</li>
 *   <li>Wraps the connection in an {@link IsoDepBibo} adapter</li>
 *   <li>Creates an {@link ImpalaSDK} instance</li>
 *   <li>Transmits the tag ID as a {@link CommandAPDU}</li>
 * </ol>
 *
 * <p>Declared in AndroidManifest.xml with {@code ACTION_TECH_DISCOVERED} and
 * a tech filter for {@code android.nfc.tech.IsoDep}. Uses {@code Theme.NoDisplay}
 * so no UI is shown. The activity finishes immediately after processing.
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

    /**
     * Connect to the IsoDep tag, instantiate the SDK, and transmit the tag ID.
     * Ensures the IsoDep connection is closed in the finally block.
     */
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

            // Use the tag ID from the intent, falling back to tag.getId()
            byte[] tagId = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
            if (tagId == null) {
                tagId = tag.getId();
            }
            if (tagId == null || tagId.length == 0) {
                Log.w(TAG, "No tag ID available");
                return;
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

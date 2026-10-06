package com.payala.impala;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.core.content.IntentCompat;

import com.payala.impala.card.CardTapEvent;
import com.payala.impala.card.ImpalaCardSession;
import com.payala.impala.card.ImpalaCardTapHandler;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Transient activity for system-dispatched IsoDep (ISO 14443-4) taps — a card
 * presented while the app is not in reader mode.
 *
 * <p>It opens an {@link ImpalaCardSession} off the main thread, reads the
 * card identity (GET_VERSION, GET_PERSONALIZATION, GET_USER_DATA,
 * GET_EC_PUB_KEY — nothing that changes card state), and forwards a
 * {@link CardTapEvent} to the registered
 * {@link com.payala.impala.card.CardTapListener} on the main thread. With no
 * listener registered it logs at DEBUG and does nothing. Signing and transfers
 * only ever happen in reader mode
 * ({@link com.payala.impala.card.CardReaderController}), where the user started
 * the action.
 *
 * <p>Declared in AndroidManifest.xml with {@code ACTION_TECH_DISCOVERED} and a
 * tech filter for {@code android.nfc.tech.IsoDep}; {@code Theme.NoDisplay}, and
 * finishes immediately.
 */
public class NfcContactActivity extends Activity {

    private static final String TAG = "NfcContactActivity";
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor();

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
        if (intent == null || !NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            return;
        }
        Tag tag = IntentCompat.getParcelableExtra(intent, NfcAdapter.EXTRA_TAG, Tag.class);
        if (tag == null) {
            Log.w(TAG, "No tag in intent");
            return;
        }
        if (ImpalaCardTapHandler.getCardTapListener() == null) {
            Log.d(TAG, "Card tapped with no CardTapListener registered");
            return;
        }
        Handler main = new Handler(Looper.getMainLooper());
        EXECUTOR.execute(() -> {
            CardTapEvent event = null;
            try (ImpalaCardSession session = ImpalaCardSession.open(tag)) {
                event = ImpalaCardTapHandler.readTap(session);
            } catch (Exception e) {
                Log.d(TAG, "System-dispatched tap could not be read: " + e.getClass().getSimpleName());
            }
            if (event != null) {
                CardTapEvent delivered = event;
                main.post(() -> ImpalaCardTapHandler.deliver(delivered));
            }
        });
    }
}

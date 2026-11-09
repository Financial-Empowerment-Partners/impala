package com.payala.impala;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.content.IntentCompat;

import com.payala.impala.card.CardAppletAid;
import com.payala.impala.card.CardTapEvent;
import com.payala.impala.card.ImpalaCardSession;
import com.payala.impala.card.ImpalaCardTapHandler;
import com.payala.impala.card.ImpalaLibLog;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Transient activity for system-dispatched IsoDep (ISO 14443-4) taps — a card
 * presented while the app is not in reader mode.
 *
 * <p>It opens an {@link ImpalaCardSession} off the main thread on the consuming
 * app's applet AID ({@link CardAppletAid#forApp}, from the app's manifest
 * meta-data; no SELECT when the app declares an empty AID), reads the
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

    /** Opens the session for a dispatched tag; replaced only by tests (no NFC hardware). */
    @VisibleForTesting
    public interface SessionOpener {
        ImpalaCardSession open(Tag tag, @Nullable String aidHex) throws Exception;
    }

    private static final SessionOpener DEFAULT_OPENER =
            (tag, aidHex) -> ImpalaCardSession.open(tag, ImpalaCardSession.DEFAULT_TIMEOUT_MS, aidHex);

    @VisibleForTesting
    public static volatile SessionOpener sessionOpener = DEFAULT_OPENER;

    /** Restores the production opener (tests). */
    @VisibleForTesting
    public static void resetSessionOpener() {
        sessionOpener = DEFAULT_OPENER;
    }

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
            ImpalaLibLog.w(TAG, "No tag in intent");
            return;
        }
        if (ImpalaCardTapHandler.getCardTapListener() == null) {
            ImpalaLibLog.d(TAG, "Card tapped with no CardTapListener registered");
            return;
        }
        String aidHex = CardAppletAid.forApp(getApplicationContext());
        SessionOpener opener = sessionOpener;
        Handler main = new Handler(Looper.getMainLooper());
        EXECUTOR.execute(() -> {
            CardTapEvent event = null;
            try (ImpalaCardSession session = opener.open(tag, aidHex)) {
                event = ImpalaCardTapHandler.readTap(session);
            } catch (Exception e) {
                ImpalaLibLog.d(TAG, "System-dispatched tap could not be read: " + e.getClass().getSimpleName());
            }
            if (event != null) {
                CardTapEvent delivered = event;
                main.post(() -> ImpalaCardTapHandler.deliver(delivered));
            }
        });
    }
}

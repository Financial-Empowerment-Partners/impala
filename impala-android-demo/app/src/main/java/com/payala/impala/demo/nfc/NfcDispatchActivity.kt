package com.payala.impala.demo.nfc

import android.app.Activity
import android.os.Bundle
import com.payala.impala.demo.log.AppLogger

/**
 * Invisible activity that catches NFC intents from the system tag dispatch
 * when no foreground activity has claimed them.
 *
 * Registered in the manifest with `ACTION_TECH_DISCOVERED` (for IsoDep tags)
 * and `ACTION_NDEF_DISCOVERED` intent filters. When the system delivers an
 * NFC intent, this activity forwards it to [NfcWatcherService] for
 * background processing and immediately finishes (no UI).
 *
 * This mirrors impala-lib's `NfcContactActivity` and `NdefDispatchActivity`
 * which receive system NFC intents and delegate to handlers.
 */
class NfcDispatchActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val action = intent?.action
        AppLogger.d("NfcDispatch", "Received NFC intent: $action")

        if (intent != null) {
            NfcWatcherService.processNfcIntent(this, intent)
        }

        finish()
    }
}

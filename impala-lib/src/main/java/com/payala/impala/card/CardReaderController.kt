package com.payala.impala.card

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.annotation.VisibleForTesting
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException

/**
 * NFC reader mode for one foreground activity, and the only way an app talks
 * to a tapped card.
 *
 * [enableReaderMode] runs `onTap` on the NFC binder thread **with the session
 * open**, so network round-trips that must happen while the card is still in
 * the field (fetching a bridge challenge) belong inside `onTap`. `onResult` is
 * delivered on the main thread. Card failures arrive as [CardFlowException]
 * (tag loss is [CardError.TagLost]); anything else `onTap` throws (an HTTP
 * error) is delivered unchanged.
 */
class CardReaderController @JvmOverloads constructor(
    private val activity: Activity,
    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity),
    private val aidHex: String? = ImpalaCardSession.TESTNET_APPLET_AID,
    private val sessionFactory: (Tag) -> ImpalaCardSession = { ImpalaCardSession.open(it, aidHex = aidHex) },
    private val mainHandler: Handler = Handler(Looper.getMainLooper())
) {
    private var tapHandler: ((ImpalaCardSession) -> Unit)? = null

    val isNfcAvailable: Boolean get() = adapter != null
    val isNfcEnabled: Boolean get() = adapter?.isEnabled == true

    /**
     * Enables reader mode (NFC-A and NFC-B, NDEF check skipped, 250 ms
     * presence check). Returns false when the device has no NFC adapter.
     */
    fun <R> enableReaderMode(onTap: (ImpalaCardSession) -> R, onResult: (Result<R>) -> Unit): Boolean {
        // Set before the adapter check so debugInjectTap works on devices
        // without NFC (the emulator lane).
        tapHandler = { session -> deliver(runCatchingCard { session.use(onTap) }, onResult) }
        val nfc = adapter ?: return false
        nfc.enableReaderMode(activity, { tag -> handleTag(tag, onTap, onResult) }, READER_FLAGS, readerExtras())
        return true
    }

    fun disableReaderMode() {
        tapHandler = null
        adapter?.disableReaderMode(activity)
    }

    /** Called on the NFC binder thread for each discovered tag. */
    @VisibleForTesting
    internal fun <R> handleTag(tag: Tag, onTap: (ImpalaCardSession) -> R, onResult: (Result<R>) -> Unit) {
        deliver(runCatchingCard { sessionFactory(tag).use(onTap) }, onResult)
    }

    /**
     * Test hook for the emulator lane (no NFC): runs the current `onTap` with
     * [session] on a background thread exactly as a tap would.
     */
    @VisibleForTesting
    fun debugInjectTap(session: ImpalaCardSession) {
        val handler = tapHandler ?: throw IllegalStateException("reader mode is not enabled")
        Thread({ handler(session) }, "impala-card-debug-tap").start()
    }

    private fun <R> deliver(result: Result<R>, onResult: (Result<R>) -> Unit) {
        mainHandler.post { onResult(result) }
    }

    companion object {
        const val READER_FLAGS: Int =
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        const val PRESENCE_CHECK_DELAY_MS = 250

        internal fun readerExtras(): Bundle =
            Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY_MS) }

        /** Card/transport failures become [CardFlowException]; everything else passes through. */
        internal inline fun <R> runCatchingCard(block: () -> R): Result<R> =
            try {
                Result.success(block())
            } catch (e: CardFlowException) {
                Result.failure(e)
            } catch (e: BIBOException) {
                Result.failure(CardFlowException(CardError.from(e), e))
            } catch (e: Exception) {
                Result.failure(e)
            }
    }
}

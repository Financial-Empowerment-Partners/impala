package com.payala.impala.demo.auth

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import androidx.core.content.IntentCompat
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.nfc.CardUser
import com.payala.impala.demo.nfc.ImpalaCardReader
import com.payala.impala.demo.nfc.IsoDepBibo

/**
 * Result of an NFC card read operation.
 *
 * Follows the same sealed-class pattern as [GoogleSignInResult] and
 * [GitHubSignInResult] for consistency across authentication methods.
 */
sealed class NfcCardResult {
    /**
     * Card was read successfully.
     *
     * @param user       card-stored identity (account ID, card ID, full name)
     * @param ecPubKey   EC (secp256r1) public key bytes (65B uncompressed)
     * @param rsaPubKey  RSA public key modulus bytes
     * @param authSignature DER-encoded ECDSA signature over the bridge-issued
     *   auth challenge (signed on-card with the `"IMPALA-AUTH:"` domain
     *   prefix), or `null` when no challenge was requested — e.g. a card
     *   registration read, where only identity and public keys are needed
     */
    data class Success(
        val user: CardUser,
        val ecPubKey: ByteArray,
        val rsaPubKey: ByteArray,
        val authSignature: ByteArray? = null
    ) : NfcCardResult()

    /** Card read failed with an error message. */
    data class Error(val message: String) : NfcCardResult()

    /** Device does not have NFC hardware. */
    data object NfcNotAvailable : NfcCardResult()
}

/**
 * Manages NFC discovery and Impala card reading.
 *
 * The preferred mechanism is **reader mode** ([enableReaderMode]/[disableReaderMode]):
 * its callback runs on a binder thread (off the main thread), so the blocking
 * IsoDep exchange in [processTag] never risks an ANR, and it disables NDEF
 * dispatch + uses a presence-check delay for smoother polling. The legacy
 * foreground-dispatch API is retained for callers that still route taps through
 * `onNewIntent`, but new code should use reader mode.
 *
 * @param activity the activity that will receive NFC tags
 */
class NfcCardAuthHelper(private val activity: Activity) {

    private val nfcAdapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    /** True if the device has NFC hardware. */
    val isNfcAvailable: Boolean get() = nfcAdapter != null

    /** True if NFC is enabled in device settings. */
    val isNfcEnabled: Boolean get() = nfcAdapter?.isEnabled == true

    /**
     * Enables reader mode. The Impala card is read on a binder thread (off the
     * main thread); [onResult] is then invoked **on the main thread** with the
     * outcome. Call in `onResume()` and pair with [disableReaderMode] in `onPause()`.
     *
     * @param challengeFetcher optional blocking callback that fetches a
     *   bridge-issued auth challenge for the given card ID. Invoked on the
     *   binder thread **while IsoDep is still connected**, so the challenge
     *   can be signed on-card within its 60-second TTL. Return `null` to skip
     *   challenge signing for this tap; throw to fail the read with the
     *   exception's message.
     */
    fun enableReaderMode(
        challengeFetcher: ((cardId: String) -> ByteArray?)? = null,
        onResult: (NfcCardResult) -> Unit
    ) {
        val adapter = nfcAdapter
        if (adapter == null) {
            onResult(NfcCardResult.NfcNotAvailable)
            return
        }
        val callback = NfcAdapter.ReaderCallback { tag ->
            // Runs off the main thread — safe to do the blocking IsoDep exchange here.
            val result = processTag(tag, challengeFetcher)
            activity.runOnUiThread { onResult(result) }
        }
        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        val extras = Bundle().apply {
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY_MS)
        }
        adapter.enableReaderMode(activity, callback, flags, extras)
    }

    /** Disables reader mode. Must be called in `onPause()`. */
    fun disableReaderMode() {
        nfcAdapter?.disableReaderMode(activity)
    }

    /**
     * Enables NFC foreground dispatch so this activity receives tag intents
     * instead of the system tag dispatch.
     *
     * Legacy mechanism — prefer [enableReaderMode], whose callback is off-main.
     */
    fun enableForegroundDispatch() {
        val intent = Intent(activity, activity.javaClass).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val pendingIntent = PendingIntent.getActivity(
            activity, 0, intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val techFilter = IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)
        val techList = arrayOf(arrayOf(IsoDep::class.java.name))
        nfcAdapter?.enableForegroundDispatch(activity, pendingIntent, arrayOf(techFilter), techList)
    }

    /**
     * Disables NFC foreground dispatch. Must be called in `onPause()`.
     */
    fun disableForegroundDispatch() {
        nfcAdapter?.disableForegroundDispatch(activity)
    }

    /**
     * Processes an NFC tag intent by connecting to the card and reading
     * identity and public keys (no auth-challenge signing).
     *
     * @param intent the intent from [Activity.onNewIntent] or [Activity.getIntent]
     * @return [NfcCardResult.Success] with card data, or an error result
     */
    fun processTag(intent: Intent): NfcCardResult {
        if (nfcAdapter == null) return NfcCardResult.NfcNotAvailable

        val tag: Tag = IntentCompat.getParcelableExtra(intent, NfcAdapter.EXTRA_TAG, Tag::class.java)
            ?: return NfcCardResult.Error("No NFC tag found")

        return processTag(tag)
    }

    /**
     * Connects to [tag] and reads identity and public keys; when
     * [challengeFetcher] is supplied (and returns non-null), additionally has
     * the card sign the bridge-issued auth challenge while still connected.
     * Blocking — must NOT be called on the main thread (reader-mode callbacks run
     * off-main; the [processTag] intent overload is invoked from `onNewIntent`,
     * whose callers should dispatch it off-main).
     */
    fun processTag(
        tag: Tag,
        challengeFetcher: ((cardId: String) -> ByteArray?)? = null
    ): NfcCardResult {
        val isoDep = IsoDep.get(tag)
            ?: return NfcCardResult.Error("Card does not support IsoDep")

        AppLogger.i("NFC", "Processing NFC tag")

        return try {
            isoDep.connect()

            val bibo = IsoDepBibo(isoDep, IsoDepBibo.DEFAULT_TIMEOUT_MS)
            val reader = ImpalaCardReader(bibo)

            val user = reader.getUserData()
            AppLogger.d("NFC", "Card user: ${user.accountId} (${user.fullName})")
            val ecPubKey = reader.getECPubKey()
            AppLogger.d("NFC", "EC pubkey read: ${ecPubKey.size} bytes")
            val rsaPubKey = try { reader.getRSAPubKey() } catch (_: Exception) { byteArrayOf() }

            // Challenge-response auth: fetch the bridge challenge while the
            // card is still connected so it can be signed on-card within the
            // challenge's 60-second TTL.
            val authSignature = challengeFetcher?.invoke(user.wireCardId)?.let { challenge ->
                reader.signAuthChallenge(challenge).also {
                    AppLogger.i("NFC", "Auth challenge signed (${it.size}-byte DER signature)")
                }
            }
            AppLogger.i("NFC", "Card read successful: ${user.cardId}")

            NfcCardResult.Success(user, ecPubKey, rsaPubKey, authSignature)
        } catch (e: Exception) {
            AppLogger.e("NFC", "Card read failed: ${e.message}")
            NfcCardResult.Error(e.message ?: "Card read failed")
        } finally {
            try { isoDep.close() } catch (_: Exception) { }
        }
    }

    companion object {
        /** Delay (ms) between presence checks in reader mode; smooths polling. */
        private const val PRESENCE_CHECK_DELAY_MS = 250
    }
}

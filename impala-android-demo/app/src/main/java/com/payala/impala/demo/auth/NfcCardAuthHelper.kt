package com.payala.impala.demo.auth

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
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
     * @param signedTimestamp DER-encoded ECDSA signature of [timestamp]
     * @param timestamp  Unix epoch seconds that was signed
     */
    data class Success(
        val user: CardUser,
        val ecPubKey: ByteArray,
        val rsaPubKey: ByteArray,
        val signedTimestamp: ByteArray,
        val timestamp: Long
    ) : NfcCardResult()

    /** Card read failed with an error message. */
    data class Error(val message: String) : NfcCardResult()

    /** Device does not have NFC hardware. */
    data object NfcNotAvailable : NfcCardResult()
}

/**
 * Manages NFC foreground dispatch and Impala card reading.
 *
 * Uses Android's [NfcAdapter] foreground dispatch system to give the active
 * activity priority over the system's tag dispatch when an IsoDep-compatible
 * smartcard is tapped. The [processTag] method connects to the card,
 * reads identity and public keys, and returns a [NfcCardResult].
 *
 * Lifecycle: call [enableForegroundDispatch] in `onResume()` and
 * [disableForegroundDispatch] in `onPause()`.
 *
 * @param activity the activity that will receive NFC intents
 */
class NfcCardAuthHelper(private val activity: Activity) {

    private val nfcAdapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    /** True if the device has NFC hardware. */
    val isNfcAvailable: Boolean get() = nfcAdapter != null

    /** True if NFC is enabled in device settings. */
    val isNfcEnabled: Boolean get() = nfcAdapter?.isEnabled == true

    /**
     * Enables NFC foreground dispatch so this activity receives tag intents
     * instead of the system tag dispatch.
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
     * identity, public keys, and a signed timestamp.
     *
     * @param intent the intent from [Activity.onNewIntent] or [Activity.getIntent]
     * @return [NfcCardResult.Success] with card data, or an error result
     */
    fun processTag(intent: Intent): NfcCardResult {
        if (nfcAdapter == null) return NfcCardResult.NfcNotAvailable

        @Suppress("DEPRECATION")
        val tag: Tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            ?: return NfcCardResult.Error("No NFC tag found")

        val isoDep = IsoDep.get(tag)
            ?: return NfcCardResult.Error("Card does not support IsoDep")

        return try {
            isoDep.connect()
            isoDep.timeout = 5000

            val bibo = IsoDepBibo(isoDep)
            val reader = ImpalaCardReader(bibo)

            val user = reader.getUserData()
            val ecPubKey = reader.getECPubKey()
            val rsaPubKey = try { reader.getRSAPubKey() } catch (_: Exception) { byteArrayOf() }
            val timestamp = System.currentTimeMillis() / 1000
            val signedTimestamp = reader.getSignedTimestamp(timestamp)

            NfcCardResult.Success(user, ecPubKey, rsaPubKey, signedTimestamp, timestamp)
        } catch (e: Exception) {
            NfcCardResult.Error(e.message ?: "Card read failed")
        } finally {
            try { isoDep.close() } catch (_: Exception) { }
        }
    }
}

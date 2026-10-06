package com.payala.impala.card

import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import androidx.annotation.VisibleForTesting
import com.impala.sdk.ImpalaSDK
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.payala.impala.IsoDepBibo
import java.io.Closeable
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One connected card: the transport, an [ImpalaSDK] over it, and the card's
 * [identity] (read once, on first access). Use with `use {}`; [close] is
 * idempotent.
 *
 * Sessions are opened off the main thread only ([open] throws
 * [IllegalStateException] on the main thread), so no caller can ANR on card
 * I/O.
 */
class ImpalaCardSession private constructor(
    private val bibo: BIBO,
    /** The NFC tag this session was opened on (UID, tech list for diagnostics); null for injected transports. */
    val tag: Tag? = null
) : Closeable {
    private val closed = AtomicBoolean(false)

    /** The SDK bound to this session's transport (no SCP03 keys: client sessions never open a secure channel). */
    val sdk: ImpalaSDK = ImpalaSDK(bibo, null)

    /**
     * The card identity, read lazily with GET_VERSION / GET_PERSONALIZATION /
     * GET_USER_DATA / GET_EC_PUB_KEY. A 0.1 applet fails with
     * [CardError.WrongProtocolVersion] here, before any V2 command.
     *
     * @throws CardFlowException on any card or transport failure
     */
    val identity: CardIdentity by lazy {
        requireBackgroundThread("Reading the card identity")
        CardIdentity.read(sdk)
    }

    val isClosed: Boolean get() = closed.get()

    override fun close() {
        if (closed.compareAndSet(false, true)) bibo.close()
    }

    companion object {
        /** Applet-instance AID of the testnet CAP (`applet.aid.app` in impala-card/applet/build.xml). */
        const val TESTNET_APPLET_AID = "01020304050607080102"

        const val DEFAULT_TIMEOUT_MS = 5000

        /**
         * Connects to [tag] over IsoDep and SELECTs the applet by [aidHex]
         * (skipped when null, relying on the card's default selection).
         *
         * @throws IllegalStateException on the main thread
         * @throws CardFlowException ([CardError.TagLost] when the card left the field)
         */
        @JvmStatic
        @JvmOverloads
        fun open(tag: Tag, timeoutMs: Int = DEFAULT_TIMEOUT_MS, aidHex: String? = TESTNET_APPLET_AID): ImpalaCardSession {
            requireBackgroundThread("Opening a card session")
            val isoDep = IsoDep.get(tag)
                ?: throw CardFlowException(CardError.InvalidRequest("tag is not an ISO 14443-4 (IsoDep) card"))
            try {
                isoDep.connect()
            } catch (e: TagLostException) {
                throw CardFlowException(CardError.TagLost, e)
            } catch (e: IOException) {
                throw CardFlowException(CardError.Other(null), e)
            }
            return withSelect(ImpalaCardSession(IsoDepBibo(isoDep, timeoutMs), tag), aidHex)
        }

        /**
         * A session over an already-connected transport (jcardsim in tests,
         * the debug TCP transport on the emulator). Not for production NFC.
         */
        @JvmStatic
        @VisibleForTesting
        fun fromBibo(bibo: BIBO, aidHex: String? = null): ImpalaCardSession =
            withSelect(ImpalaCardSession(bibo), aidHex)

        private fun withSelect(session: ImpalaCardSession, aidHex: String?): ImpalaCardSession {
            if (!aidHex.isNullOrEmpty()) {
                try {
                    select(session.bibo, aidHex)
                } catch (e: Exception) {
                    session.close()
                    throw e
                }
            }
            return session
        }

        private fun select(bibo: BIBO, aidHex: String) {
            require(aidHex.length % 2 == 0 && aidHex.length in 10..32) { "AID must be 5..16 bytes of hex" }
            val aid = ByteArray(aidHex.length / 2) { aidHex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
            val resp = try {
                bibo.transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid)
            } catch (e: BIBOException) {
                throw CardFlowException(CardError.from(e), e)
            } ?: throw CardFlowException(CardError.Other(null))
            val sw = if (resp.size >= 2) ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF) else -1
            if (sw != 0x9000) {
                // 6A82 "file not found": not an Impala card (or the other network's CAP).
                throw CardFlowException(CardError.Other(if (sw < 0) null else sw))
            }
        }
    }
}

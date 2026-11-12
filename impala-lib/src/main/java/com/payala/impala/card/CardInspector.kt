package com.payala.impala.card

import com.impala.sdk.Constants
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.BIBOTagLostException
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.CardPersonalization
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaVersion
import com.impala.sdk.models.Signable
import com.impala.sdk.models.StellarCardKey
import com.impala.sdk.models.TransferProtocol
import java.security.MessageDigest

/**
 * One inspection step: [name] is the instruction it sent (`GET_VERSION`, …);
 * [error] is the typed failure when [ok] is false.
 */
class InspectionStep(val name: String, val ok: Boolean, val error: CardError?) {
    override fun toString(): String = if (ok) "$name OK" else "$name failed: $error"
}

/**
 * The card's last signed transfer (GET_LAST_TRANSFER), decoded. Financial
 * detail: it is only ever handed out inside a [Masked].
 */
class LastTransferSummary(
    val amountMinor: Long,
    val counter: Int,
    val sendSequence: Long,
    val recipientUuid: String,
    val currency: String,
    val signatureLength: Int
) {
    override fun toString(): String = "LastTransferSummary(${Masked.MASK})"
}

/**
 * Everything a read-only inspection learned about a card. Deliberately not a
 * `data class`: [toString] is redacted, and the holder name, balance and last
 * transfer are [Masked]. Keys and the certificate appear only as fingerprints
 * and lengths; the raw public material needed to check the certificate under
 * another key is private, behind [certificateVerifiesUnder].
 *
 * Every field is null (or empty) when the step that reads it failed; [steps]
 * says which ones did and why.
 *
 * @property versionLine `major.minor · r<rev count> · g<short hash>`, e.g. `0.2 · r17 · g1a2b3c4d`
 * @property stateName `BLANK`, `INITIALIZED`, `PERSONALIZED`, `TERMINATED` or `UNKNOWN_0xNN`
 * @property flagNames the GET_PERSONALIZATION flag bits that are set, by name
 * @property certVerifiedByCardIssuer the certificate verifies under the card's own issuer key
 *   (null when the card carries no certificate or key)
 * @property lastTransfer `Masked(null)` when the card never signed a transfer; null when unread
 * @property stellarAddress the card's Stellar account id (`G…`), or null for a card without a
 *   Stellar key (or when the key was not read)
 * @property stellarEngine the Ed25519 engine behind it: `soft`, `native` or `unknown(0xNN)`
 * @property stellarBindingVerified the card's P-256 key vouches for the Stellar key (its signature
 *   over this account, card and key verifies); null when the key is unbound or an input is missing
 * @property stellarProofVerified the Stellar key's proof of possession for this account, card and
 *   P-256 key verifies; null as above
 */
class CardInspection(
    val readAtEpochMs: Long,
    val aidHex: String?,
    val transport: CardTransportFacts?,
    val steps: List<InspectionStep>,
    val exchanges: List<ApduExchange>,
    val versionLine: String?,
    val versionMajor: Int?,
    val versionMinor: Int?,
    val wireCardId: String?,
    val accountUuid: String?,
    val holderName: Masked<String>?,
    val cardKeyFingerprint: String?,
    val stateName: String?,
    val flagNames: List<String>,
    val personalized: Boolean?,
    val terminated: Boolean?,
    val programIdHex: String?,
    val currency: String?,
    val issuerKeyFingerprint: String?,
    val certificateLength: Int?,
    val certIdHex: String?,
    val certVerifiedByCardIssuer: Boolean?,
    val receiveCounter: Int?,
    val receiveDigestHex: String?,
    val balanceMinor: Masked<Long>?,
    val lastTransfer: Masked<LastTransferSummary?>?,
    val alive: Boolean?,
    val stellarAddress: String? = null,
    val stellarEngine: String? = null,
    val stellarBindingVerified: Boolean? = null,
    val stellarProofVerified: Boolean? = null
) {
    private var certMaterial: CertMaterial? = null

    private class CertMaterial(
        val programId: ByteArray, val accountId: ByteArray, val currency: ByteArray,
        val cardPub65: ByteArray, val certDer: ByteArray
    )

    internal fun attachCertMaterial(programId: ByteArray, accountId: ByteArray, currency: ByteArray, cardPub65: ByteArray, certDer: ByteArray) {
        certMaterial = CertMaterial(programId.copyOf(), accountId.copyOf(), currency.copyOf(), cardPub65.copyOf(), certDer.copyOf())
    }

    /**
     * Whether this card's certificate verifies under [issuerPublicKeyHex] (130
     * hex chars, an uncompressed P-256 point: the bridge's `/card-issuer`
     * `public_key_hex`). Null when the inspection has no certificate (or the
     * identity reads failed) or the key is not valid hex of that length.
     */
    fun certificateVerifiesUnder(issuerPublicKeyHex: String): Boolean? {
        val m = certMaterial ?: return null
        val key = try {
            Hex.decode(issuerPublicKeyHex.trim(), 65)
        } catch (_: IllegalArgumentException) {
            return null
        }
        return CardCertificates.verify(key, m.programId, m.accountId, m.currency, m.cardPub65, m.certDer)
    }

    /** True when every step succeeded. */
    val complete: Boolean get() = steps.isNotEmpty() && steps.all { it.ok }

    override fun toString(): String =
        "CardInspection(card=${wireCardId ?: "?"}, version=${versionLine ?: "?"}, state=${stateName ?: "?"}, " +
            "steps=${steps.count { it.ok }}/${steps.size} ok)"
}

/**
 * Reads everything a developer needs to troubleshoot a card, without changing
 * it: identity (GET_VERSION, GET_PERSONALIZATION, GET_USER_DATA,
 * GET_EC_PUB_KEY), IS_CARD_ALIVE, GET_RECEIVE_STATE, GET_LAST_TRANSFER and
 * GET_BALANCE, in that order, then GET_STELLAR_KEY for a card that advertises a
 * Stellar key (a card without one is not asked). Each step is separate, so a blank, terminated or
 * foreign card still yields a partial inspection; a tag loss ends the
 * inspection early (the remaining steps are not attempted). Card refusals are
 * recorded in [CardInspection.steps], never thrown.
 */
object CardInspector {
    private const val TAG = "ImpalaCardInspector"

    /**
     * Inspects [session]. Off the main thread only, and only over a read-only
     * session (`ImpalaCardSession.open(…, readOnly = true)`), so it cannot send a
     * command that changes the card, consumes a PIN try or signs.
     *
     * @throws IllegalStateException on the main thread, or when the session is not read-only
     */
    @JvmStatic
    fun inspect(session: ImpalaCardSession): CardInspection {
        requireBackgroundThread("Inspecting a card")
        check(session.isReadOnly) { "CardInspector.inspect requires a read-only session" }
        val (builder, exchanges) = session.recordingExchanges { Reader(session).run() }
        return builder.build(session, exchanges)
    }

    private class Reader(private val session: ImpalaCardSession) {
        private val sdk = session.sdk
        val steps = mutableListOf<InspectionStep>()
        /** Set when the card left the field, or the answering applet is not an Impala applet: no further command is sent. */
        private var lost = false

        var version: ImpalaVersion? = null
        var personalization: CardPersonalization? = null
        var accountId: ByteArray? = null
        var cardId: ByteArray? = null
        var fullName: String? = null
        var cardPub: ByteArray? = null
        var alive: Boolean? = null
        var receiveCounter: Int? = null
        var receiveDigestHex: String? = null
        var lastTransferRead = false
        var lastTransfer: LastTransferSummary? = null
        var balance: Long? = null
        var stellarKey: StellarCardKey? = null

        private inline fun step(name: String, block: () -> Unit) {
            if (lost) return
            try {
                block()
                steps += InspectionStep(name, true, null)
            } catch (e: Exception) {
                val error = CardError.from(e)
                steps += InspectionStep(name, false, error)
                if (error is CardError.TagLost || causedByTagLoss(e)) lost = true
            }
        }

        private fun causedByTagLoss(e: Throwable): Boolean =
            generateSequence(e) { it.cause }.any { it is BIBOTagLostException }

        fun run(): Reader {
            step("GET_VERSION") { version = sdk.getImpalaAppletVersion() }
            // Every Impala applet answers GET_VERSION unconditionally (blank or terminated too). Without
            // it the answering applet is not ours (default selection), and the remaining INS bytes have
            // other meanings there (ISO 0x04 DEACTIVATE FILE, 0x24 CHANGE REFERENCE DATA): stop.
            if (version == null) lost = true
            step("GET_PERSONALIZATION") { personalization = sdk.getPersonalization() }
            step("GET_USER_DATA") {
                val data = sdk.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data
                if (data.size < 32) throw ImpalaException("GET_USER_DATA returned ${data.size} bytes, expected >= 32")
                accountId = data.copyOfRange(0, 16)
                cardId = data.copyOfRange(16, 32)
                fullName = data.copyOfRange(32, data.size).decodeToString()
            }
            step("GET_EC_PUB_KEY") {
                val key = sdk.tx(CommandAPDU(Constants.INS_GET_EC_PUB_KEY)).data
                if (key.size != 65 || key[0] != 0x04.toByte()) throw ImpalaException("GET_EC_PUB_KEY returned ${key.size} bytes")
                cardPub = key
            }
            step("IS_CARD_ALIVE") {
                alive = try {
                    sdk.tx(CommandAPDU(Constants.INS_IS_CARD_ALIVE))
                    true
                } catch (e: ImpalaException) {
                    if (e.statusWord == 0x6687) false else throw e
                }
            }
            step("GET_RECEIVE_STATE") {
                // Parsed here rather than through ImpalaSDK.getReceiveState(), whose digest type is not on this module's API.
                val data = sdk.tx(CommandAPDU(Constants.INS_GET_RECEIVE_STATE)).data
                if (data.size != Constants.RECEIVE_STATE_LENGTH.toInt()) throw ImpalaException("GET_RECEIVE_STATE returned ${data.size} bytes")
                if (data[0].toInt() and 0x80 != 0) throw ImpalaException("receive counter has its sign bit set")
                var counter = 0
                for (i in 0..3) counter = (counter shl 8) or (data[i].toInt() and 0xFF)
                receiveCounter = counter
                receiveDigestHex = Hex.encode(data.copyOfRange(4, 36))
            }
            step("GET_LAST_TRANSFER") {
                val last = sdk.getLastTransfer()
                lastTransfer = last?.let { (signable, der) ->
                    val s = Signable.decode(signable)
                    LastTransferSummary(
                        amountMinor = s.amount,
                        counter = s.counter,
                        sendSequence = s.dateTime,
                        recipientUuid = UuidBytes.format(s.recipient),
                        currency = currencyText(s.currency),
                        signatureLength = der.size
                    )
                }
                lastTransferRead = true
            }
            step("GET_BALANCE") { balance = sdk.getBalance() }
            // Only a card that says it has a Stellar key (flag 0x80) is asked for it: an older
            // applet does not know the command.
            if (personalization?.stellarKey == true) {
                step("GET_STELLAR_KEY") { stellarKey = sdk.getStellarKey() }
            }
            if (lost) ImpalaLibLog.w(TAG, "Inspection ended early: the card left the field or is not an Impala card")
            return this
        }

        fun build(session: ImpalaCardSession, exchanges: List<ApduExchange>): CardInspection {
            val v = version
            val p = personalization
            val account = accountId
            val pub = cardPub
            val cert = p?.certificate
            val issuerKey = p?.issuerPubKey
            val haveCertInputs = p != null && account != null && pub != null && cert != null
            val certVerified = if (haveCertInputs && issuerKey != null) {
                CardCertificates.verify(issuerKey, p.programId, account, p.currency, pub, cert)
            } else null
            val certId = if (p != null && account != null && pub != null) {
                try {
                    Hex.encode(MessageDigest.getInstance("SHA-256").digest(TransferProtocol.certMessage(p.programId, account, p.currency, pub)))
                } catch (_: IllegalArgumentException) {
                    null
                }
            } else null
            val stellar = stellarKey
            val card = cardId
            val boundInputs = stellar != null && stellar.isBound && account != null && card != null && pub != null
            val inspection = CardInspection(
                readAtEpochMs = System.currentTimeMillis(),
                aidHex = session.aidHex,
                transport = session.transport,
                steps = steps.toList(),
                exchanges = exchanges,
                versionLine = v?.let { versionLine(it) },
                versionMajor = v?.major?.toInt(),
                versionMinor = v?.minor?.toInt(),
                wireCardId = cardId?.let { Hex.encode(it) },
                accountUuid = account?.let { UuidBytes.format(it) },
                holderName = fullName?.let { Masked(it) },
                cardKeyFingerprint = pub?.let { CardCertificates.fingerprint(it) },
                stateName = p?.let { stateName(it.state.toInt() and 0xFF) },
                flagNames = p?.let { flagNames(it) } ?: emptyList(),
                personalized = p?.personalized,
                terminated = p?.let { it.terminated || (it.state.toInt() and 0xFF) == 0xFF },
                programIdHex = p?.let { Hex.encode(it.programId) },
                currency = p?.let { currencyText(it.currency) },
                issuerKeyFingerprint = issuerKey?.let { CardCertificates.fingerprint(it) },
                certificateLength = cert?.size,
                certIdHex = certId,
                certVerifiedByCardIssuer = certVerified,
                receiveCounter = receiveCounter,
                receiveDigestHex = receiveDigestHex,
                balanceMinor = balance?.let { Masked(it) },
                lastTransfer = if (lastTransferRead) Masked(lastTransfer) else null,
                alive = alive,
                stellarAddress = stellar?.address,
                stellarEngine = stellar?.engineName,
                stellarBindingVerified = if (boundInputs) CardStellarKeys.bindingVerifies(pub!!, account!!, card!!, stellar!!) else null,
                stellarProofVerified = if (boundInputs) CardStellarKeys.proofVerifies(pub!!, account!!, card!!, stellar!!) else null
            )
            if (haveCertInputs) inspection.attachCertMaterial(p.programId, account, p.currency, pub, cert)
            return inspection
        }
    }

    internal fun versionLine(v: ImpalaVersion): String =
        "${v.major}.${v.minor} · r${v.revList.toInt() and 0xFFFF} · g${v.shortHash}"

    internal fun stateName(state: Int): String = when (state) {
        0x00 -> "BLANK"
        0x01 -> "INITIALIZED"
        0x02 -> "PERSONALIZED"
        0xFF -> "TERMINATED"
        else -> "UNKNOWN_0x" + state.toString(16).uppercase().padStart(2, '0')
    }

    internal fun flagNames(p: CardPersonalization): List<String> = buildList {
        if (p.initialized) add("INITIALIZED")
        if (p.programBound) add("PROGRAM_BOUND")
        if (p.personalized) add("PERSONALIZED")
        if (p.scp03KeysDefault) add("SCP03_KEYS_DEFAULT")
        if (p.pinProvisioned) add("PIN_PROVISIONED")
        if (p.provisioningEnforced) add("PROVISIONING_ENFORCED")
        if (p.terminated) add("TERMINATED")
        if (p.stellarKey) add("STELLAR_KEY")
    }

    /** The 4-byte currency tag as text (`USDC`, `XLM`), NULs dropped; hex when it is not printable ASCII. */
    internal fun currencyText(tag: ByteArray): String {
        val trimmed = tag.takeWhile { it != 0.toByte() }
        return if (trimmed.isNotEmpty() && trimmed.all { it in 0x20..0x7E }) trimmed.toByteArray().decodeToString()
        else Hex.encode(tag)
    }
}

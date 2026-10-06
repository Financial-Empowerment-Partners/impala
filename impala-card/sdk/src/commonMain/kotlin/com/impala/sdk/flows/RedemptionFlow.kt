package com.impala.sdk.flows

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferProtocol

/**
 * The bridge redemption tuple (`POST /offline/redemptions`): the 60-byte
 * signable plus the card's DER signature over the 89-byte XFER message, its
 * public key and its issuer certificate, all lowercase hex.
 */
data class RedemptionTuple(
    val signableHex: String,
    val signatureDerHex: String,
    val cardPubkeyHex: String,
    val cardCertHex: String
) {
    init {
        require(signableHex.length == 120) { "signable must be 60 bytes" }
        require(cardPubkeyHex.length == 130) { "card pubkey must be 65 bytes" }
        require(signatureDerHex.length in 16..144 && cardCertHex.length in 16..144) { "DER fields must be 8..72 bytes" }
    }

    val signable: Signable get() = Signable.decode(Hex.decode(signableHex, 60))

    /** SHA-256 of the XFER message — the bridge's `transfer_id`. */
    fun transferIdHex(programId: ByteArray): String =
        TransferProtocol.transferId(programId, Hex.decode(signableHex, 60)).hex()
}

/**
 * Card → bridge redemption: the holder authorizes (user PIN) a transfer of
 * stored value from the card to the bridge's `redemption_uuid`.
 *
 * Never re-sign: a signed tuple is persisted by the caller and re-posted
 * byte-identically; if it was lost, [recoverLastSigned] rebuilds it from the
 * card's GET_LAST_TRANSFER. Re-sending the identical signable to the card also
 * replays the cached response without a second debit.
 */
object RedemptionFlow {
    /** Largest send sequence (`dateTime`): the MSB must stay clear. */
    const val MAX_SEND_SEQUENCE: Long = Long.MAX_VALUE

    /**
     * Composes the signable. Refuses before any card command: zero amount,
     * non-positive counter, a send sequence not greater than
     * [previousSendSequence] (read from GET_LAST_TRANSFER; 0 when the card
     * never signed), and a recipient equal to the card's own account (the
     * card would answer 0x6232).
     */
    fun compose(
        identity: CardIdentity,
        redemptionUuid: ByteArray,
        amountMinor: UInt,
        sendSequence: Long,
        counter: Int,
        previousSendSequence: Long = 0L,
        phoneId: Long = 0L
    ): Signable {
        fun refuse(reason: String): Nothing = throw CardFlowException(CardError.InvalidRequest(reason))
        if (redemptionUuid.size != 16) refuse("redemption uuid must be 16 bytes")
        if (amountMinor == 0u) refuse("amount must be at least 1 minor unit")
        if (counter <= 0) refuse("counter must be positive")
        if (sendSequence < 0) refuse("send sequence must have its MSB clear")
        if (sendSequence <= previousSendSequence) refuse("send sequence must exceed the card's previous ($previousSendSequence)")
        if (redemptionUuid.contentEquals(identity.accountId)) refuse("recipient must not be the card's own account")
        return Signable(
            dateTime = sendSequence,
            sender = identity.accountId,
            recipient = redemptionUuid,
            currency = identity.currency,
            amount = amountMinor.toLong(),
            phoneId = phoneId,
            counter = counter
        )
    }

    /** The card's previous send sequence from GET_LAST_TRANSFER (0 when it never signed). */
    fun previousSendSequence(sdk: ImpalaSDK): Long = cardFlow {
        sdk.getLastTransfer()?.let { Signable.decode(it.first).dateTime } ?: 0L
    }

    /**
     * Signs [signable] with the user PIN given as 4 digit characters. The
     * temporary digit buffer is zeroed; the caller zeroes [pin].
     */
    fun sign(sdk: ImpalaSDK, identity: CardIdentity, pin: CharArray, signable: Signable): RedemptionTuple {
        if (pin.size != 4 || pin.any { it !in '0'..'9' }) throw CardFlowException(CardError.InvalidRequest("PIN must be 4 digits"))
        val digits = ByteArray(4) { (pin[it] - '0').toByte() }
        try {
            val env = cardFlow { sdk.signTransferV2Digits(digits, signable.encode()) }
            return RedemptionTuple(
                signableHex = Hex.encode(env.signable),
                signatureDerHex = Hex.encode(env.signature),
                cardPubkeyHex = Hex.encode(env.pubKey),
                cardCertHex = Hex.encode(env.certificate)
            ).also {
                check(it.cardPubkeyHex == identity.pubKeyHex) { "card answered with a different public key" }
            }
        } finally {
            digits.fill(0)
        }
    }

    /**
     * Rebuilds the last signed tuple from GET_LAST_TRANSFER plus the identity's
     * key and certificate, or null when the card never signed a transfer.
     */
    fun recoverLastSigned(sdk: ImpalaSDK, identity: CardIdentity): RedemptionTuple? = cardFlow {
        val cert = identity.certificate ?: throw CardFlowException(CardError.NotPersonalized)
        sdk.getLastTransfer()?.let { (signable, der) ->
            RedemptionTuple(Hex.encode(signable), Hex.encode(der), identity.pubKeyHex, Hex.encode(cert))
        }
    }
}

package com.impala.sdk.flows

import com.impala.sdk.Constants
import com.impala.sdk.ImpalaSDK
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.stellar.Ed25519Verifier
import com.impala.sdk.stellar.Sep10Challenge

/**
 * Card sign-in with SEP-10 (`POST /auth/sep10`): the card signs the server's
 * challenge transaction with its Stellar key.
 *
 * The caller obtains a [Sep10Challenge] from `Sep10Challenge.verify`, which is
 * the only way to get one, so the bytes sent to the card have already passed
 * the client's SEP-10 rules. The card then applies its own, narrower rules
 * (`docs/sep10-card-keys.md`, section 3.3) and may still refuse
 * ([CardError.ChallengeRefused]); a refusal is final for that challenge.
 */
object Sep10Flow {
    /** The largest challenge transaction a card stages. */
    const val MAX_TRANSACTION_BYTES: Int = 640

    /**
     * Has the card sign [challenge], checks that what came back is the
     * signature of [cardKey] (the 32-byte Stellar key the challenge was issued
     * for) over the challenge hash, and returns the signed envelope as base64,
     * ready to post.
     *
     * @param verifier Ed25519 verification, supplied by the platform
     * @throws CardFlowException [CardError.InvalidRequest] for a challenge the
     *   card cannot take (too large, a key of the wrong length), any card
     *   refusal, or [CardError.Other] when the card's answer is not a
     *   signature under [cardKey]
     */
    fun sign(sdk: ImpalaSDK, cardKey: ByteArray, challenge: Sep10Challenge, verifier: Ed25519Verifier): String {
        if (cardKey.size != Constants.ED25519_PUB_KEY_LENGTH.toInt()) {
            throw CardFlowException(CardError.InvalidRequest("the card key must be 32 bytes"))
        }
        val transaction = challenge.transactionBytes
        if (transaction.size > MAX_TRANSACTION_BYTES) {
            throw CardFlowException(
                CardError.InvalidRequest("the challenge is ${transaction.size} bytes; a card signs at most $MAX_TRANSACTION_BYTES")
            )
        }
        return cardFlow {
            val signature = sdk.signSep10(challenge.networkId, transaction)
            // A card other than the one the challenge was issued for, or a broken
            // engine: never hand the server a signature that cannot verify.
            if (!verifier.verify(cardKey.copyOf(), challenge.hash, signature.copyOf())) {
                throw ImpalaException("the card's SEP-10 signature does not verify under its Stellar key")
            }
            challenge.signedEnvelope(signature)
        }
    }
}

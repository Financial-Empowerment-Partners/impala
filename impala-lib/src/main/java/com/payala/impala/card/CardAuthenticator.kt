package com.payala.impala.card

import com.impala.sdk.flows.CardAuthFlow
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.Sep10Flow
import com.impala.sdk.models.StellarCardKey
import com.impala.sdk.models.UserVerification
import com.impala.sdk.stellar.Sep10Challenge
import com.payala.impala.stellar.Ed25519

/** How a card proves itself to a server. */
enum class CardAuthMechanism {
    /**
     * SEP-10 (Stellar Web Authentication): the card signs the server's
     * challenge transaction with its Stellar key (`SIGN_SEP10`). The default
     * for a card that has one.
     */
    SEP10,

    /**
     * The original challenge-response (`SIGN_AUTH`, `POST /auth/card`): the
     * card signs a random challenge with its P-256 key. Every card supports
     * it, and it is what a card without a Stellar key uses.
     */
    LEGACY
}

/**
 * Card login helper for Android callers: both sign-in mechanisms, and which
 * one a given card uses. [CardSignIn] runs a whole sign-in with the fallback
 * rules; these are its card-facing steps.
 */
object CardAuthenticator {
    /**
     * Signs the bridge's hex challenge with the session's card (`SIGN_AUTH`)
     * and returns the DER signature as lowercase hex. Refuses a challenge
     * outside 8..64 bytes before any APDU.
     *
     * @throws IllegalStateException on the main thread
     * @throws com.impala.sdk.flows.CardFlowException on any card failure
     */
    @JvmStatic
    fun signChallenge(session: ImpalaCardSession, challengeHex: String): String {
        requireBackgroundThread("Signing a challenge")
        return CardAuthFlow.sign(session.sdk, challengeHex)
    }

    /**
     * The mechanism this card signs in with: [CardAuthMechanism.SEP10] when it
     * advertises a Stellar key (GET_PERSONALIZATION flag `0x80`, applet 0.3+),
     * otherwise [CardAuthMechanism.LEGACY]. Reads the card identity if the
     * session has not read it yet; sends nothing else.
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException when the identity cannot be read
     */
    @JvmStatic
    fun mechanism(session: ImpalaCardSession): CardAuthMechanism {
        requireBackgroundThread("Reading the card identity")
        return if (session.identity.hasStellarKey) CardAuthMechanism.SEP10 else CardAuthMechanism.LEGACY
    }

    /**
     * The card's Stellar key (`GET_STELLAR_KEY`), or null for a card without
     * one. Read-only: allowed in a read-only session.
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException on any other card failure
     */
    @JvmStatic
    fun stellarKey(session: ImpalaCardSession): StellarCardKey? {
        requireBackgroundThread("Reading the card's Stellar key")
        return try {
            session.sdk.getStellarKey()
        } catch (e: Exception) {
            throw CardFlowException(CardError.from(e), e)
        }
    }

    /**
     * Has the card sign a verified SEP-10 [challenge] (`SIGN_SEP10`) and
     * returns the signed envelope as base64, ready for `POST` to the web-auth
     * endpoint. The card's signature is verified under [cardKey] before it is
     * returned. [cardKey] is the 32-byte Stellar key the challenge was issued
     * for ([stellarKey]`.publicKey`).
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException [CardError.ChallengeRefused] when the card's own
     *   parser rejects the transaction, or any other card failure
     */
    @JvmStatic
    fun signSep10(session: ImpalaCardSession, cardKey: ByteArray, challenge: Sep10Challenge): String {
        requireBackgroundThread("Signing a SEP-10 challenge")
        return Sep10Flow.sign(session.sdk, cardKey, challenge, Ed25519)
    }

    /**
     * The card's cardholder-verification state (applet 0.4): whether a sign-in
     * PIN is required, whether a user PIN is provisioned, and whether it is
     * verified in this session. Null for an applet older than 0.4.
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException on any card failure
     */
    @JvmStatic
    fun userVerification(session: ImpalaCardSession): UserVerification? {
        requireBackgroundThread("Reading cardholder verification")
        return try {
            session.sdk.getUserVerification()
        } catch (e: Exception) {
            throw CardFlowException(CardError.from(e), e)
        }
    }

    /**
     * Verifies the cardholder's user PIN for this session (`VERIFY_PIN`), so a
     * subsequent PIN proof or a policy-gated sign-in is allowed. A wrong or
     * blocked PIN surfaces as [CardError.WrongPin] / [CardError.PinBlocked].
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException on any card failure
     */
    @JvmStatic
    fun verifyUserPin(session: ImpalaCardSession, pin: String) {
        requireBackgroundThread("Verifying the user PIN")
        try {
            session.sdk.verifyUserPin(pin)
        } catch (e: Exception) {
            throw CardFlowException(CardError.from(e), e)
        }
    }

    /**
     * Produces a PIN proof (`SIGN_AUTH` P1=0x01) over [challenge] and returns
     * the DER signature as lowercase hex. The user PIN must have been verified
     * this session ([verifyUserPin]); the applet refuses otherwise
     * ([CardError.PinRequired]). The challenge is the same value the sign-in
     * signature covers: the legacy card challenge, or a SEP-10 transaction
     * hash.
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException on any card failure
     */
    @JvmStatic
    fun signPinProof(session: ImpalaCardSession, challenge: ByteArray): String {
        requireBackgroundThread("Signing a PIN proof")
        return CardAuthFlow.signPinProof(session.sdk, challenge)
    }
}

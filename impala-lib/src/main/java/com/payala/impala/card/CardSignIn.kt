package com.payala.impala.card

import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.Hex
import com.impala.sdk.models.StellarCardKey
import com.impala.sdk.stellar.Sep10Exception
import com.payala.impala.stellar.Sep10Client
import com.payala.impala.stellar.Sep10ClientException
import com.payala.impala.stellar.Sep10HttpException
import java.io.IOException

/** Why a card that has a Stellar key was signed in with the legacy challenge instead of SEP-10. */
enum class Sep10Fallback {
    /** The app has no SEP-10 home domain for this network. */
    NOT_CONFIGURED,

    /** The server does not offer SEP-10: no `stellar.toml`, no web-auth endpoint or signing key in it, or the endpoint answered 404 / 503. */
    NOT_OFFERED,

    /**
     * The server refused the signed challenge with 401: it does not know this
     * card's Stellar key (the card was registered before it had one), or it
     * does not serve SEP-10 to this account (the Impala bridge refuses
     * accounts with a privileged role). The two are one answer by design.
     */
    NOT_REGISTERED
}

/** What a card tap produced for sign-in. */
sealed class CardSignInResult {
    abstract val identity: CardIdentity

    /** The mechanism that produced this result. */
    abstract val mechanism: CardAuthMechanism

    /**
     * SEP-10 ran to the end with the card in the field: [tokenJson] is the
     * server's token response, verbatim (a JSON object with a `token`).
     */
    class Sep10(
        override val identity: CardIdentity,
        /** The card's Stellar account id (`G…`). */
        val stellarAddress: String,
        val tokenJson: String
    ) : CardSignInResult() {
        override val mechanism: CardAuthMechanism get() = CardAuthMechanism.SEP10
        override fun toString(): String = "CardSignInResult.Sep10(card=${identity.wireCardId})"
    }

    /**
     * The card signed the legacy challenge: exchange [signatureHex] (DER,
     * lowercase hex) at `POST /auth/card`. [fallback] says why SEP-10 was not
     * used for a card that has a Stellar key; it is null for a card without one.
     * [stellarKey] is the card's Stellar key when the tap read it (public
     * values only), so that a caller told [Sep10Fallback.NOT_REGISTERED] can
     * register it once it has a session (`PUT /card/stellar-key`).
     */
    class Legacy(
        override val identity: CardIdentity,
        val signatureHex: String,
        val fallback: Sep10Fallback?,
        val stellarKey: StellarCardKey? = null,
        /** A card PIN proof over the same challenge (DER hex), when a PIN was
         *  supplied and verified — post it as `pin_proof` to `POST /auth/card`. */
        val pinProofHex: String? = null,
        /** A phone device-key assertion over the same challenge, when a signer
         *  produced one — post `device_key_id` + `device_signature`. */
        val deviceKeyId: String? = null,
        val deviceSignatureHex: String? = null,
    ) : CardSignInResult() {
        override val mechanism: CardAuthMechanism get() = CardAuthMechanism.LEGACY
        override fun toString(): String = "CardSignInResult.Legacy(card=${identity.wireCardId}, fallback=$fallback)"
    }
}

/**
 * Optional multi-factor extras for a card sign-in
 * (`docs/mfa-card-pin-biometrics.md`): a cardholder PIN to verify on the card
 * (yielding the `pin` factor via a PIN proof), and a device-key signer (the
 * `dev`/`bio` factor). A card that requires a sign-in PIN ([CardError.PinRequired])
 * is refused before any network call unless [pin] is given.
 */
class SignInOptions @JvmOverloads constructor(
    val pin: String? = null,
    val deviceSigner: DeviceAssertionSigner? = null,
)

/**
 * One card sign-in for every card and every server: the compatibility layer
 * between SEP-10 and the legacy card challenge.
 *
 * A card that advertises a Stellar key signs in with SEP-10: `stellar.toml`,
 * a challenge transaction, the client checks, `SIGN_SEP10` on the card, and
 * the signed envelope posted to the web-auth endpoint, all while the card is
 * in the field. Any other card, and a card whose server cannot take SEP-10
 * ([Sep10Fallback]), signs the legacy challenge (`SIGN_AUTH`) in the same tap;
 * the caller exchanges that signature at `POST /auth/card` as before.
 *
 * Only the three [Sep10Fallback] cases fall back. Everything else is an error
 * and is thrown: a transport failure, a rate limit or lockout (429), a
 * challenge that fails the client checks ([Sep10Exception]: the server may be
 * misconfigured or not who it claims to be) and a challenge the card itself
 * refuses ([CardError.ChallengeRefused]). A sign-in is never quietly
 * downgraded because a check failed.
 *
 * Blocking, with the card connected: call it from the reader callback, off the
 * main thread. Nothing here logs.
 *
 * @param sep10 the SEP-10 client for this network's home domain, or null when
 *   none is configured
 * @param legacyChallenge fetches the legacy hex challenge for a card
 */
class CardSignIn(
    private val sep10: Sep10Client?,
    private val legacyChallenge: LegacyChallenge
) {
    /** `POST /auth/card/challenge`: the bridge's single-use hex challenge for [wireCardId]. */
    fun interface LegacyChallenge {
        @Throws(Exception::class)
        fun fetch(wireCardId: String): String
    }

    /** The stages of a sign-in, for progress display. */
    enum class Step { READING_CARD, CONTACTING_SERVER, SIGNING, SUBMITTING, FALLING_BACK }

    fun interface Listener {
        fun onStep(step: Step)
    }

    /**
     * Signs the card in [session] in.
     *
     * @throws IllegalStateException on the main thread
     * @throws CardFlowException for any card refusal (an unissued or terminated
     *   card fails here, before any request is made)
     * @throws Sep10Exception when the server's challenge fails the client checks
     * @throws Sep10HttpException for an HTTP answer that is not a fallback case (429 included)
     * @throws IOException for a transport failure
     * @throws Exception whatever [LegacyChallenge.fetch] throws
     */
    @JvmOverloads
    @Throws(Exception::class)
    fun signIn(
        session: ImpalaCardSession,
        listener: Listener? = null,
        options: SignInOptions = SignInOptions(),
    ): CardSignInResult {
        requireBackgroundThread("Signing in with a card")
        listener?.onStep(Step.READING_CARD)
        val identity = session.identity.requirePersonalized()

        // Cardholder verification (applet 0.4): a card that requires a sign-in
        // PIN is refused here unless one was supplied; a supplied PIN is
        // verified now so a PIN proof can be made (the `pin` factor). A wrong
        // or blocked PIN is an error, never a downgrade to a PIN-less sign-in.
        val uv = CardAuthenticator.userVerification(session)
        if (uv != null && uv.signInPinRequired && options.pin == null) {
            throw CardFlowException(CardError.PinRequired)
        }
        val pinVerified = if (options.pin != null && uv != null && uv.pinProvisioned) {
            CardAuthenticator.verifyUserPin(session, options.pin)
            true
        } else {
            false
        }

        if (!identity.hasStellarKey) return legacy(session, identity, null, listener, options = options, pinVerified = pinVerified)
        if (sep10 == null) return legacy(session, identity, Sep10Fallback.NOT_CONFIGURED, listener, options = options, pinVerified = pinVerified)

        val key = CardAuthenticator.stellarKey(session)
            // The flag said yes and the read says no: not a card to guess about.
            ?: throw CardFlowException(CardError.Other(0x623C))
        try {
            listener?.onStep(Step.CONTACTING_SERVER)
            val prepared = sep10.prepare(key.publicKey)
            listener?.onStep(Step.SIGNING)
            val envelope = CardAuthenticator.signSep10(session, key.publicKey, prepared.challenge)
            val extras = buildExtras(
                session, DeviceKeyProtocol.PURPOSE_SEP10_SIGN_IN, prepared.challenge.hash, options, pinVerified
            )
            listener?.onStep(Step.SUBMITTING)
            return CardSignInResult.Sep10(identity, key.address, sep10.submit(prepared.webAuthEndpoint, envelope, extras))
        } catch (e: Exception) {
            val fallback = fallbackFor(e) ?: throw e
            listener?.onStep(Step.FALLING_BACK)
            return legacy(session, identity, fallback, listener, key, options, pinVerified)
        }
    }

    /** The PIN proof + device assertion for a SEP-10 sign-in, over the challenge hash. */
    private fun buildExtras(
        session: ImpalaCardSession, purpose: Byte, challenge32: ByteArray,
        options: SignInOptions, pinVerified: Boolean
    ): com.payala.impala.stellar.Sep10PostExtras {
        val pinProof = if (pinVerified) CardAuthenticator.signPinProof(session, challenge32) else null
        val device = options.deviceSigner?.sign(purpose, challenge32)
        return com.payala.impala.stellar.Sep10PostExtras(pinProof, device?.keyId, device?.signatureDerHex)
    }

    private fun legacy(
        session: ImpalaCardSession, identity: CardIdentity, fallback: Sep10Fallback?, listener: Listener?,
        stellarKey: StellarCardKey? = null, options: SignInOptions = SignInOptions(), pinVerified: Boolean = false
    ): CardSignInResult {
        listener?.onStep(Step.CONTACTING_SERVER)
        val challengeHex = legacyChallenge.fetch(identity.wireCardId)
        listener?.onStep(Step.SIGNING)
        val signatureHex = CardAuthenticator.signChallenge(session, challengeHex)
        val challengeBytes = Hex.decode(challengeHex)
        val pinProof = if (pinVerified) CardAuthenticator.signPinProof(session, challengeBytes) else null
        val device = if (challengeBytes.size == DeviceKeyProtocol.CHALLENGE_LENGTH) {
            options.deviceSigner?.sign(DeviceKeyProtocol.PURPOSE_CARD_SIGN_IN, challengeBytes)
        } else {
            null
        }
        return CardSignInResult.Legacy(
            identity, signatureHex, fallback, stellarKey, pinProof, device?.keyId, device?.signatureDerHex
        )
    }

    companion object {
        /**
         * The fallback a failed SEP-10 attempt allows, or null when the failure
         * must be reported. The whole rule, in one place:
         * - `stellar.toml` without a web-auth endpoint or signing key: [Sep10Fallback.NOT_OFFERED];
         * - HTTP 404 or 503 from the server: [Sep10Fallback.NOT_OFFERED];
         * - HTTP 401: [Sep10Fallback.NOT_REGISTERED];
         * - anything else (429, other statuses, transport errors, a challenge
         *   that fails verification, a card refusal): null.
         */
        @JvmStatic
        fun fallbackFor(failure: Throwable): Sep10Fallback? = when (failure) {
            is Sep10ClientException ->
                if (failure.kind == Sep10ClientException.Kind.NOT_OFFERED) Sep10Fallback.NOT_OFFERED else null
            is Sep10HttpException -> when (failure.status) {
                404, 503 -> Sep10Fallback.NOT_OFFERED
                401 -> Sep10Fallback.NOT_REGISTERED
                else -> null
            }
            else -> null
        }
    }
}

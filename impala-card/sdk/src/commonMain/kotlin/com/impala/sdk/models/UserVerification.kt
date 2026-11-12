package com.impala.sdk.models

import com.impala.sdk.Constants

/**
 * GET_USER_VERIFICATION read-back (applet 0.4): the card's sign-in PIN policy
 * and whether the user PIN is verified in this session
 * (`docs/mfa-card-pin-biometrics.md` §3.2).
 *
 * The applet reports this in every state; a card older than 0.4 answers
 * `0x6D00` and [ImpalaSDK.getUserVerification] returns `null` for it.
 */
class UserVerification(
    /** The card requires the user PIN to be verified before it signs in (SIGN_AUTH / SIGN_SEP10). */
    val signInPinRequired: Boolean,
    /** That requirement was fixed at install and cannot be turned off. */
    val signInPinFixed: Boolean,
    /** A user PIN was provisioned by the issuer: PIN proofs (SIGN_AUTH P1=0x01) are possible. */
    val pinProvisioned: Boolean,
    /** The user PIN is verified in the current session. */
    val pinVerified: Boolean,
    /** Tries left before the user PIN blocks (0 = blocked). */
    val userPinTriesLeft: Int
) {
    override fun toString(): String =
        "UserVerification(signInPinRequired=$signInPinRequired, fixed=$signInPinFixed, " +
            "provisioned=$pinProvisioned, verified=$pinVerified, triesLeft=$userPinTriesLeft)"

    companion object {
        const val RESPONSE_LENGTH: Int = 4

        /** Parses `format(1) ‖ policy(1) ‖ userPinTriesLeft(1) ‖ session(1)`. */
        fun parse(data: ByteArray): UserVerification {
            require(data.size == RESPONSE_LENGTH) { "GET_USER_VERIFICATION must be $RESPONSE_LENGTH bytes, got ${data.size}" }
            require(data[0] == Constants.USER_VERIFICATION_FORMAT) {
                "unknown GET_USER_VERIFICATION format 0x" + (data[0].toInt() and 0xFF).toString(16)
            }
            val policy = data[1].toInt()
            val session = data[3].toInt()
            return UserVerification(
                signInPinRequired = policy and Constants.UV_POLICY_SIGN_IN_PIN.toInt() != 0,
                signInPinFixed = policy and Constants.UV_POLICY_SIGN_IN_PIN_FIXED.toInt() != 0,
                pinProvisioned = policy and Constants.UV_POLICY_PIN_PROVISIONED.toInt() != 0,
                pinVerified = session and Constants.UV_SESSION_PIN_VERIFIED.toInt() != 0,
                userPinTriesLeft = data[2].toInt() and 0xFF
            )
        }
    }
}

package com.payala.impala.card

import java.security.MessageDigest

/**
 * The phone-held device-key MFA factor's signed-message format (the client end
 * of `docs/mfa-card-pin-biometrics.md` §4.2). The key is a P-256 key in the
 * phone's keystore, optionally biometric-bound; it signs a bridge challenge so
 * the bridge can credit "something you have" (`dev`, and `bio` when the
 * operator trusts the biometric declaration).
 *
 * The bytes must match `DEVICE_KEY_DOMAIN_PREFIX` and the layout in
 * `impala-bridge/src/mfa/mod.rs`; a shared-vector test pins them together.
 */
object DeviceKeyProtocol {
    /** ASCII `IMPALA-DKEY:` (12 bytes). */
    @JvmField
    val DOMAIN_TAG: ByteArray = "IMPALA-DKEY:".toByteArray(Charsets.US_ASCII)

    const val VERSION: Byte = 0x01

    /** Purposes (the byte bound into the signed message). */
    const val PURPOSE_ENROLL: Byte = 0x01
    const val PURPOSE_STEP_UP: Byte = 0x02
    const val PURPOSE_CARD_SIGN_IN: Byte = 0x03
    const val PURPOSE_SEP10_SIGN_IN: Byte = 0x04

    /** The challenge length a device assertion covers (bytes). */
    const val CHALLENGE_LENGTH: Int = 32

    /**
     * `"IMPALA-DKEY:" || 0x01 || purpose || sha256(accountId UTF-8)(32) ||
     * challenge(32)`.
     *
     * @param accountId the account's id (its `payala_account_id`; for a card
     *   account, the on-card account UUID as a string)
     * @param challenge a 32-byte bridge challenge (a `/mfa/challenge` value, a
     *   card challenge, or a SEP-10 transaction hash)
     */
    @JvmStatic
    fun message(purpose: Byte, accountId: String, challenge: ByteArray): ByteArray {
        require(challenge.size == CHALLENGE_LENGTH) { "challenge must be $CHALLENGE_LENGTH bytes" }
        val accountHash = MessageDigest.getInstance("SHA-256").digest(accountId.toByteArray(Charsets.UTF_8))
        val out = ByteArray(DOMAIN_TAG.size + 2 + accountHash.size + challenge.size)
        var p = 0
        DOMAIN_TAG.copyInto(out, p); p += DOMAIN_TAG.size
        out[p++] = VERSION
        out[p++] = purpose
        accountHash.copyInto(out, p); p += accountHash.size
        challenge.copyInto(out, p)
        return out
    }
}

/** A device-key assertion to attach to a sign-in or step-up: the key's handle and its DER signature (hex). */
class DeviceAssertion(val keyId: String, val signatureDerHex: String)

/**
 * Produces a device-key assertion for a sign-in or step-up. The implementation
 * knows the account id, builds the message with [DeviceKeyProtocol.message],
 * and signs it with the phone's keystore key (ECDSA P-256), gating on
 * biometrics where it chooses to. Returns null when the account has no usable
 * device key on this phone, so sign-in proceeds without the factor.
 */
fun interface DeviceAssertionSigner {
    /**
     * @param purpose one of the [DeviceKeyProtocol] `PURPOSE_*` bytes
     * @param challenge the 32-byte bridge challenge (card challenge or SEP-10 hash)
     * @return the assertion, or null when no device key is enrolled here
     */
    fun sign(purpose: Byte, challenge: ByteArray): DeviceAssertion?
}

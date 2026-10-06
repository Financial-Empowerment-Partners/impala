package com.impala.sdk.flows

import com.impala.sdk.ImpalaSDK

/**
 * Card login (`POST /auth/card`): the card signs ECDSA-SHA256 over
 * `"IMPALA-AUTH:" ‖ accountId(16) ‖ challenge` and the bridge verifies it
 * against the registered `ec_pubkey`. The challenge is the bridge's hex string
 * (32 bytes today; the card accepts 8..64).
 */
object CardAuthFlow {
    const val MIN_CHALLENGE_BYTES = 8
    const val MAX_CHALLENGE_BYTES = 64

    /** Decodes and range-checks a challenge without touching the card. */
    fun decodeChallenge(challengeHex: String): ByteArray {
        val challenge = try {
            Hex.decode(challengeHex)
        } catch (e: IllegalArgumentException) {
            throw CardFlowException(CardError.InvalidRequest("challenge is not hex"), e)
        }
        if (challenge.size !in MIN_CHALLENGE_BYTES..MAX_CHALLENGE_BYTES) {
            throw CardFlowException(CardError.InvalidRequest("challenge must be $MIN_CHALLENGE_BYTES..$MAX_CHALLENGE_BYTES bytes"))
        }
        return challenge
    }

    /** Signs [challengeHex] and returns the DER signature as lowercase hex. */
    fun sign(sdk: ImpalaSDK, challengeHex: String): String {
        val challenge = decodeChallenge(challengeHex)
        return cardFlow { Hex.encode(sdk.signAuthChallenge(challenge).toByteArray()) }
    }
}

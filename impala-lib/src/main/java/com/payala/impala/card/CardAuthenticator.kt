package com.payala.impala.card

import com.impala.sdk.flows.CardAuthFlow

/** Card login helper for Android callers (`POST /auth/card`). */
object CardAuthenticator {
    /**
     * Signs the bridge's hex challenge with the session's card and returns the
     * DER signature as lowercase hex. Refuses a challenge outside 8..64 bytes
     * before any APDU.
     *
     * @throws IllegalStateException on the main thread
     * @throws com.impala.sdk.flows.CardFlowException on any card failure
     */
    @JvmStatic
    fun signChallenge(session: ImpalaCardSession, challengeHex: String): String {
        requireBackgroundThread("Signing a challenge")
        return CardAuthFlow.sign(session.sdk, challengeHex)
    }
}

package com.impala.sdk.apdu4j

import com.impala.sdk.Constants
import com.impala.sdk.scp03.SCP03Constants

/**
 * A debug-only APDU observer: `(command, response)` after each exchange.
 * Transports never log APDU bytes themselves; this hook is the only way to see
 * traffic, and every transport passes the command through [ApduTrace.mask]
 * first so PIN and key bytes never reach it.
 */
typealias ApduTraceHook = (command: ByteArray, response: ByteArray) -> Unit

object ApduTrace {
    /** Replacement byte for masked secret material (ASCII `*`). */
    const val MASK: Byte = 0x2A

    /**
     * Returns a copy of [command] with secret data bytes replaced by [MASK]:
     * the whole body of VERIFY_PIN / UPDATE_USER_PIN / UPDATE_MASTER_PIN /
     * PROVISION_PIN / APPLET_UPDATE (SCP03 keys), and the leading 4-byte PIN of
     * SIGN_TRANSFER_V2 and the retired SIGN_TRANSFER. Malformed or header-only
     * commands are returned unchanged (they carry no data).
     */
    fun mask(command: ByteArray): ByteArray {
        val out = command.copyOf()
        if (out.size <= 5) return out
        val lc = out[4].toInt() and 0xFF
        if (lc == 0) {
            // Extended length: the body starts at 7. No Impala command uses it,
            // so mask the whole body rather than guess.
            for (i in 7 until out.size) out[i] = MASK
            return out
        }
        val end = minOf(5 + lc, out.size)
        val secretLen = when (out[1]) {
            Constants.INS_VERIFY_PIN, Constants.INS_UPDATE_USER_PIN, Constants.INS_UPDATE_MASTER_PIN,
            SCP03Constants.INS_PROVISION_PIN, SCP03Constants.INS_APPLET_UPDATE -> lc
            Constants.INS_SIGN_TRANSFER_V2, Constants.INS_SIGN_TRANSFER -> 4
            else -> 0
        }
        for (i in 5 until minOf(5 + secretLen, end)) out[i] = MASK
        return out
    }
}

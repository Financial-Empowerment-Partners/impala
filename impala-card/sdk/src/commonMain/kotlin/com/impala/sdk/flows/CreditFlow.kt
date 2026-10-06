package com.impala.sdk.flows

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.models.TransferProtocol

/**
 * Bridge → card load: applies a bridge-signed issuance credit with
 * VERIFY_TRANSFER_V2. The result is the ack value for
 * `POST /offline/issuances/{id}/ack`: `"9000"` when applied, otherwise the
 * card's status word as 4 uppercase hex digits. A card refusal is an outcome to
 * report, not an exception; only transport failures (tag lost) throw.
 */
object CreditFlow {
    const val APPLIED = "9000"

    /** Splits the 209-byte tail into `(signature, pubKey, certificate)` with both DER slots trimmed. */
    fun splitTail(tail209: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        require(tail209.size == 209) { "credit tail must be 209 bytes, got ${tail209.size}" }
        return Triple(
            TransferProtocol.trimDer(tail209.copyOfRange(0, 72)),
            tail209.copyOfRange(72, 137),
            TransferProtocol.trimDer(tail209.copyOfRange(137, 209))
        )
    }

    fun apply(sdk: ImpalaSDK, signable: ByteArray, tail209: ByteArray): String {
        val (sig, pub, cert) = try {
            splitTail(tail209)
        } catch (e: IllegalArgumentException) {
            throw CardFlowException(CardError.InvalidRequest(e.message ?: "malformed credit tail"), e)
        }
        return try {
            sdk.verifyTransferV2(signable, sig, pub, cert)
            APPLIED
        } catch (e: Exception) {
            val err = CardError.from(e)
            val sw = (e as? com.impala.sdk.models.ImpalaException)?.statusWord
            if (err is CardError.TagLost || sw == null) throw CardFlowException(err, e)
            sw.toString(16).uppercase().padStart(4, '0')
        }
    }
}

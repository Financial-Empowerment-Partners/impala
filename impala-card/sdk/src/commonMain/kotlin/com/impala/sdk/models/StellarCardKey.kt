package com.impala.sdk.models

import com.impala.sdk.Constants
import com.impala.sdk.stellar.StrKey

/**
 * GET_STELLAR_KEY read-back (applet 0.3): the card's Stellar key and the two
 * static signatures that bind it to the card's P-256 key, its account and its
 * card id (`docs/sep10-card-keys.md`, section 3.2).
 *
 * [bindingSignature] and [proofSignature] are `null` until the card is
 * personalized (both slots read as zeros before that). The SDK does no
 * signature verification itself; [bindingMessage] and [proofMessage] build the
 * exact bytes a verifier checks them over.
 */
class StellarCardKey(
    /** The Ed25519 engine on the card: [ENGINE_SOFT] or [ENGINE_NATIVE]. */
    val engine: Int,
    /** The 32-byte Ed25519 public key (RFC 8032 encoding): the bytes of a Stellar account id. */
    val publicKey: ByteArray,
    /** The card P-256 key's DER ECDSA-SHA256 signature over [bindingMessage], trimmed. */
    val bindingSignature: ByteArray?,
    /** The Stellar key's 64-byte Ed25519 signature over [proofMessage]. */
    val proofSignature: ByteArray?
) {
    /** The key as a Stellar account id (`G…`, 56 characters). Never fund it: nothing can sign a payment from it. */
    val address: String get() = StrKey.encodeAccountId(publicKey)

    /** True once both cross-signatures are present (the card is personalized). */
    val isBound: Boolean get() = bindingSignature != null && proofSignature != null

    /** `soft` (JavaCard 3.0.5, software arithmetic over the card's ECDH), `native` (JavaCard 3.1 EdDSA) or `unknown(0xNN)`. */
    val engineName: String
        get() = when (engine) {
            ENGINE_SOFT -> "soft"
            ENGINE_NATIVE -> "native"
            else -> "unknown(0x" + engine.toString(16).uppercase().padStart(2, '0') + ")"
        }

    override fun toString(): String = "StellarCardKey($address, engine=$engineName, bound=$isBound)"

    companion object {
        const val ENGINE_SOFT: Int = 0x01
        const val ENGINE_NATIVE: Int = 0x02

        const val RESPONSE_LENGTH: Int = 169

        /** ASCII `IMPALA-SKEY:`. */
        val DOMAIN_TAG: ByteArray get() = "IMPALA-SKEY:".encodeToByteArray()

        /** Parses the 169-byte response `engine(1) ‖ ed25519Pub(32) ‖ bindingSig(72) ‖ proofSig(64)`. */
        fun parse(data: ByteArray): StellarCardKey {
            require(data.size == RESPONSE_LENGTH) { "GET_STELLAR_KEY must be $RESPONSE_LENGTH bytes, got ${data.size}" }
            val bindingSlot = data.copyOfRange(33, 105)
            val proof = data.copyOfRange(105, 169)
            return StellarCardKey(
                engine = data[0].toInt() and 0xFF,
                publicKey = data.copyOfRange(1, 33),
                bindingSignature = if (bindingSlot.all { it == 0.toByte() }) null else TransferProtocol.trimDer(bindingSlot),
                proofSignature = if (proof.all { it == 0.toByte() }) null else proof
            )
        }

        /**
         * SKEY message 0x01 (77 bytes), signed by the card's P-256 key:
         * `"IMPALA-SKEY:" ‖ 0x01 ‖ accountId(16) ‖ cardId(16) ‖ ed25519Pub(32)`.
         */
        fun bindingMessage(accountId: ByteArray, cardId: ByteArray, stellarPublicKey: ByteArray): ByteArray {
            require(accountId.size == 16 && cardId.size == 16) { "accountId and cardId are 16 bytes each" }
            require(stellarPublicKey.size == Constants.ED25519_PUB_KEY_LENGTH.toInt()) { "the Stellar public key is 32 bytes" }
            return DOMAIN_TAG + byteArrayOf(Constants.SKEY_BINDING_VERSION) + accountId + cardId + stellarPublicKey
        }

        /**
         * SKEY message 0x02 (110 bytes), signed by the card's Stellar key (pure
         * Ed25519): `"IMPALA-SKEY:" ‖ 0x02 ‖ accountId(16) ‖ cardId(16) ‖ ecPub(65)`.
         */
        fun proofMessage(accountId: ByteArray, cardId: ByteArray, ecPublicKey: ByteArray): ByteArray {
            require(accountId.size == 16 && cardId.size == 16) { "accountId and cardId are 16 bytes each" }
            require(ecPublicKey.size == Constants.PUB_KEY_LENGTH.toInt() && ecPublicKey[0] == 0x04.toByte()) {
                "the card key is a 65-byte uncompressed point"
            }
            return DOMAIN_TAG + byteArrayOf(Constants.SKEY_PROOF_VERSION) + accountId + cardId + ecPublicKey
        }
    }
}

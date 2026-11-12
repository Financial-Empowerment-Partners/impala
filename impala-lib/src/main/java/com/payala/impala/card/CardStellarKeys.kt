package com.payala.impala.card

import com.impala.sdk.models.StellarCardKey
import com.payala.impala.stellar.Ed25519
import java.security.GeneralSecurityException
import java.security.Signature

/**
 * Local checks of the two signatures that bind a card's Stellar key to its
 * P-256 key, its account and its card id (`docs/sep10-card-keys.md`, section
 * 3.2). A server checks the same two before it registers the key; here they
 * tell a developer whether the card would pass. Nothing here logs.
 */
object CardStellarKeys {
    /**
     * True when the card's P-256 key ([cardPub65]) signed "this is my Stellar
     * key" for this account and card: [key]'s binding signature verifies over
     * `StellarCardKey.bindingMessage`. False for an unbound key or any
     * malformed input, never an exception.
     */
    @JvmStatic
    fun bindingVerifies(cardPub65: ByteArray, accountId: ByteArray, cardId: ByteArray, key: StellarCardKey): Boolean {
        val signature = key.bindingSignature ?: return false
        return try {
            val message = StellarCardKey.bindingMessage(accountId, cardId, key.publicKey)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(CardCertificates.p256PublicKey(cardPub65))
                update(message)
                verify(signature)
            }
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    /**
     * True when the Stellar key itself signed for this account, card and
     * P-256 key (proof of possession): [key]'s proof signature verifies over
     * `StellarCardKey.proofMessage`. False for an unbound key or any malformed
     * input, never an exception.
     */
    @JvmStatic
    fun proofVerifies(cardPub65: ByteArray, accountId: ByteArray, cardId: ByteArray, key: StellarCardKey): Boolean {
        val signature = key.proofSignature ?: return false
        return try {
            Ed25519.verify(key.publicKey, StellarCardKey.proofMessage(accountId, cardId, cardPub65), signature)
        } catch (_: IllegalArgumentException) {
            false
        }
    }
}

package com.payala.impala.card

import com.impala.sdk.models.TransferProtocol
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Local checks of a card's issuer certificate with `java.security` (the SDK
 * deliberately carries no crypto). The certificate is the issuer's DER
 * ECDSA-P256-SHA256 signature over `TransferProtocol.certMessage(programId,
 * accountId, currency, cardPubKey)`. Nothing here logs.
 */
object CardCertificates {
    /** SubjectPublicKeyInfo header for an uncompressed P-256 point (id-ecPublicKey, prime256v1). */
    private val P256_SPKI_PREFIX = byteArrayOf(
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    )

    /**
     * True when [certDer] verifies under [issuerPub65] over the certificate
     * message of this card. Any malformed input (bad point, bad DER, wrong
     * field length) is false, never an exception.
     */
    @JvmStatic
    fun verify(
        issuerPub65: ByteArray, programId: ByteArray, accountId: ByteArray,
        currency: ByteArray, cardPub65: ByteArray, certDer: ByteArray
    ): Boolean = try {
        val message = TransferProtocol.certMessage(programId, accountId, currency, cardPub65)
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(p256PublicKey(issuerPub65))
            update(message)
            verify(certDer)
        }
    } catch (_: GeneralSecurityException) {
        false
    } catch (_: IllegalArgumentException) {
        false
    }

    /** SHA-256 of [pub65], first 10 bytes as lower-case hex pairs joined by `:` (`ab:cd:…`). */
    @JvmStatic
    fun fingerprint(pub65: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(pub65).copyOf(10)
            .joinToString(":") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

    internal fun p256PublicKey(pub65: ByteArray): PublicKey {
        require(pub65.size == 65 && pub65[0] == 0x04.toByte()) { "not an uncompressed P-256 point" }
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(P256_SPKI_PREFIX + pub65))
    }
}

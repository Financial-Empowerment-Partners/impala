package com.payala.impala.card

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey

/**
 * The phone's device-key MFA factor (`docs/mfa-card-pin-biometrics.md` §4):
 * a P-256 key in the Android Keystore, never exported, that signs bridge
 * challenges so the bridge can credit "something you have" (`dev`), and `bio`
 * where the key is biometric-bound and the operator trusts that.
 *
 * This class owns the keystore operations (generate, read the public key,
 * sign, delete). The *biometric prompt* is the app's: a key created with
 * [requireBiometric] can only sign inside a `BiometricPrompt`-authorized
 * window, so the app shows the prompt, then calls [sign]. The mapping from the
 * bridge's `key_id` to a keystore [alias] is the app's to keep too.
 *
 * Signatures are DER ECDSA-SHA256 — the shape the bridge verifies.
 */
object DeviceKeys {
    private const val PROVIDER = "AndroidKeyStore"

    /** An uncompressed SEC1 P-256 point, as the bridge stores it. */
    private const val UNCOMPRESSED_LEN = 65

    /**
     * Generates (or replaces) a P-256 device key under [alias] and returns its
     * 65-byte uncompressed public key. With [requireBiometric] the key is
     * usable only for [AUTH_VALIDITY_SECONDS] after a successful strong
     * biometric authentication, and is invalidated when biometrics are
     * re-enrolled — so a device-key signature means a recent biometric.
     */
    fun generate(alias: String, requireBiometric: Boolean): ByteArray {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (requireBiometric) {
                    setUserAuthenticationRequired(true)
                    // Seconds-based validity keeps one BiometricPrompt covering
                    // the whole tap; invalidate on new biometric enrollment.
                    setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS)
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()
        generator.initialize(spec)
        val pair = generator.generateKeyPair()
        return uncompressed(pair.public as ECPublicKey)
    }

    /** The 65-byte uncompressed public key for [alias], or null when absent. */
    fun publicKey(alias: String): ByteArray? {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val cert = ks.getCertificate(alias) ?: return null
        val pub = cert.publicKey as? ECPublicKey ?: return null
        return uncompressed(pub)
    }

    /** True when [alias] holds a device key. */
    fun exists(alias: String): Boolean {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        return ks.containsAlias(alias)
    }

    /**
     * Signs [message] with the key under [alias], returning a DER ECDSA-SHA256
     * signature. Throws when the key is absent or (for a biometric-bound key)
     * no biometric authorization is in force — the app must show its
     * `BiometricPrompt` first.
     */
    fun sign(alias: String, message: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val entry = ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("no device key under alias")
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(message)
            sign()
        }
    }

    /** Removes the key under [alias] (a revoked or replaced device key). */
    fun delete(alias: String) {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private fun uncompressed(pub: ECPublicKey): ByteArray {
        fun pad32(v: java.math.BigInteger): ByteArray {
            val raw = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - raw.size) + raw
        }
        val out = ByteArray(UNCOMPRESSED_LEN)
        out[0] = 0x04
        pad32(pub.w.affineX).copyInto(out, 1)
        pad32(pub.w.affineY).copyInto(out, 33)
        return out
    }

    /** How long a biometric authorization covers device-key signing. */
    const val AUTH_VALIDITY_SECONDS = 30
}

package com.payala.impala.demo.auth

import android.content.SharedPreferences
import com.impala.sdk.flows.Hex
import com.payala.impala.card.DeviceAssertion
import com.payala.impala.card.DeviceAssertionSigner
import com.payala.impala.card.DeviceKeyProtocol
import com.payala.impala.card.DeviceKeys
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.EnrollDeviceKeyRequest

/**
 * The phone device-key MFA factor for this app (`docs/mfa-card-pin-biometrics.md`
 * §4): a P-256 Keystore key, biometric-bound, that signs bridge challenges so
 * the bridge can credit `dev` (and `bio`). This object owns enrollment and the
 * [DeviceAssertionSigner] the sign-in / step-up flows use; the *biometric
 * prompt* is the caller's (show a class-3 `BiometricPrompt`, then sign within
 * [DeviceKeys.AUTH_VALIDITY_SECONDS]).
 *
 * The bridge's `key_id` ↔ Keystore alias mapping lives in [prefs]; the alias is
 * never the key_id (the key is generated before the bridge assigns an id).
 */
class DeviceMfa(
    private val prefs: SharedPreferences,
    private val keystore: DeviceKeystore = AndroidDeviceKeystore,
) {
    /** The Keystore operations, injectable so unit tests can avoid the platform Keystore. */
    interface DeviceKeystore {
        fun generate(alias: String, requireBiometric: Boolean): ByteArray
        fun sign(alias: String, message: ByteArray): ByteArray
        fun delete(alias: String)
    }

    /** Production Keystore (`com.payala.impala.card.DeviceKeys`). */
    object AndroidDeviceKeystore : DeviceKeystore {
        override fun generate(alias: String, requireBiometric: Boolean) = DeviceKeys.generate(alias, requireBiometric)
        override fun sign(alias: String, message: ByteArray) = DeviceKeys.sign(alias, message)
        override fun delete(alias: String) = DeviceKeys.delete(alias)
    }

    /** The key id of the device key enrolled on this phone for [accountId], or null. */
    fun enrolledKeyId(accountId: String): String? = prefs.getString(keyIdPref(accountId), null)

    /** True when this phone has a device key for [accountId]. */
    fun isEnrolled(accountId: String): Boolean = enrolledKeyId(accountId) != null

    /**
     * A signer the sign-in / step-up flows call: it signs the assertion message
     * for a purpose and challenge with this phone's device key, or returns null
     * when none is enrolled for [accountId]. Signing a biometric-bound key
     * requires a recent `BiometricPrompt`; the caller shows it first.
     */
    fun signer(accountId: String): DeviceAssertionSigner? {
        val keyId = enrolledKeyId(accountId) ?: return null
        val alias = prefs.getString(aliasPref(accountId), null) ?: return null
        return DeviceAssertionSigner { purpose, challenge ->
            val message = DeviceKeyProtocol.message(purpose, accountId, challenge)
            DeviceAssertion(keyId, Hex.encode(keystore.sign(alias, message)))
        }
    }

    /**
     * Enrolls a new device key for [accountId]: generates a biometric-bound
     * Keystore key, proves possession by signing a fresh `/mfa/challenge`
     * (purpose enroll), registers it, and records the `key_id`↔alias mapping.
     * The caller must hold a multi-factor session the bridge accepts for a
     * factor change. Returns the new key id.
     */
    suspend fun enroll(api: BridgeApiService, accountId: String, label: String): String {
        val alias = "impala_device_" + accountId + "_" + System.currentTimeMillis()
        val publicKey = keystore.generate(alias, requireBiometric = true)
        try {
            val challenge = api.mfaChallenge().challenge
            val challengeBytes = Hex.decode(challenge)
            val assertion = keystore.sign(alias, DeviceKeyProtocol.message(DeviceKeyProtocol.PURPOSE_ENROLL, accountId, challengeBytes))
            val response = api.enrollDeviceKey(
                EnrollDeviceKeyRequest(
                    public_key = Hex.encode(publicKey),
                    label = label,
                    platform = "android",
                    user_verification = "biometric",
                    challenge = challenge,
                    signature = Hex.encode(assertion),
                )
            )
            val keyId = response.key_id
            if (!response.success || keyId == null) {
                keystore.delete(alias)
                throw IllegalStateException("device key enrollment was refused")
            }
            prefs.edit()
                .putString(keyIdPref(accountId), keyId)
                .putString(aliasPref(accountId), alias)
                .apply()
            AppLogger.i("Mfa", "Device key enrolled for the account")
            return keyId
        } catch (e: Exception) {
            keystore.delete(alias)
            throw e
        }
    }

    /** Forgets this phone's device key for [accountId] (after a bridge revoke). */
    fun forget(accountId: String) {
        prefs.getString(aliasPref(accountId), null)?.let { keystore.delete(it) }
        prefs.edit().remove(keyIdPref(accountId)).remove(aliasPref(accountId)).apply()
    }

    private fun keyIdPref(accountId: String) = "device_mfa_key_id_$accountId"
    private fun aliasPref(accountId: String) = "device_mfa_alias_$accountId"
}

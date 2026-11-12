package com.payala.impala.demo

import androidx.test.core.app.ApplicationProvider
import com.impala.sdk.flows.Hex
import com.impala.simulator.Jca
import com.payala.impala.card.DeviceKeyProtocol
import com.payala.impala.demo.auth.DeviceMfa
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The app's device-key MFA wiring ([DeviceMfa]): the signer it hands the
 * sign-in / step-up flows produces a device assertion that verifies under the
 * enrolled key over the shared `IMPALA-DKEY:` message — without touching the
 * platform Keystore (a JCA key stands in for it).
 */
@RunWith(RobolectricTestRunner::class)
class DeviceMfaTest {
    /** A JCA-backed stand-in for the Android Keystore. */
    private class FakeKeystore : DeviceMfa.DeviceKeystore {
        val keys = HashMap<String, KeyPair>()
        override fun generate(alias: String, requireBiometric: Boolean): ByteArray {
            val kp = Jca.genP256()
            keys[alias] = kp
            return Jca.uncompressedPoint(kp.public as ECPublicKey)
        }
        override fun sign(alias: String, message: ByteArray): ByteArray =
            Jca.signP256(keys.getValue(alias).private, message)
        override fun delete(alias: String) { keys.remove(alias) }
    }

    private fun prefs() =
        ApplicationProvider.getApplicationContext<android.content.Context>()
            .getSharedPreferences("device_mfa_test", android.content.Context.MODE_PRIVATE)

    @Test
    fun `no signer and not enrolled before enrollment`() {
        val mfa = DeviceMfa(prefs(), FakeKeystore())
        assertFalse(mfa.isEnrolled("acct-1"))
        assertNull(mfa.signer("acct-1"))
        assertNull(mfa.enrolledKeyId("acct-1"))
    }

    @Test
    fun `the signer produces an assertion that verifies under the enrolled key`() {
        val ks = FakeKeystore()
        val p = prefs()
        val accountId = "acct-xyz"
        // Simulate a completed enrollment: a generated key and a recorded mapping.
        val alias = "impala_device_${accountId}_1"
        val pub = ks.generate(alias, requireBiometric = true)
        p.edit().putString("device_mfa_key_id_$accountId", "key-7")
            .putString("device_mfa_alias_$accountId", alias).apply()

        val mfa = DeviceMfa(p, ks)
        assertTrue(mfa.isEnrolled(accountId))
        val signer = mfa.signer(accountId)!!
        val challenge = ByteArray(32) { (it + 3).toByte() }
        val assertion = signer.sign(DeviceKeyProtocol.PURPOSE_STEP_UP, challenge)!!

        assertEquals("key-7", assertion.keyId)
        val der = Hex.decode(assertion.signatureDerHex)
        val expected = DeviceKeyProtocol.message(DeviceKeyProtocol.PURPOSE_STEP_UP, accountId, challenge)
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(pub), expected, der))
        // A different purpose is a different signed message: not interchangeable.
        val wrong = DeviceKeyProtocol.message(DeviceKeyProtocol.PURPOSE_CARD_SIGN_IN, accountId, challenge)
        assertFalse(Jca.verifyP256(Jca.jcaPublicKey(pub), wrong, der))
    }

    @Test
    fun `forget deletes the key and clears the mapping`() {
        val ks = FakeKeystore()
        val p = prefs()
        val alias = "impala_device_acct-9_1"
        ks.generate(alias, true)
        p.edit().putString("device_mfa_key_id_acct-9", "k").putString("device_mfa_alias_acct-9", alias).apply()
        val mfa = DeviceMfa(p, ks)
        mfa.forget("acct-9")
        assertFalse(mfa.isEnrolled("acct-9"))
        assertNull(mfa.signer("acct-9"))
    }
}

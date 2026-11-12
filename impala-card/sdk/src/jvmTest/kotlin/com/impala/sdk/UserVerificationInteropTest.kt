package com.impala.sdk

import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.simulator.SimulatorBibo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Cardholder verification for sign-in (applet 0.4), on the real applet under
 * jcardsim: the PIN proof (`SIGN_AUTH` P1=0x01), the sign-in PIN policy
 * (`SET_SIGN_IN_POLICY`, and the install flag that fixes it), `CHANGE_USER_PIN`,
 * and `GET_USER_VERIFICATION`. Signatures are checked by the JDK via [Jca].
 *
 * The contract is `docs/mfa-card-pin-biometrics.md` §3.
 */
class UserVerificationInteropTest {
    private val issuer = TestIssuer()
    private fun account(n: Int) = ByteArray(16) { (n * 16 + it + 1).toByte() }

    private fun sw(block: () -> Unit): Int =
        assertNotNull(assertFailsWith<ImpalaException> { block() }.statusWord, "a card status word")

    /** ASCII "IMPALA-APIN:" ‖ accountId(16) ‖ challenge — the PIN-proof message. */
    private fun pinProofMessage(accountId: ByteArray, challenge: ByteArray): ByteArray =
        "IMPALA-APIN:".encodeToByteArray() + accountId + challenge

    private fun authMessage(accountId: ByteArray, challenge: ByteArray): ByteArray =
        "IMPALA-AUTH:".encodeToByteArray() + accountId + challenge

    /** Reset the card and re-SELECT the applet (clears the transient PIN-verified flag). */
    private fun reselect(card: PersonalizedCard) {
        card.bibo.reset()
        val aid = SimulatorBibo.APPLET_INSTANCE_AID.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertEquals(0x9000, swOf(card.bibo.transceive(byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid)))
    }

    // ------------------------------------------------------------------ PIN proof

    @Test
    fun `a PIN proof verifies host-side and is produced only after the user PIN is verified`() {
        val card = personalizedCard(issuer, account(1), userPin = "2468")
        val challenge = ByteArray(32) { (it + 1).toByte() }

        // Before the user PIN is verified: 0x6690.
        assertEquals(0x6690, sw { card.sdk.signPinProof(challenge) })

        card.sdk.verifyUserPin("2468")
        val proof = card.sdk.signPinProof(challenge).toByteArray()

        // Verifies under the card's P-256 key over the "IMPALA-APIN:" message...
        val pub = Jca.jcaPublicKey(card.pub65)
        assertTrue(Jca.verifyP256(pub, pinProofMessage(card.accountId, challenge), proof))
        // ...and NOT over the plain sign-in message (the tags differ).
        assertFalse(Jca.verifyP256(pub, authMessage(card.accountId, challenge), proof))
    }

    @Test
    fun `a plain sign-in signature is not a PIN proof`() {
        val card = personalizedCard(issuer, account(2), userPin = "2468")
        val challenge = ByteArray(16) { (0x30 + it).toByte() }
        val plain = card.sdk.signAuthChallenge(challenge).toByteArray()
        val pub = Jca.jcaPublicKey(card.pub65)
        // The plain signature is over "IMPALA-AUTH:", so it cannot pass as a PIN proof.
        assertTrue(Jca.verifyP256(pub, authMessage(card.accountId, challenge), plain))
        assertFalse(Jca.verifyP256(pub, pinProofMessage(card.accountId, challenge), plain))
    }

    @Test
    fun `a card without a provisioned user PIN cannot produce a PIN proof`() {
        val card = personalizedCard(issuer, account(3), provisionPin = false)
        // No provisioned user PIN: 0x6985, even though the factory PIN 1111 exists.
        assertEquals(0x6985, sw { card.sdk.signPinProof(ByteArray(32)) })
        // And a verified factory PIN still does not unlock a proof.
        card.sdk.verifyUserPin("1111")
        assertEquals(0x6985, sw { card.sdk.signPinProof(ByteArray(32)) })
    }

    // ------------------------------------------------------------- user verification read

    @Test
    fun `GET_USER_VERIFICATION reflects provisioning, policy and session state`() {
        val card = personalizedCard(issuer, account(4), userPin = "2468")
        val before = assertNotNull(card.sdk.getUserVerification())
        assertTrue(before.pinProvisioned)
        assertFalse(before.signInPinRequired)
        assertFalse(before.signInPinFixed)
        assertFalse(before.pinVerified)
        assertEquals(5, before.userPinTriesLeft)

        card.sdk.verifyUserPin("2468")
        assertTrue(assertNotNull(card.sdk.getUserVerification()).pinVerified)
    }

    @Test
    fun `an unprovisioned card reports no provisioned PIN`() {
        val card = personalizedCard(issuer, account(5), provisionPin = false)
        val uv = assertNotNull(card.sdk.getUserVerification())
        assertFalse(uv.pinProvisioned)
        assertFalse(uv.pinVerified)
    }

    // ------------------------------------------------------------------ sign-in policy

    @Test
    fun `turning the sign-in PIN policy on makes sign-in need the user PIN`() {
        val card = personalizedCard(issuer, account(6), userPin = "2468")
        val challenge = ByteArray(32) { it.toByte() }

        // Off by default: plain SIGN_AUTH works with no PIN.
        card.sdk.signAuthChallenge(challenge)

        // Turning it on needs the user PIN verified.
        assertEquals(0x6690, sw { card.sdk.setSignInPinRequired(true) })
        card.sdk.verifyUserPin("2468")
        card.sdk.setSignInPinRequired(true)
        assertTrue(assertNotNull(card.sdk.getUserVerification()).signInPinRequired)

        // A card reset clears the verified flag (the policy is persistent): plain
        // sign-in is now refused until the user PIN is verified again.
        reselect(card)
        assertEquals(0x6690, sw { card.sdk.signAuthChallenge(challenge) })
        card.sdk.verifyUserPin("2468")
        card.sdk.signAuthChallenge(challenge)
    }

    @Test
    fun `the install flag fixes the sign-in PIN policy so it cannot be turned off`() {
        // Install with ENFORCE + keys + the sign-in PIN flag, then provision + personalize by hand.
        val keys = customKeys()
        val params = PersonalizationProtocol.installParams(
            enforce = true, keys = keys, pins = null, program = null, signInPin = true
        )
        val bibo = SimulatorBibo(installParams = params)
        val sdk = ImpalaSDK(bibo, keys)
        sdk.setSeed()
        val pub = sdk.getECPubKey().toByteArray()
        val cert = issuer.certify(account(7), USDC, pub)
        sdk.openSecureChannel()
        sdk.personalize(account(7), USDC, issuer.programId, cert, issuerPubKey = issuer.pub65)
        sdk.provisionUserPIN("2468")
        sdk.closeSecureChannel()

        val uv = assertNotNull(sdk.getUserVerification())
        assertTrue(uv.signInPinRequired)
        assertTrue(uv.signInPinFixed)

        // Sign-in needs the PIN...
        assertEquals(0x6690, sw { sdk.signAuthChallenge(ByteArray(32)) })
        sdk.verifyUserPin("2468")
        sdk.signAuthChallenge(ByteArray(32))
        // ...and the requirement cannot be turned off, even by the verified holder.
        assertEquals(0x6985, sw { sdk.setSignInPinRequired(false) })
    }

    // ------------------------------------------------------------------ change user PIN

    @Test
    fun `CHANGE_USER_PIN replaces the PIN and drops the verified session`() {
        val card = personalizedCard(issuer, account(8), userPin = "2468")
        assertEquals(0x6690, sw { card.sdk.changeUserPin("1357") })

        card.sdk.verifyUserPin("2468")
        card.sdk.changeUserPin("1357")
        // The session is no longer verified (a proof now needs the NEW PIN).
        assertFalse(assertNotNull(card.sdk.getUserVerification()).pinVerified)

        // The old PIN no longer verifies; the new one does.
        assertTrue(sw { card.sdk.verifyUserPin("2468") } in 0x69C0..0x69C9)
        card.sdk.verifyUserPin("1357")
        assertTrue(assertNotNull(card.sdk.getUserVerification()).pinVerified)
    }

    @Test
    fun `CHANGE_USER_PIN refuses the PIN-less marker`() {
        val card = personalizedCard(issuer, account(9), userPin = "2468")
        card.sdk.verifyUserPin("2468")
        // "0000" is the SIGN_TRANSFER_V2 PIN-less marker: refused (0x6691).
        assertEquals(0x6691, swOf(card.bibo.transceive(
            CommandAPDU(0x00, Constants.INS_CHANGE_USER_PIN.toInt(), 0x00, 0x00, byteArrayOf(0, 0, 0, 0)).bytes
        )))
    }

    // ------------------------------------------------------------------ older applets

    @Test
    fun `nothing here disturbs a card without a Stellar key`() {
        // A legacy (no-Ed25519) card still answers GET_USER_VERIFICATION (0.4 is
        // orthogonal to the Stellar key).
        val card = personalizedCard(issuer, account(10), userPin = "2468", ed25519 = SimulatorBibo.ED25519_NONE)
        assertNull(card.sdk.getStellarKey())
        assertTrue(assertNotNull(card.sdk.getUserVerification()).pinProvisioned)
    }
}

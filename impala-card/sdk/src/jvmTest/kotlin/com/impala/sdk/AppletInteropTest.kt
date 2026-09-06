package com.impala.sdk

import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaInsufficientFundsException
import com.impala.sdk.models.ImpalaPersonalizationException
import com.impala.sdk.models.ImpalaPinException
import com.impala.sdk.models.ImpalaSecurityException
import com.impala.sdk.models.ImpalaWrongLengthException
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end interop tests of the SDK against the real [com.impala.applet.ImpalaApplet]
 * running in jcardsim (applet 0.2, transfer protocol v1). This is the interop
 * oracle for the SCP03 wire format, the personalization ceremony and the SIGN_AUTH
 * contract; the certified transfer chain lives in [CertifiedTransferInteropTest]
 * and personalization in [PersonalizationInteropTest]. Shared helpers are in
 * IssuerFixture.kt.
 */
class AppletInteropTest {

    private companion object {
        /** Mirrors MAX_PINLESS_TRANSFERS in ImpalaApplet.java. */
        const val MAX_PINLESS_TRANSFERS = 4

        /** The bridge golden account UUID (card_auth.rs test_uuid). */
        val GOLDEN_ACCOUNT = "00112233445566778899aabbccddeeff".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun newSdk(): ImpalaSDK = ImpalaSDK(SimulatorBibo(), defaultKeys())

    // --- Plain (unsecured) command round-trips ---

    @Test
    fun `plain commands round-trip against the simulated applet`() {
        val sdk = newSdk()

        assertEquals(0L, sdk.getBalance())
        assertEquals("00000000-0000-0000-0000-000000000000", sdk.getAccountId())

        val version = sdk.getImpalaAppletVersion()
        assertEquals(0, version.major.toInt())
        assertEquals(2, version.minor.toInt())

        sdk.setUserName("Jane Impala")
        assertEquals("Jane Impala", sdk.getFullName())

        sdk.setGender("F")
        assertEquals("F", sdk.getGender())

        assertTrue(sdk.isCardAlive())
        sdk.verifyUserPin("1111") // applet default user PIN
    }

    @Test
    fun `initialize generates an exportable EC public key`() {
        val sdk = newSdk()
        sdk.setSeed() // INS_INITIALIZE: seeds the PRNG and generates the card keypair
        val pubKey = sdk.getECPubKey()
        assertEquals(65, pubKey.size)
        assertEquals(0x04, pubKey[0].toInt())
    }

    // --- SIGN_AUTH domain tag (pinned card-auth contract) ---

    /**
     * Golden test for the cross-stream card-auth contract: the bridge's
     * POST /auth/card verifier checks ECDSA-SHA256 over exactly
     * ASCII "IMPALA-AUTH:" (12 bytes) || accountId(16) || challenge.
     */
    @Test
    fun `sign auth signature verifies host-side over the pinned domain-tagged message`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, GOLDEN_ACCOUNT)
        val cardPublicKey = Jca.jcaPublicKey(card.sdk.getECPubKey().toByteArray())

        val challenge = ByteArray(32) { it.toByte() }
        val signature = card.sdk.signAuthChallenge(challenge).toByteArray()

        // Pinned domain tag bytes: 49 4D 50 41 4C 41 2D 41 55 54 48 3A
        val domainTag = byteArrayOf(0x49, 0x4D, 0x50, 0x41, 0x4C, 0x41, 0x2D, 0x41, 0x55, 0x54, 0x48, 0x3A)
        assertContentEquals("IMPALA-AUTH:".encodeToByteArray(), domainTag)
        // The bridge golden (card_auth.rs:404): "IMPALA-AUTH:" ‖ accountId
        assertEquals("494d50414c412d415554483a00112233445566778899aabbccddeeff",
            (domainTag + GOLDEN_ACCOUNT).toByteString().hex())

        assertTrue(Jca.verifyP256(cardPublicKey, domainTag + GOLDEN_ACCOUNT + challenge, signature))
        // The signature must NOT verify without the tag, over the bare challenge, or for a different account
        assertFalse(Jca.verifyP256(cardPublicKey, GOLDEN_ACCOUNT + challenge, signature))
        assertFalse(Jca.verifyP256(cardPublicKey, challenge, signature))
        assertFalse(Jca.verifyP256(cardPublicKey, domainTag + ByteArray(16) { 1 } + challenge, signature))
    }

    @Test
    fun `sign auth accepts 8 to 64 byte challenges and rejects lengths outside that range`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, GOLDEN_ACCOUNT)
        val cardPublicKey = Jca.jcaPublicKey(card.sdk.getECPubKey().toByteArray())
        val domainTag = "IMPALA-AUTH:".encodeToByteArray()

        for (length in intArrayOf(8, 64)) {
            val challenge = ByteArray(length) { (length + it).toByte() }
            val signature = card.sdk.signAuthChallenge(challenge).toByteArray()
            assertTrue(Jca.verifyP256(cardPublicKey, domainTag + GOLDEN_ACCOUNT + challenge, signature))
        }

        for (length in intArrayOf(1, 7, 65)) {
            // raw APDU: the length floor/ceiling is enforced by the applet itself
            assertFailsWith<ImpalaWrongLengthException> {
                card.sdk.tx(CommandAPDU(Constants.INS_SIGN_AUTH, ByteArray(length)))
            }
        }
    }

    // --- PIN-less budget (tearing fix) ---

    @Test
    fun `failed PIN-less transfers do not burn the PIN-less budget`() {
        val issuer = TestIssuer()
        val cardAId = ByteArray(16) { (it + 1).toByte() }
        val card = personalizedCard(issuer, cardAId)
        val treasury = issuer.externalSender(ByteArray(16) { (0x50 + it).toByte() })
        val recipient = ByteArray(16) { (0x70 + it).toByte() }
        val seq = SeqAllocator()

        // Balance is zero: PIN-less attempts keep failing with insufficient funds —
        // never "PIN required" (before the tearing fix each failed attempt burned budget).
        repeat(MAX_PINLESS_TRANSFERS + 1) {
            assertFailsWith<ImpalaInsufficientFundsException> {
                card.sdk.signTransferV2("0000", signable(cardAId, recipient, amount = 1, counter = 1, seq))
            }
        }

        // Fund the card — the full PIN-less budget must still be available
        fund(card, treasury, 1000, seq)
        repeat(MAX_PINLESS_TRANSFERS) {
            card.sdk.signTransferV2("0000", signable(cardAId, recipient, amount = 1, counter = 1, seq))
        }
        // Budget exhausted: the next PIN-less attempt requires a real PIN (0x6690)
        assertFailsWith<ImpalaSecurityException> {
            card.sdk.signTransferV2("0000", signable(cardAId, recipient, amount = 1, counter = 1, seq))
        }
        // A PIN-verified transfer resets the counter, re-enabling PIN-less
        card.sdk.signTransferV2("1111", signable(cardAId, recipient, amount = 1, counter = 1, seq))
        card.sdk.signTransferV2("0000", signable(cardAId, recipient, amount = 1, counter = 1, seq))
    }

    // --- Master-PIN-authorized user PIN update ---

    @Test
    fun `update user PIN rejects lengths other than 4 digits`() {
        val sdk = newSdk()
        sdk.tx(Jca.verifyMasterPinCmd(byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8)))

        // A stored PIN of any other length could never satisfy SIGN_TRANSFER's
        // fixed 4-digit check and would lock the user out attempt by attempt
        for (pin in listOf(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3, 4, 5))) {
            assertFailsWith<ImpalaWrongLengthException> {
                sdk.tx(CommandAPDU(0x00, Constants.INS_UPDATE_USER_PIN.toInt(), 0x00, Constants.P2_USER_PIN.toInt(), pin))
            }
        }
        // The stored PIN is unchanged, and a 4-digit update still works
        sdk.verifyUserPin("1111")
        sdk.tx(CommandAPDU(0x00, Constants.INS_UPDATE_USER_PIN.toInt(), 0x00, Constants.P2_USER_PIN.toInt(), byteArrayOf(9, 9, 9, 9)))
        sdk.verifyUserPin("9999")
    }

    // --- Install-parameter provisioning ---

    @Test
    fun `empty install parameters leave all defaults in place`() {
        // exercises the install envelope parser with a zero-length applet data field
        val sdk = ImpalaSDK(SimulatorBibo(installParams = ByteArray(0)), defaultKeys())
        sdk.verifyUserPin("1111")
        assertTrue(sdk.openSecureChannel())
        sdk.closeSecureChannel()
        sdk.setSeed()
        // No provisioning gate (no 0x6985); an unpersonalized card refuses SIGN_AUTH with 0x6234
        assertFailsWith<ImpalaPersonalizationException> { sdk.signAuthChallenge(ByteArray(32)) }
    }

    @Test
    fun `install-time key and PIN injection takes effect`() {
        val enc = ByteArray(16) { (0x10 + it).toByte() }
        val mac = ByteArray(16) { (0x20 + it).toByte() }
        val dek = ByteArray(16) { (0x30 + it).toByte() }
        val masterPin = byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1)
        val userPin = byteArrayOf(4, 3, 2, 1)
        val params = byteArrayOf(0x01, 0x06) + enc + mac + dek + masterPin + userPin

        val bibo = SimulatorBibo(installParams = params)

        // The default static keys must no longer open a secure channel...
        assertFailsWith<ImpalaException> {
            ImpalaSDK(bibo, defaultKeys()).openSecureChannel()
        }
        // ...but the injected keys do
        val sdk = ImpalaSDK(bibo, Triple(enc, mac, dek))
        assertTrue(sdk.openSecureChannel())
        sdk.closeSecureChannel()

        // The injected PINs replace the defaults
        sdk.verifyUserPin("4321")
        sdk.tx(Jca.verifyMasterPinCmd(masterPin))
        assertFailsWith<ImpalaPinException> { sdk.verifyUserPin("1111") }
    }

    @Test
    fun `provisioning enforcement gates signing until a user PIN is provisioned`() {
        val bibo = SimulatorBibo(installParams = byteArrayOf(0x01, 0x01)) // ENFORCE, default keys
        val sdk = ImpalaSDK(bibo, defaultKeys())
        sdk.setSeed()

        // SIGN_AUTH and SIGN_TRANSFER_V2 answer 0x6985 while unprovisioned...
        assertFailsWith<ImpalaSecurityException> { sdk.signAuthChallenge(ByteArray(32)) }
        assertFailsWith<ImpalaSecurityException> {
            sdk.signTransferV2("1111", signable(ByteArray(16), ByteArray(16) { 1 }, amount = 1, counter = 1, SeqAllocator()))
        }
        // ...while plain reads still work
        assertEquals(0L, sdk.getBalance())

        // PROVISION_PIN over the default keys is refused (0x6236): the ENFORCE gate
        // must not be liftable while the SCP03 keys are still public.
        sdk.openSecureChannel()
        assertFailsWith<ImpalaSecurityException> { sdk.provisionUserPIN("2468") }
        val custom = customKeys()
        sdk.rotateScp03Keys(custom.first, custom.second, custom.third)
        sdk.closeSecureChannel()

        // Reopen with the rotated keys — now PROVISION_PIN succeeds and lifts the gate
        val sdk2 = ImpalaSDK(bibo, custom)
        sdk2.openSecureChannel()
        sdk2.provisionUserPIN("2468")
        sdk2.closeSecureChannel()

        // Gate lifted, but the card is still unpersonalized → SIGN_AUTH is 0x6234
        assertFailsWith<ImpalaPersonalizationException> { sdk2.signAuthChallenge(ByteArray(32)) }

        // Personalize, then SIGN_AUTH succeeds
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 2).toByte() }
        sdk2.openSecureChannel()
        val pub = sdk2.getECPubKey().toByteArray()
        sdk2.personalize(accountId, USDC, issuer.programId, issuer.certify(accountId, USDC, pub), issuerPubKey = issuer.pub65)
        sdk2.closeSecureChannel()
        assertTrue(sdk2.signAuthChallenge(ByteArray(32)).size > 0)
    }

    @Test
    fun `install-time PIN injection satisfies provisioning enforcement`() {
        val custom = customKeys()
        val params = byteArrayOf(0x01, 0x07) + custom.first + custom.second + custom.third +
            byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1) + byteArrayOf(4, 3, 2, 1)
        val bibo = SimulatorBibo(installParams = params)
        val sdk = ImpalaSDK(bibo, custom)
        sdk.setSeed()

        // ENFORCE is satisfied by the install PINs, but the card is not personalized → 0x6234
        assertFailsWith<ImpalaPersonalizationException> { sdk.signAuthChallenge(ByteArray(32)) }

        // Personalize over the custom keys (no PROVISION_PIN needed) → signing works
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 3).toByte() }
        sdk.openSecureChannel()
        val pub = sdk.getECPubKey().toByteArray()
        sdk.personalize(accountId, USDC, issuer.programId, issuer.certify(accountId, USDC, pub), issuerPubKey = issuer.pub65)
        sdk.closeSecureChannel()
        assertTrue(sdk.signAuthChallenge(ByteArray(32)).size > 0)
    }

    @Test
    fun `malformed install parameters fail the install cleanly`() {
        val validPub = ByteArray(65) { if (it == 0) 0x04 else (it + 1).toByte() }
        val custom = customKeys()

        // truncated key block (flags claim keys but only 8 bytes follow)
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x01, 0x02) + ByteArray(8)) }
        // unknown tag
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x7F, 0x00)) }
        // unknown flag bits
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x01, 0x40)) }
        // all-zeros user PIN is reserved for PIN-less transfers
        assertFails {
            SimulatorBibo(installParams = byteArrayOf(0x01, 0x04) + byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8) + ByteArray(4))
        }
        // program binding without custom keys (0x08 without 0x02)
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x01, 0x08) + PROGRAM_A + validPub) }
        // program binding with a zero programId
        assertFails {
            SimulatorBibo(installParams = byteArrayOf(0x01, 0x0A) + custom.first + custom.second + custom.third + ByteArray(16) + validPub)
        }
        // custom-key flag but the key bytes ARE the GP defaults
        assertFails {
            SimulatorBibo(installParams = byteArrayOf(0x01, 0x02) + ByteArray(48) { (0x40 + (it % 16)).toByte() })
        }
        // a fresh default install still works after the failures above
        ImpalaSDK(SimulatorBibo(), defaultKeys()).verifyUserPin("1111")
    }

    // --- SCP03 secure channel ---

    @Test
    fun `scp03 channel opens with default static keys`() {
        val sdk = newSdk()
        assertTrue(sdk.openSecureChannel())
    }

    @Test
    fun `external authenticate without C-MAC in the security level is refused`() {
        val sdk = newSdk()
        // C-MAC is the mandatory minimum: any level without bit 0x01 must be
        // rejected, or PROVISION_PIN / APPLET_UPDATE would run un-MACed
        for (level in byteArrayOf(0x00, 0x02, 0x30)) {
            assertFailsWith<ImpalaException> { sdk.openSecureChannel(level) }
        }
        // The rejection happens before any cryptogram work: a compliant retry
        // on the same card still opens
        assertTrue(sdk.openSecureChannel())
    }

    @Test
    fun `secured CLA without an open session is rejected`() {
        val bibo = SimulatorBibo()
        val resp = bibo.transceive(byteArrayOf(0x84.toByte(), 0x04, 0x00, 0x00, 0x08) + ByteArray(8))
        assertEquals(0x6985, swOf(resp))
    }

    @Test
    fun `unwrapped CLA 80 provision and update commands are no longer dispatched`() {
        val bibo = SimulatorBibo()
        val sdk = ImpalaSDK(bibo, defaultKeys())
        sdk.openSecureChannel()

        // Even with an authenticated session, the plain (un-MACed) CLA 0x80 path
        // for PROVISION_PIN / APPLET_UPDATE is gone: both answer 0x6D00.
        val provisionPin = byteArrayOf(0x80.toByte(), 0x70, 0x00, 0x00, 0x06, Constants.P2_USER_PIN, 0x04, 9, 9, 9, 9)
        assertEquals(0x6D00, swOf(bibo.transceive(provisionPin)))

        val keyRotation = byteArrayOf(0x80.toByte(), 0x71, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00)
        assertEquals(0x6D00, swOf(bibo.transceive(keyRotation)))

        sdk.closeSecureChannel()
        // The rejected plain-path command did not change the user PIN
        sdk.verifyUserPin("1111")
        assertFailsWith<ImpalaPinException> { sdk.verifyUserPin("9999") }
    }

    @Test
    fun `user PIN provisioned over the secure channel takes effect`() {
        val sdk = newSdk()
        sdk.openSecureChannel()
        sdk.provisionUserPIN("4321")
        sdk.closeSecureChannel()

        sdk.verifyUserPin("4321")
        assertFailsWith<ImpalaPinException> { sdk.verifyUserPin("1111") }
    }

    @Test
    fun `master PIN provisioned over the secure channel takes effect`() {
        val sdk = newSdk()
        // Default master PIN digits accepted before provisioning
        sdk.tx(Jca.verifyMasterPinCmd(byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8)))

        sdk.openSecureChannel()
        sdk.provisionMasterPIN("87654321")
        sdk.closeSecureChannel()

        sdk.tx(Jca.verifyMasterPinCmd(byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1)))
        assertFailsWith<ImpalaPinException> {
            sdk.tx(Jca.verifyMasterPinCmd(byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8)))
        }
    }

    @Test
    fun `verifyMasterPin string API maps digits, not ASCII`() {
        val sdk = newSdk()
        sdk.verifyMasterPin("14117298") // throws on any non-9000 SW
        assertFailsWith<ImpalaPinException> {
            sdk.verifyMasterPin("00000000")
        }
    }

    @Test
    fun `wrapped command with response data round-trips`() {
        val sdk = newSdk()
        sdk.openSecureChannel()
        val resp = sdk.secureTx(CommandAPDU(Constants.INS_GET_BALANCE))
        assertEquals(8, resp.data.size)
        assertEquals(0L, resp.data.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) })
    }

    @Test
    fun `sequential secured commands stay in sync`() {
        val sdk = newSdk()
        sdk.setUserName("Alice Impala")

        sdk.openSecureChannel()
        sdk.provisionUserPIN("2468")
        sdk.provisionMasterPIN("87654321")
        assertEquals("Alice Impala", sdk.secureTx(CommandAPDU(Constants.INS_GET_FULL_NAME)).data.decodeToString())
        assertEquals(8, sdk.secureTx(CommandAPDU(Constants.INS_GET_BALANCE)).data.size)
        sdk.closeSecureChannel()

        sdk.verifyUserPin("2468")
    }
}

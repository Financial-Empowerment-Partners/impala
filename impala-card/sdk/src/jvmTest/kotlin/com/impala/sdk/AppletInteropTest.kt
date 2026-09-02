package com.impala.sdk

import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaInsufficientFundsException
import com.impala.sdk.models.ImpalaPinException
import com.impala.sdk.models.ImpalaSecurityException
import com.impala.sdk.models.ImpalaWrongLengthException
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end interop tests of the SDK against the real [com.impala.applet.ImpalaApplet]
 * running in jcardsim. This is the interop oracle for the SCP03 wire format:
 * the SDK's pure-Kotlin crypto on one side, jcardsim's JCA-backed JavaCard
 * crypto on the other.
 */
class AppletInteropTest {

    private companion object {
        /** Mirrors MAX_PINLESS_TRANSFERS in ImpalaApplet.java. */
        const val MAX_PINLESS_TRANSFERS = 4
    }

    private fun defaultScp03Keys(): Triple<ByteArray, ByteArray, ByteArray> {
        // gp-master.jar default static keys (0x40..0x4F), as set in the applet constructor
        val key = ByteArray(16) { (0x40 + it).toByte() }
        return Triple(key, key.copyOf(), key.copyOf())
    }

    private fun newSdk(): ImpalaSDK = ImpalaSDK(SimulatorBibo(), defaultScp03Keys())

    // --- Plain (unsecured) command round-trips ---

    @Test
    fun `plain commands round-trip against the simulated applet`() {
        val sdk = newSdk()

        assertEquals(0L, sdk.getBalance())
        assertEquals("00000000-0000-0000-0000-000000000000", sdk.getAccountId())

        val version = sdk.getImpalaAppletVersion()
        assertEquals(0, version.major.toInt())
        assertEquals(1, version.minor.toInt())

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

    // --- signTransfer / verifyTransfer (ECDSA via jcardsim) ---

    @Test
    fun `verifyTransfer credits and signTransfer debits with a JCA-verifiable signature`() {
        val sdk = newSdk()
        sdk.setSeed()

        // Fund the card: an external JCA keypair signs a transfer whose recipient
        // is the card's account id (all zeros until provisioned). verifyTransfer
        // trusts the pubkey embedded in the message tail.
        val externalKeys = genP256()
        val externalId = ByteArray(16) { (it + 1).toByte() }
        val cardAccountId = ByteArray(16)

        val funding = buildSignable(sender = externalId, recipient = cardAccountId, amount = 1000)
        sdk.verifyTransfer(
            funding,
            pad72(signP256(externalKeys.private, funding)),
            uncompressedPoint(externalKeys.public as ECPublicKey),
            ByteArray(72)
        )
        assertEquals(1000L, sdk.getBalance())

        // Spend from the card with the default user PIN; verify the card's
        // ECDSA-SHA256 signature host-side with JCA.
        val spend = buildSignable(sender = cardAccountId, recipient = externalId, amount = 250)
        val (signature, pubKey, _) = sdk.signTransfer("1111", spend)
        assertEquals(750L, sdk.getBalance())

        assertEquals(65, pubKey.size)
        val cardPublicKey = jcaPublicKey(pubKey.toByteArray())
        assertTrue(verifyP256(cardPublicKey, spend, trimDer(signature.toByteArray())))
    }

    // --- verifyTransfer replay protection (receive counter) ---

    @Test
    fun `verifyTransfer rejects replays and stale counters but allows counter gaps`() {
        val sdk = newSdk()
        sdk.setSeed()
        val externalKeys = genP256()
        val externalId = ByteArray(16) { (it + 1).toByte() }
        val cardAccountId = ByteArray(16)
        val pubKey = uncompressedPoint(externalKeys.public as ECPublicKey)

        val funding = buildSignable(externalId, cardAccountId, amount = 1000, counter = 1)
        val sig = pad72(signP256(externalKeys.private, funding))
        sdk.verifyTransfer(funding, sig, pubKey, ByteArray(72))
        assertEquals(1000L, sdk.getBalance())

        // Replaying the full two-phase exchange must not credit again (0x6233)
        val fullReplay = assertFailsWith<ImpalaException> {
            sdk.verifyTransfer(funding, sig, pubKey, ByteArray(72))
        }
        assertTrue(fullReplay.message!!.contains("6233"))
        assertEquals(1000L, sdk.getBalance())

        // Replaying only the P1=0x01 tail cannot re-verify either: the applet
        // consumed the buffered signable after the successful credit
        assertFailsWith<ImpalaException> {
            sdk.tx(
                CommandAPDU(
                    0x00, Constants.INS_VERIFY_TRANSFER.toInt(), 0x01, 0x00,
                    sig + pubKey + ByteArray(72)
                )
            )
        }
        assertEquals(1000L, sdk.getBalance())

        // A fresh, differently-signed transfer whose counter is not strictly
        // greater than the last accepted one is rejected too
        val stale = buildSignable(externalId, cardAccountId, amount = 500, counter = 1)
        assertFailsWith<ImpalaException> {
            sdk.verifyTransfer(stale, pad72(signP256(externalKeys.private, stale)), pubKey, ByteArray(72))
        }
        assertEquals(1000L, sdk.getBalance())

        // ...while a gap in the counter stream is fine (5 > 1): a transfer that
        // was signed but never presented must not jam later ones
        val next = buildSignable(externalId, cardAccountId, amount = 500, counter = 5)
        sdk.verifyTransfer(next, pad72(signP256(externalKeys.private, next)), pubKey, ByteArray(72))
        assertEquals(1500L, sdk.getBalance())
    }

    @Test
    fun `verifyTransfer never accepts a zero or negative counter`() {
        val sdk = newSdk()
        sdk.setSeed()
        val externalKeys = genP256()
        val externalId = ByteArray(16) { (it + 1).toByte() }
        val cardAccountId = ByteArray(16)
        val pubKey = uncompressedPoint(externalKeys.public as ECPublicKey)

        for (counter in intArrayOf(0, -1)) {
            val transfer = buildSignable(externalId, cardAccountId, amount = 100, counter = counter)
            assertFailsWith<ImpalaException> {
                sdk.verifyTransfer(
                    transfer,
                    pad72(signP256(externalKeys.private, transfer)),
                    pubKey,
                    ByteArray(72)
                )
            }
            assertEquals(0L, sdk.getBalance())
        }
    }

    // --- SIGN_AUTH domain tag (pinned card-auth contract) ---

    /**
     * Golden test for the cross-stream card-auth contract: the bridge's
     * POST /auth/card verifier checks ECDSA-SHA256 over exactly
     * ASCII "IMPALA-AUTH:" (12 bytes) || accountId(16) || challenge.
     */
    @Test
    fun `sign auth signature verifies host-side over the pinned domain-tagged message`() {
        val sdk = newSdk()
        sdk.setSeed()
        val cardPublicKey = jcaPublicKey(sdk.getECPubKey().toByteArray())

        val challenge = ByteArray(32) { it.toByte() }
        val signature = sdk.signAuthChallenge(challenge).toByteArray()

        // Pinned domain tag bytes: 49 4D 50 41 4C 41 2D 41 55 54 48 3A
        val domainTag = byteArrayOf(
            0x49, 0x4D, 0x50, 0x41, 0x4C, 0x41, 0x2D, 0x41, 0x55, 0x54, 0x48, 0x3A
        )
        assertContentEquals("IMPALA-AUTH:".encodeToByteArray(), domainTag)

        val accountId = ByteArray(16) // all zeros until provisioned
        assertTrue(verifyP256(cardPublicKey, domainTag + accountId + challenge, signature))

        // The signature must NOT verify without the tag (the pre-contract format)...
        assertFalse(verifyP256(cardPublicKey, accountId + challenge, signature))
        // ...nor over the bare challenge, nor a different account id
        assertFalse(verifyP256(cardPublicKey, challenge, signature))
        assertFalse(verifyP256(cardPublicKey, domainTag + ByteArray(16) { 1 } + challenge, signature))
    }

    @Test
    fun `sign auth accepts 8 to 64 byte challenges and rejects lengths outside that range`() {
        val sdk = newSdk()
        sdk.setSeed()
        val cardPublicKey = jcaPublicKey(sdk.getECPubKey().toByteArray())
        val domainTag = "IMPALA-AUTH:".encodeToByteArray()
        val accountId = ByteArray(16)

        for (length in intArrayOf(8, 64)) {
            val challenge = ByteArray(length) { (length + it).toByte() }
            val signature = sdk.signAuthChallenge(challenge).toByteArray()
            assertTrue(verifyP256(cardPublicKey, domainTag + accountId + challenge, signature))
        }

        for (length in intArrayOf(1, 7, 65)) {
            // raw APDU: the length floor/ceiling is enforced by the applet itself
            assertFailsWith<ImpalaWrongLengthException> {
                sdk.tx(CommandAPDU(Constants.INS_SIGN_AUTH, ByteArray(length)))
            }
        }
    }

    // --- PIN-less budget (tearing fix) ---

    @Test
    fun `failed PIN-less transfers do not burn the PIN-less budget`() {
        val sdk = newSdk()
        sdk.setSeed()
        val externalKeys = genP256()
        val externalId = ByteArray(16) { (it + 1).toByte() }
        val cardAccountId = ByteArray(16)

        // Balance is zero: PIN-less attempts keep failing with insufficient
        // funds — never with "PIN required" (before the tearing fix, each failed
        // attempt burned a unit of PIN-less budget before the balance check).
        repeat(MAX_PINLESS_TRANSFERS + 1) {
            assertFailsWith<ImpalaInsufficientFundsException> {
                sdk.signTransfer("0000", buildSignable(cardAccountId, externalId, amount = 1))
            }
        }

        // Fund the card — the full PIN-less budget must still be available
        val funding = buildSignable(externalId, cardAccountId, amount = 1000)
        sdk.verifyTransfer(
            funding,
            pad72(signP256(externalKeys.private, funding)),
            uncompressedPoint(externalKeys.public as ECPublicKey),
            ByteArray(72)
        )
        repeat(MAX_PINLESS_TRANSFERS) {
            sdk.signTransfer("0000", buildSignable(cardAccountId, externalId, amount = 1))
        }
        // Budget exhausted: the next PIN-less attempt requires a real PIN (0x6690)
        assertFailsWith<ImpalaSecurityException> {
            sdk.signTransfer("0000", buildSignable(cardAccountId, externalId, amount = 1))
        }
        // A PIN-verified transfer resets the counter, re-enabling PIN-less
        sdk.signTransfer("1111", buildSignable(cardAccountId, externalId, amount = 1))
        sdk.signTransfer("0000", buildSignable(cardAccountId, externalId, amount = 1))
    }

    // --- Master-PIN-authorized user PIN update ---

    @Test
    fun `update user PIN rejects lengths other than 4 digits`() {
        val sdk = newSdk()
        sdk.tx(verifyMasterPinCmd(byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8)))

        // A stored PIN of any other length could never satisfy SIGN_TRANSFER's
        // fixed 4-digit check and would lock the user out attempt by attempt
        for (pin in listOf(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3, 4, 5))) {
            assertFailsWith<ImpalaWrongLengthException> {
                sdk.tx(
                    CommandAPDU(
                        0x00, Constants.INS_UPDATE_USER_PIN.toInt(),
                        0x00, Constants.P2_USER_PIN.toInt(), pin
                    )
                )
            }
        }
        // The stored PIN is unchanged, and a 4-digit update still works
        sdk.verifyUserPin("1111")
        sdk.tx(
            CommandAPDU(
                0x00, Constants.INS_UPDATE_USER_PIN.toInt(),
                0x00, Constants.P2_USER_PIN.toInt(), byteArrayOf(9, 9, 9, 9)
            )
        )
        sdk.verifyUserPin("9999")
    }

    // --- Install-parameter provisioning ---

    @Test
    fun `empty install parameters leave all defaults in place`() {
        // exercises the install envelope parser with a zero-length applet data field
        val sdk = ImpalaSDK(SimulatorBibo(installParams = ByteArray(0)), defaultScp03Keys())
        sdk.verifyUserPin("1111")
        assertTrue(sdk.openSecureChannel())
        sdk.closeSecureChannel()
        sdk.setSeed()
        assertTrue(sdk.signAuthChallenge(ByteArray(32)).size > 0) // no signing gate
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
            ImpalaSDK(bibo, defaultScp03Keys()).openSecureChannel()
        }
        // ...but the injected keys do
        val sdk = ImpalaSDK(bibo, Triple(enc, mac, dek))
        assertTrue(sdk.openSecureChannel())
        sdk.closeSecureChannel()

        // The injected PINs replace the defaults
        sdk.verifyUserPin("4321")
        sdk.tx(verifyMasterPinCmd(masterPin))
        assertFailsWith<ImpalaPinException> { sdk.verifyUserPin("1111") }
    }

    @Test
    fun `provisioning enforcement gates signing until a user PIN is provisioned`() {
        val sdk = ImpalaSDK(SimulatorBibo(installParams = byteArrayOf(0x01, 0x01)), defaultScp03Keys())
        sdk.setSeed()

        // SIGN_AUTH and SIGN_TRANSFER answer 0x6985 while unprovisioned...
        assertFailsWith<ImpalaSecurityException> { sdk.signAuthChallenge(ByteArray(32)) }
        assertFailsWith<ImpalaSecurityException> {
            sdk.signTransfer("1111", buildSignable(ByteArray(16), ByteArray(16) { 1 }, amount = 1))
        }
        // ...while plain reads still work
        assertEquals(0L, sdk.getBalance())

        // Provisioning a user PIN over SCP03 lifts the gate
        sdk.openSecureChannel()
        sdk.provisionUserPIN("2468")
        sdk.closeSecureChannel()
        assertTrue(sdk.signAuthChallenge(ByteArray(32)).size > 0)
    }

    @Test
    fun `install-time PIN injection satisfies provisioning enforcement`() {
        val params = byteArrayOf(0x01, 0x05) +
            byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1) + byteArrayOf(4, 3, 2, 1)
        val sdk = ImpalaSDK(SimulatorBibo(installParams = params), defaultScp03Keys())
        sdk.setSeed()
        assertTrue(sdk.signAuthChallenge(ByteArray(32)).size > 0)
    }

    @Test
    fun `malformed install parameters fail the install cleanly`() {
        // truncated key block (flags claim keys but only 8 bytes follow)
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x01, 0x02) + ByteArray(8)) }
        // unknown tag
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x7F, 0x00)) }
        // unknown flag bits
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x01, 0x40)) }
        // all-zeros user PIN is reserved for PIN-less transfers
        assertFails {
            SimulatorBibo(
                installParams = byteArrayOf(0x01, 0x04) +
                    byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8) + ByteArray(4)
            )
        }
        // a fresh default install still works after the failures above
        ImpalaSDK(SimulatorBibo(), defaultScp03Keys()).verifyUserPin("1111")
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
        val sdk = ImpalaSDK(bibo, defaultScp03Keys())
        sdk.openSecureChannel()

        // Even with an authenticated session, the plain (un-MACed) CLA 0x80 path
        // for PROVISION_PIN / APPLET_UPDATE is gone: both answer 0x6D00.
        val provisionPin = byteArrayOf(
            0x80.toByte(), 0x70, 0x00, 0x00, 0x06, Constants.P2_USER_PIN, 0x04, 9, 9, 9, 9
        )
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
        sdk.tx(verifyMasterPinCmd(byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8)))

        sdk.openSecureChannel()
        sdk.provisionMasterPIN("87654321")
        sdk.closeSecureChannel()

        sdk.tx(verifyMasterPinCmd(byteArrayOf(8, 7, 6, 5, 4, 3, 2, 1)))
        assertFailsWith<ImpalaPinException> {
            sdk.tx(verifyMasterPinCmd(byteArrayOf(1, 4, 1, 1, 7, 2, 9, 8)))
        }
    }

    @Test
    fun `verifyMasterPin string API maps digits, not ASCII`() {
        // Exercise the PUBLIC ImpalaSDK.verifyMasterPin(String) — the other
        // tests build the APDU from raw bytes and so never covered the string
        // mapping, which sent ASCII char codes ([0x31,...]) against a card
        // storing raw digits ([1,...]): verification could never succeed and
        // 10 attempts would brick the master PIN. The install default is
        // 14117298; a correct mapping must verify, a wrong PIN must not.
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

    // --- Helpers ---

    /** Extracts the status word from a raw response APDU. */
    private fun swOf(resp: ByteArray): Int =
        ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)

    /**
     * Builds the 60-byte signable transaction buffer:
     * [dateTime(8) | sender(16) | recipient(16) | currency(4) | amount(4) | phoneId(8) | counter(4)]
     */
    private fun buildSignable(sender: ByteArray, recipient: ByteArray, amount: Int, counter: Int = 1): ByteArray {
        require(sender.size == 16 && recipient.size == 16)
        val signable = ByteArray(60)
        sender.copyInto(signable, 8)
        recipient.copyInto(signable, 24)
        writeInt32(signable, 44, amount)
        writeInt32(signable, 56, counter)
        return signable
    }

    private fun writeInt32(dest: ByteArray, offset: Int, value: Int) {
        dest[offset] = ((value shr 24) and 0xFF).toByte()
        dest[offset + 1] = ((value shr 16) and 0xFF).toByte()
        dest[offset + 2] = ((value shr 8) and 0xFF).toByte()
        dest[offset + 3] = (value and 0xFF).toByte()
    }

    private fun verifyMasterPinCmd(pinDigits: ByteArray): CommandAPDU =
        CommandAPDU(0x00, Constants.INS_VERIFY_PIN.toInt(), 0x00, Constants.P2_MASTER_PIN.toInt(), pinDigits)

    /** Pads a DER signature with trailing zeros to the fixed 72-byte wire slot. */
    private fun pad72(der: ByteArray): ByteArray {
        require(der.size <= 72) { "DER signature too long: ${der.size}" }
        return der + ByteArray(72 - der.size)
    }

    /** Trims the trailing zero padding off a 72-byte signature slot using the DER length byte. */
    private fun trimDer(padded: ByteArray): ByteArray =
        padded.copyOfRange(0, (padded[1].toInt() and 0xFF) + 2)

    private fun genP256(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun signP256(privateKey: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    private fun verifyP256(publicKey: PublicKey, data: ByteArray, der: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(data)
            verify(der)
        }

    /** Encodes a JCA EC public key as a 65-byte uncompressed SEC1 point. */
    private fun uncompressedPoint(publicKey: ECPublicKey): ByteArray {
        fun pad32(value: BigInteger): ByteArray {
            val raw = value.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - raw.size) + raw
        }
        return byteArrayOf(0x04) + pad32(publicKey.w.affineX) + pad32(publicKey.w.affineY)
    }

    /** Reconstructs a JCA public key from a 65-byte uncompressed SEC1 point on secp256r1. */
    private fun jcaPublicKey(uncompressed: ByteArray): PublicKey {
        require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte())
        val x = BigInteger(1, uncompressed.copyOfRange(1, 33))
        val y = BigInteger(1, uncompressed.copyOfRange(33, 65))
        val params = AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
    }
}

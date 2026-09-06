package com.impala.sdk

import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.ResponseAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.scp03.SCP03Constants
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Interop tests for the personalization ceremony and card lifecycle (applet 0.2):
 * PERSONALIZE parts A/B/C, TERMINATE, GET_PERSONALIZATION, the default-key and
 * C-DEC gates, key rotation and diversification. Runs against jcardsim, no hardware.
 */
class PersonalizationInteropTest {

    private val GOLDEN_ACCOUNT = "00112233445566778899aabbccddeeff".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val DUMMY_DER = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

    /** Asserts the block throws an ImpalaException whose message carries [hex]. */
    private fun expectSw(hex: String, block: () -> Unit) {
        val ex = assertFailsWith<ImpalaException> { block() }
        assertTrue(ex.message!!.uppercase().contains(hex.uppercase()), "expected $hex, got '${ex.message}'")
    }

    /** A fresh, initialized, custom-key card with ENFORCE set (optionally program-bound at install). */
    private fun freshInitialized(issuer: TestIssuer? = null): ImpalaSDK {
        val keys = customKeys()
        val params = PersonalizationProtocol.installParams(
            enforce = true, keys = keys, pins = null,
            program = issuer?.let { Pair(it.programId, it.pub65) }
        )
        val sdk = ImpalaSDK(SimulatorBibo(installParams = params), keys)
        sdk.setSeed()
        return sdk
    }

    private fun part(sdk: ImpalaSDK, p1: Int, data: ByteArray): ResponseAPDU =
        sdk.secureTx(CommandAPDU(SCP03Constants.CLA_GP.toInt(), SCP03Constants.INS_PERSONALIZE.toInt(), p1, 0x00, data))

    // --- P1 ---
    @Test
    fun `personalize commits identity, issuer key, certificate and initial counter atomically`() {
        for (initial in intArrayOf(0, 4711)) {
            val issuer = TestIssuer()
            val card = personalizedCard(issuer, GOLDEN_ACCOUNT, initialCounter = initial)
            assertEquals("00112233-4455-6677-8899-aabbccddeeff", card.sdk.getAccountId())

            val p = card.sdk.getPersonalization()
            assertEquals(0x02, p.state.toInt())
            assertTrue(p.initialized && p.programBound && p.personalized && p.pinProvisioned && p.provisioningEnforced)
            assertFalse(p.scp03KeysDefault)
            assertFalse(p.terminated)
            assertContentEquals(issuer.programId, p.programId)
            assertContentEquals(USDC, p.currency)
            assertContentEquals(issuer.pub65, p.issuerPubKey)
            assertContentEquals(card.cert, p.certificate)
            assertEquals(initial, card.sdk.getReceiveState().counter)
        }
    }

    // --- P2 ---
    @Test
    fun `personalize is refused over default SCP03 keys`() {
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 1).toByte() }
        val bibo = SimulatorBibo(installParams = byteArrayOf(0x01, 0x01)) // ENFORCE only, default keys
        val sdk = ImpalaSDK(bibo, defaultKeys())
        sdk.setSeed()
        val pub = sdk.getECPubKey().toByteArray()
        val cert = issuer.certify(accountId, USDC, pub)

        sdk.openSecureChannel()
        expectSw("6236") { part(sdk, 0x01, PersonalizationProtocol.identityPart(accountId, USDC, issuer.programId)) }
        expectSw("6236") { sdk.provisionUserPIN("2468") }
        val custom = customKeys()
        sdk.rotateScp03Keys(custom.first, custom.second, custom.third)
        sdk.closeSecureChannel()

        val sdk2 = ImpalaSDK(bibo, custom)
        sdk2.openSecureChannel()
        sdk2.personalize(accountId, USDC, issuer.programId, cert, issuerPubKey = issuer.pub65)
        sdk2.provisionUserPIN("2468")
        sdk2.closeSecureChannel()
        assertEquals(0x02, sdk2.getPersonalization().state.toInt())
    }

    // --- P3 ---
    @Test
    fun `personalize twice is refused`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, GOLDEN_ACCOUNT)
        card.sdk.openSecureChannel()
        expectSw("6235") {
            card.sdk.personalize(GOLDEN_ACCOUNT, USDC, issuer.programId,
                issuer.certify(GOLDEN_ACCOUNT, USDC, card.pub65), issuerPubKey = issuer.pub65)
        }
        card.sdk.closeSecureChannel()
        assertEquals(0x02, card.sdk.getPersonalization().state.toInt())
    }

    // --- P4 ---
    @Test
    fun `certificate over the wrong key or account or currency or program is refused`() {
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 1).toByte() }
        val sdk = freshInitialized()
        val pub = sdk.getECPubKey().toByteArray()
        val otherPub = TestIssuer().pub65

        val wrong = listOf(
            issuer.certify(accountId, USDC, otherPub),                 // wrong card key
            issuer.certify(ByteArray(16) { (it + 9).toByte() }, USDC, pub), // wrong account
            issuer.certify(accountId, EUR_, pub),                      // wrong currency
            Jca.signP256(issuer.keys.private, com.impala.sdk.models.TransferProtocol.certMessage(PROGRAM_B, accountId, USDC, pub)) // wrong program
        )
        sdk.openSecureChannel()
        for (cert in wrong) {
            expectSw("6677") { sdk.personalize(accountId, USDC, issuer.programId, cert, issuerPubKey = issuer.pub65) }
        }
        sdk.closeSecureChannel()

        val p = sdk.getPersonalization()
        assertEquals(0x01, p.state.toInt())
        assertFalse(p.programBound)
        assertNull(p.issuerPubKey)

        // A correct ceremony afterwards still succeeds (retry property)
        sdk.openSecureChannel()
        sdk.personalize(accountId, USDC, issuer.programId, issuer.certify(accountId, USDC, pub), issuerPubKey = issuer.pub65)
        sdk.closeSecureChannel()
        assertEquals(0x02, sdk.getPersonalization().state.toInt())
    }

    // --- P5 ---
    @Test
    fun `parts out of order are refused`() {
        val issuer = TestIssuer()
        val id1 = ByteArray(16) { (it + 1).toByte() }
        val id2 = ByteArray(16) { (it + 2).toByte() }

        run {
            val sdk = freshInitialized()
            sdk.openSecureChannel()
            expectSw("6237") { part(sdk, 0x03, DUMMY_DER) }                                    // C first
            expectSw("6237") { part(sdk, 0x02, issuer.pub65) }                                 // B first
            part(sdk, 0x01, PersonalizationProtocol.identityPart(id1, USDC, issuer.programId)) // A ...
            expectSw("6237") { part(sdk, 0x03, DUMMY_DER) }                                    // ... then C without B
            sdk.closeSecureChannel()
        }

        // A then A' (new identity) then B then C for A' succeeds — A' resets the stage
        val sdk = freshInitialized()
        val pub = sdk.getECPubKey().toByteArray()
        sdk.openSecureChannel()
        part(sdk, 0x01, PersonalizationProtocol.identityPart(id1, USDC, issuer.programId))
        part(sdk, 0x01, PersonalizationProtocol.identityPart(id2, USDC, issuer.programId))
        part(sdk, 0x02, issuer.pub65)
        part(sdk, 0x03, issuer.certify(id2, USDC, pub))
        sdk.closeSecureChannel()
        assertContentEquals(id2, hexUuidToBytes(sdk.getAccountId()))
    }

    // --- P6 ---
    @Test
    fun `personalize rejects nil ids, bad counter, bad key, malformed DER and wrong lengths`() {
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 1).toByte() }
        val sdk = freshInitialized()
        val pub = sdk.getECPubKey().toByteArray()
        sdk.openSecureChannel()

        val identity = PersonalizationProtocol.identityPart(accountId, USDC, issuer.programId)
        // Every failing part clears the stage (spec §4.7), so re-stage before the next.
        // six 0x6A80 (wrong data) cases
        expectSw("6A80") { part(sdk, 0x01, ByteArray(16) + USDC + issuer.programId + ByteArray(4)) }        // nil account
        expectSw("6A80") { part(sdk, 0x01, accountId + ByteArray(4) + issuer.programId + ByteArray(4)) }    // zero currency
        expectSw("6A80") { part(sdk, 0x01, accountId + USDC + ByteArray(16) + ByteArray(4)) }               // zero program
        expectSw("6A80") { part(sdk, 0x01, accountId + USDC + issuer.programId + byteArrayOf(0x80.toByte(), 0, 0, 0)) } // negative counter
        part(sdk, 0x01, identity)
        expectSw("6A80") { part(sdk, 0x02, ByteArray(65) { if (it == 0) 0x02 else it.toByte() }) }          // non-0x04 issuer key
        part(sdk, 0x01, identity)
        part(sdk, 0x02, issuer.pub65)
        expectSw("6A80") { part(sdk, 0x03, ByteArray(40) { 0x11 }) }                                        // malformed DER (no 0x30)

        // wrong lengths (0x6700): part A 39/41, part B 64, part C 73
        expectSw("6700") { part(sdk, 0x01, ByteArray(39)) }
        expectSw("6700") { part(sdk, 0x01, ByteArray(41)) }
        part(sdk, 0x01, identity)
        expectSw("6700") { part(sdk, 0x02, ByteArray(64) { if (it == 0) 0x04 else it.toByte() }) }
        part(sdk, 0x01, identity)
        part(sdk, 0x02, issuer.pub65)
        expectSw("6700") { part(sdk, 0x03, ByteArray(73) { 0x30 }) }

        // P2 != 0 and P1 = 4 both answer 0x6A86
        expectSw("6A86") { sdk.secureTx(CommandAPDU(SCP03Constants.CLA_GP.toInt(), SCP03Constants.INS_PERSONALIZE.toInt(), 0x01, 0x01, PersonalizationProtocol.identityPart(accountId, USDC, issuer.programId))) }
        expectSw("6A86") { part(sdk, 0x04, PersonalizationProtocol.identityPart(accountId, USDC, issuer.programId)) }
        sdk.closeSecureChannel()

        // before INITIALIZE → 0x6230
        val keys = customKeys()
        val blank = ImpalaSDK(SimulatorBibo(installParams = PersonalizationProtocol.installParams(false, keys, null, null)), keys)
        blank.openSecureChannel()
        expectSw("6230") { part(blank, 0x01, PersonalizationProtocol.identityPart(accountId, USDC, issuer.programId)) }
        blank.closeSecureChannel()
    }

    // --- P7 ---
    @Test
    fun `personalize without C-DEC is refused`() {
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 1).toByte() }

        // level 0x11 = C-MAC | R-MAC, no C-DEC → 0x6982
        val sdk = freshInitialized()
        sdk.openSecureChannel(0x11)
        expectSw("6982") { part(sdk, 0x01, PersonalizationProtocol.identityPart(accountId, USDC, issuer.programId)) }
        sdk.closeSecureChannel()

        // CLA 0x00 INS 0x72 → 0x6D00 (not an application INS)
        val bibo = SimulatorBibo()
        assertEquals(0x6D00, swOf(bibo.transceive(byteArrayOf(0x00, 0x72, 0x01, 0x00, 0x28) + ByteArray(40))))

        // CLA 0x84 without a session → 0x6985
        assertEquals(0x6985, swOf(bibo.transceive(byteArrayOf(0x84.toByte(), 0x72, 0x01, 0x00, 0x10) + ByteArray(16))))
    }

    // --- P8 ---
    @Test
    fun `program bound at install refuses part B and a different programId`() {
        val issuer = TestIssuer()
        val accountId = ByteArray(16) { (it + 1).toByte() }
        val keys = customKeys()
        val params = PersonalizationProtocol.installParams(true, keys, null, Pair(issuer.programId, issuer.pub65))
        val sdk = ImpalaSDK(SimulatorBibo(installParams = params), keys)
        sdk.setSeed()

        // Bound at install: programBound before any personalization, issuer key visible
        val before = sdk.getPersonalization()
        assertEquals(0x01, before.state.toInt())
        assertTrue(before.programBound)
        assertContentEquals(issuer.pub65, before.issuerPubKey)

        val pub = sdk.getECPubKey().toByteArray()
        sdk.openSecureChannel()
        expectSw("623B") { part(sdk, 0x02, issuer.pub65) }                                       // B on a bound card
        expectSw("623B") { part(sdk, 0x01, PersonalizationProtocol.identityPart(accountId, USDC, PROGRAM_B)) } // different programId
        // A(PROGRAM_A) then C succeeds (no B needed)
        sdk.personalize(accountId, USDC, issuer.programId, issuer.certify(accountId, USDC, pub), issuerPubKey = null)
        sdk.closeSecureChannel()
        assertEquals(0x02, sdk.getPersonalization().state.toInt())
    }

    // --- P9 ---
    @Test
    fun `install or update with the GP default key bytes is refused`() {
        // install fails
        assertFails { SimulatorBibo(installParams = byteArrayOf(0x01, 0x02) + ByteArray(48) { (0x40 + (it % 16)).toByte() }) }

        // APPLET_UPDATE with the default key value → 0x6684, and the old keys still open a channel
        val sdk = freshInitialized()
        sdk.openSecureChannel()
        val dflt = defaultKeys()
        expectSw("6684") { sdk.rotateScp03Keys(dflt.first, dflt.second, dflt.third) }
        sdk.closeSecureChannel()
        assertTrue(sdk.openSecureChannel())
        sdk.closeSecureChannel()
    }

    // --- P10 ---
    @Test
    fun `SCP03 key diversification reports the card id`() {
        val keys = customKeys()
        val sdk = ImpalaSDK(SimulatorBibo(installParams = PersonalizationProtocol.installParams(false, keys, null, null)), keys)

        sdk.openSecureChannel()
        val div1 = sdk.keyDiversification!!
        val cardId1 = sdk.getUserData().cardId
        assertContentEquals(hexUuidToBytes(cardId1).copyOfRange(0, 10), div1)
        sdk.closeSecureChannel()

        sdk.setSeed() // INITIALIZE regenerates cardId in place
        sdk.openSecureChannel()
        val div2 = sdk.keyDiversification!!
        val cardId2 = sdk.getUserData().cardId
        assertContentEquals(hexUuidToBytes(cardId2).copyOfRange(0, 10), div2)
        sdk.closeSecureChannel()

        assertFalse(div1.contentEquals(div2), "cardId (hence diversification) must change at INITIALIZE")
    }

    // --- P11 ---
    @Test
    fun `APPLET_UPDATE with an unknown sequence answers 6A86 and changes nothing`() {
        val sdk = freshInitialized()
        sdk.openSecureChannel()
        expectSw("6A86") { sdk.sendAppletUpdate(2, ByteArray(4)) }
        sdk.closeSecureChannel()
        assertTrue(sdk.openSecureChannel())
        sdk.closeSecureChannel()
    }

    // --- P12 ---
    @Test
    fun `terminate blocks signing and is irreversible`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, GOLDEN_ACCOUNT)

        // Guard checks on a still-alive card
        card.sdk.openSecureChannel()
        expectSw("6A80") { card.sdk.terminate(ByteArray(16) { 0xFF.toByte() }) } // wrong accountId
        assertTrue(card.sdk.isCardAlive())
        card.sdk.closeSecureChannel()

        // Without C-DEC → 0x6982
        card.sdk.openSecureChannel(0x11)
        expectSw("6982") { card.sdk.terminate(card.accountId) }
        card.sdk.closeSecureChannel()

        // Over default keys (a non-ENFORCE default-key card) → 0x6236
        val dfltSdk = ImpalaSDK(SimulatorBibo(), defaultKeys())
        dfltSdk.openSecureChannel()
        expectSw("6236") { dfltSdk.terminate(ByteArray(16)) }
        dfltSdk.closeSecureChannel()

        // The real terminate
        card.sdk.openSecureChannel()
        card.sdk.terminate(card.accountId)
        assertFalse(card.sdk.isCardAlive())
        expectSw("6687") { card.sdk.signTransferV2("1111", signable(card.accountId, ByteArray(16) { 1 }, amount = 1, counter = 1, SeqAllocator())) }
        expectSw("6687") { card.sdk.signAuthChallenge(ByteArray(32)) }
        // Reads stay available post-mortem
        assertEquals(0L, card.sdk.getBalance())
        val p = card.sdk.getPersonalization()
        assertEquals(0xFF, p.state.toInt() and 0xFF)
        assertTrue(p.terminated)
        // Second terminate → still 0x6687
        expectSw("6687") { card.sdk.terminate(card.accountId) }
        card.sdk.closeSecureChannel()
    }

    // --- P13 ---
    @Test
    fun `GET_EC_PUB_KEY before INITIALIZE answers 6230`() {
        val sdk = ImpalaSDK(SimulatorBibo(), defaultKeys())
        expectSw("6230") { sdk.getECPubKey() }
    }

    // --- P14 ---
    @Test
    fun `retired INS 06 and 14 answer 6D00`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, GOLDEN_ACCOUNT)
        assertEquals(0x6D00, swOf(card.bibo.transceive(byteArrayOf(0x00, 0x06, 0x00, 0x00, 0x00))))
        assertEquals(0x6D00, swOf(card.bibo.transceive(byteArrayOf(0x00, 0x14, 0x00, 0x00, 0x00))))
    }

    // --- P15 ---
    @Test
    fun `transfer commands refuse the secured CLA`() {
        val issuer = TestIssuer()
        val card = personalizedCard(issuer, GOLDEN_ACCOUNT)
        card.sdk.openSecureChannel()
        for (ins in intArrayOf(0x30, 0x31, 0x34, 0x36)) {
            expectSw("6E00") { card.sdk.secureTx(CommandAPDU(ins.toByte())) }
        }
        // GET_RECEIVE_STATE fits the wrap and is allowed secured
        assertEquals(36, card.sdk.secureTx(CommandAPDU(Constants.INS_GET_RECEIVE_STATE)).data.size)
        card.sdk.closeSecureChannel()
    }

    private fun hexUuidToBytes(uuid: String): ByteArray =
        uuid.replace("-", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

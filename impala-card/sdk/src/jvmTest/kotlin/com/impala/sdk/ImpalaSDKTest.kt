package com.impala.sdk

import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.ResponseAPDU
import com.impala.sdk.models.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Mock BIBO that records transmitted APDUs and returns configurable responses.
 */
class MockBIBO : BIBO {
    val sentCommands = mutableListOf<CommandAPDU>()
    var nextResponse: ByteArray = byteArrayOf(0x90.toByte(), 0x00)

    override fun transceive(bytes: ByteArray?): ByteArray {
        if (bytes != null) {
            sentCommands.add(CommandAPDU(bytes))
        }
        return nextResponse
    }

    override fun close() {}

    /** Helper: set response to data bytes + SW 0x9000 */
    fun respondWith(data: ByteArray) {
        nextResponse = data + byteArrayOf(0x90.toByte(), 0x00)
    }

    /** Helper: set response to an error status word */
    fun respondWithSW(sw: Int) {
        nextResponse = byteArrayOf(
            ((sw shr 8) and 0xFF).toByte(),
            (sw and 0xFF).toByte()
        )
    }

    /** Get the last sent CommandAPDU */
    fun lastCommand(): CommandAPDU = sentCommands.last()
}

/**
 * Unit tests for ImpalaSDK APDU construction, input validation, and error handling.
 */
class ImpalaSDKTest {

    // --- APDU construction tests ---

    @Test
    fun `getBalance sends correct INS`() {
        val mock = MockBIBO()
        mock.respondWith(ByteArray(8)) // 8-byte balance
        val sdk = ImpalaSDK(mock)
        sdk.getBalance()

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_GET_BALANCE.toInt() and 0xFF, cmd.iNS)
    }

    @Test
    fun `getBalance parses 8 byte big-endian response`() {
        val mock = MockBIBO()
        // balance = 1000 = 0x00000000000003E8
        mock.respondWith(byteArrayOf(0, 0, 0, 0, 0, 0, 0x03, 0xE8.toByte()))
        val sdk = ImpalaSDK(mock)
        assertEquals(1000L, sdk.getBalance())
    }

    @Test
    fun `getAccountId sends correct INS`() {
        val mock = MockBIBO()
        mock.respondWith(ByteArray(16)) // 16-byte UUID
        val sdk = ImpalaSDK(mock)
        sdk.getAccountId()

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_GET_ACCOUNT_ID.toInt() and 0xFF, cmd.iNS)
    }

    @Test
    fun `getFullName sends correct INS`() {
        val mock = MockBIBO()
        mock.respondWith("John Doe".encodeToByteArray())
        val sdk = ImpalaSDK(mock)
        val name = sdk.getFullName()

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_GET_FULL_NAME.toInt() and 0xFF, cmd.iNS)
        assertEquals("John Doe", name)
    }

    @Test
    fun `setCardData sends correct INS and data`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        val testData = byteArrayOf(0x01, 0x02, 0x03)
        sdk.setCardData(testData)

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_SET_CARD_DATA.toInt() and 0xFF, cmd.iNS)
        assertEquals(testData.toList(), cmd.data.toList())
    }

    @Test
    fun `updateMasterPin sends correct INS and P1 P2`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        sdk.updateMasterPin("12345678")

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_UPDATE_MASTER_PIN.toInt() and 0xFF, cmd.iNS)
        assertEquals(0x00, cmd.p1)
        assertEquals(0x00, cmd.p2)
    }

    @Test
    fun `isCardAlive sends correct INS and returns true on SW_OK`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertTrue(sdk.isCardAlive())

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_IS_CARD_ALIVE.toInt() and 0xFF, cmd.iNS)
    }

    @Test
    fun `isCardAlive returns false on error SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6687) // card terminated
        val sdk = ImpalaSDK(mock)
        assertFalse(sdk.isCardAlive())
    }

    @Test
    fun `verifyUserPin sends correct INS and P2`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        sdk.verifyUserPin("1234")

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_VERIFY_PIN.toInt() and 0xFF, cmd.iNS)
        assertEquals(Constants.P2_USER_PIN.toInt() and 0xFF, cmd.p2)
    }

    @Test
    fun `verifyMasterPin sends correct INS and P2`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        sdk.verifyMasterPin("14117298")

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_VERIFY_PIN.toInt() and 0xFF, cmd.iNS)
        assertEquals(Constants.P2_MASTER_PIN.toInt() and 0xFF, cmd.p2)
    }

    @Test
    fun `signTransfer sends correct INS with pin and signable data`() {
        val mock = MockBIBO()
        // Response: sig(72) + pubKey(65) + pubKeySig(72) = 209 bytes + SW
        mock.respondWith(ByteArray(209))
        val sdk = ImpalaSDK(mock)
        val signableData = ByteArray(60) // SIGNABLE_LENGTH
        sdk.signTransfer("1234", signableData)

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_SIGN_TRANSFER.toInt() and 0xFF, cmd.iNS)
        // Payload = 4-byte pin + 60-byte signable = 64
        assertEquals(64, cmd.nc)
    }

    @Test
    fun `verifyTransfer sends two APDUs with correct P1 values`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        val signableData = ByteArray(60)
        val signature = ByteArray(72)
        val pubKey = ByteArray(65)
        val pubKeySig = ByteArray(72)
        sdk.verifyTransfer(signableData, signature, pubKey, pubKeySig)

        assertEquals(2, mock.sentCommands.size)
        // First command: P1=0x00
        assertEquals(0x00, mock.sentCommands[0].p1)
        assertEquals(Constants.INS_VERIFY_TRANSFER.toInt() and 0xFF, mock.sentCommands[0].iNS)
        // Second command: P1=0x01
        assertEquals(0x01, mock.sentCommands[1].p1)
        assertEquals(Constants.INS_VERIFY_TRANSFER.toInt() and 0xFF, mock.sentCommands[1].iNS)
    }

    @Test
    fun `getImpalaAppletVersion parses 10-byte response`() {
        val mock = MockBIBO()
        // major=0x0001, minor=0x0002, revList=0x0003, hash=0xAABBCCDD
        mock.respondWith(byteArrayOf(
            0x00, 0x01,             // major
            0x00, 0x02,             // minor
            0x00, 0x03,             // revList
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte()  // shortHash
        ))
        val sdk = ImpalaSDK(mock)
        val version = sdk.getImpalaAppletVersion()

        assertEquals(1, version.major.toInt())
        assertEquals(2, version.minor.toInt())
        assertEquals(3, version.revList.toInt())
        assertEquals("aabbccdd", version.shortHash)
    }

    // --- Input validation tests ---

    @Test
    fun `setUserName rejects empty name`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.setUserName("")
        }
    }

    @Test
    fun `setUserName rejects oversized name`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.setUserName("A".repeat(129))
        }
    }

    @Test
    fun `setUserName accepts 128-byte name`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        sdk.setUserName("A".repeat(128))
        assertEquals(128, mock.lastCommand().nc)
    }

    @Test
    fun `setGender rejects empty gender`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.setGender("")
        }
    }

    @Test
    fun `setGender rejects oversized gender`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.setGender("A".repeat(17))
        }
    }

    @Test
    fun `verifyMasterPin rejects wrong length`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.verifyMasterPin("1234") // too short
        }
        assertFailsWith<IllegalArgumentException> {
            sdk.verifyMasterPin("123456789") // too long
        }
    }

    @Test
    fun `verifyMasterPin rejects non-digit characters`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.verifyMasterPin("1234567a")
        }
    }

    @Test
    fun `updateUserPin rejects wrong length`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.updateUserPin("123") // too short
        }
        assertFailsWith<IllegalArgumentException> {
            sdk.updateUserPin("12345") // too long
        }
    }

    @Test
    fun `updateUserPin rejects 0000`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.updateUserPin("0000")
        }
    }

    @Test
    fun `updateUserPin rejects non-digit characters`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.updateUserPin("12ab")
        }
    }

    @Test
    fun `updateMasterPin rejects wrong length`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.updateMasterPin("1234")
        }
    }

    @Test
    fun `signTransfer rejects wrong signable length`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<IllegalArgumentException> {
            sdk.signTransfer("1234", ByteArray(59)) // too short
        }
        assertFailsWith<IllegalArgumentException> {
            sdk.signTransfer("1234", ByteArray(61)) // too long
        }
    }

    // --- Error handling tests ---

    @Test
    fun `tx throws ImpalaPinException on PIN failure SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x69C3) // 3 tries left
        val sdk = ImpalaSDK(mock)

        val ex = assertFailsWith<ImpalaPinException> {
            sdk.getBalance()
        }
        assertEquals(3, ex.triesRemaining)
    }

    @Test
    fun `tx throws ImpalaCardTerminatedException on terminated SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6687)
        val sdk = ImpalaSDK(mock)

        assertFailsWith<ImpalaCardTerminatedException> {
            sdk.getBalance()
        }
    }

    @Test
    fun `tx throws ImpalaInsufficientFundsException on insufficient funds SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6224)
        val sdk = ImpalaSDK(mock)

        assertFailsWith<ImpalaInsufficientFundsException> {
            sdk.getBalance()
        }
    }

    @Test
    fun `tx throws ImpalaInstructionNotSupportedException on INS not supported SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6D00)
        val sdk = ImpalaSDK(mock)

        assertFailsWith<ImpalaInstructionNotSupportedException> {
            sdk.getBalance()
        }
    }

    @Test
    fun `tx throws ImpalaSecurityException on security not satisfied SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6982)
        val sdk = ImpalaSDK(mock)

        assertFailsWith<ImpalaSecurityException> {
            sdk.getBalance()
        }
    }

    @Test
    fun `tx throws ImpalaWrongLengthException on wrong length SW`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6700)
        val sdk = ImpalaSDK(mock)

        assertFailsWith<ImpalaWrongLengthException> {
            sdk.getBalance()
        }
    }

    // --- Transfer protocol v1 (applet 0.2) APDU construction ---

    /** A 72-byte DER slot carrying a minimal 8-byte DER SEQUENCE, zero-padded. */
    private fun derSlot72(): ByteArray = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01) + ByteArray(64)

    @Test
    fun `signTransferV2 sends INS 30 with Nc 64 and parses 209`() {
        val mock = MockBIBO()
        // 209-byte response: sig slot (72) ‖ pubkey (65) ‖ cert slot (72), both slots valid DER
        mock.respondWith(derSlot72() + (byteArrayOf(0x04) + ByteArray(64)) + derSlot72())
        val sdk = ImpalaSDK(mock)
        val env = sdk.signTransferV2("1234", ByteArray(60))

        val cmd = mock.lastCommand()
        assertEquals(Constants.INS_SIGN_TRANSFER_V2.toInt() and 0xFF, cmd.iNS)
        assertEquals(64, cmd.nc) // 4-byte PIN + 60-byte signable
        assertEquals(8, env.signature.size)
        assertEquals(65, env.pubKey.size)
        assertEquals(8, env.certificate.size)
    }

    @Test
    fun `verifyTransferV2 sends INS 31 P1 0 then 1 with Nc 60 and 209`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        sdk.verifyTransferV2(ByteArray(60), ByteArray(8) { 0x30 }, ByteArray(65), ByteArray(8) { 0x30 })

        assertEquals(2, mock.sentCommands.size)
        assertEquals(Constants.INS_VERIFY_TRANSFER_V2.toInt() and 0xFF, mock.sentCommands[0].iNS)
        assertEquals(0x00, mock.sentCommands[0].p1)
        assertEquals(60, mock.sentCommands[0].nc)
        assertEquals(0x01, mock.sentCommands[1].p1)
        assertEquals(209, mock.sentCommands[1].nc)
    }

    @Test
    fun `getPersonalization rejects sizes other than 159`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        mock.respondWith(ByteArray(158))
        assertFailsWith<ImpalaException> { sdk.getPersonalization() }
        mock.respondWith(ByteArray(160))
        assertFailsWith<ImpalaException> { sdk.getPersonalization() }
    }

    @Test
    fun `getReceiveState parses 36`() {
        val mock = MockBIBO()
        mock.respondWith(ByteArray(36))
        val sdk = ImpalaSDK(mock)
        val rs = sdk.getReceiveState()
        assertEquals(0, rs.counter)
        assertEquals(32, rs.lastDigest.size)
        assertEquals(Constants.INS_GET_RECEIVE_STATE.toInt() and 0xFF, mock.lastCommand().iNS)
    }

    @Test
    fun `getLastTransfer maps 6A83 to null`() {
        val mock = MockBIBO()
        mock.respondWithSW(0x6A83)
        val sdk = ImpalaSDK(mock)
        assertEquals(null, sdk.getLastTransfer())
    }

    @Test
    fun `requireCertifiedProtocol rejects 0_1 and accepts 0_2 and 1_0`() {
        fun versionBytes(major: Int, minor: Int) =
            byteArrayOf(0, major.toByte(), 0, minor.toByte(), 0, 0, 0, 0, 0, 0)
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)

        mock.respondWith(versionBytes(0, 1))
        assertFailsWith<ImpalaException> { sdk.requireCertifiedProtocol() }
        mock.respondWith(versionBytes(0, 2))
        assertEquals(2, sdk.requireCertifiedProtocol().minor.toInt())
        mock.respondWith(versionBytes(1, 0))
        assertEquals(1, sdk.requireCertifiedProtocol().major.toInt())
    }

    @Test
    fun `personalize throws without an open channel`() {
        val mock = MockBIBO()
        val sdk = ImpalaSDK(mock)
        assertFailsWith<ImpalaException> {
            sdk.personalize(ByteArray(16) { 1 }, "USDC".encodeToByteArray(), ByteArray(16) { 2 }, byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01))
        }
    }
}

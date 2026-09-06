package com.impala.sdk

import com.impala.sdk.scp03.SCP03Constants
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Unit tests for SDK Constants — verifies that APDU instruction codes,
 * PIN types, length constants, and status words have the expected values.
 *
 * These tests serve as a regression guard against accidental changes to
 * protocol-critical constants.
 */
class ConstantsTest {

    @Test
    fun `INS codes match applet protocol`() {
        assertEquals(2, Constants.INS_NOP.toInt())
        assertEquals(4, Constants.INS_GET_BALANCE.toInt())
        assertEquals(6, Constants.INS_SIGN_TRANSFER.toInt())
        assertEquals(7, Constants.INS_GET_RSA_PUB_KEY.toInt())
        assertEquals(22, Constants.INS_GET_ACCOUNT_ID.toInt())
        assertEquals(24, Constants.INS_VERIFY_PIN.toInt())
        assertEquals(25, Constants.INS_UPDATE_USER_PIN.toInt())
        assertEquals(30, Constants.INS_GET_USER_DATA.toInt())
        assertEquals(36, Constants.INS_GET_EC_PUB_KEY.toInt())
        assertEquals(37, Constants.INS_SIGN_AUTH.toInt())
        assertEquals(38, Constants.INS_SET_CARD_DATA.toInt())
        assertEquals(44, Constants.INS_INITIALIZE.toInt())
        assertEquals(45, Constants.INS_SUICIDE.toInt())
        assertEquals(46, Constants.INS_IS_CARD_ALIVE.toInt())
        assertEquals(100, Constants.INS_GET_VERSION.toInt())
        // applet 0.2 / transfer protocol v1
        assertEquals(0x30, Constants.INS_SIGN_TRANSFER_V2.toInt())
        assertEquals(0x31, Constants.INS_VERIFY_TRANSFER_V2.toInt())
        assertEquals(0x34, Constants.INS_GET_PERSONALIZATION.toInt())
        assertEquals(0x35, Constants.INS_GET_RECEIVE_STATE.toInt())
        assertEquals(0x36, Constants.INS_GET_LAST_TRANSFER.toInt())
        assertEquals(0x72, SCP03Constants.INS_PERSONALIZE.toInt())
        assertEquals(0x73, SCP03Constants.INS_TERMINATE.toInt())
    }

    @Test
    fun `transfer protocol v1 status words and constants are pinned`() {
        assertEquals(0x6233.toShort(), Constants.SW_ERROR_TRANSFER_COUNTER_INVALID)
        assertEquals(0x6234.toShort(), Constants.SW_ERROR_NOT_PERSONALIZED)
        assertEquals(0x6235.toShort(), Constants.SW_ERROR_ALREADY_PERSONALIZED)
        assertEquals(0x6236.toShort(), Constants.SW_ERROR_DEFAULT_SCP03_KEYS)
        assertEquals(0x6237.toShort(), Constants.SW_ERROR_PERSONALIZE_SEQUENCE)
        assertEquals(0x6238.toShort(), Constants.SW_ERROR_SEND_SEQUENCE_INVALID)
        assertEquals(0x6239.toShort(), Constants.SW_ERROR_ZERO_AMOUNT)
        assertEquals(0x623A.toShort(), Constants.SW_ERROR_TRANSFER_COUNTER_JUMP)
        assertEquals(0x623B.toShort(), Constants.SW_ERROR_PROGRAM_ALREADY_BOUND)
        assertEquals(0x6A80.toShort(), Constants.SW_WRONG_DATA)
        assertEquals(0x6984.toShort(), Constants.SW_DATA_INVALID)
        assertEquals(0x6A83.toShort(), Constants.SW_RECORD_NOT_FOUND)
        assertEquals(0x6E00.toShort(), Constants.SW_CLA_NOT_SUPPORTED)
        assertEquals(1024.toShort(), Constants.MAX_COUNTER_JUMP)
        assertEquals(1, Constants.TRANSFER_PROTOCOL_VERSION.toInt())
        assertEquals(1, Constants.CERT_VERSION.toInt())
        assertEquals(89, Constants.XFER_MESSAGE_LENGTH.toInt())
        assertEquals(114, Constants.CERT_MESSAGE_LENGTH.toInt())
        assertEquals(159, Constants.PERSONALIZATION_LENGTH.toInt())
        assertEquals(36, Constants.RECEIVE_STATE_LENGTH.toInt())
        assertEquals(132, Constants.LAST_TRANSFER_LENGTH.toInt())
        assertEquals(209, Constants.TRANSFER_RESPONSE_LENGTH.toInt())
        assertEquals(81, Constants.PROGRAM_BLOCK_LENGTH.toInt())
        assertEquals(40, Constants.PERSONALIZE_IDENTITY_LENGTH.toInt())
    }

    @Test
    fun `PIN type constants`() {
        assertEquals(0x81.toByte(), Constants.P2_MASTER_PIN)
        assertEquals(0x82.toByte(), Constants.P2_USER_PIN)
        assertNotEquals(Constants.P2_MASTER_PIN, Constants.P2_USER_PIN)
    }

    @Test
    fun `length constants are consistent`() {
        assertEquals(16, Constants.UUID_LENGTH)
        assertEquals(32, Constants.HASH_LENGTH)
        assertEquals(65, Constants.PUB_KEY_LENGTH)
        assertEquals(32, Constants.PRIV_KEY_LENGTH)
        assertTrue(Constants.MAX_SIG_LENGTH >= 64, "DER-encoded EC signature can be up to 72 bytes")
    }

    @Test
    fun `SW_OK is 0x9000`() {
        assertEquals(0x9000.toShort(), Constants.SW_OK)
    }

    @Test
    fun `all INS codes are unique`() {
        val codes = listOf(
            Constants.INS_NOP,
            Constants.INS_GET_BALANCE,
            Constants.INS_SIGN_TRANSFER,
            Constants.INS_GET_RSA_PUB_KEY,
            Constants.INS_GET_ACCOUNT_ID,
            Constants.INS_VERIFY_PIN,
            Constants.INS_UPDATE_USER_PIN,
            Constants.INS_GET_USER_DATA,
            Constants.INS_SET_FULL_NAME,
            Constants.INS_GET_FULL_NAME,
            Constants.INS_GET_GENDER,
            Constants.INS_SET_GENDER,
            Constants.INS_GET_CARD_NONCE,
            Constants.INS_GET_EC_PUB_KEY,
            Constants.INS_SIGN_AUTH,
            Constants.INS_SET_CARD_DATA,
            Constants.INS_UPDATE_MASTER_PIN,
            Constants.INS_INITIALIZE,
            Constants.INS_SUICIDE,
            Constants.INS_IS_CARD_ALIVE,
            Constants.INS_GET_VERSION,
            Constants.INS_SIGN_TRANSFER_V2,
            Constants.INS_VERIFY_TRANSFER_V2,
            Constants.INS_GET_PERSONALIZATION,
            Constants.INS_GET_RECEIVE_STATE,
            Constants.INS_GET_LAST_TRANSFER,
        )
        assertEquals(codes.size, codes.toSet().size, "All INS codes should be unique")

        // The secure-channel INS (CLA 0x84 only) must not overlap the application INS either
        val scp03 = listOf(
            SCP03Constants.INS_PROVISION_PIN,
            SCP03Constants.INS_APPLET_UPDATE,
            SCP03Constants.INS_PERSONALIZE,
            SCP03Constants.INS_TERMINATE,
        )
        assertEquals(scp03.size, scp03.toSet().size, "All SCP03 INS codes should be unique")
        assertTrue(codes.toSet().intersect(scp03.toSet()).isEmpty(), "SCP03 INS must not overlap application INS")
    }
}

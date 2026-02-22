package com.impala.sdk

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
        )
        assertEquals(codes.size, codes.toSet().size, "All INS codes should be unique")
    }
}

package com.impala.sdk

object Constants {
    const val INIT_SEED_LENGTH: Short = 4
    const val ZERO: Short = 0
    const val ONE: Short = 1
    const val TWO: Short = 2

    const val INS_NOP: Byte = 2
    const val INS_GET_BALANCE: Byte = 4
    const val INS_SIGN_TRANSFER: Byte = 6
    const val INS_GET_RSA_PUB_KEY: Byte = 7
    const val INS_VERIFY_TRANSFER: Byte = 20
    const val INS_GET_ACCOUNT_ID: Byte = 22
    const val INS_VERIFY_PIN: Byte = 24 // P2=1 for master PIN P1=2 for user_pin
    const val INS_UPDATE_USER_PIN: Byte = 25 // set new user PIN
    const val INS_GET_USER_DATA: Byte = 30
    const val INS_SET_FULL_NAME: Byte = 31
    const val INS_GET_FULL_NAME: Byte = 32
    const val INS_GET_GENDER: Byte = 33
    const val INS_SET_GENDER: Byte = 34
    const val INS_GET_CARD_NONCE: Byte = 35
    const val INS_GET_EC_PUB_KEY: Byte = 36
    const val INS_SIGN_AUTH: Byte = 37
    const val INS_SET_CARD_DATA: Byte = 38
    const val INS_UPDATE_MASTER_PIN: Byte = 43
    const val INS_INITIALIZE: Byte = 44
    const val INS_SUICIDE: Byte = 45
    const val INS_IS_CARD_ALIVE: Byte = 46
    const val INS_GET_VERSION: Byte = 100

    // PIN type
    const val P2_MASTER_PIN: Byte = 129.toByte() // P2 byte for Master PIN in Verify 0x81
    const val P2_USER_PIN: Byte = 130.toByte() // P2 byte for User PIN in Verify 0x82

    const val INT32_LENGTH: Short = 4
    const val INT64_LENGTH: Short = 8
    const val UUID_LENGTH: Short = 16

    const val HASH_LENGTH: Short = 32
    const val HASHABLE_LENGTH: Short = 252
    const val INIT_LENGTH: Short = 56
    const val MAX_SIG_LENGTH: Short = 72
    const val PRIV_KEY_LENGTH: Short = 32
    const val PUB_KEY_LENGTH: Short = 65
    const val SIGNABLE_LENGTH: Short = 60
    const val TAG_LENGTH_LENGTH: Short = 2
    const val SW_OK: Short = 0x9000.toShort()
    const val SW_INS_NOT_SUPPORTED: Short = 0x6d00
    const val SW_ERROR_KEY_VERIFICATION_FAILED: Short = 0x0022
    const val SW_ERROR_SIGNATURE_VERIFICATION_FAILED: Short = 0x0023
    const val SW_INCORRECT_P1P2: Short = 0x6a86
    const val SW_SET_BALANCE_FAILED: Short = 0x6C02
    const val SW_SET_ACCOUNT_ID_FAILED: Short = 0x6C01
    const val SW_PIN_FAILED_NO_TRIES_LEFT: Short = 0x69C0
    const val SW_PIN_FAILED_1_TRIES_LEFT: Short = 0x69C1
    const val SW_PIN_FAILED_2_TRIES_LEFT: Short = 0x69C2
    const val SW_PIN_FAILED_3_TRIES_LEFT: Short = 0x69C3
    const val SW_PIN_FAILED_4_TRIES_LEFT: Short = 0x69C4
    const val SW_PIN_FAILED_5_TRIES_LEFT: Short = 0x69c5
    const val SW_PIN_FAILED_6_TRIES_LEFT: Short = 0x69c6
    const val SW_PIN_FAILED_7_TRIES_LEFT: Short = 0x69c7
    const val SW_PIN_FAILED_8_TRIES_LEFT: Short = 0x69c8
    const val SW_PIN_FAILED_9_TRIES_LEFT: Short = 0x69c9
    const val SW_CONDITIONS_NOT_SATISFIED: Short = 0x6985
    const val SW_SECURITY_STATUS_NOT_SATISFIED: Short = 0x6982
    const val SW_WRONG_LENGTH: Short = 0x6700
    const val SW_INSUFFICIENT_FUNDS: Short = 0x6224
    const val SW_ERROR_PARSING_RECIPIENT: Short = 0x6226
    const val SW_ERROR_INIT_SIGNER: Short = 0x6227
    const val SW_ERROR_WRONG_CURRENCY: Short = 0x6229
    const val SW_ERROR_EC_CARD_KEY_MISSING: Short = 0x6230
    const val SW_ERROR_WRONG_SENDER: Short = 0x6231
    const val SW_ERROR_WRONG_RECIPIENT: Short = 0x6232
    const val SW_ERROR_CARD_DATA_SIGNATURE_INVALID: Short = 0x6677
    const val SW_ERROR_CARD_DATA_NONCE_INVALID: Short = 0x6678
    const val SW_ERROR_WRONG_CARD_ID: Short = 0x6679
    const val SW_ERROR_CRYPTO_EXCEPTION: Short = 0x6683
    const val SW_ERROR_INVALID_AES_KEY: Short = 0x6684
    const val SW_ERROR_PUB_KEY_ALREADY_SET: Short = 0x6685
    const val SW_ERROR_PRNG_ALREADY_SEEDED: Short = 0x6686
    const val SW_ERROR_CARD_TERMINATED: Short = 0x6687
    const val SW_ERROR_NULL_POINTER_EXCEPTION: Short = 0x6688
    const val SW_ERROR_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION: Short = 0x6689
    const val SW_ERROR_PIN_REQUIRED: Short = 0x6690
    const val SW_ERROR_PIN_REJECTED: Short = 0x6691
    const val SW_UNKNOWN: Short = 0x6F00
    const val SW_UNKNOWN_4469: Short = 0x4469
    const val SW_UNKNOWN_6F15: Short = 0x6F15
    const val TAG_LOST: Short = 0x0000
    const val SW_ERROR_STATUS_BROKEN: Short = 0x0001
}

package com.impala.sdk

/**
 * Protocol constants for APDU communication with the Impala JavaCard applet.
 *
 * Contains ISO/IEC 7816-4 instruction bytes (INS), PIN type selectors (P2),
 * cryptographic length constants, and status word (SW) response codes.
 *
 * INS codes identify the applet command to execute. Status words in the
 * response indicate success ([SW_OK] = 0x9000) or a specific error condition.
 *
 * This file mirrors `applet/.../Constants.java` byte-for-byte (applet 0.2,
 * transfer protocol v1); `ApduDocDriftTest` and `ConstantsTest` pin the two
 * together. Secure-channel INS live in [com.impala.sdk.scp03.SCP03Constants].
 */
object Constants {
    // ---- Numeric helpers ----
    const val INIT_SEED_LENGTH: Short = 4
    const val ZERO: Short = 0
    const val ONE: Short = 1
    const val TWO: Short = 2

    // ---- APDU instruction (INS) bytes ----
    const val INS_NOP: Byte = 2
    const val INS_GET_BALANCE: Byte = 4
    /** Retired in applet 0.2 — the applet answers 0x6D00; never reuse. */
    const val INS_SIGN_TRANSFER: Byte = 6
    const val INS_GET_RSA_PUB_KEY: Byte = 7
    /** Retired in applet 0.2 — the applet answers 0x6D00; never reuse. */
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

    // Transfer protocol v1 (applet 0.2). 0x32 / 0x33 are never assigned.
    const val INS_SIGN_TRANSFER_V2: Byte = 0x30      // CLA 0x00 only
    const val INS_VERIFY_TRANSFER_V2: Byte = 0x31    // CLA 0x00 only
    const val INS_GET_PERSONALIZATION: Byte = 0x34   // CLA 0x00 only
    const val INS_GET_RECEIVE_STATE: Byte = 0x35     // CLA 0x00 or 0x84
    const val INS_GET_LAST_TRANSFER: Byte = 0x36     // CLA 0x00 only

    // PERSONALIZE parts (P1)
    const val P1_PERSONALIZE_IDENTITY: Byte = 0x01
    const val P1_PERSONALIZE_ISSUER_KEY: Byte = 0x02
    const val P1_PERSONALIZE_CERTIFICATE: Byte = 0x03

    // GET_PERSONALIZATION state byte
    const val PERSONALIZATION_STATE_BLANK: Byte = 0x00
    const val PERSONALIZATION_STATE_INITIALIZED: Byte = 0x01
    const val PERSONALIZATION_STATE_PERSONALIZED: Byte = 0x02
    const val PERSONALIZATION_STATE_TERMINATED: Byte = 0xFF.toByte()

    // GET_PERSONALIZATION flags byte
    const val PFLAG_INITIALIZED: Byte = 0x01
    const val PFLAG_PROGRAM_BOUND: Byte = 0x02
    const val PFLAG_PERSONALIZED: Byte = 0x04
    const val PFLAG_SCP03_KEYS_DEFAULT: Byte = 0x08
    const val PFLAG_PIN_PROVISIONED: Byte = 0x10
    const val PFLAG_PROVISIONING_ENFORCED: Byte = 0x20
    const val PFLAG_TERMINATED: Byte = 0x40

    // PIN type
    const val P2_MASTER_PIN: Byte = 129.toByte() // P2 byte for Master PIN in Verify 0x81
    const val P2_USER_PIN: Byte = 130.toByte() // P2 byte for User PIN in Verify 0x82

    // ---- Data field lengths (bytes) ----
    const val INT32_LENGTH: Short = 4
    const val INT64_LENGTH: Short = 8
    const val UUID_LENGTH: Short = 16

    const val HASH_LENGTH: Short = 32
    @Deprecated("the 252-byte hashable record was removed in applet 0.2")
    const val HASHABLE_LENGTH: Short = 252
    const val INIT_LENGTH: Short = 56
    const val MAX_SIG_LENGTH: Short = 72
    const val MIN_DER_SIG_LENGTH: Short = 8
    const val PRIV_KEY_LENGTH: Short = 32
    const val PUB_KEY_LENGTH: Short = 65
    const val SIGNABLE_LENGTH: Short = 60
    const val TAG_LENGTH_LENGTH: Short = 2

    // Transfer protocol v1 lengths / versions
    const val PROGRAM_ID_LENGTH: Short = 16
    const val CURRENCY_LENGTH: Short = 4
    const val DOMAIN_TAG_LENGTH: Short = 12
    const val XFER_MESSAGE_LENGTH: Short = 89
    const val CERT_MESSAGE_LENGTH: Short = 114
    const val PERSONALIZE_IDENTITY_LENGTH: Short = 40
    const val PERSONALIZE_STAGE_LENGTH: Short = 177
    const val PERSONALIZATION_LENGTH: Short = 159
    const val RECEIVE_STATE_LENGTH: Short = 36
    const val LAST_TRANSFER_LENGTH: Short = 132
    const val TRANSFER_RESPONSE_LENGTH: Short = 209
    const val PROGRAM_BLOCK_LENGTH: Short = 81
    const val KEY_DIVERSIFICATION_LENGTH: Short = 10
    const val TRANSFER_PROTOCOL_VERSION: Byte = 0x01
    const val CERT_VERSION: Byte = 0x01
    const val MAX_COUNTER_JUMP: Short = 1024

    // ---- Status words (SW1-SW2) ----
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
    const val SW_ERROR_TRANSFER_COUNTER_INVALID: Short = 0x6233
    const val SW_ERROR_NOT_PERSONALIZED: Short = 0x6234
    const val SW_ERROR_ALREADY_PERSONALIZED: Short = 0x6235
    const val SW_ERROR_DEFAULT_SCP03_KEYS: Short = 0x6236
    const val SW_ERROR_PERSONALIZE_SEQUENCE: Short = 0x6237
    const val SW_ERROR_SEND_SEQUENCE_INVALID: Short = 0x6238
    const val SW_ERROR_ZERO_AMOUNT: Short = 0x6239
    const val SW_ERROR_TRANSFER_COUNTER_JUMP: Short = 0x623A
    const val SW_ERROR_PROGRAM_ALREADY_BOUND: Short = 0x623B
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
    const val SW_SET_FULL_NAME_FAILED: Short = 0x6C03
    const val SW_SET_GENDER_FAILED: Short = 0x6C04
    const val SW_ERROR_WRONG_SIGNABLE_LENGTH: Short = 0x6226
    const val SW_ERROR_WRONG_TAIL_LENGTH: Short = 0x6C02
    const val SW_ERROR_ALREADY_INITIALIZED: Short = 0x6686
    // ISO 7816-4 words the applet throws
    const val SW_WRONG_DATA: Short = 0x6A80
    const val SW_DATA_INVALID: Short = 0x6984
    const val SW_RECORD_NOT_FOUND: Short = 0x6A83
    const val SW_CLA_NOT_SUPPORTED: Short = 0x6E00
    const val SW_UNKNOWN: Short = 0x6F00
    const val SW_UNKNOWN_4469: Short = 0x4469
    const val SW_UNKNOWN_6F15: Short = 0x6F15
    const val TAG_LOST: Short = 0x0000
    const val SW_ERROR_STATUS_BROKEN: Short = 0x0001
}

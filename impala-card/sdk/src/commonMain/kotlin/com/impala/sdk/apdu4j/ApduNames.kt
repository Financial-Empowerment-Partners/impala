package com.impala.sdk.apdu4j

/**
 * The APDU vocabulary by name: instruction names, status-word names, and the
 * read-only allow-list. Apps render traces and errors through this object so
 * they never need an instruction byte of their own.
 *
 * Names are the ones in `impala-card/docs/apdu.md` (pinned by
 * `ApduNamesDocTest`). Status words the JCRE answers before the applet sees
 * the command ([PLATFORM_STATUS_WORDS]) are not in that document's table.
 */
object ApduNames {
    /** ISO 7816-4 SELECT (`00 A4`), sent before any applet command. */
    const val SELECT_INS: Int = 0xA4

    /**
     * Instructions that never change card state, consume a PIN try or produce a
     * signature (card-audit §4): NOP, GET_BALANCE, GET_ACCOUNT_ID, GET_USER_DATA,
     * GET_FULL_NAME, GET_GENDER, GET_EC_PUB_KEY, IS_CARD_ALIVE,
     * GET_PERSONALIZATION, GET_RECEIVE_STATE, GET_LAST_TRANSFER,
     * GET_STELLAR_KEY, GET_USER_VERIFICATION, GET_VERSION. Valid at CLA 0x00 only.
     */
    val READ_ONLY_INS: Set<Int> = setOf(0x02, 0x04, 0x16, 0x1E, 0x20, 0x21, 0x24, 0x2E, 0x34, 0x35, 0x36, 0x37, 0x39, 0x64)

    /**
     * Dispatched application instructions that change card state, consume a PIN
     * try or produce a signature: VERIFY_PIN, UPDATE_USER_PIN, SET_FULL_NAME,
     * SET_GENDER, SIGN_AUTH, INITIALIZE, SIGN_TRANSFER_V2, VERIFY_TRANSFER_V2,
     * SIGN_SEP10, SET_SIGN_IN_POLICY, CHANGE_USER_PIN. Disjoint from [READ_ONLY_INS].
     */
    val MUTATING_INS: Set<Int> = setOf(0x18, 0x19, 0x1F, 0x22, 0x25, 0x2C, 0x30, 0x31, 0x38, 0x3A, 0x3B)

    /**
     * Status words from the card platform rather than the applet: `6A82` (the
     * JCRE has no applet under the SELECTed AID) and `6999` (applet selection
     * failed; jcardsim's VSmartCard path answers it).
     */
    val PLATFORM_STATUS_WORDS: Set<Int> = setOf(0x6A82, 0x6999)

    private val APPLICATION = mapOf(
        0x02 to "NOP",
        0x04 to "GET_BALANCE",
        0x16 to "GET_ACCOUNT_ID",
        0x18 to "VERIFY_PIN",
        0x19 to "UPDATE_USER_PIN",
        0x1E to "GET_USER_DATA",
        0x1F to "SET_FULL_NAME",
        0x20 to "GET_FULL_NAME",
        0x21 to "GET_GENDER",
        0x22 to "SET_GENDER",
        0x24 to "GET_EC_PUB_KEY",
        0x25 to "SIGN_AUTH",
        0x2C to "INITIALIZE",
        0x2E to "IS_CARD_ALIVE",
        0x30 to "SIGN_TRANSFER_V2",
        0x31 to "VERIFY_TRANSFER_V2",
        0x34 to "GET_PERSONALIZATION",
        0x35 to "GET_RECEIVE_STATE",
        0x36 to "GET_LAST_TRANSFER",
        0x37 to "GET_STELLAR_KEY",
        0x38 to "SIGN_SEP10",
        0x39 to "GET_USER_VERIFICATION",
        0x3A to "SET_SIGN_IN_POLICY",
        0x3B to "CHANGE_USER_PIN",
        0x64 to "GET_VERSION",
        // Declared but not dispatched (the applet answers 6D00).
        0x07 to "GET_RSA_PUB_KEY",
        0x23 to "GET_CARD_NONCE",
        0x26 to "SET_CARD_DATA",
        0x2B to "UPDATE_MASTER_PIN",
        0x2D to "SUICIDE",
        // Retired in applet 0.2 (the applet answers 6D00).
        0x06 to "SIGN_TRANSFER",
        0x14 to "VERIFY_TRANSFER",
    )

    private val SECURE_CHANNEL = mapOf(
        0x50 to "INITIALIZE UPDATE",
        0x82 to "EXTERNAL AUTHENTICATE",
        0x70 to "PROVISION_PIN",
        0x71 to "APPLET_UPDATE",
        0x72 to "PERSONALIZE",
        0x73 to "TERMINATE",
    )

    private val STATUS = mapOf(
        0x9000 to "OK",
        0x0000 to "TAG_LOST",
        0x0001 to "STATUS_BROKEN",
        0x0022 to "CERT_VERIFY_FAILED",
        0x0023 to "TRANSFER_SIG_INVALID",
        0x4469 to "UNKNOWN_4469",
        0x6224 to "INSUFFICIENT_FUNDS",
        0x6226 to "WRONG_SIGNABLE_LENGTH",
        0x6227 to "SIGNER_INIT_FAILED",
        0x6229 to "WRONG_CURRENCY",
        0x6230 to "CARD_KEY_MISSING",
        0x6231 to "WRONG_SENDER",
        0x6232 to "WRONG_RECIPIENT",
        0x6233 to "COUNTER_INVALID",
        0x6234 to "NOT_PERSONALIZED",
        0x6235 to "ALREADY_PERSONALIZED",
        0x6236 to "DEFAULT_KEYS",
        0x6237 to "PERSONALIZE_SEQUENCE",
        0x6238 to "SEND_SEQUENCE_INVALID",
        0x6239 to "ZERO_AMOUNT",
        0x623A to "COUNTER_JUMP",
        0x623B to "PROGRAM_BOUND",
        0x623C to "STELLAR_KEY_MISSING",
        0x6240 to "SEP10_MALFORMED",
        0x6241 to "SEP10_SEQUENCE_NOT_ZERO",
        0x6242 to "SEP10_NOT_MANAGE_DATA",
        0x6243 to "SEP10_WRONG_ACCOUNT",
        0x6244 to "SEP10_NOT_AUTH_CHALLENGE",
        0x6245 to "SEP10_NO_TIME_BOUNDS",
        0x6300 to "SCP03_AUTH_FAILED",
        0x6677 to "CERT_SELF_CHECK_FAILED",
        0x6678 to "NONCE_INVALID",
        0x6679 to "WRONG_CARD_ID",
        0x6683 to "CRYPTO_ERROR",
        0x6684 to "INVALID_AES_KEY",
        0x6685 to "PUBKEY_ALREADY_SET",
        0x6686 to "ALREADY_INITIALIZED",
        0x6687 to "TERMINATED",
        0x6688 to "INTERNAL_NULL",
        0x6689 to "INTERNAL_BOUNDS",
        0x6690 to "PIN_REQUIRED",
        0x6691 to "PIN_REJECTED",
        0x6700 to "WRONG_LENGTH",
        0x6982 to "SECURITY_STATUS",
        0x6984 to "DATA_INVALID",
        0x6985 to "CONDITIONS_NOT_SATISFIED",
        0x6999 to "APPLET_SELECT_FAILED",
        0x69C0 to "PIN_BLOCKED",
        0x6A80 to "WRONG_DATA",
        0x6A82 to "APPLET_NOT_FOUND",
        0x6A83 to "RECORD_NOT_FOUND",
        0x6A86 to "WRONG_P1P2",
        0x6C01 to "SET_ACCOUNT_FAILED",
        0x6C02 to "WRONG_TAIL_LENGTH",
        0x6C03 to "NAME_TOO_LONG",
        0x6C04 to "GENDER_TOO_LONG",
        0x6D00 to "INS_NOT_SUPPORTED",
        0x6E00 to "CLA_NOT_SUPPORTED",
        0x6F00 to "UNKNOWN_ERROR",
        0x6F15 to "UNKNOWN_6F15",
    )

    /** The name of [ins] (SELECT, an application command or a secure-channel command), or `INS 0xNN`. */
    fun ins(cla: Int, ins: Int): String {
        val i = ins and 0xFF
        if (i == SELECT_INS && (cla and 0xFF) == 0x00) return "SELECT"
        return APPLICATION[i] ?: SECURE_CHANNEL[i] ?: "INS 0x" + hex(i, 2)
    }

    /** The name of status word [sw] (`69C1`..`69C9` → `WRONG_PIN_<tries>`), or `UNKNOWN`. */
    fun sw(sw: Int): String {
        val s = sw and 0xFFFF
        if (s in 0x69C1..0x69C9) return "WRONG_PIN_" + (s and 0x0F)
        return STATUS[s] ?: "UNKNOWN"
    }

    /** GET_LAST_TRANSFER (`0x36`): answers [SW_RECORD_NOT_FOUND] on a card that has never signed a transfer. */
    private const val GET_LAST_TRANSFER_INS: Int = 0x36

    /** `6A83` RECORD_NOT_FOUND. */
    private const val SW_RECORD_NOT_FOUND: Int = 0x6A83

    /** GET_STELLAR_KEY (`0x37`): answers [SW_STELLAR_KEY_MISSING] on a card without a Stellar key. */
    private const val GET_STELLAR_KEY_INS: Int = 0x37

    /** `623C` STELLAR_KEY_MISSING. */
    private const val SW_STELLAR_KEY_MISSING: Int = 0x623C

    /**
     * True when [sw] is the documented normal answer of a read rather than a
     * failure (`docs/apdu.md`): GET_LAST_TRANSFER's `6A83` on a card that has
     * never signed a transfer, and GET_STELLAR_KEY's `623C` on a card without
     * a Stellar key. Traces and stats show such an exchange as an expected
     * answer, not as a card error.
     */
    fun isExpectedStatus(cla: Int, ins: Int, sw: Int?): Boolean {
        if (sw == null || (cla and 0xFF) != 0x00) return false
        return when (ins and 0xFF) {
            GET_LAST_TRANSFER_INS -> (sw and 0xFFFF) == SW_RECORD_NOT_FOUND
            GET_STELLAR_KEY_INS -> (sw and 0xFFFF) == SW_STELLAR_KEY_MISSING
            else -> false
        }
    }

    /** True only for SELECT and [READ_ONLY_INS] at CLA 0x00 (the read-only session allow-list). */
    fun isReadOnly(cla: Int, ins: Int): Boolean =
        cla == 0x00 && (ins == SELECT_INS || ins in READ_ONLY_INS)

    /** Upper-case hex of [value], zero-padded to [digits] (no `String.format`: commonMain builds for iOS). */
    internal fun hex(value: Int, digits: Int): String = value.toString(16).uppercase().padStart(digits, '0')
}

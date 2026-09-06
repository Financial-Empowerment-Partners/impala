package com.impala.applet;


/**
 * Constants shared across the applet: APDU instruction codes, PIN type identifiers,
 * data size definitions, and status word error codes.
 *
 * This is the number registry for the card protocol (applet 0.2, transfer
 * protocol v1). Every INS / SW / length here is mirrored byte-for-byte in the
 * SDK's Constants.kt and documented in docs/apdu.md; ApduDocDriftTest pins the
 * three together.
 */
public class Constants {
    public static final short INIT_SEED_LENGTH = 4;
    public static final short ZERO = 0;
    public static final short ONE = 1;
    public static final short TWO = 2;

    public static final byte INS_NOP = 2;
    public static final byte INS_GET_BALANCE = 4;
    /** Retired in applet 0.2 (untagged v0 envelope) — declared, never dispatched, never reuse. */
    public static final byte INS_SIGN_TRANSFER = 6;
    public static final byte INS_GET_RSA_PUB_KEY = 7;
    /** Retired in applet 0.2 (untagged v0 envelope) — declared, never dispatched, never reuse. */
    public static final byte INS_VERIFY_TRANSFER = 20;
    public static final byte INS_GET_ACCOUNT_ID = 22;
    public static final byte INS_VERIFY_PIN = 24; // P2=1 for master PIN P1=2 for user_pin
    public static final byte INS_UPDATE_USER_PIN = 25;// set new user PIN
    public static final byte INS_GET_USER_DATA = 30;
    public static final byte INS_SET_FULL_NAME = 31;
    public static final byte INS_GET_FULL_NAME = 32;
    public static final byte INS_GET_GENDER = 33;
    public static final byte INS_SET_GENDER = 34;
    public static final byte INS_GET_CARD_NONCE = 35;
    public static final byte INS_GET_EC_PUB_KEY = 36;
    public static final byte INS_SIGN_AUTH = 37;
    public static final byte INS_SET_CARD_DATA = 38;
    public static final byte INS_UPDATE_MASTER_PIN = 43;
    public static final byte INS_INITIALIZE = 44;
    public static final byte INS_SUICIDE = 45;
    public static final byte INS_IS_CARD_ALIVE = 46;
    public static final byte INS_GET_VERSION = 100;

    // Transfer protocol v1 (applet 0.2). 0x32 / 0x33 are never assigned
    // (historically documented as Set/Get Ext Pubkey; never dispatched).
    public static final byte INS_SIGN_TRANSFER_V2 = (byte) 0x30;     // CLA 0x00 only (209-byte response)
    public static final byte INS_VERIFY_TRANSFER_V2 = (byte) 0x31;   // CLA 0x00 only (209-byte tail)
    public static final byte INS_GET_PERSONALIZATION = (byte) 0x34;  // CLA 0x00 only (159-byte response)
    public static final byte INS_GET_RECEIVE_STATE = (byte) 0x35;    // CLA 0x00 or 0x84
    public static final byte INS_GET_LAST_TRANSFER = (byte) 0x36;    // CLA 0x00 only (132-byte response)

    // SCP03 instruction codes (only dispatched via the secured CLA 0x84 path)
    public static final byte INS_SCP03_PROVISION_PIN = (byte) 0x70;
    public static final byte INS_SCP03_APPLET_UPDATE = (byte) 0x71;
    public static final byte INS_SCP03_PERSONALIZE = (byte) 0x72;    // three parts, C-DEC required
    public static final byte INS_SCP03_TERMINATE = (byte) 0x73;      // C-DEC required

    // PERSONALIZE parts (P1)
    public static final byte P1_PERSONALIZE_IDENTITY = (byte) 0x01;
    public static final byte P1_PERSONALIZE_ISSUER_KEY = (byte) 0x02;
    public static final byte P1_PERSONALIZE_CERTIFICATE = (byte) 0x03;

    // GET_PERSONALIZATION state byte
    public static final byte PERSONALIZATION_STATE_BLANK = (byte) 0x00;
    public static final byte PERSONALIZATION_STATE_INITIALIZED = (byte) 0x01;
    public static final byte PERSONALIZATION_STATE_PERSONALIZED = (byte) 0x02;
    public static final byte PERSONALIZATION_STATE_TERMINATED = (byte) 0xFF;

    // GET_PERSONALIZATION flags byte
    public static final byte PFLAG_INITIALIZED = (byte) 0x01;
    public static final byte PFLAG_PROGRAM_BOUND = (byte) 0x02;
    public static final byte PFLAG_PERSONALIZED = (byte) 0x04;
    public static final byte PFLAG_SCP03_KEYS_DEFAULT = (byte) 0x08;
    public static final byte PFLAG_PIN_PROVISIONED = (byte) 0x10;
    public static final byte PFLAG_PROVISIONING_ENFORCED = (byte) 0x20;
    public static final byte PFLAG_TERMINATED = (byte) 0x40;

    // SCP03 status words
    public static final short SW_SCP03_AUTH_FAILED = (short) 0x6300;

    // PIN type
    public static final byte P2_MASTER_PIN = (byte) 129; // P2 byte for Master PIN in Verify 0x81
    public static final byte P2_USER_PIN = (byte) 130; // P2 byte for User PIN in Verify 0x82

    public static final short INT32_LENGTH = 4;
    public static final short INT64_LENGTH = 8;
    public static final short UUID_LENGTH = 16;

    public static final short HASH_LENGTH = 32;
    public static final short INIT_LENGTH = 56;
    public static final short MAX_SIG_LENGTH = 72;
    public static final short MIN_DER_SIG_LENGTH = 8;
    public static final short PRIV_KEY_LENGTH = 32;
    public static final short PUB_KEY_LENGTH = 65;
    public static final short SIGNABLE_LENGTH = 60;
    public static final short TAG_LENGTH_LENGTH = 2;

    // Transfer protocol v1 lengths / versions
    public static final short PROGRAM_ID_LENGTH = 16;
    public static final short CURRENCY_LENGTH = 4;
    public static final short DOMAIN_TAG_LENGTH = 12;
    public static final short XFER_MESSAGE_LENGTH = 89;      // tag(12) ‖ version(1) ‖ programId(16) ‖ signable(60)
    public static final short CERT_MESSAGE_LENGTH = 114;     // tag(12) ‖ version(1) ‖ programId(16) ‖ accountId(16) ‖ currency(4) ‖ pubkey(65)
    public static final short PERSONALIZE_IDENTITY_LENGTH = 40; // accountId(16) ‖ currency(4) ‖ programId(16) ‖ initialReceiveCounter(4)
    public static final short PERSONALIZE_STAGE_LENGTH = 177;   // identity(40) ‖ issuerPubKey(65) ‖ spare
    public static final short PERSONALIZATION_LENGTH = 159;  // state(1) ‖ flags(1) ‖ programId(16) ‖ currency(4) ‖ issuerPubKey(65) ‖ cardCert(72)
    public static final short RECEIVE_STATE_LENGTH = 36;     // lastReceiveCounter(4) ‖ lastReceiveDigest(32)
    public static final short LAST_TRANSFER_LENGTH = 132;    // lastSentSignable(60) ‖ lastSentSig(72)
    public static final short TRANSFER_RESPONSE_LENGTH = 209; // sig(72) ‖ pubkey(65) ‖ cardCert(72)
    public static final short PROGRAM_BLOCK_LENGTH = 81;     // install TLV: programId(16) ‖ issuerPubKey(65)
    public static final short KEY_DIVERSIFICATION_LENGTH = 10;
    public static final byte TRANSFER_PROTOCOL_VERSION = (byte) 0x01;
    public static final byte CERT_VERSION = (byte) 0x01;
    public static final short MAX_COUNTER_JUMP = (short) 1024;

    public static final short SW_OK = (short) 0x9000;
    public static final short SW_INS_NOT_SUPPORTED = 0x6d00;
    public static final short SW_ERROR_KEY_VERIFICATION_FAILED = 0x0022;
    public static final short SW_ERROR_SIGNATURE_VERIFICATION_FAILED = 0x0023;
    public static final short SW_INCORRECT_P1P2 = 0x6a86;
    public static final short SW_SET_BALANCE_FAILED = 0x6C02;
    public static final short SW_SET_ACCOUNT_ID_FAILED = 0x6C01;
    public static final short SW_PIN_FAILED_NO_TRIES_LEFT = 0x69C0;
    public static final short SW_PIN_FAILED_1_TRIES_LEFT = 0x69C1;
    public static final short SW_PIN_FAILED_2_TRIES_LEFT = 0x69C2;
    public static final short SW_PIN_FAILED_3_TRIES_LEFT = 0x69C3;
    public static final short SW_PIN_FAILED_4_TRIES_LEFT = 0x69C4;
    public static final short SW_PIN_FAILED_5_TRIES_LEFT = 0x69c5;
    public static final short SW_PIN_FAILED_6_TRIES_LEFT = 0x69c6;
    public static final short SW_PIN_FAILED_7_TRIES_LEFT = 0x69c7;
    public static final short SW_PIN_FAILED_8_TRIES_LEFT = 0x69c8;
    public static final short SW_PIN_FAILED_9_TRIES_LEFT = 0x69c9;
    public static final short SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    public static final short SW_WRONG_LENGTH = 0x6700;
    public static final short SW_INSUFFICIENT_FUNDS = 0x6224;
    public static final short SW_ERROR_PARSING_RECIPIENT = 0x6226;
    public static final short SW_ERROR_INIT_SIGNER = 0x6227;
    public static final short SW_ERROR_WRONG_CURRENCY = 0x6229;
    public static final short SW_ERROR_EC_CARD_KEY_MISSING = 0x6230;
    public static final short SW_ERROR_WRONG_SENDER = 0x6231;
    public static final short SW_ERROR_WRONG_RECIPIENT = 0x6232;
    public static final short SW_ERROR_TRANSFER_COUNTER_INVALID = 0x6233;
    public static final short SW_ERROR_NOT_PERSONALIZED = 0x6234;
    public static final short SW_ERROR_ALREADY_PERSONALIZED = 0x6235;
    public static final short SW_ERROR_DEFAULT_SCP03_KEYS = 0x6236;
    public static final short SW_ERROR_PERSONALIZE_SEQUENCE = 0x6237;
    public static final short SW_ERROR_SEND_SEQUENCE_INVALID = 0x6238;
    public static final short SW_ERROR_ZERO_AMOUNT = 0x6239;
    public static final short SW_ERROR_TRANSFER_COUNTER_JUMP = 0x623A;
    public static final short SW_ERROR_PROGRAM_ALREADY_BOUND = 0x623B;
    public static final short SW_ERROR_CARD_DATA_SIGNATURE_INVALID = 0x6677;
    public static final short SW_ERROR_CARD_DATA_NONCE_INVALID = 0x6678;
    public static final short SW_ERROR_WRONG_CARD_ID = 0x6679;
    public static final short SW_ERROR_CRYPTO_EXCEPTION = 0x6683;
    public static final short SW_ERROR_INVALID_AES_KEY = 0x6684;
    public static final short SW_ERROR_PUB_KEY_ALREADY_SET = 0x6685;
    public static final short SW_ERROR_PRNG_ALREADY_SEEDED = 0x6686;
    public static final short SW_ERROR_CARD_TERMINATED = 0x6687;
    public static final short SW_ERROR_NULL_POINTER_EXCEPTION = 0x6688;
    public static final short SW_ERROR_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION = 0x6689;
    public static final short SW_ERROR_PIN_REQUIRED = 0x6690;
    public static final short SW_ERROR_PIN_REJECTED = 0x6691;
    public static final short SW_SET_FULL_NAME_FAILED = 0x6C03;
    public static final short SW_SET_GENDER_FAILED = 0x6C04;
    public static final short SW_ERROR_WRONG_SIGNABLE_LENGTH = 0x6226;
    public static final short SW_ERROR_WRONG_TAIL_LENGTH = 0x6C02;
    public static final short SW_ERROR_ALREADY_INITIALIZED = 0x6686;
    // ISO 7816-4 words the applet throws (javacard.framework.ISO7816 values)
    public static final short SW_WRONG_DATA = 0x6A80;
    public static final short SW_DATA_INVALID = 0x6984;
    public static final short SW_RECORD_NOT_FOUND = 0x6A83;
    public static final short SW_CLA_NOT_SUPPORTED = 0x6E00;
    public static final short SW_UNKNOWN = 0x6F00;
    public static final short SW_UNKNOWN_4469 = 0x4469;
    public static final short SW_UNKNOWN_6F15 = 0x6F15;
    public static final short TAG_LOST = 0x0000;
    public static final short SW_ERROR_STATUS_BROKEN = 0x0001;
}

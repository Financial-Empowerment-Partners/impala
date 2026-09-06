package com.impala.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;

import static com.impala.applet.ArrayUtil.isNegative;
import static com.impala.applet.BuildConfig.GIT_HASH_SHORT;
import static com.impala.applet.BuildConfig.GIT_REV_LIST;
import static com.impala.applet.BuildConfig.MAJOR_VERSION;
import static com.impala.applet.BuildConfig.MINOR_VERSION;
import static com.impala.applet.Constants.CERT_MESSAGE_LENGTH;
import static com.impala.applet.Constants.CERT_VERSION;
import static com.impala.applet.Constants.CURRENCY_LENGTH;
import static com.impala.applet.Constants.DOMAIN_TAG_LENGTH;
import static com.impala.applet.Constants.HASH_LENGTH;
import static com.impala.applet.Constants.INS_GET_ACCOUNT_ID;
import static com.impala.applet.Constants.INS_GET_BALANCE;
import static com.impala.applet.Constants.INS_GET_EC_PUB_KEY;
import static com.impala.applet.Constants.INS_GET_FULL_NAME;
import static com.impala.applet.Constants.INS_GET_GENDER;
import static com.impala.applet.Constants.INS_GET_LAST_TRANSFER;
import static com.impala.applet.Constants.INS_GET_PERSONALIZATION;
import static com.impala.applet.Constants.INS_GET_RECEIVE_STATE;
import static com.impala.applet.Constants.INS_GET_USER_DATA;
import static com.impala.applet.Constants.INS_GET_VERSION;
import static com.impala.applet.Constants.INS_INITIALIZE;
import static com.impala.applet.Constants.INS_IS_CARD_ALIVE;
import static com.impala.applet.Constants.INS_NOP;
import static com.impala.applet.Constants.INS_SCP03_APPLET_UPDATE;
import static com.impala.applet.Constants.INS_SCP03_PERSONALIZE;
import static com.impala.applet.Constants.INS_SCP03_PROVISION_PIN;
import static com.impala.applet.Constants.INS_SCP03_TERMINATE;
import static com.impala.applet.Constants.INS_SET_FULL_NAME;
import static com.impala.applet.Constants.INS_SET_GENDER;
import static com.impala.applet.Constants.INS_SIGN_AUTH;
import static com.impala.applet.Constants.INS_SIGN_TRANSFER_V2;
import static com.impala.applet.Constants.INS_UPDATE_USER_PIN;
import static com.impala.applet.Constants.INS_VERIFY_PIN;
import static com.impala.applet.Constants.INS_VERIFY_TRANSFER_V2;
import static com.impala.applet.Constants.INT32_LENGTH;
import static com.impala.applet.Constants.INT64_LENGTH;
import static com.impala.applet.Constants.LAST_TRANSFER_LENGTH;
import static com.impala.applet.Constants.MAX_COUNTER_JUMP;
import static com.impala.applet.Constants.MAX_SIG_LENGTH;
import static com.impala.applet.Constants.MIN_DER_SIG_LENGTH;
import static com.impala.applet.Constants.P1_PERSONALIZE_CERTIFICATE;
import static com.impala.applet.Constants.P1_PERSONALIZE_IDENTITY;
import static com.impala.applet.Constants.P1_PERSONALIZE_ISSUER_KEY;
import static com.impala.applet.Constants.P2_MASTER_PIN;
import static com.impala.applet.Constants.P2_USER_PIN;
import static com.impala.applet.Constants.PERSONALIZATION_LENGTH;
import static com.impala.applet.Constants.PERSONALIZATION_STATE_BLANK;
import static com.impala.applet.Constants.PERSONALIZATION_STATE_INITIALIZED;
import static com.impala.applet.Constants.PERSONALIZATION_STATE_PERSONALIZED;
import static com.impala.applet.Constants.PERSONALIZATION_STATE_TERMINATED;
import static com.impala.applet.Constants.PERSONALIZE_IDENTITY_LENGTH;
import static com.impala.applet.Constants.PERSONALIZE_STAGE_LENGTH;
import static com.impala.applet.Constants.PFLAG_INITIALIZED;
import static com.impala.applet.Constants.PFLAG_PERSONALIZED;
import static com.impala.applet.Constants.PFLAG_PIN_PROVISIONED;
import static com.impala.applet.Constants.PFLAG_PROGRAM_BOUND;
import static com.impala.applet.Constants.PFLAG_PROVISIONING_ENFORCED;
import static com.impala.applet.Constants.PFLAG_SCP03_KEYS_DEFAULT;
import static com.impala.applet.Constants.PFLAG_TERMINATED;
import static com.impala.applet.Constants.PROGRAM_BLOCK_LENGTH;
import static com.impala.applet.Constants.PROGRAM_ID_LENGTH;
import static com.impala.applet.Constants.PUB_KEY_LENGTH;
import static com.impala.applet.Constants.RECEIVE_STATE_LENGTH;
import static com.impala.applet.Constants.SIGNABLE_LENGTH;
import static com.impala.applet.Constants.SW_ERROR_ALREADY_PERSONALIZED;
import static com.impala.applet.Constants.SW_ERROR_CRYPTO_EXCEPTION;
import static com.impala.applet.Constants.SW_ERROR_DEFAULT_SCP03_KEYS;
import static com.impala.applet.Constants.SW_ERROR_INVALID_AES_KEY;
import static com.impala.applet.Constants.SW_ERROR_KEY_VERIFICATION_FAILED;
import static com.impala.applet.Constants.SW_ERROR_NOT_PERSONALIZED;
import static com.impala.applet.Constants.SW_ERROR_PERSONALIZE_SEQUENCE;
import static com.impala.applet.Constants.SW_ERROR_PROGRAM_ALREADY_BOUND;
import static com.impala.applet.Constants.SW_ERROR_SEND_SEQUENCE_INVALID;
import static com.impala.applet.Constants.SW_ERROR_TRANSFER_COUNTER_INVALID;
import static com.impala.applet.Constants.SW_ERROR_TRANSFER_COUNTER_JUMP;
import static com.impala.applet.Constants.SW_ERROR_ZERO_AMOUNT;
import static com.impala.applet.Constants.TAG_LENGTH_LENGTH;
import static com.impala.applet.Constants.TRANSFER_PROTOCOL_VERSION;
import static com.impala.applet.Constants.TRANSFER_RESPONSE_LENGTH;
import static com.impala.applet.Constants.UUID_LENGTH;
import static com.impala.applet.Constants.XFER_MESSAGE_LENGTH;
import static com.impala.applet.Constants.ZERO;

/**
 * Main JavaCard applet for the Impala payment card (applet 0.2, transfer
 * protocol v1).
 *
 * <p>Handles APDU commands for account management, PIN verification, the
 * issuer-certified offline transfer protocol (SIGN_TRANSFER_V2 /
 * VERIFY_TRANSFER_V2), personalization over SCP03, and card lifecycle.</p>
 *
 * <p>Target property: after personalization, a card signs nothing without an
 * issuer-certified identity, credits nothing that is not signed by an
 * issuer-certified key of the same program bound to the signable's sender and
 * currency, and no command reachable with card-management (SCP03) keys can
 * alter that trust root.</p>
 */
public class ImpalaApplet extends Applet {
    // --- Status word constants for APDU error responses (applet-local names;
    //     the cross-stream registry is Constants.java / docs/apdu.md) ---
    public static final short SW_ERROR_SIGNATURE_VERIFICATION_FAILED = 0x0023;
    public static final short SW_INSUFFICIENT_FUNDS = 0x6224;
    public static final short SW_ERROR_WRONG_SIGNABLE_LENGTH = 0x6226;
    public static final short SW_ERROR_INIT_SIGNER = 0x6227;
    public static final short SW_ERROR_EC_CARD_KEY_MISSING = 0x6230;
    public static final short SW_ERROR_WRONG_SENDER = 0x6231;
    public static final short SW_ERROR_WRONG_RECIPIENT = 0x6232;
    public static final short SW_WRONG_PIN_CARD_BLOCKED = 0x6201;
    public static final short SW_WRONG_PIN_TWO_RETRIES_LEFT = 0x6302;
    public static final short SW_WRONG_PIN_ONE_RETRY_LEFT = 0x6301;
    public static final short SW_ERROR_WRONG_TAIL_LENGTH = 0x6C02;
    public static final short SW_SET_FULL_NAME_FAILED = 0x6C03;
    public static final short SW_SET_GENDER_FAILED = 0x6C04;
    public static final short SW_PIN_FAILED = 0x69C0; // SW bytes for PIN Failed condition
    public static final short SW_ERROR_ALREADY_INITIALIZED = 0x6686;
    public static final short SW_ERROR_CARD_TERMINATED = 0x6687;
    public static final short SW_ERROR_NULL_POINTER_EXCEPTION = 0x6688;
    public static final short SW_ERROR_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION = 0x6689;
    public static final short SW_ERROR_PIN_REQUIRED = 0x6690;
    public static final short SW_ERROR_PIN_REJECTED = 0x6691;

    private static final byte USER_PIN_LENGTH = 4;
    private static final byte MASTER_PIN_LENGTH = 8;
    // In SIGN_TRANSFER_V2, the signable data starts after the 4-byte user PIN
    private static final short OFFSET_SIGNABLE = ISO7816.OFFSET_CDATA + USER_PIN_LENGTH;

    private static final short MAX_PINLESS_TRANSFERS = 4; // max consecutive transfers without PIN
    private static final short MAX_FULL_NAME_LENGTH = 128;
    private static final short MAX_GENDER_LENGTH = 16;

    // --- Domain separation tags (pinned cross-stream contracts) ---
    // ASCII "IMPALA-AUTH:" — must match CARD_AUTH_DOMAIN_PREFIX in
    // impala-bridge/src/constants.rs. The bridge /auth/card verifier checks
    // ECDSA-SHA256 over AUTH_DOMAIN_TAG || accountId(16) || challenge(8..=64).
    private static final byte[] AUTH_DOMAIN_TAG = {
            (byte) 0x49, (byte) 0x4D, (byte) 0x50, (byte) 0x41, // "IMPA"
            (byte) 0x4C, (byte) 0x41, (byte) 0x2D, (byte) 0x41, // "LA-A"
            (byte) 0x55, (byte) 0x54, (byte) 0x48, (byte) 0x3A  // "UTH:"
    };
    // ASCII "IMPALA-XFER:" — the transfer message a card signs is
    // XFER_DOMAIN_TAG || 0x01 || programId(16) || signable(60) (89 bytes).
    private static final byte[] XFER_DOMAIN_TAG = {
            (byte) 0x49, (byte) 0x4D, (byte) 0x50, (byte) 0x41, // "IMPA"
            (byte) 0x4C, (byte) 0x41, (byte) 0x2D, (byte) 0x58, // "LA-X"
            (byte) 0x46, (byte) 0x45, (byte) 0x52, (byte) 0x3A  // "FER:"
    };
    // ASCII "IMPALA-CERT:" — the certificate message an issuer signs is
    // CERT_DOMAIN_TAG || 0x01 || programId(16) || accountId(16) || currency(4) || cardPubKey(65) (114 bytes).
    private static final byte[] CERT_DOMAIN_TAG = {
            (byte) 0x49, (byte) 0x4D, (byte) 0x50, (byte) 0x41, // "IMPA"
            (byte) 0x4C, (byte) 0x41, (byte) 0x2D, (byte) 0x43, // "LA-C"
            (byte) 0x45, (byte) 0x52, (byte) 0x54, (byte) 0x3A  // "ERT:"
    };
    private static final short AUTH_DOMAIN_TAG_LENGTH = 12;
    private static final short MIN_AUTH_CHALLENGE_LENGTH = 8;
    private static final short MAX_AUTH_CHALLENGE_LENGTH = 64;

    // --- Install-parameter TLV (the applet data / GP "C9" parameter value) ---
    // [TAG_INSTALL_PROVISIONING][flags]
    //   [ENC(16) | MAC(16) | DEK(16)      if flags & FLAG_INSTALL_KEYS]
    //   [masterPIN(8) | userPIN(4)        if flags & FLAG_INSTALL_PINS]
    //   [programId(16) | issuerPubKey(65) if flags & FLAG_INSTALL_PROGRAM (requires FLAG_INSTALL_KEYS)]
    private static final byte TAG_INSTALL_PROVISIONING = (byte) 0x01;
    private static final byte FLAG_INSTALL_ENFORCE = (byte) 0x01;
    private static final byte FLAG_INSTALL_KEYS = (byte) 0x02;
    private static final byte FLAG_INSTALL_PINS = (byte) 0x04;
    private static final byte FLAG_INSTALL_PROGRAM = (byte) 0x08;
    private static final short SCP03_KEY_SET_LENGTH = 48;
    private static final short INSTALL_PIN_BLOCK_LENGTH = 12;

    // GlobalPlatform test key 0x40..0x4F (gp-master.jar default). Installed by
    // the constructor; refused as an install / APPLET_UPDATE key value so a
    // personalized card can never run on it. NOTE: this flag is a policy
    // tripwire, not a cryptographic barrier — whoever holds the current SCP03
    // keys can rotate them.
    private static final byte[] DEFAULT_SCP03_KEY = {
            (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43,
            (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
            (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B,
            (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x4F
    };

    // Maximum amount (200 in lowest denomination) allowed for PIN-less transfers
    private static final byte[] PINLESS_LIMIT = new byte[] {
            0, 0, 0, 0, 0, 0, 0, (byte) 0xc8
    };

    private static final byte[] FOUR_ZERO_PIN = new byte[] {
            0, 0, 0, 0
    };

    // --- Cryptographic engines ---
    private MessageDigest messageDigest; // SHA-256 for the transfer id digest
    private RandomData randomData;     // Secure RNG for card ID and SCP03 challenges
    private Signature signer;          // ECDSA-SHA256 signing with card key
    private Signature verifier;        // ECDSA-SHA256 verification (issuer key, sender key)

    // --- Card lifecycle state ---
    private boolean initialized;       // True after INS_INITIALIZE generates keys
    private boolean personalized;      // True after PERSONALIZE part C commits (LAST write of that transaction)
    private boolean terminated;        // True after TERMINATE; card becomes inoperable (irreversible)

    // --- Account and balance data (persisted in EEPROM) ---
    private byte[] accountId;          // 16-byte UUID linking to Payala account (PERSONALIZE part A)
    private byte[] cardId;             // 16-byte UUID unique to this card, randomly generated
    private byte[] currency;           // 4-byte currency code (PERSONALIZE part A)
    private byte[] myBalance;          // 8-byte (int64) on-card balance in lowest denomination
    private byte[] lastReceiveCounter; // 4-byte last accepted incoming-transfer counter (replay guard)
    private byte[] lastReceiveDigest;  // 32-byte SHA-256 of the last accepted XFER message (= transfer id)

    // --- Program / issuer trust root (immutable once personalized) ---
    private byte[] programId;          // 16-byte issuer-allocated program id
    private ECPublicKey issuerPubKey;  // program (issuer) public key — THE receive-side trust root
    private boolean programBound;      // programId + issuerPubKey set (install flag 0x08 or PERSONALIZE part C)
    private byte[] cardCert;           // 72-byte slot: issuer's DER signature over this card's CERT message

    // --- Send-side idempotency record ---
    private byte[] lastSentSignable;   // 60 bytes; [0..8) is the send sequence; sender all-zero == never sent
    private byte[] lastSentSig;        // 72-byte slot: DER signature of the last committed debit

    // --- Cryptographic keys ---
    private ECPrivateKey cardECPrivateKey;   // Card's EC private key (secp256r1) for signing
    private ECPublicKey cardECPublicKey;     // Card's EC public key (secp256r1)

    // --- Cardholder data ---
    private byte[] fullName;
    private short fullNameLength;
    private byte[] gender;
    private short genderLength;
    private OwnerPIN masterPIN;        // Administrative PIN (10 retries, 8 digits)
    private OwnerPIN userPIN;          // Cardholder PIN (5 retries, 4 digits)
    private byte howManyPINless;       // Counter for consecutive PIN-less transfers

    // --- Install-time provisioning policy ---
    private boolean provisioningEnforced; // FLAG_INSTALL_ENFORCE: gate signing until a user PIN is provisioned
    private boolean pinProvisioned;       // set by install-time PIN injection or SCP03 PROVISION_PIN
    private boolean scp03KeysCustom;      // static SCP03 keys are not the GP defaults (install keys or APPLET_UPDATE)

    // --- Transient working buffers ---
    private byte[] scratchpad;         // General-purpose transient buffer (255 bytes, CLEAR_ON_RESET)
    private byte[] sigBuffer;          // Holds signature output from signing operations
    private byte[] signableBuffer;     // Holds signable data during two-phase verify
    private byte[] tempAmount;         // Temporary buffer for parsed transaction amount
    private byte[] tempCounter;        // Temporary buffer for parsed transaction counter
    private byte[] tempLimit;          // Counter bound arithmetic (L + MAX_COUNTER_JUMP)
    private byte[] tempBalance;        // Overflow-checked credit computed BEFORE the transaction
    private byte[] hashBuffer;         // SHA-256 output
    private ECPublicKey tempPubKey;    // Reusable EC public key for transfer / certificate verification
    private byte[] personalizeStage;   // PERSONALIZE parts A(40)@0 and B(65)@40, staged across APDUs (CLEAR_ON_DESELECT)
    private byte[] stageState;         // bit0 = part A received, bit1 = part B received (CLEAR_ON_DESELECT)
    private byte[] verifyStage;        // 1 after a successful VERIFY_TRANSFER_V2 P1=0x00 (CLEAR_ON_DESELECT)

    // --- SCP03 secure channel ---
    private SCP03 scp03;

    /**
     * Private constructor called during applet installation.
     * Initializes all crypto engines, allocates persistent and transient buffers,
     * sets default PINs, and generates a random card ID.
     */
    private ImpalaApplet(byte[] bArray, short bOffset, byte bLength) {
        messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        verifier = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        initialized = false;
        personalized = false;
        terminated = false;

        accountId = new byte[UUID_LENGTH];
        cardId = new byte[UUID_LENGTH];

        randomData.generateData(cardId, ZERO, UUID_LENGTH);

        currency = new byte[CURRENCY_LENGTH];
        myBalance = new byte[INT64_LENGTH];
        lastReceiveCounter = new byte[INT32_LENGTH];
        lastReceiveDigest = new byte[HASH_LENGTH];

        programId = new byte[PROGRAM_ID_LENGTH];
        issuerPubKey = SecP256r1.newPubKey();
        programBound = false;
        cardCert = new byte[MAX_SIG_LENGTH];

        lastSentSignable = new byte[SIGNABLE_LENGTH];
        lastSentSig = new byte[MAX_SIG_LENGTH];

        cardECPrivateKey = null;
        cardECPublicKey = null;

        fullName = new byte[MAX_FULL_NAME_LENGTH];
        fullNameLength = 0;
        gender = new byte[MAX_GENDER_LENGTH];
        genderLength = 0;
        masterPIN = new OwnerPIN((byte) 10, (byte) 8); // retries:10 and length:8
        masterPIN.update(new byte[] { 1, 4, 1, 1, 7, 2, 9, 8 }, ZERO, (byte) 8);
        userPIN = new OwnerPIN((byte) 5, (byte) 5); // retries:5 and length:5
        userPIN.update(new byte[] { 1, 1, 1, 1 }, ZERO, USER_PIN_LENGTH);
        howManyPINless = 0;
        provisioningEnforced = false;
        pinProvisioned = false;
        scp03KeysCustom = false;

        scratchpad = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        sigBuffer = JCSystem.makeTransientByteArray(MAX_SIG_LENGTH, JCSystem.CLEAR_ON_RESET);
        signableBuffer = JCSystem.makeTransientByteArray(SIGNABLE_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempAmount = JCSystem.makeTransientByteArray(INT64_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempCounter = JCSystem.makeTransientByteArray(INT32_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempLimit = JCSystem.makeTransientByteArray(INT32_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempBalance = JCSystem.makeTransientByteArray(INT64_LENGTH, JCSystem.CLEAR_ON_RESET);
        hashBuffer = JCSystem.makeTransientByteArray(HASH_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempPubKey = SecP256r1.newPubKey();
        personalizeStage = JCSystem.makeTransientByteArray(PERSONALIZE_STAGE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        stageState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        verifyStage = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        // SCP03 secure channel — default static keys (matches gp-master.jar defaults: 0x40..0x4F).
        // INITIALIZE UPDATE reports cardId[0..10) as key diversification data; the
        // reference stays valid because INITIALIZE regenerates cardId in place.
        scp03 = new SCP03(randomData);
        scp03.setDiversificationSource(cardId);
        scp03.setStaticKeys(DEFAULT_SCP03_KEY, ZERO, DEFAULT_SCP03_KEY, ZERO, DEFAULT_SCP03_KEY, ZERO);

        // Install parameters may override the SCP03 keys / PINs, bind the program
        // and enable the provisioning gate. Throws on malformed input, failing the
        // install cleanly before register() — never with partially-applied state.
        applyInstallParameters(bArray, bOffset, bLength);

        register();
    }

    /**
     * Installs this applet.
     *
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ImpalaApplet(bArray, bOffset, bLength);
    }

    /**
     * Called by the JCRE to inform this applet that it has been selected.
     *
     * @return If this method returns false, it indicates to the JCRE
     *         that this Applet declines to be selected.
     */
    @Override
    public boolean select() {
        return true;
    }

    /**
     * Performs the session finalization.
     */
    @Override
    public void deselect() {
        userPIN.reset();
        masterPIN.reset();
        // Tear down SCP03 secure channel
        scp03.reset();
    }

    /**
     * Processes an incoming APDU.
     *
     * <p><b>Access control requirements per INS code:</b></p>
     * <ul>
     *   <li><b>No auth required (public reads):</b>
     *       INS_NOP (0x02), INS_GET_BALANCE (0x04), INS_GET_ACCOUNT_ID (0x16),
     *       INS_GET_VERSION (0x64), INS_GET_EC_PUB_KEY (0x24, 0x6230 before INITIALIZE),
     *       INS_GET_FULL_NAME (0x20), INS_GET_GENDER (0x21), INS_GET_USER_DATA (0x1E),
     *       INS_GET_PERSONALIZATION (0x34), INS_GET_RECEIVE_STATE (0x35),
     *       INS_GET_LAST_TRANSFER (0x36) — readable in every state, TERMINATED included</li>
     *   <li><b>Card must not be terminated:</b>
     *       INS_INITIALIZE (0x2C), INS_VERIFY_PIN (0x18), INS_SET_FULL_NAME (0x1F),
     *       INS_SET_GENDER (0x22), INS_SIGN_AUTH (0x25), INS_SIGN_TRANSFER_V2 (0x30),
     *       INS_VERIFY_TRANSFER_V2 (0x31), INS_UPDATE_USER_PIN (0x19), INS_IS_CARD_ALIVE (0x2E),
     *       and every SCP03 command</li>
     *   <li><b>Card must be personalized (0x6234 otherwise):</b>
     *       INS_SIGN_AUTH, INS_SIGN_TRANSFER_V2, INS_VERIFY_TRANSFER_V2</li>
     *   <li><b>CLA 0x00 only (0x6E00 when secured):</b>
     *       INS_SIGN_TRANSFER_V2, INS_VERIFY_TRANSFER_V2, INS_GET_PERSONALIZATION,
     *       INS_GET_LAST_TRANSFER — their payloads do not fit the SCP03 wrap</li>
     *   <li><b>Master PIN required:</b>
     *       INS_UPDATE_USER_PIN (0x19) — masterPIN.isValidated()</li>
     *   <li><b>User PIN required (or PIN-less within limits):</b>
     *       INS_SIGN_TRANSFER_V2 (0x30) — userPIN verified via validatePIN() or isPINlessEligible()</li>
     *   <li><b>SCP03 secure channel required (CLA 0x84, C-MAC wrapped):</b>
     *       INS_SCP03_PROVISION_PIN (0x70), INS_SCP03_APPLET_UPDATE (0x71),
     *       INS_SCP03_PERSONALIZE (0x72, C-DEC required), INS_SCP03_TERMINATE (0x73, C-DEC required)
     *       — only reachable through scp03.unwrapCommand(); the plain CLA 0x80
     *       dispatch path was removed (per-command MACs are mandatory).
     *       PERSONALIZE / TERMINATE (and PROVISION_PIN under ENFORCE) are refused
     *       over the GP default keys (0x6236)</li>
     *   <li><b>Provisioning gate (install-time FLAG_INSTALL_ENFORCE):</b>
     *       INS_SIGN_TRANSFER_V2 (0x30), INS_SIGN_AUTH (0x25) answer 0x6985 until
     *       a user PIN has been provisioned</li>
     * </ul>
     *
     * @param apdu the incoming APDU
     * @throws ISOException with the response bytes per ISO 7816-4
     * @see APDU
     */
    @Override
    public void process(APDU apdu) {
        try {
            if (apdu.isISOInterindustryCLA()) {
                if (this.selectingApplet()) {
                    return;
                }
            }

            byte[] buffer = apdu.getBuffer();
            short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xff);

            // --- SCP03 dispatch (CLA 0x80 = GP plain, CLA 0x84 = GP secured) ---
            byte cla = buffer[ISO7816.OFFSET_CLA];
            byte ins = buffer[ISO7816.OFFSET_INS];

            scp03.clearSecuredCommand();

            if (cla == (byte) 0x80) {
                // GlobalPlatform channel setup. PROVISION_PIN / APPLET_UPDATE /
                // PERSONALIZE / TERMINATE are deliberately NOT dispatched here:
                // without per-command C-MACs the plain CLA 0x80 path would accept
                // unauthenticated payloads on an open session — they are only
                // reachable via the secured CLA 0x84 path below.
                switch (ins) {
                    case (byte) 0x50: { // INITIALIZE UPDATE
                        // A new SCP03 session discards half-staged PERSONALIZE / VERIFY state
                        stageState[0] = 0;
                        verifyStage[0] = 0;
                        apdu.setIncomingAndReceive();
                        short respLen = scp03.processInitializeUpdate(buffer, ISO7816.OFFSET_CDATA, dataLength);
                        sendBytes(apdu, buffer, ZERO, respLen);
                        return;
                    }
                    case (byte) 0x82: { // EXTERNAL AUTHENTICATE
                        apdu.setIncomingAndReceive();
                        scp03.processExternalAuthenticate(buffer, ISO7816.OFFSET_CDATA, dataLength,
                                buffer[ISO7816.OFFSET_P1]);
                        return;
                    }
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        return;
                }
            }

            if (cla == (byte) 0x84) {
                apdu.setIncomingAndReceive();
                if (ins == (byte) 0x82) {
                    // EXTERNAL AUTHENTICATE arrives with the secured CLA (its C-MAC
                    // is verified inside processExternalAuthenticate, not unwrapped)
                    scp03.processExternalAuthenticate(buffer, ISO7816.OFFSET_CDATA, dataLength,
                            buffer[ISO7816.OFFSET_P1]);
                    return;
                }
                // Secured APDU — unwrap, then fall through to normal dispatch
                dataLength = scp03.unwrapCommand(buffer, ISO7816.OFFSET_CDATA, dataLength);
                if (ins == INS_SCP03_PROVISION_PIN) {
                    failIfCardIsTerminated();
                    processProvisionPIN(buffer, dataLength);
                    return;
                }
                if (ins == INS_SCP03_APPLET_UPDATE) {
                    failIfCardIsTerminated();
                    processAppletUpdate(buffer, dataLength);
                    return;
                }
                if (ins == INS_SCP03_PERSONALIZE) {
                    failIfCardIsTerminated();
                    processPersonalize(buffer, dataLength);
                    return;
                }
                if (ins == INS_SCP03_TERMINATE) {
                    failIfCardIsTerminated();
                    processTerminate(buffer, dataLength);
                    return;
                }
            } else if (dataLength > 0) {
                // Plain command: receive the data field once, here, for every INS.
                // On a physical card only the header is guaranteed in the buffer
                // before this call; calling it twice throws APDUException, so no
                // handler below may call it again.
                short received = apdu.setIncomingAndReceive();
                if (received < dataLength) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
            }

            // --- Standard INS dispatch (CLA 0x00 or unwrapped CLA 0x84) ---
            switch (ins) {
                case INS_INITIALIZE: {
                    failIfCardIsTerminated();
                    if (!initialized) {
                        // Host-provided entropy only SUPPLEMENTS this RandomData
                        // instance (per the JavaCard spec, setSeed on a secure RNG
                        // mixes seed material in — a malicious host cannot reduce
                        // its entropy). It influences only cardId generation and
                        // SCP03 card challenges; EC keypair generation below does
                        // NOT consume it (see createECKeypair).
                        randomData.setSeed(buffer, ISO7816.OFFSET_CDATA, dataLength);

                        randomData.generateData(cardId, ZERO, UUID_LENGTH);

                        createECKeypair();

                        initialized = true;
                    } else {
                        ISOException.throwIt(SW_ERROR_ALREADY_INITIALIZED);
                    }
                    break;
                }
                case INS_UPDATE_USER_PIN: {
                    failIfCardIsTerminated();
                    if (masterPIN.isValidated()) {
                        processUpdateUserPIN(buffer, dataLength);
                    } else {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // 0x6985
                    }
                    break;
                }
                case INS_VERIFY_PIN: {
                    failIfCardIsTerminated();
                    processVerifyPIN(buffer, dataLength);
                    break;
                }
                case INS_NOP: {
                    break;
                }
                case INS_GET_BALANCE: {
                    sendBytes(apdu, myBalance, ZERO, INT64_LENGTH);
                    break;
                }
                case INS_GET_ACCOUNT_ID: {
                    sendBytes(apdu, accountId, ZERO, UUID_LENGTH);
                    break;
                }
                case INS_GET_VERSION: {
                    sendVersion(apdu);
                    break;
                }
                case INS_SIGN_AUTH: {
                    failIfCardIsTerminated();
                    failIfProvisioningRequired();
                    failIfNotPersonalized();
                    signAuth(apdu, buffer, dataLength);
                    break;
                }
                case INS_SIGN_TRANSFER_V2: {
                    failIfSecured();
                    failIfCardIsTerminated();
                    failIfProvisioningRequired();
                    failIfNotPersonalized();
                    if (dataLength != (short) (USER_PIN_LENGTH + SIGNABLE_LENGTH)) {
                        ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH); // 0x6226
                    }
                    // Idempotent retry: a byte-identical signable to the last committed
                    // debit replays the identical 209 bytes — no PIN check, no debit,
                    // no PIN-less budget burn (torn-response recovery).
                    if (!isAllZero(lastSentSignable, TransactionParser.OFFSET_SENDER, UUID_LENGTH)
                            && Util.arrayCompare(buffer, OFFSET_SIGNABLE,
                                    lastSentSignable, ZERO, SIGNABLE_LENGTH) == 0) {
                        buildTransferResponse(lastSentSig);
                        sendBytes(apdu, scratchpad, ZERO, TRANSFER_RESPONSE_LENGTH);
                        break;
                    }
                    boolean pinless = isPINlessEligible(buffer);
                    if (pinless || validatePIN(buffer, ISO7816.OFFSET_CDATA, USER_PIN_LENGTH)) {
                        signTransferV2(buffer, pinless);
                        sendBytes(apdu, scratchpad, ZERO, TRANSFER_RESPONSE_LENGTH);
                    }
                    break;
                }
                case INS_VERIFY_TRANSFER_V2: {
                    failIfSecured();
                    failIfCardIsTerminated();
                    failIfNotPersonalized();
                    verifyTransferV2(buffer, dataLength);
                    break;
                }
                case INS_GET_PERSONALIZATION: {
                    failIfSecured();
                    Util.arrayFillNonAtomic(scratchpad, ZERO, PERSONALIZATION_LENGTH, (byte) 0);
                    scratchpad[0] = terminated ? PERSONALIZATION_STATE_TERMINATED
                            : personalized ? PERSONALIZATION_STATE_PERSONALIZED
                            : initialized ? PERSONALIZATION_STATE_INITIALIZED
                            : PERSONALIZATION_STATE_BLANK;
                    scratchpad[1] = personalizationFlags();
                    Util.arrayCopyNonAtomic(programId, ZERO, scratchpad, (short) 2, PROGRAM_ID_LENGTH);
                    Util.arrayCopyNonAtomic(currency, ZERO, scratchpad, (short) 18, CURRENCY_LENGTH);
                    if (issuerPubKey.isInitialized()) {
                        issuerPubKey.getW(scratchpad, (short) 22);
                    }
                    Util.arrayCopyNonAtomic(cardCert, ZERO, scratchpad, (short) 87, MAX_SIG_LENGTH);
                    sendBytes(apdu, scratchpad, ZERO, PERSONALIZATION_LENGTH);
                    break;
                }
                case INS_GET_RECEIVE_STATE: {
                    Util.arrayCopyNonAtomic(lastReceiveCounter, ZERO, scratchpad, ZERO, INT32_LENGTH);
                    Util.arrayCopyNonAtomic(lastReceiveDigest, ZERO, scratchpad, INT32_LENGTH, HASH_LENGTH);
                    sendBytes(apdu, scratchpad, ZERO, RECEIVE_STATE_LENGTH);
                    break;
                }
                case INS_GET_LAST_TRANSFER: {
                    failIfSecured();
                    if (isAllZero(lastSentSignable, TransactionParser.OFFSET_SENDER, UUID_LENGTH)) {
                        ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND); // 0x6A83: never sent
                    }
                    Util.arrayCopyNonAtomic(lastSentSignable, ZERO, scratchpad, ZERO, SIGNABLE_LENGTH);
                    Util.arrayCopyNonAtomic(lastSentSig, ZERO, scratchpad, SIGNABLE_LENGTH, MAX_SIG_LENGTH);
                    sendBytes(apdu, scratchpad, ZERO, LAST_TRANSFER_LENGTH);
                    break;
                }
                case INS_GET_EC_PUB_KEY: {
                    if (cardECPublicKey == null) {
                        ISOException.throwIt(SW_ERROR_EC_CARD_KEY_MISSING); // 0x6230 before INITIALIZE
                    }
                    cardECPublicKey.getW(scratchpad, ZERO);
                    sendBytes(apdu, scratchpad, ZERO, PUB_KEY_LENGTH);
                    break;
                }
                case INS_GET_FULL_NAME: {
                    sendBytes(apdu, fullName, ZERO, fullNameLength);
                    break;
                }
                case INS_SET_FULL_NAME: {
                    failIfCardIsTerminated();
                    if (dataLength > MAX_FULL_NAME_LENGTH) {
                        ISOException.throwIt(SW_SET_FULL_NAME_FAILED);
                    }

                    JCSystem.beginTransaction();

                    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, fullName, ZERO, dataLength);
                    fullNameLength = dataLength;

                    JCSystem.commitTransaction();
                    break;
                }
                case INS_GET_GENDER: {
                    sendBytes(apdu, gender, ZERO, genderLength);
                    break;
                }
                case INS_SET_GENDER: {
                    failIfCardIsTerminated();
                    if (dataLength > MAX_GENDER_LENGTH) {
                        ISOException.throwIt(SW_SET_GENDER_FAILED);
                    }

                    JCSystem.beginTransaction();

                    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, gender, ZERO, dataLength);
                    genderLength = dataLength;

                    JCSystem.commitTransaction();
                    break;
                }
                case INS_GET_USER_DATA: {
                    Util.arrayCopyNonAtomic(accountId, ZERO, scratchpad, ZERO, UUID_LENGTH);
                    Util.arrayCopyNonAtomic(cardId, ZERO, scratchpad, UUID_LENGTH, UUID_LENGTH);
                    Util.arrayCopyNonAtomic(fullName, ZERO,
                            scratchpad, (short) (UUID_LENGTH + UUID_LENGTH), fullNameLength);
                    sendBytes(apdu, scratchpad, ZERO,
                            (short) (UUID_LENGTH + UUID_LENGTH + fullNameLength));
                    break;
                }
                case INS_IS_CARD_ALIVE: {
                    failIfCardIsTerminated();
                    break;
                }
                default: {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); // 0x6d00
                }
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ERROR_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_ERROR_NULL_POINTER_EXCEPTION);
        } catch (CryptoException e) {
            // e.g. an invalid EC point handed to tempPubKey.setW / verifier.init.
            // Every value check in this applet runs BEFORE beginTransaction, so
            // no transaction is ever open when an exception leaves process().
            ISOException.throwIt(SW_ERROR_CRYPTO_EXCEPTION); // 0x6683
        }
    }

    // ------------------------------------------------------------------
    // Guards
    // ------------------------------------------------------------------

    /** Throws an exception if the card has been permanently terminated. */
    private void failIfCardIsTerminated() {
        if (terminated) {
            ISOException.throwIt(SW_ERROR_CARD_TERMINATED);
        }
    }

    /**
     * Throws 0x6985 when install-time policy (FLAG_INSTALL_ENFORCE) requires a
     * provisioned user PIN before the card may sign (SIGN_TRANSFER_V2 / SIGN_AUTH).
     * The gate is lifted by install-time PIN injection (FLAG_INSTALL_PINS) or
     * by provisioning a user PIN over the SCP03 channel.
     */
    private void failIfProvisioningRequired() {
        if (provisioningEnforced && !pinProvisioned) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /** Throws 0x6234 until PERSONALIZE part C has committed the card's identity and certificate. */
    private void failIfNotPersonalized() {
        if (!personalized) {
            ISOException.throwIt(SW_ERROR_NOT_PERSONALIZED);
        }
    }

    /** Throws 0x6E00 for commands whose payload cannot ride the SCP03 wrap (CLA 0x00 only). */
    private void failIfSecured() {
        if (scp03.isSecuredCommand()) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    /** Throws 0x6236 while the static SCP03 keys are still the GP defaults. */
    private void failIfDefaultKeys() {
        if (!scp03KeysCustom) {
            ISOException.throwIt(SW_ERROR_DEFAULT_SCP03_KEYS);
        }
    }

    /** Throws 0x6982 unless the current SCP03 session carries C-DEC (encrypted commands). */
    private void failIfNoCdec() {
        if ((scp03.getSecurityLevel() & SCP03.SEC_CDEC) == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    // ------------------------------------------------------------------
    // Install parameters
    // ------------------------------------------------------------------

    /**
     * Parses the JavaCard install parameter array:
     * [instanceAIDLength][instanceAID][controlInfoLength][controlInfo][appletDataLength][appletData].
     * The applet data (the GlobalPlatform "C9" parameter value, gp --params)
     * carries the optional provisioning TLV; absent or empty applet data leaves
     * all defaults in place. Malformed structures throw (clean install failure)
     * after defensive bounds checks — never an out-of-bounds access.
     */
    private void applyInstallParameters(byte[] bArray, short bOffset, short bLength) {
        if (bLength == 0) {
            return; // no install parameters (e.g. jcardsim's parameterless install)
        }
        short end = (short) (bOffset + (short) (bLength & 0xFF));
        short cursor = bOffset;

        // [instanceAIDLength][instanceAID], then [controlInfoLength][controlInfo]
        cursor = skipLengthPrefixedField(bArray, cursor, end);
        cursor = skipLengthPrefixedField(bArray, cursor, end);

        // [appletDataLength][appletData]
        if (cursor >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short appletDataLength = (short) (bArray[cursor] & 0xFF);
        cursor++;
        if ((short) (cursor + appletDataLength) > end) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (appletDataLength == 0) {
            return; // empty parameters — defaults
        }
        applyProvisioningParameters(bArray, cursor, appletDataLength);
    }

    /** Skips a length-prefixed install parameter field, with bounds checks. */
    private short skipLengthPrefixedField(byte[] bArray, short cursor, short end) {
        if (cursor >= end) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short fieldLength = (short) (bArray[cursor] & 0xFF);
        cursor = (short) (cursor + 1 + fieldLength);
        if (cursor > end) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return cursor;
    }

    /**
     * Applies the provisioning TLV from the applet data field:
     * [0x01][flags] [ENC|MAC|DEK if flags&amp;0x02] [masterPIN|userPIN if flags&amp;0x04]
     * [programId(16)|issuerPubKey(65) if flags&amp;0x08].
     * FLAG_INSTALL_ENFORCE (0x01) gates SIGN_TRANSFER_V2 and SIGN_AUTH with 0x6985
     * until a user PIN is provisioned. FLAG_INSTALL_PROGRAM (0x08) requires
     * FLAG_INSTALL_KEYS (a bound card must never run on default keys); any key
     * equal to the GP default is refused (0x6684). The whole TLV is validated
     * before any state is mutated.
     */
    private void applyProvisioningParameters(byte[] bArray, short offset, short length) {
        if (length < 2 || bArray[offset] != TAG_INSTALL_PROVISIONING) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte flags = bArray[(short) (offset + 1)];
        if ((byte) (flags & ~(FLAG_INSTALL_ENFORCE | FLAG_INSTALL_KEYS
                | FLAG_INSTALL_PINS | FLAG_INSTALL_PROGRAM)) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // unknown flag bits
        }
        if ((flags & FLAG_INSTALL_PROGRAM) != 0 && (flags & FLAG_INSTALL_KEYS) == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // program binding needs custom keys
        }

        short expectedLength = 2;
        if ((flags & FLAG_INSTALL_KEYS) != 0) {
            expectedLength += SCP03_KEY_SET_LENGTH;
        }
        if ((flags & FLAG_INSTALL_PINS) != 0) {
            expectedLength += INSTALL_PIN_BLOCK_LENGTH;
        }
        if ((flags & FLAG_INSTALL_PROGRAM) != 0) {
            expectedLength += PROGRAM_BLOCK_LENGTH;
        }
        if (length != expectedLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short cursor = (short) (offset + 2);
        short keysOffset = -1;
        short pinsOffset = -1;
        short programOffset = -1;
        if ((flags & FLAG_INSTALL_KEYS) != 0) {
            keysOffset = cursor;
            cursor += SCP03_KEY_SET_LENGTH;
            if (containsDefaultScp03Key(bArray, keysOffset)) {
                ISOException.throwIt(SW_ERROR_INVALID_AES_KEY); // 0x6684
            }
        }
        if ((flags & FLAG_INSTALL_PINS) != 0) {
            pinsOffset = cursor;
            cursor += INSTALL_PIN_BLOCK_LENGTH;
            // The all-zeros user PIN is reserved for PIN-less transfers
            if (Util.arrayCompare(bArray, (short) (pinsOffset + MASTER_PIN_LENGTH),
                    FOUR_ZERO_PIN, ZERO, USER_PIN_LENGTH) == 0) {
                ISOException.throwIt(SW_ERROR_PIN_REJECTED);
            }
        }
        if ((flags & FLAG_INSTALL_PROGRAM) != 0) {
            programOffset = cursor;
            if (isAllZero(bArray, programOffset, PROGRAM_ID_LENGTH)
                    || bArray[(short) (programOffset + PROGRAM_ID_LENGTH)] != (byte) 0x04) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }

        // All validation passed — apply
        if (keysOffset >= 0) {
            scp03.setStaticKeys(bArray, keysOffset,
                    bArray, (short) (keysOffset + 16),
                    bArray, (short) (keysOffset + 32));
            scp03KeysCustom = true;
        }
        if (pinsOffset >= 0) {
            masterPIN.update(bArray, pinsOffset, MASTER_PIN_LENGTH);
            userPIN.update(bArray, (short) (pinsOffset + MASTER_PIN_LENGTH), USER_PIN_LENGTH);
            pinProvisioned = true;
        }
        if ((flags & FLAG_INSTALL_ENFORCE) != 0) {
            provisioningEnforced = true;
        }
        if (programOffset >= 0) {
            // A CryptoException here (invalid point) propagates = clean install failure
            issuerPubKey.setW(bArray, (short) (programOffset + PROGRAM_ID_LENGTH), PUB_KEY_LENGTH);
            Util.arrayCopyNonAtomic(bArray, programOffset, programId, ZERO, PROGRAM_ID_LENGTH);
            programBound = true;
        }
    }

    // ------------------------------------------------------------------
    // SCP03-only commands (CLA 0x84)
    // ------------------------------------------------------------------

    /**
     * Processes a PIN provisioning command received over the SCP03 secure channel.
     * Payload: [PIN_TYPE (1B)] [PIN_LENGTH (1B)] [PIN_DATA (var)].
     * PIN_TYPE 0x81 = master PIN (8 digits), 0x82 = user PIN (4 digits).
     * Under FLAG_INSTALL_ENFORCE the command is refused over the GP default
     * keys (0x6236): the ENFORCE gate must not be liftable with a public key set.
     */
    private void processProvisionPIN(byte[] buffer, short dataLength) {
        if (provisioningEnforced && !scp03KeysCustom) {
            ISOException.throwIt(SW_ERROR_DEFAULT_SCP03_KEYS);
        }
        if (dataLength < 3) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte pinType = buffer[ISO7816.OFFSET_CDATA];
        byte pinLength = buffer[(short) (ISO7816.OFFSET_CDATA + 1)];
        short pinDataOffset = (short) (ISO7816.OFFSET_CDATA + 2);

        if ((short) (2 + pinLength) > dataLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        switch (pinType) {
            case P2_MASTER_PIN: // 0x81
                if (pinLength != 8) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                masterPIN.update(buffer, pinDataOffset, pinLength);
                break;
            case P2_USER_PIN: // 0x82
                if (pinLength != 4) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                if (Util.arrayCompare(buffer, pinDataOffset, FOUR_ZERO_PIN, ZERO, pinLength) == 0) {
                    ISOException.throwIt(SW_ERROR_PIN_REJECTED);
                }
                userPIN.update(buffer, pinDataOffset, pinLength);
                // A provisioned user PIN lifts the install-time signing gate
                // (a master-PIN-only update does not — signing is user-PIN bound)
                pinProvisioned = true;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Processes an applet data update command received over the SCP03 secure channel.
     * Payload: [SEQ (2B)] [LEN (2B)] [DATA (var)].
     * Sequence 0x0001 (48 bytes) rotates the static SCP03 keys atomically; the GP
     * default key value is refused (0x6684). Any other (seq, len) answers 0x6A86.
     * Remains reachable over default keys — it is how a stock card leaves them.
     */
    private void processAppletUpdate(byte[] buffer, short dataLength) {
        if (dataLength < 4) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short seq = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short len = Util.getShort(buffer, (short) (ISO7816.OFFSET_CDATA + 2));
        short updateDataOffset = (short) (ISO7816.OFFSET_CDATA + 4);

        if ((short) (4 + len) > dataLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Sequence 0x0001: SCP03 key rotation — data = newENC(16) + newMAC(16) + newDEK(16)
        if (seq == (short) 0x0001 && len == (short) SCP03_KEY_SET_LENGTH) {
            if (containsDefaultScp03Key(buffer, updateDataOffset)) {
                ISOException.throwIt(SW_ERROR_INVALID_AES_KEY); // 0x6684
            }
            JCSystem.beginTransaction();
            scp03.setStaticKeys(
                    buffer, updateDataOffset,
                    buffer, (short) (updateDataOffset + 16),
                    buffer, (short) (updateDataOffset + 32));
            scp03KeysCustom = true;
            JCSystem.commitTransaction();
            return;
        }
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // 0x6A86: unknown (seq, len) is never a silent 0x9000
    }

    /**
     * PERSONALIZE (CLA 0x84, INS 0x72): three C-DEC-protected parts.
     * <ul>
     *   <li>P1=0x01 A identity: accountId(16) ‖ currency(4) ‖ programId(16) ‖ initialReceiveCounter(4)</li>
     *   <li>P1=0x02 B issuer key: issuerPubKey(65) — omitted when program-bound at install</li>
     *   <li>P1=0x03 C certificate: DER ECDSA signature (8..72) over the CERT message,
     *       verified under the issuer key; commits everything in one transaction with
     *       {@code personalized} as the last write</li>
     * </ul>
     * Any failure of a part clears the stage: the ceremony restarts from part A.
     */
    private void processPersonalize(byte[] buffer, short dataLength) {
        failIfNoCdec();                                                    // 0x6982
        if (!initialized) {
            ISOException.throwIt(SW_ERROR_EC_CARD_KEY_MISSING);            // 0x6230
        }
        if (personalized) {
            ISOException.throwIt(SW_ERROR_ALREADY_PERSONALIZED);           // 0x6235
        }
        failIfDefaultKeys();                                               // 0x6236
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);              // 0x6A86
        }
        try {
            switch (buffer[ISO7816.OFFSET_P1]) {
                case P1_PERSONALIZE_IDENTITY:
                    personalizeIdentity(buffer, dataLength);
                    break;
                case P1_PERSONALIZE_ISSUER_KEY:
                    personalizeIssuerKey(buffer, dataLength);
                    break;
                case P1_PERSONALIZE_CERTIFICATE:
                    personalizeCertificate(buffer, dataLength);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        } catch (ISOException e) {
            stageState[0] = 0;
            ISOException.throwIt(e.getReason());
        } catch (CryptoException e) {
            stageState[0] = 0;
            ISOException.throwIt(SW_ERROR_CRYPTO_EXCEPTION);
        }
    }

    /** PERSONALIZE part A: stages the identity; a repeated A discards a staged B. */
    private void personalizeIdentity(byte[] buffer, short dataLength) {
        if (dataLength != PERSONALIZE_IDENTITY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short d = ISO7816.OFFSET_CDATA;
        if (isAllZero(buffer, d, UUID_LENGTH)
                || isAllZero(buffer, (short) (d + UUID_LENGTH), CURRENCY_LENGTH)
                || isAllZero(buffer, (short) (d + UUID_LENGTH + CURRENCY_LENGTH), PROGRAM_ID_LENGTH)
                || (buffer[(short) (d + UUID_LENGTH + CURRENCY_LENGTH + PROGRAM_ID_LENGTH)] & 0x80) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if (programBound && Util.arrayCompare(buffer, (short) (d + UUID_LENGTH + CURRENCY_LENGTH),
                programId, ZERO, PROGRAM_ID_LENGTH) != 0) {
            ISOException.throwIt(SW_ERROR_PROGRAM_ALREADY_BOUND);
        }
        Util.arrayCopyNonAtomic(buffer, d, personalizeStage, ZERO, PERSONALIZE_IDENTITY_LENGTH);
        stageState[0] = (byte) 0x01;
    }

    /** PERSONALIZE part B: stages the issuer public key (only for cards not bound at install). */
    private void personalizeIssuerKey(byte[] buffer, short dataLength) {
        // programBound wins over the stage check: a card bound at install refuses
        // an issuer key outright (0x623B), even before any part A (spec §8.3 P8).
        if (programBound) {
            ISOException.throwIt(SW_ERROR_PROGRAM_ALREADY_BOUND);
        }
        if ((stageState[0] & 0x01) == 0) {
            ISOException.throwIt(SW_ERROR_PERSONALIZE_SEQUENCE);
        }
        if (dataLength != PUB_KEY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (buffer[ISO7816.OFFSET_CDATA] != (byte) 0x04) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        tempPubKey.setW(buffer, ISO7816.OFFSET_CDATA, PUB_KEY_LENGTH); // CryptoException -> 0x6683
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, personalizeStage,
                PERSONALIZE_IDENTITY_LENGTH, PUB_KEY_LENGTH);
        stageState[0] |= (byte) 0x02;
    }

    /** PERSONALIZE part C: verifies the certificate over the staged identity and commits. */
    private void personalizeCertificate(byte[] buffer, short dataLength) {
        if ((stageState[0] & 0x01) == 0 || (!programBound && (stageState[0] & 0x02) == 0)) {
            ISOException.throwIt(SW_ERROR_PERSONALIZE_SEQUENCE);
        }
        if (dataLength < MIN_DER_SIG_LENGTH || dataLength > MAX_SIG_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (derSigLength(buffer, ISO7816.OFFSET_CDATA) != dataLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // CERT message over the staged identity and the card's OWN public key
        buildCertMessage(personalizeStage, (short) (UUID_LENGTH + CURRENCY_LENGTH),
                personalizeStage, ZERO,
                personalizeStage, UUID_LENGTH,
                null, ZERO);
        PublicKey issuer;
        if (programBound) {
            issuer = issuerPubKey;
        } else {
            // Always re-set from the stage: tempPubKey is shared with VERIFY_TRANSFER_V2
            tempPubKey.setW(personalizeStage, PERSONALIZE_IDENTITY_LENGTH, PUB_KEY_LENGTH);
            issuer = tempPubKey;
        }
        if (!verifySig(scratchpad, ZERO, CERT_MESSAGE_LENGTH,
                buffer, ISO7816.OFFSET_CDATA, dataLength, issuer)) {
            ISOException.throwIt(Constants.SW_ERROR_CARD_DATA_SIGNATURE_INVALID); // 0x6677
        }

        JCSystem.beginTransaction();
        Util.arrayCopy(personalizeStage, ZERO, accountId, ZERO, UUID_LENGTH);
        Util.arrayCopy(personalizeStage, UUID_LENGTH, currency, ZERO, CURRENCY_LENGTH);
        Util.arrayCopy(personalizeStage, (short) (UUID_LENGTH + CURRENCY_LENGTH),
                programId, ZERO, PROGRAM_ID_LENGTH);
        // Replacement floor: envelopes the lost card already accepted can never re-verify here
        Util.arrayCopy(personalizeStage, (short) (UUID_LENGTH + CURRENCY_LENGTH + PROGRAM_ID_LENGTH),
                lastReceiveCounter, ZERO, INT32_LENGTH);
        if (!programBound) {
            issuerPubKey.setW(personalizeStage, PERSONALIZE_IDENTITY_LENGTH, PUB_KEY_LENGTH);
            programBound = true;
        }
        Util.arrayFillNonAtomic(cardCert, ZERO, MAX_SIG_LENGTH, (byte) 0);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cardCert, ZERO, dataLength);
        personalized = true; // LAST write: a tear before this leaves the card unpersonalized
        JCSystem.commitTransaction();

        stageState[0] = 0;
        Util.arrayFillNonAtomic(personalizeStage, ZERO, PERSONALIZE_STAGE_LENGTH, (byte) 0);
    }

    /**
     * TERMINATE (CLA 0x84, INS 0x73, C-DEC required): irreversibly disables the
     * card. The 16-byte payload must equal the card's accountId (binds the
     * operator to the card in the reader). The signing key is cleared so signing
     * is impossible even if a guard were missed; public reads stay available.
     */
    private void processTerminate(byte[] buffer, short dataLength) {
        failIfNoCdec();                                                    // 0x6982
        failIfDefaultKeys();                                               // 0x6236
        if (dataLength != UUID_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, accountId, ZERO, UUID_LENGTH) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);                  // 0x6A80
        }
        JCSystem.beginTransaction();
        terminated = true;
        JCSystem.commitTransaction();
        if (cardECPrivateKey != null) {
            cardECPrivateKey.clearKey();
        }
    }

    // ------------------------------------------------------------------
    // Transfers
    // ------------------------------------------------------------------

    /**
     * Read-only eligibility check for PIN-less transfers: true when the PIN field
     * is all zeros, the amount is within the PIN-less limit, and the consecutive
     * PIN-less counter has headroom. Deliberately does NOT increment the counter —
     * signTransferV2() commits the increment atomically with the balance mutation,
     * so failed or torn transfers never burn PIN-less budget.
     */
    private boolean isPINlessEligible(byte[] buffer) {
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, FOUR_ZERO_PIN, ZERO, USER_PIN_LENGTH) == 0) {
            TransactionParser.getAmount(buffer, OFFSET_SIGNABLE, tempAmount);
            if (ArrayUtil.unsignedByteArrayCompare(tempAmount, ZERO, PINLESS_LIMIT, ZERO, INT64_LENGTH) <= 0 &&
                    howManyPINless < MAX_PINLESS_TRANSFERS) {
                return true;
            }
            // an all-zero PIN field outside the PIN-less limits requires a real PIN
            ISOException.throwIt(SW_ERROR_PIN_REQUIRED);
        }
        return false;
    }

    /** Sends the applet version (major, minor, git rev count, git hash) as response bytes. */
    private void sendVersion(APDU apdu) {
        scratchpad[0] = (byte) ((MAJOR_VERSION >> 8) & 0xff);
        scratchpad[1] = (byte) (MAJOR_VERSION & 0xff);

        scratchpad[2] = (byte) ((MINOR_VERSION >> 8) & 0xff);
        scratchpad[3] = (byte) (MINOR_VERSION & 0xff);

        scratchpad[4] = (byte) ((GIT_REV_LIST >> 8) & 0xff);
        scratchpad[5] = (byte) (GIT_REV_LIST & 0xff);

        Util.arrayCopy(GIT_HASH_SHORT, ZERO, scratchpad, (short) 6, (short) GIT_HASH_SHORT.length);
        sendBytes(apdu, scratchpad, ZERO, (short) (2 + 2 + 2 + GIT_HASH_SHORT.length));
    }

    /**
     * Validates the user PIN from the APDU buffer. On failure, throws an ISOException
     * encoding the number of remaining tries in the status word. On success, resets
     * the PIN-less transfer counter.
     */
    private boolean validatePIN(byte[] buffer, short offset, byte length) {
        if (!userPIN.check(buffer, offset, length)) {
            short triesRemaining = userPIN.getTriesRemaining();
            // The last nibble of return code is number of remaining tries
            ISOException.throwIt((short) (SW_PIN_FAILED + triesRemaining));
        }
        // reset howManyPINless
        howManyPINless = 0;
        return true;
    }

    /**
     * Signs a bridge-issued authentication challenge with the card's EC key.
     * The signed message is AUTH_DOMAIN_TAG ("IMPALA-AUTH:", 12 bytes) ||
     * accountId(16) || challenge(8..=64) — the pinned card-auth contract; the
     * bridge /auth/card verifier (CARD_AUTH_DOMAIN_PREFIX in
     * impala-bridge/src/constants.rs) checks exactly those bytes.
     * Challenges outside 8..=64 bytes are rejected with 0x6700.
     */
    private void signAuth(APDU apdu, byte[] buffer, short dataLength) {
        if (dataLength < MIN_AUTH_CHALLENGE_LENGTH || dataLength > MAX_AUTH_CHALLENGE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(AUTH_DOMAIN_TAG, ZERO, scratchpad, ZERO, AUTH_DOMAIN_TAG_LENGTH);
        Util.arrayCopyNonAtomic(accountId, ZERO, scratchpad, AUTH_DOMAIN_TAG_LENGTH, UUID_LENGTH);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, scratchpad,
                (short) (AUTH_DOMAIN_TAG_LENGTH + UUID_LENGTH), dataLength);
        short sigLength = signWithMyKey(scratchpad, ZERO,
                (short) (AUTH_DOMAIN_TAG_LENGTH + UUID_LENGTH + dataLength));
        sendBytes(apdu, sigBuffer, ZERO, sigLength);
    }

    /**
     * Signs an outgoing transfer (SIGN_TRANSFER_V2). The card signs the 89-byte
     * XFER message ("IMPALA-XFER:" ‖ 0x01 ‖ programId ‖ signable) — never the bare
     * signable — and debits atomically with the idempotency record. The 209-byte
     * response is sig(72 slot) ‖ pubkey(65) ‖ cardCert(72 slot), assembled into a
     * zero-filled scratchpad.
     *
     * Checks, in order: sender is me (0x6231); recipient is not me (0x6232);
     * currency matches unconditionally (0x6229); amount non-zero (0x6239) and
     * covered (0x6224); counter positive (0x6233); send sequence (dateTime) MSB
     * clear and strictly greater than the last committed one (0x6238).
     *
     * @param pinless true when this transfer was authorized PIN-less; the
     *                PIN-less counter is then incremented atomically with the
     *                balance mutation (tearing-safe)
     */
    private void signTransferV2(byte[] buffer, boolean pinless) {
        if (Util.arrayCompare(buffer, (short) (OFFSET_SIGNABLE + TransactionParser.OFFSET_SENDER),
                accountId, ZERO, UUID_LENGTH) != 0) {
            ISOException.throwIt(SW_ERROR_WRONG_SENDER);
        }
        if (Util.arrayCompare(buffer, (short) (OFFSET_SIGNABLE + TransactionParser.OFFSET_RECIPIENT),
                accountId, ZERO, UUID_LENGTH) == 0) {
            ISOException.throwIt(SW_ERROR_WRONG_RECIPIENT);
        }
        if (Util.arrayCompare(buffer, (short) (OFFSET_SIGNABLE + TransactionParser.OFFSET_CURRENCY),
                currency, ZERO, CURRENCY_LENGTH) != 0) {
            ISOException.throwIt(Constants.SW_ERROR_WRONG_CURRENCY);
        }

        TransactionParser.getAmount(buffer, OFFSET_SIGNABLE, tempAmount);
        if (isAllZero(tempAmount, ZERO, INT64_LENGTH)) {
            ISOException.throwIt(SW_ERROR_ZERO_AMOUNT);
        }
        if (!checkAmount(tempAmount)) {
            ISOException.throwIt(SW_INSUFFICIENT_FUNDS); // 0x6224
        }

        // The card never chooses the recipient counter, but refuses one no receiver
        // could ever accept (it would only burn a debit).
        TransactionParser.getCounter(buffer, OFFSET_SIGNABLE, tempCounter);
        if (isNegative(tempCounter) || ArrayUtil.isZero(tempCounter)) {
            ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
        }

        // Send sequence: dateTime is a strictly increasing 63-bit per-sender
        // sequence, never a trusted timestamp.
        if ((buffer[OFFSET_SIGNABLE] & 0x80) != 0
                || ArrayUtil.unsignedByteArrayCompare(buffer, OFFSET_SIGNABLE,
                        lastSentSignable, ZERO, INT64_LENGTH) <= 0) {
            ISOException.throwIt(SW_ERROR_SEND_SEQUENCE_INVALID);
        }

        buildXferMessage(buffer, OFFSET_SIGNABLE);
        Util.arrayFillNonAtomic(sigBuffer, ZERO, MAX_SIG_LENGTH, (byte) 0);
        signWithMyKey(scratchpad, ZERO, XFER_MESSAGE_LENGTH);

        JCSystem.beginTransaction();
        subtractFromBalance(tempAmount);
        if (pinless) {
            // Committed atomically with the balance mutation: a torn or failed
            // transfer burns no PIN-less budget (see isPINlessEligible)
            howManyPINless++;
        }
        Util.arrayCopy(buffer, OFFSET_SIGNABLE, lastSentSignable, ZERO, SIGNABLE_LENGTH);
        Util.arrayCopy(sigBuffer, ZERO, lastSentSig, ZERO, MAX_SIG_LENGTH);
        JCSystem.commitTransaction();

        buildTransferResponse(sigBuffer);
    }

    /**
     * Verifies and accepts an incoming transfer (VERIFY_TRANSFER_V2) in two phases:
     * <ul>
     *   <li>P1=0x00: stages the 60-byte signable</li>
     *   <li>P1=0x01: takes the 209-byte tail (sig ‖ pubkey ‖ certificate). Cheap
     *       checks first (lengths, DER headers, identities, currency, amount,
     *       counter rule, overflow-checked credit), then the certificate under
     *       the card's OWN issuer key over the CERT message rebuilt from its own
     *       programId, the signable's sender and currency, and the tail pubkey
     *       (0x0022), then the transfer signature over the XFER message under
     *       the tail pubkey (0x0023). Nothing mutates before the transaction;
     *       the credit, the counter and the transfer digest commit together.</li>
     * </ul>
     * No PIN is required to receive; the trust root is issuerPubKey, not the holder.
     */
    private void verifyTransferV2(byte[] buffer, short dataLength) {
        byte p1 = buffer[ISO7816.OFFSET_P1];
        if (p1 == (byte) 0x00) {
            if (dataLength != SIGNABLE_LENGTH) {
                ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH); // 0x6226
            }
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, signableBuffer, ZERO, SIGNABLE_LENGTH);
            verifyStage[0] = 1;
            return;
        }
        if (p1 != (byte) 0x01) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2); // 0x6A86
        }

        if (dataLength != TRANSFER_RESPONSE_LENGTH) {
            ISOException.throwIt(SW_ERROR_WRONG_TAIL_LENGTH); // 0x6C02
        }
        if (verifyStage[0] != 1) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // 0x6985: no staged signable
        }
        short sigOffset = ISO7816.OFFSET_CDATA;
        short pubOffset = (short) (ISO7816.OFFSET_CDATA + MAX_SIG_LENGTH);
        short certOffset = (short) (pubOffset + PUB_KEY_LENGTH);
        short sigLength = derSigLength(buffer, sigOffset);
        short certLength = derSigLength(buffer, certOffset);
        if (buffer[pubOffset] != (byte) 0x04) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Identities: the sender is NOT this card, the recipient IS this card
        if (Util.arrayCompare(signableBuffer, TransactionParser.OFFSET_SENDER,
                accountId, ZERO, UUID_LENGTH) == 0) {
            ISOException.throwIt(SW_ERROR_WRONG_SENDER);
        }
        if (Util.arrayCompare(signableBuffer, TransactionParser.OFFSET_RECIPIENT,
                accountId, ZERO, UUID_LENGTH) != 0) {
            ISOException.throwIt(SW_ERROR_WRONG_RECIPIENT);
        }
        if (Util.arrayCompare(signableBuffer, TransactionParser.OFFSET_CURRENCY,
                currency, ZERO, CURRENCY_LENGTH) != 0) {
            ISOException.throwIt(Constants.SW_ERROR_WRONG_CURRENCY);
        }

        TransactionParser.getAmount(signableBuffer, ZERO, tempAmount);
        if (isAllZero(tempAmount, ZERO, INT64_LENGTH)) {
            ISOException.throwIt(SW_ERROR_ZERO_AMOUNT);
        }

        // Replay protection: ONE strictly increasing counter stream per receiving
        // card (all senders), bounded forward jump. See checkReceiveCounter.
        TransactionParser.getCounter(signableBuffer, ZERO, tempCounter);
        checkReceiveCounter();

        // Overflow-checked credit BEFORE the transaction (jcardsim never rolls back)
        computeCredit(tempAmount);

        tempPubKey.setW(buffer, pubOffset, PUB_KEY_LENGTH); // CryptoException -> 0x6683

        // Certificate first: the issuer certified THIS key for THIS program, for
        // exactly the signable's sender UUID and currency.
        buildCertMessage(programId, ZERO,
                signableBuffer, TransactionParser.OFFSET_SENDER,
                signableBuffer, TransactionParser.OFFSET_CURRENCY,
                buffer, pubOffset);
        if (!verifySig(scratchpad, ZERO, CERT_MESSAGE_LENGTH,
                buffer, certOffset, certLength, issuerPubKey)) {
            ISOException.throwIt(SW_ERROR_KEY_VERIFICATION_FAILED); // 0x0022
        }

        // Then the transfer signature over the tagged XFER message
        buildXferMessage(signableBuffer, ZERO);
        if (!verifySig(scratchpad, ZERO, XFER_MESSAGE_LENGTH,
                buffer, sigOffset, sigLength, tempPubKey)) {
            ISOException.throwIt(SW_ERROR_SIGNATURE_VERIFICATION_FAILED); // 0x0023
        }
        messageDigest.doFinal(scratchpad, ZERO, XFER_MESSAGE_LENGTH, hashBuffer, ZERO);

        // Credit, counter and transfer digest advance in ONE transaction: a tear
        // can never credit without consuming the counter (or vice versa).
        JCSystem.beginTransaction();
        Util.arrayCopy(tempBalance, ZERO, myBalance, ZERO, INT64_LENGTH);
        Util.arrayCopy(tempCounter, ZERO, lastReceiveCounter, ZERO, INT32_LENGTH);
        Util.arrayCopy(hashBuffer, ZERO, lastReceiveDigest, ZERO, HASH_LENGTH);
        JCSystem.commitTransaction();

        // Consume the staged signable: a repeated P1=0x01 tail must not be able
        // to re-verify against it within the same session.
        Util.arrayFillNonAtomic(signableBuffer, ZERO, SIGNABLE_LENGTH, (byte) 0);
        verifyStage[0] = 0;
    }

    /**
     * Exact receive accept rule on tempCounter vs lastReceiveCounter (L, J = 1024):
     * accept iff MSB clear, c != 0, c > L and c <= min(L + J, 0x7FFFFFFF).
     * c <= 0 or c <= L -> 0x6233 (stale / replay); c - L > J -> 0x623A (allocator
     * ahead: the terminal must re-read GET_RECEIVE_STATE).
     */
    private void checkReceiveCounter() {
        if (isNegative(tempCounter) || ArrayUtil.isZero(tempCounter)
                || ArrayUtil.unsignedByteArrayCompare(tempCounter, ZERO,
                        lastReceiveCounter, ZERO, INT32_LENGTH) <= 0) {
            ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
        }
        Util.arrayCopyNonAtomic(lastReceiveCounter, ZERO, tempLimit, ZERO, INT32_LENGTH);
        ArrayUtil.addUnsignedShort(tempLimit, MAX_COUNTER_JUMP); // L + 1024, carry propagated
        if (isNegative(tempLimit)) {
            // clamp to 0x7FFFFFFF
            tempLimit[0] = (byte) 0x7F;
            tempLimit[1] = (byte) 0xFF;
            tempLimit[2] = (byte) 0xFF;
            tempLimit[3] = (byte) 0xFF;
        }
        if (ArrayUtil.unsignedByteArrayCompare(tempCounter, ZERO, tempLimit, ZERO, INT32_LENGTH) > 0) {
            ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_JUMP);
        }
    }

    /** tempBalance := myBalance + amount; 0x6984 on carry-out. Called BEFORE beginTransaction. */
    private void computeCredit(byte[] amount) {
        short carry = 0;
        for (short i = (short) (INT64_LENGTH - 1); i >= 0; i--) {
            short r = (short) ((myBalance[i] & 0xFF) + (amount[i] & 0xFF) + carry);
            tempBalance[i] = (byte) r;
            carry = (short) ((r >> 8) & 1);
        }
        if (carry != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID); // balance overflow
        }
    }

    // ------------------------------------------------------------------
    // Message builders / parsers
    // ------------------------------------------------------------------

    /** 0x30 LL ...; returns the total DER length; 0x6A80 unless 8 <= len <= 72 (slot check by the caller). */
    private short derSigLength(byte[] b, short off) {
        if (b[off] != (byte) 0x30) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short len = (short) ((b[(short) (off + 1)] & 0xFF) + TAG_LENGTH_LENGTH);
        if (len < MIN_DER_SIG_LENGTH || len > MAX_SIG_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return len;
    }

    private static boolean isAllZero(byte[] b, short off, short len) {
        for (short i = 0; i < len; i++) {
            if (b[(short) (off + i)] != 0) {
                return false;
            }
        }
        return true;
    }

    /** True when any of ENC/MAC/DEK at b[off..off+48) equals the GP default key. */
    private static boolean containsDefaultScp03Key(byte[] b, short off) {
        return Util.arrayCompare(b, off, DEFAULT_SCP03_KEY, ZERO, (short) 16) == 0
                || Util.arrayCompare(b, (short) (off + 16), DEFAULT_SCP03_KEY, ZERO, (short) 16) == 0
                || Util.arrayCompare(b, (short) (off + 32), DEFAULT_SCP03_KEY, ZERO, (short) 16) == 0;
    }

    /** scratchpad[0..89) := XFER_DOMAIN_TAG ‖ 0x01 ‖ programId ‖ src[srcOff..+60). */
    private void buildXferMessage(byte[] src, short srcOff) {
        Util.arrayCopyNonAtomic(XFER_DOMAIN_TAG, ZERO, scratchpad, ZERO, DOMAIN_TAG_LENGTH);
        scratchpad[DOMAIN_TAG_LENGTH] = TRANSFER_PROTOCOL_VERSION;
        Util.arrayCopyNonAtomic(programId, ZERO, scratchpad, (short) (DOMAIN_TAG_LENGTH + 1), PROGRAM_ID_LENGTH);
        Util.arrayCopyNonAtomic(src, srcOff, scratchpad,
                (short) (DOMAIN_TAG_LENGTH + 1 + PROGRAM_ID_LENGTH), SIGNABLE_LENGTH);
    }

    /**
     * scratchpad[0..114) := CERT_DOMAIN_TAG ‖ 0x01 ‖ prog ‖ acct ‖ cur ‖ pub65.
     * {@code pub == null} uses the card's OWN public key (PERSONALIZE part C).
     */
    private void buildCertMessage(byte[] prog, short progOff,
            byte[] acct, short acctOff,
            byte[] cur, short curOff,
            byte[] pub, short pubOff) {
        Util.arrayCopyNonAtomic(CERT_DOMAIN_TAG, ZERO, scratchpad, ZERO, DOMAIN_TAG_LENGTH);
        scratchpad[DOMAIN_TAG_LENGTH] = CERT_VERSION;
        Util.arrayCopyNonAtomic(prog, progOff, scratchpad, (short) 13, PROGRAM_ID_LENGTH);
        Util.arrayCopyNonAtomic(acct, acctOff, scratchpad, (short) 29, UUID_LENGTH);
        Util.arrayCopyNonAtomic(cur, curOff, scratchpad, (short) 45, CURRENCY_LENGTH);
        if (pub == null) {
            cardECPublicKey.getW(scratchpad, (short) 49);
        } else {
            Util.arrayCopyNonAtomic(pub, pubOff, scratchpad, (short) 49, PUB_KEY_LENGTH);
        }
    }

    /** scratchpad[0..209) := sig72 ‖ pubkey65 ‖ cardCert72, zero-filled first (no stale bytes). */
    private void buildTransferResponse(byte[] sig72) {
        Util.arrayFillNonAtomic(scratchpad, ZERO, TRANSFER_RESPONSE_LENGTH, (byte) 0);
        Util.arrayCopyNonAtomic(sig72, ZERO, scratchpad, ZERO, MAX_SIG_LENGTH);
        cardECPublicKey.getW(scratchpad, MAX_SIG_LENGTH);
        Util.arrayCopyNonAtomic(cardCert, ZERO, scratchpad,
                (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH), MAX_SIG_LENGTH);
    }

    /** GET_PERSONALIZATION flags byte. */
    private byte personalizationFlags() {
        byte f = 0;
        if (initialized) {
            f |= PFLAG_INITIALIZED;
        }
        if (programBound) {
            f |= PFLAG_PROGRAM_BOUND;
        }
        if (personalized) {
            f |= PFLAG_PERSONALIZED;
        }
        if (!scp03KeysCustom) {
            f |= PFLAG_SCP03_KEYS_DEFAULT;
        }
        if (pinProvisioned) {
            f |= PFLAG_PIN_PROVISIONED;
        }
        if (provisioningEnforced) {
            f |= PFLAG_PROVISIONING_ENFORCED;
        }
        if (terminated) {
            f |= PFLAG_TERMINATED;
        }
        return f;
    }

    // ------------------------------------------------------------------
    // PINs
    // ------------------------------------------------------------------

    /**
     * Updates the user PIN. Requires prior master PIN verification.
     * Rejects the all-zeros PIN (0000) as it is reserved for PIN-less transfers.
     */
    private void processUpdateUserPIN(byte[] buffer, short dataLength) {
        // SIGN_TRANSFER_V2 always checks exactly USER_PIN_LENGTH digits, so a PIN
        // stored with any other length could never verify again — every attempt
        // would burn a retry until the user PIN blocks. Enforce the same fixed
        // length the SCP03 provisioning path does.
        if (dataLength != USER_PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, FOUR_ZERO_PIN, ZERO, USER_PIN_LENGTH) == 0) {
            ISOException.throwIt(SW_ERROR_PIN_REJECTED);
        }
        userPIN.update(buffer, ISO7816.OFFSET_CDATA, USER_PIN_LENGTH);
    }

    /**
     * Handles Verify Pin APDU (P2 selects the PIN; the data field is the PIN digits).
     */
    private void processVerifyPIN(byte[] buffer, short dataLength) {
        byte pinLength = (byte) dataLength;
        byte triesRemaining;
        byte pinType = buffer[ISO7816.OFFSET_P2];

        switch (pinType) {
            case P2_MASTER_PIN:
                if (!masterPIN.check(buffer, ISO7816.OFFSET_CDATA, pinLength)) {
                    triesRemaining = masterPIN.getTriesRemaining();
                    // The last nibble of return code is number of remaining tries
                    ISOException.throwIt((short) (SW_PIN_FAILED + triesRemaining));
                }
                break;
            case P2_USER_PIN:
                if (!userPIN.check(buffer, ISO7816.OFFSET_CDATA, pinLength)) {
                    triesRemaining = userPIN.getTriesRemaining();
                    // The last nibble of return code is number of remaining tries
                    ISOException.throwIt((short) (SW_PIN_FAILED + triesRemaining));
                }
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // ------------------------------------------------------------------
    // Balance arithmetic
    // ------------------------------------------------------------------

    /** Returns true if the given amount is less than or equal to the current balance. */
    private boolean checkAmount(byte[] amount) {
        return ArrayUtil.unsignedByteArrayCompare(amount, ZERO, myBalance, ZERO, INT64_LENGTH) <= ZERO;
    }

    /** Subtracts an 8-byte unsigned amount from the on-card balance using byte-level arithmetic. */
    private void subtractFromBalance(byte[] amount) {
        short borrow = 0;
        for (short i = INT64_LENGTH - 1; i >= 0; i--) {
            short x = (short) (this.myBalance[i] & 0xFF);
            short y = (short) (amount[i] & 0xFF);
            short result = (short) (x - y - borrow);
            this.myBalance[i] = (byte) result;
            borrow = (short) ((result >> 8) & 1);
        }
        if (borrow != 0) {
            ISOException.throwIt(SW_INSUFFICIENT_FUNDS); // balance underflow
        }
    }

    // ------------------------------------------------------------------
    // Keys / crypto
    // ------------------------------------------------------------------

    /**
     * Generates a new secp256r1 EC key pair and stores it as the card's signing key.
     *
     * Keygen entropy is card-internal: per the JavaCard API, KeyPair.genKeyPair()
     * draws its randomness from the platform's own secure random source (TRNG/DRBG).
     * It does not — and cannot — consume the applet's host-seeded {@code randomData}
     * instance, so the INS_INITIALIZE host seed has no influence over the generated
     * private key.
     */
    private void createECKeypair() {
        KeyPair keyPair = SecP256r1.newKeyPair();
        keyPair.genKeyPair();

        cardECPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        cardECPublicKey = (ECPublicKey) keyPair.getPublic();
    }

    /** Signs data with the card's EC private key (ECDSA-SHA256). Returns signature length. */
    private short signWithMyKey(byte[] buffer, short offset, short length) {
        if (cardECPrivateKey == null || !cardECPrivateKey.isInitialized()) {
            ISOException.throwIt(SW_ERROR_EC_CARD_KEY_MISSING);
        }
        try {
            signer.init(cardECPrivateKey, Signature.MODE_SIGN);
        } catch (Exception e) {
            ISOException.throwIt(SW_ERROR_INIT_SIGNER);
        }
        return signer.sign(buffer, offset, length, sigBuffer, ZERO);
    }

    /** Verifies an ECDSA-SHA256 signature against the given public key. */
    private boolean verifySig(byte[] inBuff, short inOffset, short inLength,
            byte[] sig, short sigOffset, short sigLength, PublicKey pubKey) {
        verifier.init(pubKey, Signature.MODE_VERIFY);
        return verifier.verify(inBuff, inOffset, inLength, sig, sigOffset, sigLength);
    }

    /**
     * Sends a byte array as the APDU response. Responses to SCP03-secured
     * commands (CLA 0x84) are wrapped (R-ENC/R-MAC per the session security
     * level) in the APDU buffer before sending. The in-buffer wrap needs
     * roughly 2*paddedLen + 18 bytes of the 260-byte APDU buffer (plaintext
     * responses <= 111 bytes); the commands whose responses do not fit refuse
     * the secured CLA up front (0x6E00) rather than leaking unwrapped data.
     */
    private void sendBytes(APDU apdu, byte[] outData, short bOff, short len) {
        if (scp03.isSecuredCommand()) {
            byte[] buffer = apdu.getBuffer();
            Util.arrayCopyNonAtomic(outData, bOff, buffer, ZERO, len);
            len = scp03.wrapResponse(buffer, ZERO, len, ISO7816.SW_NO_ERROR);
            outData = buffer;
            bOff = ZERO;
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(outData, bOff, len);
    }
}

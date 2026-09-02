package com.impala.applet;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacard.framework.APDU;

import static com.impala.applet.ArrayUtil.isNegative;
import static com.impala.applet.BuildConfig.GIT_HASH_SHORT;
import static com.impala.applet.BuildConfig.GIT_REV_LIST;
import static com.impala.applet.BuildConfig.MAJOR_VERSION;
import static com.impala.applet.BuildConfig.MINOR_VERSION;
import static com.impala.applet.Constants.HASHABLE_LENGTH;
import static com.impala.applet.Constants.HASH_LENGTH;
import static com.impala.applet.Constants.INS_GET_ACCOUNT_ID;
import static com.impala.applet.Constants.INS_GET_BALANCE;
import static com.impala.applet.Constants.INS_GET_EC_PUB_KEY;
import static com.impala.applet.Constants.INS_GET_FULL_NAME;
import static com.impala.applet.Constants.INS_GET_GENDER;
import static com.impala.applet.Constants.INS_GET_USER_DATA;
import static com.impala.applet.Constants.INS_GET_VERSION;
import static com.impala.applet.Constants.INS_INITIALIZE;
import static com.impala.applet.Constants.INS_IS_CARD_ALIVE;
import static com.impala.applet.Constants.INS_NOP;
import static com.impala.applet.Constants.INS_SET_FULL_NAME;
import static com.impala.applet.Constants.INS_SET_GENDER;
import static com.impala.applet.Constants.INS_SIGN_AUTH;
import static com.impala.applet.Constants.INS_SIGN_TRANSFER;
import static com.impala.applet.Constants.INS_UPDATE_USER_PIN;
import static com.impala.applet.Constants.INS_VERIFY_PIN;
import static com.impala.applet.Constants.INS_VERIFY_TRANSFER;
import static com.impala.applet.Constants.INT32_LENGTH;
import static com.impala.applet.Constants.INT64_LENGTH;
import static com.impala.applet.Constants.MAX_SIG_LENGTH;
import static com.impala.applet.Constants.P2_MASTER_PIN;
import static com.impala.applet.Constants.P2_USER_PIN;
import static com.impala.applet.Constants.PUB_KEY_LENGTH;
import static com.impala.applet.Constants.SIGNABLE_LENGTH;
import static com.impala.applet.Constants.TAG_LENGTH_LENGTH;
import static com.impala.applet.Constants.UUID_LENGTH;
import static com.impala.applet.Constants.INS_SCP03_PROVISION_PIN;
import static com.impala.applet.Constants.INS_SCP03_APPLET_UPDATE;
import static com.impala.applet.Constants.ZERO;

/**
 * Main JavaCard applet for the Impala payment card.
 *
 * Handles APDU commands for account management, PIN verification, transaction
 * signing/verification, cryptographic key operations, and card lifecycle management.
 * Supports both online Stellar and Payala payments
 */
public class ImpalaApplet extends Applet {
    // --- Status word constants for APDU error responses ---
    public static final short SW_ERROR_SIGNATURE_VERIFICATION_FAILED = 0x0023;
    public static final short SW_INSUFFICIENT_FUNDS = 0x6224;
    public static final short SW_ERROR_WRONG_SIGNABLE_LENGTH = 0x6226;
    public static final short SW_ERROR_INIT_SIGNER = 0x6227;
    public static final short SW_ERROR_EC_CARD_KEY_MISSING = 0x6230;
    public static final short SW_ERROR_WRONG_SENDER = 0x6231;
    public static final short SW_ERROR_WRONG_RECIPIENT = 0x6232;
    public static final short SW_ERROR_TRANSFER_COUNTER_INVALID = 0x6233;
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
    // In SIGN_TRANSFER, the signable data starts after the 4-byte user PIN
    private static final short OFFSET_SIGNABLE = ISO7816.OFFSET_CDATA + USER_PIN_LENGTH;

    private static final short MAX_PINLESS_TRANSFERS = 4; // max consecutive transfers without PIN
    private static final short MAX_FULL_NAME_LENGTH = 128;
    private static final short MAX_GENDER_LENGTH = 16;

    // --- SIGN_AUTH domain separation (pinned cross-stream contract) ---
    // ASCII "IMPALA-AUTH:" — must match CARD_AUTH_DOMAIN_PREFIX in
    // impala-bridge/src/constants.rs. The bridge /auth/card verifier checks
    // ECDSA-SHA256 over AUTH_DOMAIN_TAG || accountId(16) || challenge(8..=64),
    // so an auth signature can never be replayed as a transfer signature.
    private static final byte[] AUTH_DOMAIN_TAG = {
            (byte) 0x49, (byte) 0x4D, (byte) 0x50, (byte) 0x41, // "IMPA"
            (byte) 0x4C, (byte) 0x41, (byte) 0x2D, (byte) 0x41, // "LA-A"
            (byte) 0x55, (byte) 0x54, (byte) 0x48, (byte) 0x3A  // "UTH:"
    };
    private static final short AUTH_DOMAIN_TAG_LENGTH = 12;
    private static final short MIN_AUTH_CHALLENGE_LENGTH = 8;
    private static final short MAX_AUTH_CHALLENGE_LENGTH = 64;

    // --- Install-parameter TLV (the applet data / GP "C9" parameter value) ---
    // [TAG_INSTALL_PROVISIONING][flags]
    //   [ENC(16) | MAC(16) | DEK(16)  if flags & FLAG_INSTALL_KEYS]
    //   [masterPIN(8) | userPIN(4)    if flags & FLAG_INSTALL_PINS]
    private static final byte TAG_INSTALL_PROVISIONING = (byte) 0x01;
    private static final byte FLAG_INSTALL_ENFORCE = (byte) 0x01;
    private static final byte FLAG_INSTALL_KEYS = (byte) 0x02;
    private static final byte FLAG_INSTALL_PINS = (byte) 0x04;
    private static final short SCP03_KEY_SET_LENGTH = 48;
    private static final short INSTALL_PIN_BLOCK_LENGTH = 12;

    // DER-encoded zero signature placeholder used for online (non-LUK) transfers
    // where no pubKeySig is needed. Maintains consistent response format.
    private static final byte[] SIXTY_FOUR_ZEROES = {
            (byte) 0x30, (byte) 0x06,
            (byte) 0x02, (byte) 0x01, (byte) 0x00,
            (byte) 0x02, (byte) 0x01, (byte) 0x00
    };

    // Maximum amount (200 in lowest denomination) allowed for PIN-less transfers
    private static final byte[] PINLESS_LIMIT = new byte[] {
            0, 0, 0, 0, 0, 0, 0, (byte) 0xc8
    };

    private static final byte[] FOUR_ZERO_PIN = new byte[] {
            0, 0, 0, 0
    };

    // --- Cryptographic engines ---
    private MessageDigest messageDigest; // SHA-256 for transaction hashing
    private RandomData randomData;     // Secure RNG for card ID and nonces
    private Signature signer;          // ECDSA-SHA256 signing with card key
    private Signature verifier;        // ECDSA-SHA256 verification with program key

    // --- Card lifecycle state ---
    private boolean initialized;       // True after INS_INITIALIZE generates keys
    private boolean terminated;        // True after card termination; card becomes inoperable

    // --- Account and balance data (persisted in EEPROM) ---
    private byte[] accountId;          // 16-byte UUID linking to Payala account
    private byte[] cardId;             // 16-byte UUID unique to this card, randomly generated
    private byte[] currency;           // 4-byte currency code
    private byte[] myBalance;          // 8-byte (int64) on-card balance in lowest denomination
    private byte[] lastReceiveCounter; // 4-byte last accepted incoming-transfer counter (replay guard)

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

    // --- Transient working buffers (cleared on card reset) ---
    private byte[] scratchpad;         // General-purpose transient buffer (255 bytes)
    private byte[] sigBuffer;          // Holds signature output from signing operations
    private byte[] signableBuffer;     // Holds signable data during two-phase verify
    private byte[] tempAmount;         // Temporary buffer for parsed transaction amount
    private byte[] tempCounter;        // Temporary buffer for parsed transaction counter
    private ECPublicKey tempPubKey;    // Reusable EC public key for transfer verification

    // --- SCP03 secure channel ---
    private SCP03 scp03;

    // --- Transaction hash storage ---
    private byte[] hashBuffer;
    private Hashable hashable;         // Reusable hashable object for transaction records

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
        terminated = false;

        accountId = new byte[UUID_LENGTH];
        cardId = new byte[UUID_LENGTH];

        randomData.generateData(cardId, ZERO, UUID_LENGTH);

        currency = new byte[4];
        myBalance = new byte[INT64_LENGTH];
        lastReceiveCounter = new byte[INT32_LENGTH];

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

        scratchpad = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        sigBuffer = JCSystem.makeTransientByteArray(MAX_SIG_LENGTH, JCSystem.CLEAR_ON_RESET);
        signableBuffer = JCSystem.makeTransientByteArray(SIGNABLE_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempAmount = JCSystem.makeTransientByteArray(INT64_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempCounter = JCSystem.makeTransientByteArray(INT32_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempPubKey = SecP256r1.newPubKey();

        hashBuffer = JCSystem.makeTransientByteArray(HASH_LENGTH, JCSystem.CLEAR_ON_RESET);
        hashable = new Hashable(JCSystem.makeTransientByteArray(HASH_LENGTH, JCSystem.CLEAR_ON_RESET),
                JCSystem.makeTransientByteArray(HASHABLE_LENGTH, JCSystem.CLEAR_ON_RESET));

        // SCP03 secure channel — default static keys (matches gp-master.jar defaults: 0x40..0x4F)
        scp03 = new SCP03(randomData);
        byte[] defaultKey = new byte[] {
                (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43,
                (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
                (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B,
                (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x4F
        };
        scp03.setStaticKeys(defaultKey, ZERO, defaultKey, ZERO, defaultKey, ZERO);

        // Install parameters may override the SCP03 keys / PINs and enable the
        // provisioning gate. Throws on malformed input, failing the install
        // cleanly before register() — never with partially-applied state.
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
     * Called by the JCRE to inform this applet that it has been
     * selected. Perform any initialization that may be required to
     * process APDU commands. This method returns a boolean to
     * indicate whether it is ready to accept incoming APDU commands
     * via its process() method.
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
     *   <li><b>No auth required (public):</b>
     *       INS_NOP (0x02), INS_GET_BALANCE (0x04), INS_GET_ACCOUNT_ID (0x16),
     *       INS_GET_VERSION (0x64), INS_GET_EC_PUB_KEY (0x24), INS_GET_FULL_NAME (0x20),
     *       INS_GET_GENDER (0x21), INS_GET_USER_DATA (0x1E), INS_GET_CARD_NONCE (0x23),
     *       INS_IS_CARD_ALIVE (0x2E), INS_GET_RSA_PUB_KEY (0x07)</li>
     *   <li><b>Card must not be terminated:</b>
     *       INS_INITIALIZE (0x2C), INS_VERIFY_PIN (0x18), INS_SET_FULL_NAME (0x1F),
     *       INS_SET_GENDER (0x22), INS_SIGN_AUTH (0x25), INS_SIGN_TRANSFER (0x06),
     *       INS_VERIFY_TRANSFER (0x14), INS_UPDATE_USER_PIN (0x19), INS_SET_CARD_DATA (0x26),
     *       INS_IS_CARD_ALIVE (0x2E)</li>
     *   <li><b>Master PIN required:</b>
     *       INS_UPDATE_USER_PIN (0x19) — masterPIN.isValidated()</li>
     *   <li><b>User PIN required (or PIN-less within limits):</b>
     *       INS_SIGN_TRANSFER (0x06) — userPIN verified via validatePIN() or isPINlessEligible()</li>
     *   <li><b>SCP03 secure channel required (CLA 0x84, C-MAC wrapped):</b>
     *       INS_SCP03_PROVISION_PIN (0x70), INS_SCP03_APPLET_UPDATE (0x71)
     *       — only reachable through scp03.unwrapCommand(); the plain CLA 0x80
     *       dispatch path was removed (per-command MACs are mandatory)</li>
     *   <li><b>Provisioning gate (install-time FLAG_INSTALL_ENFORCE):</b>
     *       INS_SIGN_TRANSFER (0x06), INS_SIGN_AUTH (0x25) answer 0x6985 until
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
                // GlobalPlatform channel setup. PROVISION_PIN / APPLET_UPDATE are
                // deliberately NOT dispatched here: without per-command C-MACs the
                // plain CLA 0x80 path would accept unauthenticated payloads on an
                // open session — they are only reachable via the secured CLA 0x84
                // path below (scp03.unwrapCommand verifies the MAC per command).
                switch (ins) {
                    case (byte) 0x50: { // INITIALIZE UPDATE
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
            }

            // --- Standard INS dispatch (CLA 0x00 or unwrapped CLA 0x84) ---
            switch (buffer[ISO7816.OFFSET_INS]) {
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
                        processUpdateUserPIN(apdu);
                        return;
                    } else {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // 0x6985
                    }
                    return;
                }
                case INS_VERIFY_PIN: {
                    failIfCardIsTerminated();
                    processVerifyPIN(apdu);
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
                    signAuth(apdu, buffer, dataLength);
                    break;
                }
                case INS_SIGN_TRANSFER: {
                    failIfCardIsTerminated();
                    failIfProvisioningRequired();
                    boolean pinless = isPINlessEligible(buffer);
                    if (pinless || validatePIN(buffer, ISO7816.OFFSET_CDATA, USER_PIN_LENGTH)) {
                        signTransfer(buffer, dataLength, pinless);
                        sendBytes(apdu, scratchpad, ZERO,
                                (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH + MAX_SIG_LENGTH));
                    }
                    break;
                }
                case INS_VERIFY_TRANSFER: {
                    failIfCardIsTerminated();
                    verifyTransfer(buffer, dataLength);
                    break;
                }
                case INS_GET_EC_PUB_KEY: {
                    // check if null to prevent a NullPointerException
                    if (cardECPublicKey != null) {
                        cardECPublicKey.getW(scratchpad, ZERO);
                    }
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
        }
    }

    /** Throws an exception if the card has been permanently terminated. */
    private void failIfCardIsTerminated() {
        if (terminated) {
            ISOException.throwIt(SW_ERROR_CARD_TERMINATED);
        }
    }

    /**
     * Throws 0x6985 when install-time policy (FLAG_INSTALL_ENFORCE) requires a
     * provisioned user PIN before the card may sign (SIGN_TRANSFER / SIGN_AUTH).
     * The gate is lifted by install-time PIN injection (FLAG_INSTALL_PINS) or
     * by provisioning a user PIN over the SCP03 channel.
     */
    private void failIfProvisioningRequired() {
        if (provisioningEnforced && !pinProvisioned) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

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
     * [0x01][flags] [ENC(16)|MAC(16)|DEK(16) if flags&amp;0x02] [masterPIN(8)|userPIN(4) if flags&amp;0x04].
     * FLAG_INSTALL_ENFORCE (0x01) gates SIGN_TRANSFER and SIGN_AUTH with 0x6985
     * until a user PIN is provisioned (here, or later via SCP03 PROVISION_PIN).
     * The whole TLV is validated before any state is mutated.
     */
    private void applyProvisioningParameters(byte[] bArray, short offset, short length) {
        if (length < 2 || bArray[offset] != TAG_INSTALL_PROVISIONING) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte flags = bArray[(short) (offset + 1)];
        if ((byte) (flags & ~(FLAG_INSTALL_ENFORCE | FLAG_INSTALL_KEYS | FLAG_INSTALL_PINS)) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA); // unknown flag bits
        }

        short expectedLength = 2;
        if ((flags & FLAG_INSTALL_KEYS) != 0) {
            expectedLength += SCP03_KEY_SET_LENGTH;
        }
        if ((flags & FLAG_INSTALL_PINS) != 0) {
            expectedLength += INSTALL_PIN_BLOCK_LENGTH;
        }
        if (length != expectedLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short cursor = (short) (offset + 2);
        short keysOffset = -1;
        short pinsOffset = -1;
        if ((flags & FLAG_INSTALL_KEYS) != 0) {
            keysOffset = cursor;
            cursor += SCP03_KEY_SET_LENGTH;
        }
        if ((flags & FLAG_INSTALL_PINS) != 0) {
            pinsOffset = cursor;
            // The all-zeros user PIN is reserved for PIN-less transfers
            if (Util.arrayCompare(bArray, (short) (pinsOffset + MASTER_PIN_LENGTH),
                    FOUR_ZERO_PIN, ZERO, USER_PIN_LENGTH) == 0) {
                ISOException.throwIt(SW_ERROR_PIN_REJECTED);
            }
        }

        // All validation passed — apply
        if (keysOffset >= 0) {
            scp03.setStaticKeys(bArray, keysOffset,
                    bArray, (short) (keysOffset + 16),
                    bArray, (short) (keysOffset + 32));
        }
        if (pinsOffset >= 0) {
            masterPIN.update(bArray, pinsOffset, MASTER_PIN_LENGTH);
            userPIN.update(bArray, (short) (pinsOffset + MASTER_PIN_LENGTH), USER_PIN_LENGTH);
            pinProvisioned = true;
        }
        if ((flags & FLAG_INSTALL_ENFORCE) != 0) {
            provisioningEnforced = true;
        }
    }

    /**
     * Processes a PIN provisioning command received over the SCP03 secure channel.
     * Payload: [PIN_TYPE (1B)] [PIN_LENGTH (1B)] [PIN_DATA (var)].
     * PIN_TYPE 0x81 = master PIN (8 digits), 0x82 = user PIN (4 digits).
     */
    private void processProvisionPIN(byte[] buffer, short dataLength) {
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
     * Used for key rotation and applet reconfiguration — not CAP-file replacement.
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

        // Sequence 0x0001: SCP03 key rotation
        if (seq == (short) 0x0001 && len == (short) 48) {
            // Data = newENC(16) + newMAC(16) + newDEK(16)
            scp03.setStaticKeys(
                    buffer, updateDataOffset,
                    buffer, (short) (updateDataOffset + 16),
                    buffer, (short) (updateDataOffset + 32));
        }
        // Other sequences can be added for future applet reconfiguration
    }

    /**
     * Read-only eligibility check for PIN-less transfers: true when the PIN field
     * is all zeros, the amount is within the PIN-less limit, and the consecutive
     * PIN-less counter has headroom. Deliberately does NOT increment the counter —
     * signTransfer() commits the increment atomically with the balance mutation,
     * so failed or torn transfers no longer burn PIN-less budget.
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
     * Signs an outgoing transfer transaction. Validates the sender is this card,
     * the recipient is not this card, and sufficient funds exist.
     *
     * Note: SIGN_TRANSFER is deliberately NOT domain-tagged like SIGN_AUTH —
     * tagging it would break card-to-card verifyTransfer for already-flashed CAPs.
     *
     * Response format: [signature (72B) | pubKey (65B) | pubKeySig (72B)]
     *
     * @param pinless true when this transfer was authorized PIN-less; the
     *                PIN-less counter is then incremented atomically with the
     *                balance mutation (tearing-safe)
     */
    private void signTransfer(byte[] buffer, short dataLength, boolean pinless) {
        if (dataLength != (short) (USER_PIN_LENGTH + SIGNABLE_LENGTH)) {
            ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH);
        }

        boolean senderIsMe = Util.arrayCompare(buffer,
                (short) (OFFSET_SIGNABLE + TransactionParser.OFFSET_SENDER),
                accountId, ZERO, UUID_LENGTH) == 0;
        if (!senderIsMe) {
            ISOException.throwIt(SW_ERROR_WRONG_SENDER);
        }

        boolean recipientIsMe = Util.arrayCompare(buffer,
                (short) (OFFSET_SIGNABLE + TransactionParser.OFFSET_RECIPIENT),
                accountId, ZERO, UUID_LENGTH) == 0;
        if (recipientIsMe) {
            ISOException.throwIt(SW_ERROR_WRONG_RECIPIENT);
        }

        // Currency validation: if the card has a currency set (non-zero),
        // verify the transaction currency matches.
        if (currency[0] != 0 || currency[1] != 0 || currency[2] != 0 || currency[3] != 0) {
            if (Util.arrayCompare(buffer,
                    (short) (OFFSET_SIGNABLE + TransactionParser.OFFSET_CURRENCY),
                    currency, ZERO, (short) 4) != 0) {
                ISOException.throwIt(Constants.SW_ERROR_WRONG_CURRENCY);
            }
        }

        TransactionParser.getAmount(buffer, OFFSET_SIGNABLE, tempAmount);
        if (!checkAmount(tempAmount)) {
            ISOException.throwIt(SW_INSUFFICIENT_FUNDS); // 0x6224
        }

        TransactionParser.getCounter(buffer, OFFSET_SIGNABLE, tempCounter);
        if (isNegative(tempCounter)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        signWithMyKey(buffer, OFFSET_SIGNABLE, SIGNABLE_LENGTH);
        // copy pubKey to scratchpad
        cardECPublicKey.getW(scratchpad, ZERO);
        // makeHashable will use the pubKey in scratchpad
        makeHashable(buffer, OFFSET_SIGNABLE,
                sigBuffer, ZERO,
                scratchpad, ZERO,
                SIXTY_FOUR_ZEROES, ZERO);

        JCSystem.beginTransaction();

        subtractFromBalance(tempAmount);
        if (pinless) {
            // Committed atomically with the balance mutation: a torn or failed
            // transfer burns no PIN-less budget (see isPINlessEligible)
            howManyPINless++;
        }

        JCSystem.commitTransaction();

        // FROM THIS POINT ONWARD, THE SCRATCHPAD IS USED TO STORE THE RESPONSE
        Util.arrayCopyNonAtomic(sigBuffer, ZERO, scratchpad, ZERO, MAX_SIG_LENGTH);
        cardECPublicKey.getW(scratchpad, MAX_SIG_LENGTH);
        Util.arrayCopyNonAtomic(SIXTY_FOUR_ZEROES, ZERO,
                scratchpad, (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH),
                (short) SIXTY_FOUR_ZEROES.length);
    }

    /**
     * Verifies and accepts an incoming transfer in two phases:
     * - P1=0x00: Receives the signable transaction data (60 bytes)
     * - P1=0x01: Receives signature + pubKey + pubKeySig, verifies all cryptographic
     *   proofs, checks the recipient is this card, enforces the strictly-increasing
     *   receive counter (replay protection), and credits the amount to the on-card
     *   balance atomically with the counter advance.
     *
     * NOTE (tracking): verification trusts the public key embedded in the message
     * tail — the trust chain on that key (pubKeySig) is established off-card, not
     * by this applet.
     */
    private void verifyTransfer(byte[] buffer, short dataLength) {
        if (buffer[ISO7816.OFFSET_P1] == 0x00) {
            if (dataLength != SIGNABLE_LENGTH) {
                ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH);
            }
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, signableBuffer, ZERO, SIGNABLE_LENGTH);
        }
        if (buffer[ISO7816.OFFSET_P1] == 0x01) {
            if (dataLength != (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH + MAX_SIG_LENGTH)) {
                ISOException.throwIt(SW_ERROR_WRONG_TAIL_LENGTH);
            }

            // set the tempPubKey to the public key in the transfer to be verified
            tempPubKey.setW(buffer, (short) (ISO7816.OFFSET_CDATA + MAX_SIG_LENGTH), PUB_KEY_LENGTH);

            boolean messageVerified = verifySig(signableBuffer, ZERO, SIGNABLE_LENGTH,
                    buffer, ISO7816.OFFSET_CDATA,
                    (short) (buffer[(short) (ISO7816.OFFSET_CDATA + 1)] + TAG_LENGTH_LENGTH),
                    tempPubKey);
            if (!messageVerified) {
                ISOException.throwIt(SW_ERROR_SIGNATURE_VERIFICATION_FAILED);
            }

            // check that the sender is NOT this card (receiving a transfer, not sending)
            boolean senderIsMe = Util.arrayCompare(signableBuffer,
                    TransactionParser.OFFSET_SENDER,
                    accountId, ZERO, UUID_LENGTH) == 0;
            if (senderIsMe) {
                ISOException.throwIt(SW_ERROR_WRONG_SENDER);
            }

            // check that the recipient IS this card
            boolean recipientIsMe = Util.arrayCompare(signableBuffer,
                    TransactionParser.OFFSET_RECIPIENT,
                    accountId, ZERO, UUID_LENGTH) == 0;
            if (!recipientIsMe) {
                ISOException.throwIt(SW_ERROR_WRONG_RECIPIENT);
            }

            // Replay protection: the signable's counter must be strictly greater
            // than the last counter this card accepted a credit for.
            //
            // Counter scope: ONE stream per receiving card, not per sender. The
            // sending side persists no counter of its own — signTransfer signs
            // whatever non-negative counter the coordinating host puts in the
            // signable — so incoming counters are allocated per recipient by the
            // transfer coordinator (as in the original seenOfflineCounter
            // design). Strictly-greater rather than exactly stored+1 so that a
            // signed-but-never-presented transfer cannot jam the stream: gaps
            // are acceptable, repeats are not. Zero is never accepted because
            // the stored counter starts at zero.
            TransactionParser.getCounter(signableBuffer, ZERO, tempCounter);
            if (isNegative(tempCounter) ||
                    ArrayUtil.unsignedByteArrayCompare(tempCounter, ZERO,
                            lastReceiveCounter, ZERO, INT32_LENGTH) <= 0) {
                ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
            }

            // Credit the transfer amount to on-card balance. The counter
            // advances in the same transaction as the credit, so a tear can
            // never credit without consuming the counter (or vice versa).
            TransactionParser.getAmount(signableBuffer, ZERO, tempAmount);

            JCSystem.beginTransaction();
            addToBalance(tempAmount);
            Util.arrayCopy(tempCounter, ZERO, lastReceiveCounter, ZERO, INT32_LENGTH);
            JCSystem.commitTransaction();

            // Consume the buffered signable: a repeated P1=0x01 tail must not
            // be able to re-verify against it within the same session.
            Util.arrayFillNonAtomic(signableBuffer, ZERO, SIGNABLE_LENGTH, (byte) 0);
        }
    }

    /**
     * Assembles a hashable transaction record from the signable data, signature,
     * public key, and public key signature (all converted to raw bytes), then
     * computes its SHA-256 hash.
     */
    private void makeHashable(byte[] signable, short signableOffset,
            byte[] sig, short sigOffset,
            byte[] pubKey, short pubKeyOffset,
            byte[] pubKeySig, short pubKeySigOffset) {
        Util.arrayCopy(signable, signableOffset, hashable.contents, ZERO, SIGNABLE_LENGTH);
        CryptoPrimitivesConverter.convertSignatureToRawBytes(sig, sigOffset,
                hashable.contents, SIGNABLE_LENGTH);
        CryptoPrimitivesConverter.convertPublicKeyToRawBytes(pubKey, pubKeyOffset,
                hashable.contents, (short) (SIGNABLE_LENGTH + 64));
        CryptoPrimitivesConverter.convertSignatureToRawBytes(pubKeySig, pubKeySigOffset,
                hashable.contents, (short) (SIGNABLE_LENGTH + 64 + 64));

        messageDigest.doFinal(hashable.contents, ZERO, HASHABLE_LENGTH, hashable.hash, ZERO);
    }

    /**
     * Updates the user PIN. Requires prior master PIN verification.
     * Rejects the all-zeros PIN (0000) as it is reserved for PIN-less transfers.
     */
    private void processUpdateUserPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        short count = apdu.setIncomingAndReceive();
        if (count < pinLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // SIGN_TRANSFER always checks exactly USER_PIN_LENGTH digits, so a PIN
        // stored with any other length could never verify again — every attempt
        // would burn a retry until the user PIN blocks. Enforce the same fixed
        // length the SCP03 provisioning path does.
        if (pinLength != USER_PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, FOUR_ZERO_PIN, ZERO, pinLength) == 0) {
            ISOException.throwIt(SW_ERROR_PIN_REJECTED);
        }
        userPIN.update(buffer, ISO7816.OFFSET_CDATA, pinLength);
    }

    /**
     * Handles Verify Pin APDU.
     *
     * @param apdu APDU object
     */
    private void processVerifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        byte triesRemaining;
        short count = apdu.setIncomingAndReceive(); // get expected data
        if (count < pinLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
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

    /** Returns true if the given amount is less than or equal to the current balance. */
    private boolean checkAmount(byte[] amount) {
        return ArrayUtil.unsignedByteArrayCompare(amount, ZERO, myBalance, ZERO, INT64_LENGTH) <= ZERO;
    }

    /** Adds an 8-byte unsigned amount to the on-card balance using byte-level arithmetic. */
    private void addToBalance(byte[] amount) {
        short carry = 0;
        for (short i = INT64_LENGTH - 1; i >= 0; i--) {
            short x = (short) (this.myBalance[i] & 0xFF);
            short y = (short) (amount[i] & 0xFF);
            short result = (short) (x + y + carry);
            this.myBalance[i] = (byte) result;
            carry = (short) ((result >> 8) & 1);
        }
        if (carry != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID); // balance overflow
        }
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
     * roughly 2*paddedLen + 18 bytes of APDU buffer; oversized responses
     * surface as 0x6689 rather than leaking unwrapped data.
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

package com.impala.applet;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javacard.framework.APDU;

import static com.impala.applet.ArrayUtil.isNegative;
import static com.impala.applet.ArrayUtil.isPositive;
import static com.impala.applet.ArrayUtil.isSmallerOrEqual;
import static com.impala.applet.ArrayUtil.isZero;
import static com.impala.applet.BuildConfig.GIT_HASH_SHORT;
import static com.impala.applet.BuildConfig.GIT_REV_LIST;
import static com.impala.applet.BuildConfig.MAJOR_VERSION;
import static com.impala.applet.BuildConfig.MINOR_VERSION;
import static com.impala.applet.Constants.HASHABLE_LENGTH;
import static com.impala.applet.Constants.HASH_LENGTH;
import static com.impala.applet.Constants.INIT_LENGTH;
import static com.impala.applet.Constants.INS_DELETE_LUKS;
import static com.impala.applet.Constants.INS_DELETE_TRANSFER;
import static com.impala.applet.Constants.INS_GET_ACCOUNT_ID;
import static com.impala.applet.Constants.INS_GET_BALANCE;
import static com.impala.applet.Constants.INS_GET_CARD_NONCE;
import static com.impala.applet.Constants.INS_GET_EC_PUB_KEY;
import static com.impala.applet.Constants.INS_GET_FULL_NAME;
import static com.impala.applet.Constants.INS_GET_GENDER;
import static com.impala.applet.Constants.INS_GET_HASH_BATCH;
import static com.impala.applet.Constants.INS_GET_OFFLINE_COUNTER;
import static com.impala.applet.Constants.INS_GET_RSA_PUB_KEY;
import static com.impala.applet.Constants.INS_GET_TRANSFER;
import static com.impala.applet.Constants.INS_GET_USER_DATA;
import static com.impala.applet.Constants.INS_GET_VERSION;
import static com.impala.applet.Constants.INS_INITIALIZE;
import static com.impala.applet.Constants.INS_IS_CARD_ALIVE;
import static com.impala.applet.Constants.INS_NOP;
import static com.impala.applet.Constants.INS_SET_CARD_DATA;
import static com.impala.applet.Constants.INS_SET_FULL_NAME;
import static com.impala.applet.Constants.INS_SET_GENDER;
import static com.impala.applet.Constants.INS_SIGN_AUTH;
import static com.impala.applet.Constants.INS_SIGN_TRANSFER;
import static com.impala.applet.Constants.INS_SUICIDE;
import static com.impala.applet.Constants.INS_UPDATE_MASTER_PIN;
import static com.impala.applet.Constants.INS_UPDATE_USER_PIN;
import static com.impala.applet.Constants.INS_VERIFY_PIN;
import static com.impala.applet.Constants.INS_VERIFY_TRANSFER;
import static com.impala.applet.Constants.INT32_LENGTH;
import static com.impala.applet.Constants.INT64_LENGTH;
import static com.impala.applet.Constants.MAX_SIG_LENGTH;
import static com.impala.applet.Constants.ONE;
import static com.impala.applet.Constants.P2_MASTER_PIN;
import static com.impala.applet.Constants.P2_USER_PIN;
import static com.impala.applet.Constants.PUB_KEY_LENGTH;
import static com.impala.applet.Constants.SIGNABLE_LENGTH;
import static com.impala.applet.Constants.TAG_LENGTH_LENGTH;
import static com.impala.applet.Constants.TWO;
import static com.impala.applet.Constants.UUID_LENGTH;
import static com.impala.applet.Constants.INS_SCP03_PROVISION_PIN;
import static com.impala.applet.Constants.INS_SCP03_APPLET_UPDATE;
import static com.impala.applet.Constants.ZERO;

/**
 * Main JavaCard applet for the Impala payment card.
 *
 * Handles APDU commands for account management, PIN verification, transaction
 * signing/verification, cryptographic key operations, and card lifecycle management.
 * Supports both online (server-signed) and offline (LUK-signed) payment transfers
 * with balance tracking stored on-card.
 */
public class ImpalaApplet extends Applet {
    // --- Status word constants for APDU error responses ---
    public static final short SW_ERROR_KEY_VERIFICATION_FAILED = 0x0022;
    public static final short SW_ERROR_SIGNATURE_VERIFICATION_FAILED = 0x0023;
    public static final short SW_INSUFFICIENT_FUNDS = 0x6224;
    public static final short SW_INSUFFICIENT_LUK_LIMIT = 0x6225;
    public static final short SW_ERROR_WRONG_SIGNABLE_LENGTH = 0x6226;
    public static final short SW_ERROR_INIT_SIGNER = 0x6227;
    public static final short SW_ERROR_LUK_MISSING = 0x6228;
    public static final short SW_ERROR_WRONG_KEY_LENGTH = 0x6229;
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
    public static final short SW_ERROR_CARD_DATA_SIGNATURE_INVALID = 0x6677;
    public static final short SW_ERROR_CARD_DATA_NONCE_INVALID = 0x6678;
    public static final short SW_ERROR_WRONG_CARD_ID = 0x6679;
    public static final short SW_ERROR_CRYPTO_EXCEPTION = 0x6683;
    public static final short SW_ERROR_INVALID_AES_KEY = 0x6684;
    public static final short SW_ERROR_ALREADY_INITIALIZED = 0x6686;
    public static final short SW_ERROR_CARD_TERMINATED = 0x6687;
    public static final short SW_ERROR_NULL_POINTER_EXCEPTION = 0x6688;
    public static final short SW_ERROR_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION = 0x6689;
    public static final short SW_ERROR_PIN_REQUIRED = 0x6690;
    public static final short SW_ERROR_PIN_REJECTED = 0x6691;

    private static final short AES_IV_LENGTH = 16;
    private static final short RSA_PUB_MOD_LENGTH = 128; // 1024-bit RSA modulus

    // Field offsets within the SET_CARD_DATA APDU payload
    private static final short OFFSET_ACCOUNT_ID = ISO7816.OFFSET_CDATA;
    private static final short OFFSET_CARD_ID = OFFSET_ACCOUNT_ID + UUID_LENGTH;
    private static final short OFFSET_CARD_NONCE = OFFSET_CARD_ID + UUID_LENGTH;
    private static final short OFFSET_CURRENCY = OFFSET_CARD_NONCE + INT32_LENGTH;
    private static final short OFFSET_MY_BALANCE = OFFSET_CURRENCY + 4;

    private static final byte USER_PIN_LENGTH = 4;
    // In SIGN_TRANSFER, the signable data starts after the 4-byte user PIN
    private static final short OFFSET_SIGNABLE = ISO7816.OFFSET_CDATA + USER_PIN_LENGTH;

    private static final short MAX_PINLESS_TRANSFERS = 4; // max consecutive transfers without PIN
    private static final short MAX_FULL_NAME_LENGTH = 128;
    private static final short MAX_GENDER_LENGTH = 16;

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
    private Cipher cipherAES;          // AES-128-CBC decryption (session key transport)
    private Cipher cipherRSA;          // RSA PKCS#1 decryption (master PIN update)
    private MessageDigest messageDigest; // SHA-256 for transaction hashing
    private RandomData randomData;     // Secure RNG for card ID and nonces
    private Signature signer;          // ECDSA-SHA256 signing with card key
    private Signature verifier;        // ECDSA-SHA256 verification with program key

    // --- Card lifecycle state ---
    private boolean initialized;       // True after INS_INITIALIZE generates keys
    private boolean terminated;        // True after INS_SUICIDE; card becomes inoperable

    // --- Account and balance data (persisted in EEPROM) ---
    private byte[] accountId;          // 16-byte UUID linking to Payala account
    private byte[] cardId;             // 16-byte UUID unique to this card, randomly generated
    private byte[] currency;           // 4-byte currency code
    private byte[] myBalance;          // 8-byte (int64) on-card balance in lowest denomination

    // --- Cryptographic keys ---
    private ECPrivateKey cardECPrivateKey;   // Card's EC private key (secp256r1) for signing
    private ECPublicKey cardECPublicKey;     // Card's EC public key (secp256r1)
    private RSAPrivateKey cardRSAPrivateKey; // Card's RSA-1024 private key for decryption
    private RSAPublicKey cardRSAPublicKey;   // Card's RSA-1024 public key
    private byte[] sessionIV;               // AES initialization vector for session encryption
    private AESKey sessionKey;              // AES-256 session key

    // --- Cardholder data ---
    private byte[] fullName;
    private short fullNameLength;
    private byte[] gender;
    private short genderLength;
    private OwnerPIN masterPIN;        // Administrative PIN (10 retries, 8 digits)
    private OwnerPIN userPIN;          // Cardholder PIN (5 retries, 4 digits)
    private byte howManyPINless;       // Counter for consecutive PIN-less transfers

    // --- Transient working buffers (cleared on card reset) ---
    private byte[] scratchpad;         // General-purpose transient buffer (255 bytes)
    private byte[] sigBuffer;          // Holds signature output from signing operations
    private byte[] signableBuffer;     // Holds signable data during two-phase verify
    private byte[] tempAmount;         // Temporary buffer for parsed transaction amount
    private byte[] tempCounter;        // Temporary buffer for parsed transaction counter
    private byte[] tempPlusOne;        // Temporary buffer for counter+1 comparison
    private ECPublicKey tempPubKey;    // Reusable EC public key for transfer verification

    // --- SCP03 secure channel ---
    private SCP03 scp03;

    // --- Transaction hash storage ---
    private byte[] hashBuffer;
    private Hashable hashable;         // Reusable hashable object for transaction records
    public Repository repository;      // On-card store of transaction hashes

    /**
     * Private constructor called during applet installation.
     * Initializes all crypto engines, allocates persistent and transient buffers,
     * sets default PINs, and generates a random card ID.
     */
    private ImpalaApplet(byte[] bArray, short bOffset, byte bLength) {
        // ! >> WalletCardlet()
        cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
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

        cardECPrivateKey = null;
        cardECPublicKey = null;
        cardRSAPrivateKey = null;
        cardRSAPublicKey = null;
        sessionIV = new byte[] {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };
        sessionKey = null;

        fullName = new byte[MAX_FULL_NAME_LENGTH];
        fullNameLength = 0;
        gender = new byte[MAX_GENDER_LENGTH];
        genderLength = 0;
        masterPIN = new OwnerPIN((byte) 10, (byte) 8); // retries:10 and length:8
        masterPIN.update(new byte[] { 1, 4, 1, 1, 7, 2, 9, 8 }, ZERO, (byte) 8);
        userPIN = new OwnerPIN((byte) 5, (byte) 5); // retries:5 and length:5
        userPIN.update(new byte[] { 1, 1, 1, 1 }, ZERO, USER_PIN_LENGTH);
        howManyPINless = 0;

        scratchpad = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        sigBuffer = JCSystem.makeTransientByteArray(MAX_SIG_LENGTH, JCSystem.CLEAR_ON_RESET);
        signableBuffer = JCSystem.makeTransientByteArray(SIGNABLE_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempAmount = JCSystem.makeTransientByteArray(INT64_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempCounter = JCSystem.makeTransientByteArray(INT32_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempPlusOne = JCSystem.makeTransientByteArray(INT32_LENGTH, JCSystem.CLEAR_ON_RESET);
        tempPubKey = SecP256r1.newPubKey();

        hashBuffer = JCSystem.makeTransientByteArray(HASH_LENGTH, JCSystem.CLEAR_ON_RESET);
        hashable = new Hashable(JCSystem.makeTransientByteArray(HASH_LENGTH, JCSystem.CLEAR_ON_RESET),
                JCSystem.makeTransientByteArray(HASHABLE_LENGTH, JCSystem.CLEAR_ON_RESET));
        repository = new Repository((short) 7, REPOSITORY_CAPACITY);

        // SCP03 secure channel — default static keys (matches gp-master.jar defaults: 0x40..0x4F)
        scp03 = new SCP03(randomData);
        byte[] defaultKey = new byte[] {
                (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43,
                (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
                (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B,
                (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x4F
        };
        scp03.setStaticKeys(defaultKey, ZERO, defaultKey, ZERO, defaultKey, ZERO);

        register();
        // ! << WalletCardlet()
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
        // ! select()
        return true;
    }

    /**
     * Performs the session finalization.
     */
    @Override
    public void deselect() {
        // ! deselect() | called.
        // ! deselect() | userPIN.reset
        userPIN.reset();
        // ! deselect() | masterPIN.reset
        masterPIN.reset();
        // Tear down SCP03 secure channel
        scp03.reset();
    }

    /**
     * Processes an incoming APDU. Will always respond with the helloFidesmo string,
     * regardless of what is received.
     *
     * @param apdu the incoming APDU
     * @throws ISOException with the response bytes per ISO 7816-4
     * @see APDU
     */
    @Override
    public void process(APDU apdu) {
        try {
            // ! process() | Start...
            // ---------------=========+++++++++=========---------------
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

            if (cla == (byte) 0x80) {
                // GlobalPlatform commands (unsecured channel setup + SCP03-protected commands)
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
                    case INS_SCP03_PROVISION_PIN: {
                        failIfCardIsTerminated();
                        if (!scp03.isAuthenticated()) {
                            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        }
                        apdu.setIncomingAndReceive();
                        processProvisionPIN(buffer, dataLength);
                        return;
                    }
                    case INS_SCP03_APPLET_UPDATE: {
                        failIfCardIsTerminated();
                        if (!scp03.isAuthenticated()) {
                            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        }
                        apdu.setIncomingAndReceive();
                        processAppletUpdate(buffer, dataLength);
                        return;
                    }
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        return;
                }
            }

            if (cla == (byte) 0x84) {
                // Secured APDU — unwrap, then fall through to normal dispatch
                apdu.setIncomingAndReceive();
                dataLength = scp03.unwrapCommand(buffer, ISO7816.OFFSET_CDATA, dataLength);
            }

            // --- Standard INS dispatch (CLA 0x00 or unwrapped CLA 0x84) ---
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_INITIALIZE: {
                    failIfCardIsTerminated();
                    if (!initialized) {
                        randomData.setSeed(buffer, ISO7816.OFFSET_CDATA, dataLength);
                        // ! Overwrite cardId

                        randomData.generateData(cardId, ZERO, UUID_LENGTH);

                        // ! Generate key pairs
                        createECKeypair();
                        createRSAKeypair();
                        sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                                KeyBuilder.LENGTH_AES_256, false);

                        initialized = true;
                    } else {
                        ISOException.throwIt(SW_ERROR_ALREADY_INITIALIZED);
                    }
                    break;
                }
                case INS_UPDATE_USER_PIN: {
                    failIfCardIsTerminated();
                    // ! INS_UPDATE_USER_PIN
                    if (masterPIN.isValidated()) {
                        // ! process() | Master PIN is validated
                        processUpdateUserPIN(apdu);
                        return;
                    } else {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // 0x6985
                    }
                    return;
                }
                case INS_VERIFY_PIN: {
                    failIfCardIsTerminated();
                    // ! INS_VERIFY_PIN
                    processVerifyPIN(apdu);
                    break;
                }
                case INS_UPDATE_MASTER_PIN: {
                    failIfCardIsTerminated();
                    // ! INS_UPDATE_MASTER_PIN
                    updateMasterPIN(buffer);
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
                    signAuth(apdu, buffer, dataLength);
                    break;
                }
                case INS_SIGN_TRANSFER: {
                    failIfCardIsTerminated();
                    if (checkPINless(buffer) || validatePIN(buffer, ISO7816.OFFSET_CDATA, USER_PIN_LENGTH)) {
                        signTransfer(buffer, dataLength);
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
                case INS_GET_RSA_PUB_KEY: {
                    // check if null to prevent a NullPointerException
                    if (cardRSAPublicKey != null) {
                        cardRSAPublicKey.getModulus(scratchpad, ZERO);
                    }
                    sendBytes(apdu, scratchpad, ZERO, RSA_PUB_MOD_LENGTH);
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
                case INS_SET_CARD_DATA: {
                    failIfCardIsTerminated();
                    setCardData(apdu, buffer);
                    break;
                }
                case INS_SUICIDE: {
                    suicide(buffer, dataLength);
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

    /** Throws an exception if the card has been permanently terminated via INS_SUICIDE. */
    private void failIfCardIsTerminated() {
        if (terminated) {
            ISOException.throwIt(SW_ERROR_CARD_TERMINATED);
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
     * Checks if a transfer can proceed without PIN verification.
     * Allowed when the PIN field is all zeros, the amount is within the PIN-less limit,
     * and the number of consecutive PIN-less transfers hasn't been exceeded.
     */
    private boolean checkPINless(byte[] buffer) {
        // ! checkPINless | 1. check pin is 0000
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, FOUR_ZERO_PIN, ZERO, USER_PIN_LENGTH) == 0) {
            // ! checkPINless | 2. check amount is < 200
            // ! checkPINless | 3. check howManyPINless < MAX_PINLESS_TRANSFERS
            TransactionParser.getAmount(buffer, OFFSET_SIGNABLE, tempAmount);
            if (ArrayUtil.unsignedByteArrayCompare(tempAmount, ZERO, PINLESS_LIMIT, ZERO, INT64_LENGTH) <= 0 &&
                    howManyPINless < MAX_PINLESS_TRANSFERS) {
                // ! checkPINless | 4. increase howManyPINless
                howManyPINless++;
                return true;
            }
            // if this verification fails, throw an exception
            ISOException.throwIt(SW_ERROR_PIN_REQUIRED);
        }
        return false;
    }

    /**
     * Updates the master PIN. The new PIN is RSA-encrypted in the APDU payload,
     * accompanied by a nonce (for replay protection) and a server signature.
     */
    private void updateMasterPIN(byte[] buffer) {
        // ! updateMasterPIN() | buffer: {buffer}
        decryptWithRSA(buffer, ISO7816.OFFSET_CDATA, (short) 128);
        byte[] nonce = new byte[4];
        Util.arrayCopy(scratchpad, ZERO, nonce, ZERO, (short) 4);

        boolean nonceOk = verifyNonce(nonce);
        if (!nonceOk) {
            ISOException.throwIt(SW_ERROR_CARD_DATA_NONCE_INVALID);
        } else {
            cardNonces.delete(new CardNonce(nonce));
        }

        short sigOffset = (short) (128 + ISO7816.OFFSET_CDATA);
        short sigLength = (short) (buffer[(short) (sigOffset + ONE)] + TWO);

        boolean verified = verifySig(buffer, ISO7816.OFFSET_CDATA, (short) 128,
                buffer, sigOffset, sigLength, masterPublicKey);

        if (verified) {
            // ! updating master pin
            masterPIN.update(scratchpad, (short) 4, (byte) 0x8);
        } else {
            ISOException.throwIt(SW_ERROR_SIGNATURE_VERIFICATION_FAILED);
        }

        // run garbage collector
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
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
     * Sets card account data (account ID, currency, balance) from a server-signed payload.
     * Verifies the server signature, card ID match, and nonce before updating persistent state
     * within an atomic transaction.
     */
    private void setCardData(APDU apdu, byte[] buffer) {
        short payloadLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xff);
        boolean success = verifySig(buffer, ISO7816.OFFSET_CDATA, INIT_LENGTH,
                buffer, (short) (ISO7816.OFFSET_CDATA + INIT_LENGTH), (short) (payloadLength - INIT_LENGTH),
                masterPublicKey);

        if (!success) {
            ISOException.throwIt(SW_ERROR_CARD_DATA_SIGNATURE_INVALID);
        }

        // Verify cardId (return error)
        boolean cardIdOk = Util.arrayCompare(buffer, OFFSET_CARD_ID, cardId, ZERO, UUID_LENGTH) == 0;
        if (!cardIdOk) {
            ISOException.throwIt(SW_ERROR_WRONG_CARD_ID);
        }

        // Verify nonce (return error)
        byte[] nonceBytes = new byte[4];
        Util.arrayCopy(buffer, OFFSET_CARD_NONCE, nonceBytes, ZERO, INT32_LENGTH);
        boolean nonceOk = verifyNonce(nonceBytes);
        if (!nonceOk) {
            ISOException.throwIt(SW_ERROR_CARD_DATA_NONCE_INVALID);
        } else {
            cardNonces.delete(new CardNonce(nonceBytes));
        }

        JCSystem.beginTransaction();

        Util.arrayCopy(buffer, OFFSET_ACCOUNT_ID, accountId, ZERO, UUID_LENGTH);
        Util.arrayCopy(buffer, OFFSET_CURRENCY, currency, ZERO, (short) 4);
        Util.arrayCopy(buffer, OFFSET_MY_BALANCE, myBalance, ZERO, INT64_LENGTH);
        // ! setCardData() | new myBalance: {myBalance}

        JCSystem.commitTransaction();

        // run garbage collector
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }

    /** Generates a random nonce and sends it to the terminal for replay protection. */
    private void sendCardNonce(APDU apdu) {
        // ! getCardNonce() |
        CardNonce nonce = new CardNonce(randomData);
        cardNonces.add(nonce);
        // ! getCardNonce() | Nonce: {nonce.bytes, (short)0, (short)nonce.bytes.length}
        sendBytes(apdu, nonce.bytes, ZERO, (short) nonce.bytes.length);
    }

    private boolean verifyNonce(byte[] bytes) {
        return cardNonces.contains(new CardNonce(bytes));
    }

    /**
     * Validates the user PIN from the APDU buffer. On failure, throws an ISOException
     * encoding the number of remaining tries in the status word. On success, resets
     * the PIN-less transfer counter.
     */
    private boolean validatePIN(byte[] buffer, short offset, byte length) {
        // ! >> validatePIN() entered PIN: {buffer, offset, length}
        if (!userPIN.check(buffer, offset, length)) {
            // ! processVerifyPIN() | User PIN verification failed
            short triesRemaining = userPIN.getTriesRemaining();
            // The last nibble of return code is number of remaining tries
            ISOException.throwIt((short) (SW_PIN_FAILED + triesRemaining));
        }
        // reset howManyPINless
        howManyPINless = 0;
        // ! << validatePIN()
        return true;
    }

    /** Signs an authentication challenge (accountId + challenge data) with the card's EC key. */
    private void signAuth(APDU apdu, byte[] buffer, short dataLength) {
        Util.arrayCopyNonAtomic(accountId, ZERO, scratchpad, ZERO, UUID_LENGTH);
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, scratchpad, UUID_LENGTH, dataLength);
        short sigLength = signWithMyKey(scratchpad, ZERO, (short) (UUID_LENGTH + dataLength));
        sendBytes(apdu, sigBuffer, ZERO, sigLength);
    }

    /**
     * Signs an outgoing transfer transaction. Validates the sender is this card,
     * the recipient is not this card, and sufficient funds exist. For offline transfers
     * (positive counter), signs with a Limited Use Key (LUK). For online transfers
     * (zero counter), signs with the card's permanent EC key. Deducts the amount
     * from balance and stores the transaction hash in the repository.
     *
     * Response format: [signature (72B) | pubKey (65B) | pubKeySig (72B)]
     */
    private void signTransfer(byte[] buffer, short dataLength) {
        // ! >> signTransfer
        if (dataLength != (short) (USER_PIN_LENGTH + SIGNABLE_LENGTH)) {
            ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH);
        }

        if (!repository.checkCapacity()) {
            ISOException.throwIt(SW_ERROR_STORAGE_OUT_OF_CAPACITY);
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

        // TODO: check currency

        TransactionParser.getAmount(buffer, OFFSET_SIGNABLE, tempAmount);
        if (!checkAmount(tempAmount)) {
            ISOException.throwIt(SW_INSUFFICIENT_FUNDS); // 0x6224
        }

        TransactionParser.getCounter(buffer, OFFSET_SIGNABLE, tempCounter);
        if (isNegative(tempCounter)) {
            ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
        }

        if (isPositive(tempCounter)) {
            if (!checkLUKLimit(tempAmount)) {
                ISOException.throwIt(SW_INSUFFICIENT_LUK_LIMIT);// 0x6225
            }
            signWithLUK(buffer, OFFSET_SIGNABLE, SIGNABLE_LENGTH);
            makeHashable(buffer, OFFSET_SIGNABLE,
                    sigBuffer, ZERO,
                    myLUKs[myLUKIndex].pubKeyBytes, ZERO,
                    myLUKs[myLUKIndex].sig, ZERO);

            JCSystem.beginTransaction();

            // no need to check whether repository.store succeeded because
            // repository.checkCapacity was called earlier
            repository.store(hashable);
            LUK currentLUK = myLUKs[myLUKIndex];
            // ! Delete current LUK and increase myLUKIndex
            myLUKs[myLUKIndex].valid = false;
            if (myLUKIndex < MAX_NUMBER_OF_LUKS - 1) {
                myLUKIndex++;
            }
            // ! Subtract myBalance after successful signing
            subtractFromBalance(tempAmount);

            JCSystem.commitTransaction();

            // FROM THIS POINT ONWARD, THE SCRATCHPAD IS USED TO STORE THE RESPONSE
            // copy to scratchpad
            Util.arrayCopyNonAtomic(sigBuffer, ZERO, scratchpad, ZERO, MAX_SIG_LENGTH);
            Util.arrayCopyNonAtomic(currentLUK.pubKeyBytes, ZERO,
                    scratchpad, MAX_SIG_LENGTH, PUB_KEY_LENGTH);
            Util.arrayCopyNonAtomic(currentLUK.sig, ZERO,
                    scratchpad, (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH),
                    MAX_SIG_LENGTH);
        } else {
            signWithMyKey(buffer, OFFSET_SIGNABLE, SIGNABLE_LENGTH);
            // copy pubKey to scratchpad
            cardECPublicKey.getW(scratchpad, ZERO);
            // makeHashable will use the pubKey in scratchpad
            makeHashable(buffer, OFFSET_SIGNABLE,
                    sigBuffer, ZERO,
                    scratchpad, ZERO,
                    SIXTY_FOUR_ZEROES, ZERO);

            JCSystem.beginTransaction();

            // no need to check whether repository.store succeeded because
            // repository.checkCapacity was called earlier
            repository.store(hashable);
            // ! Subtract myBalance after successful signing
            subtractFromBalance(tempAmount);

            JCSystem.commitTransaction();

            // FROM THIS POINT ONWARD, THE SCRATCHPAD IS USED TO STORE THE RESPONSE
            // copy to scratchpad
            Util.arrayCopyNonAtomic(sigBuffer, ZERO, scratchpad, ZERO, MAX_SIG_LENGTH);
            cardECPublicKey.getW(scratchpad, MAX_SIG_LENGTH);
            Util.arrayCopyNonAtomic(SIXTY_FOUR_ZEROES, ZERO,
                    scratchpad, (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH),
                    (short) SIXTY_FOUR_ZEROES.length);
        }
        // ! << signTransfer
    }

    /**
     * Verifies and accepts an incoming transfer in two phases:
     * - P1=0x00: Receives the signable transaction data (60 bytes)
     * - P1=0x01: Receives signature + pubKey + pubKeySig, verifies all cryptographic
     *   proofs, checks the recipient is this card, validates the counter sequence,
     *   and credits the amount to the on-card balance.
     */
    private void verifyTransfer(byte[] buffer, short dataLength) {
        // ! >> verifyTransfer() | dataLength: {dataLength}
        if (buffer[ISO7816.OFFSET_P1] == 0x00) {
            if (dataLength != SIGNABLE_LENGTH) {
                ISOException.throwIt(SW_ERROR_WRONG_SIGNABLE_LENGTH);
            }
            // ! verifyTransfer() | INS_VERIFY_TRANSFER save commit message: buffer:
            // {buffer, (short)0, (short)buffer.length}
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, signableBuffer, ZERO, SIGNABLE_LENGTH);
            // ! verifyTransfer() | INS_VERIFY_TRANSFER signableBuffer {signableBuffer}
        }
        if (buffer[ISO7816.OFFSET_P1] == 0x01) {
            // ! verifyTransfer() | INS_VERIFY_TRANSFER save signature
            if (dataLength != (short) (MAX_SIG_LENGTH + PUB_KEY_LENGTH + MAX_SIG_LENGTH)) {
                ISOException.throwIt(SW_ERROR_WRONG_TAIL_LENGTH);
            }

            if (!repository.checkCapacity()) {
                ISOException.throwIt(SW_ERROR_STORAGE_OUT_OF_CAPACITY);
            }

            // first check that the sig and pubKeySig are valid
            // set the tempPubKey to the public key in the transfer to be verified
            tempPubKey.setW(buffer, (short) (ISO7816.OFFSET_CDATA + MAX_SIG_LENGTH), PUB_KEY_LENGTH);

            boolean messageVerified = verifySig(signableBuffer, ZERO, SIGNABLE_LENGTH,
                    buffer, ISO7816.OFFSET_CDATA,
                    (short) (buffer[(short) (ISO7816.OFFSET_CDATA + 1)] + TAG_LENGTH_LENGTH),
                    tempPubKey);
            if (!messageVerified) {
                ISOException.throwIt(SW_ERROR_SIGNATURE_VERIFICATION_FAILED);
            }

            // then check that the signable transfer is valid
            boolean senderIsMe = Util.arrayCompare(signableBuffer,
                    TransactionParser.OFFSET_SENDER,
                    accountId, ZERO, UUID_LENGTH) == 0;
            if (senderIsMe) {
                ISOException.throwIt(SW_ERROR_WRONG_SENDER);
            }

            boolean recipientIsMe = Util.arrayCompare(signableBuffer,
                    TransactionParser.OFFSET_RECIPIENT,
                    accountId, ZERO, UUID_LENGTH) == 0;
            if (!recipientIsMe) {
                ISOException.throwIt(SW_ERROR_WRONG_RECIPIENT);
            }

            TransactionParser.getAmount(signableBuffer, ZERO, tempAmount);

            TransactionParser.getCounter(signableBuffer, ZERO, tempCounter);
            if (!verifyTempCounter()) {
                ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
            }
            if (isPositive(tempCounter)) {
                if (!checkLUKLimit(tempAmount)) {
                    ISOException.throwIt(SW_INSUFFICIENT_LUK_LIMIT);
                }
                // store transfer into repository
                makeHashable(signableBuffer, ZERO,
                        buffer, ISO7816.OFFSET_CDATA,
                        buffer, (short) (ISO7816.OFFSET_CDATA + MAX_SIG_LENGTH),
                        buffer, (short) (ISO7816.OFFSET_CDATA + MAX_SIG_LENGTH + PUB_KEY_LENGTH));

                JCSystem.beginTransaction();

                // no need to check whether repository.store succeeded because
                // repository.checkCapacity was called earlier
                repository.store(hashable);
                // update balance and offline counter
                addToBalance(tempAmount);
                Util.arrayCopy(tempCounter, ZERO, seenOfflineCounter, ZERO, INT32_LENGTH);

                JCSystem.commitTransaction();
            } else if (isNegative(tempCounter)) {
                JCSystem.beginTransaction();

                // update balance and remote counter
                addToBalance(tempAmount);
                Util.arrayCopy(tempCounter, ZERO, remoteCounter, ZERO, INT32_LENGTH);

                JCSystem.commitTransaction();
            } else {
                // counter may not be zero
                ISOException.throwIt(SW_ERROR_TRANSFER_COUNTER_INVALID);
            }
        }
        // ! << verifyTransfer()
    }

    /**
     * Validates the transaction counter for incoming transfers.
     * - Zero counters are rejected (invalid).
     * - Negative counters represent online/remote transactions and must be sequential.
     * - Positive counters represent offline transactions and must fall within the
     *   expected range (sent but not yet seen).
     */
    private boolean verifyTempCounter() {
        // ! verifyTempCounter() | counter: {counter}
        // ! verifyTempCounter() | sentOfflineCounter: {sentOfflineCounter}
        // ! verifyTempCounter() | seenOfflineCounter: {seenOfflineCounter}
        // ! verifyTempCounter() | remoteCounter: {remoteCounter}
        if (isZero(tempCounter)) {
            // ! Counter may never be zero
            return false;
        }
        if (isNegative(tempCounter)) {
            // ! verifyTempCounter() | remote counter
            // ! verifyTempCounter() | counter {counter}
            // ! verifyTempCounter() | remoteCounter {remoteCounter}
            Util.arrayCopyNonAtomic(tempCounter, ZERO, tempPlusOne, ZERO, INT32_LENGTH);
            ArrayUtil.incNumber(tempPlusOne);
            return Util.arrayCompare(tempPlusOne, ZERO, remoteCounter, ZERO, INT32_LENGTH) == 0;
        } else {
            // ! verifyTempCounter() | offline counter
            return isSmallerOrEqual(tempCounter, sentOfflineCounter) &&
                    !isSmallerOrEqual(tempCounter, seenOfflineCounter);
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
        // ! >> makeHashable()
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
        // ! processVerifyPIN() | start
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
                    // ! processVerifyPIN() | Master PIN verification failed
                    triesRemaining = masterPIN.getTriesRemaining();
                    // The last nibble of return code is number of remaining tries
                    ISOException.throwIt((short) (SW_PIN_FAILED + triesRemaining));
                }
                // ! process() | Master PIN verified
                break;
            case P2_USER_PIN:
                if (!userPIN.check(buffer, ISO7816.OFFSET_CDATA, pinLength)) {
                    // ! processVerifyPIN() | User PIN verification failed
                    triesRemaining = userPIN.getTriesRemaining();
                    // The last nibble of return code is number of remaining tries
                    ISOException.throwIt((short) (SW_PIN_FAILED + triesRemaining));
                }
                // ! processVerifyPIN() | User PIN verified
                break;
            default:
                // ! process() | Unknown kind of PIN {pinType}
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /** Returns true if the given amount is less than or equal to the current balance. */
    private boolean checkAmount(byte[] amount) {
        // ! checkAmount()
        // ! checkAmount() | amount <= myBalance ?
        return ArrayUtil.unsignedByteArrayCompare(amount, ZERO, myBalance, ZERO, INT64_LENGTH) <= ZERO;
    }

    /** Adds an 8-byte unsigned amount to the on-card balance using byte-level arithmetic. */
    private void addToBalance(byte[] amount) {
        short carry = 0;
        for (short i = INT64_LENGTH - 1; i >= 0; i--) {
            short x = (short) (this.myBalance[i] & 0xFF);
            // ! addToBalance | x: {x}
            short y = (short) (amount[i] & 0xFF);
            // ! addToBalance | y: {y}
            short result = (short) (x + y + carry);
            // ! addToBalance | result: {result}
            this.myBalance[i] = (byte) result;
            carry = (short) ((result >> 8) & 1);
            // ! addToBalance | carry: {carry}
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
    }

    /** Generates a new secp256r1 EC key pair and stores it as the card's signing key. */
    private void createECKeypair() {
        // ! createECKeypair()
        KeyPair keyPair = SecP256r1.newKeyPair();
        keyPair.genKeyPair();
        // ! createECKeypair() | genKeyPair() done

        cardECPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        cardECPublicKey = (ECPublicKey) keyPair.getPublic();
        // ! createECKeypair() | done.
    }

    /** Generates a new RSA-1024 key pair used for encrypted data transport (e.g., master PIN update). */
    private void createRSAKeypair() {
        // ! createRSAKeypair()
        KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        rsaKeyPair.genKeyPair();
        // ! createRSAKeypair() | genKeyPair() done

        cardRSAPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        cardRSAPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        // ! createRSAKeypair() | done.

    }

    /** Decrypts data using the card's RSA private key (PKCS#1 padding). Result goes to scratchpad. */
    private void decryptWithRSA(byte[] inBuff, short inOffset, short inLength) {
        try {
            cipherRSA.init(cardRSAPrivateKey, Cipher.MODE_DECRYPT);
            cipherRSA.doFinal(inBuff, inOffset, inLength, scratchpad, ZERO);
        } catch (CryptoException e) {
            ISOException.throwIt(SW_ERROR_CRYPTO_EXCEPTION);
        }
    }

    /** Decrypts data using the AES-256 session key in CBC mode. Result goes to scratchpad. */
    private void decryptWithAES(byte[] inBuff, short inOffset, short inLength) {
        try {
            cipherAES.init(sessionKey, Cipher.MODE_DECRYPT, sessionIV, ZERO, AES_IV_LENGTH);
            cipherAES.doFinal(inBuff, inOffset, inLength, scratchpad, ZERO);
        } catch (CryptoException e) {
            ISOException.throwIt(SW_ERROR_CRYPTO_EXCEPTION);
        }
    }

    /**
     * Permanently terminates the card. Requires a valid server signature over the card ID
     * to prevent unauthorized termination. Deletes all LUKs and sets the terminated flag.
     */
    private void suicide(byte[] buffer, short dataLength) {
        boolean sigVerified = verifySig(cardId, ZERO, UUID_LENGTH,
                buffer, ISO7816.OFFSET_CDATA, dataLength, masterPublicKey);
        if (sigVerified) {
            terminated = true;
        } else {
            ISOException.throwIt(SW_ERROR_SIGNATURE_VERIFICATION_FAILED);
        }
    }

    /** Signs data with the card's EC private key (ECDSA-SHA256). Returns signature length. */
    private short signWithMyKey(byte[] buffer, short offset, short length) {
        // ! signWithMyKey() | length: {length}
        // ! signWithMyKey() | {buffer, offset, length}
        if (!cardECPrivateKey.isInitialized()) {
            ISOException.throwIt(SW_ERROR_EC_CARD_KEY_MISSING);
        }
        try {
            signer.init(cardECPrivateKey, Signature.MODE_SIGN);

            // ! signWithMyKey() | Signature.init() done
        } catch (Exception e) {
            // ! signWithMyKey() | Exception thrown during signer.init
            ISOException.throwIt(SW_ERROR_INIT_SIGNER);
        }
        // ! signWithMyKey() | sigBuffer
        return signer.sign(buffer, offset, length, sigBuffer, ZERO);
    }

    /** Verifies an ECDSA-SHA256 signature against the given public key. */
    private boolean verifySig(byte[] inBuff, short inOffset, short inLength,
            byte[] sig, short sigOffset, short sigLength, PublicKey pubKey) {
        // ! verifySig() | Message: {inBuff, inOffset, inLength}
        // ! verifySig() | Signature: {sig, sigOffset, sigLength}
        verifier.init(pubKey, Signature.MODE_VERIFY);
        return verifier.verify(inBuff, inOffset, inLength, sig, sigOffset, sigLength);
    }

    /** Sends a byte array as the APDU response. */
    private void sendBytes(APDU apdu, byte[] outData, short bOff, short len) {
        // ! >> sendBytes
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(outData, bOff, len);
        // ! << sendBytes
    }
}

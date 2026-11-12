package com.impala.jcardsim.jc31;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.NamedParameterSpec;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.Signature;

/**
 * The entry points of the simulated platform. The patched jcardsim classes
 * ({@code KeyBuilder}, {@code Signature}, {@code KeyAgreement},
 * {@code MessageDigest}, {@code JCSystem}) and this module's {@code KeyPair}
 * and {@code NamedParameterSpec} call in here, and every answer depends on
 * the {@link CardPlatform} of the card the calling thread is acting as
 * ({@link CardPlatform.Card#execute}).
 *
 * <p>Code that does not run inside a card (a unit test that builds an engine
 * directly) gets a platform with every optional algorithm present, no memory
 * limit and the JavaCard 3.1 EdDSA API in the flavour the system property
 * {@value #EDDSA_PROPERTY} names. The property is read on every call, so a
 * test can change it between two installs:</p>
 * <ul>
 *   <li>{@code any} (default): pure Ed25519 as {@code SIG_CIPHER_EDDSA} under
 *       both message digest constants an applet may pass,
 *       {@code MessageDigest.ALG_NULL} and {@code ALG_SHA_512};</li>
 *   <li>{@code null} / {@code sha512}: pure Ed25519 under that constant only,
 *       {@code NO_SUCH_ALGORITHM} under the other;</li>
 *   <li>{@code not-pure}: both constants are accepted but give a signature
 *       scheme that is not pure Ed25519 (the message is hashed first), as a
 *       platform that mapped the request to a pre-hash variant would;</li>
 *   <li>{@code sign-not-pure}: verification is pure Ed25519 under both
 *       constants, signing is not (the message is hashed first): a platform
 *       whose two directions disagree, which a verify-only self-test would
 *       accept;</li>
 *   <li>{@code none}: no Ed25519 at all.</li>
 * </ul>
 * The JavaCard 3.2 constant {@code SIG_CIPHER_EDDSA_ED25519} is offered only
 * by a card whose platform says so ({@link CardPlatform#JC32}), never by this
 * default.
 */
public final class Jc31 {
    public static final String EDDSA_PROPERTY = "jcardsim.jc31.eddsa";

    /** JavaCard 3.2: pure Ed25519 named by its curve ({@code Signature.SIG_CIPHER_EDDSA_ED25519}). */
    public static final byte SIG_CIPHER_EDDSA_ED25519 = 15;
    private static final byte SIG_CIPHER_EDDSA_ED448 = 16;
    private static final byte SIG_CIPHER_EDDSAPH_ED25519 = 17;
    private static final byte SIG_CIPHER_EDDSAPH_ED448 = 18;

    private static final CardPlatform DEFAULT_ANY = defaults("any").edDsa(true, true, false).build();
    private static final CardPlatform DEFAULT_NULL = defaults("null").edDsa(true, false, false).build();
    private static final CardPlatform DEFAULT_SHA512 = defaults("sha512").edDsa(false, true, false).build();
    private static final CardPlatform DEFAULT_NOT_PURE =
            defaults("not-pure").edDsa(true, true, false).edDsaNotPure(false).build();
    private static final CardPlatform DEFAULT_SIGN_NOT_PURE =
            defaults("sign-not-pure").edDsa(true, true, false).edDsaNotPure(true).build();
    private static final CardPlatform DEFAULT_NONE = defaults("none").noEdDsa().build();

    private Jc31() {
    }

    private static CardPlatform.Builder defaults(String profile) {
        return CardPlatform.builder("default-" + profile, CardPlatform.Level.JC31)
                .description("outside a simulated card: everything present, EdDSA profile '" + profile + "'");
    }

    /** The platform of code that runs outside a simulated card (see the class comment). */
    static CardPlatform defaultPlatform() {
        String profile = System.getProperty(EDDSA_PROPERTY, "any");
        switch (profile) {
            case "any":
                return DEFAULT_ANY;
            case "null":
                return DEFAULT_NULL;
            case "sha512":
                return DEFAULT_SHA512;
            case "not-pure":
                return DEFAULT_NOT_PURE;
            case "sign-not-pure":
                return DEFAULT_SIGN_NOT_PURE;
            case "none":
                return DEFAULT_NONE;
            default:
                throw new IllegalArgumentException(EDDSA_PROPERTY
                        + " must be any, null, sha512, not-pure, sign-not-pure or none, not " + profile);
        }
    }

    /** False when the simulated platform has no Ed25519. */
    public static boolean edDsaAvailable() {
        return CardPlatform.currentPlatform().edDsaOffered();
    }

    // ------------------------------------------------------------------ JavaCard 3.1 / 3.2: EdDSA

    /** {@code KeyBuilder.buildXECKey}. */
    public static Key buildXecKey(NamedParameterSpec params, short attributes, boolean keyEncryption)
            throws CryptoException {
        CardPlatform platform = CardPlatform.currentPlatform();
        short memoryType = (short) (attributes & 0x7FFF);
        if (params.getName() != NamedParameterSpec.ED25519 || keyEncryption || !platform.edDsaOffered()
                || memoryType < 0 || memoryType > 2) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        if ((attributes & KeyBuilder.ATTR_PRIVATE) != 0) {
            return new XecPrivateKeyImpl(params, (byte) memoryType, platform.xecPrivateKeyImport());
        }
        return new XecPublicKeyImpl(params, (byte) memoryType);
    }

    /** {@code Signature.getInstance(byte, byte, byte, boolean)}. */
    public static Signature signature(byte messageDigestAlgorithm, byte cipherAlgorithm,
            byte paddingAlgorithm, boolean externalAccess) throws CryptoException {
        switch (cipherAlgorithm) {
            case Signature.SIG_CIPHER_EDDSA:
            case SIG_CIPHER_EDDSA_ED25519:
                return EdDsaSignature.create(CardPlatform.currentPlatform(), messageDigestAlgorithm,
                        cipherAlgorithm, paddingAlgorithm);
            case Signature.SIG_CIPHER_EDDSAPH:
            case SIG_CIPHER_EDDSA_ED448:
            case SIG_CIPHER_EDDSAPH_ED25519:
            case SIG_CIPHER_EDDSAPH_ED448:
                // Pre-hash EdDSA and Ed448 are not simulated: no card of this simulator has them.
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null;
            default:
                return Signature.jcardsimGetInstance(messageDigestAlgorithm, cipherAlgorithm,
                        paddingAlgorithm, externalAccess);
        }
    }

    public static boolean isXecKey(Key key) {
        return key instanceof XecKeyImpl;
    }

    /** {@code KeyPair(PublicKey, PrivateKey)}: both halves must be XEC keys of the right kind. */
    public static void checkXecPair(PublicKey publicKey, PrivateKey privateKey) throws CryptoException {
        if (!(publicKey instanceof XecPublicKeyImpl) || !(privateKey instanceof XecPrivateKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }

    /** {@code KeyPair.genKeyPair()} for an XEC pair: a fresh key from the JVM's secure random source. */
    public static void generateXecPair(PublicKey publicKey, PrivateKey privateKey) throws CryptoException {
        byte[][] pair = Ed25519Jdk.generate();
        try {
            // Generated on the card: this is not a key import, whatever the platform says about those.
            ((XecKeyImpl) privateKey).load(pair[0]);
            ((XecKeyImpl) publicKey).load(pair[1]);
        } finally {
            java.util.Arrays.fill(pair[0], (byte) 0);
        }
    }

    // ------------------------------------------------------------------ JavaCard 3.0.5: optional algorithms

    /** For {@code KeyPair}: how the card that is building a key pair treats curves that are not its own. */
    public static Object customCurvesOfThisCard() {
        return CardPlatform.currentPlatform().customCurves();
    }

    /**
     * {@code KeyPair.genKeyPair()} for every key type jcardsim knows.
     * {@code curves} is what {@link #customCurvesOfThisCard()} answered when
     * the pair was built. On a custom curve a card that refuses those throws,
     * and a card with wrong arithmetic ends up with the negative of the
     * right public point, as its ECDH does ({@link CurveBoundKeyAgreement}).
     */
    public static void generateEcPair(com.licel.jcardsim.crypto.KeyPairImpl pair, Object curves)
            throws CryptoException {
        byte[] custom = curves == CardPlatform.CustomCurves.SUPPORTED ? null : Curves.customField(pair.getPublic());
        if (custom != null && curves == CardPlatform.CustomCurves.REFUSED) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        pair.genKeyPair();
        if (custom != null) {
            Curves.negate((javacard.security.ECPublicKey) pair.getPublic(), custom);
        }
    }

    /** {@code KeyAgreement.getInstance(byte, boolean)}. */
    public static KeyAgreement keyAgreement(byte algorithm, boolean externalAccess) throws CryptoException {
        CardPlatform platform = CardPlatform.currentPlatform();
        if (algorithm == KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY && !platform.ecdhPlainXy()) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        KeyAgreement agreement = KeyAgreement.jcardsimGetInstance(algorithm, externalAccess);
        if (platform.customCurves() == CardPlatform.CustomCurves.SUPPORTED) {
            return agreement;
        }
        return new CurveBoundKeyAgreement(agreement, platform.customCurves());
    }

    /** {@code MessageDigest.getInstance(byte, boolean)}. */
    public static MessageDigest messageDigest(byte algorithm, boolean externalAccess) throws CryptoException {
        if (algorithm == MessageDigest.ALG_SHA_512 && !CardPlatform.currentPlatform().sha512()) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return MessageDigest.jcardsimGetInstance(algorithm, externalAccess);
    }

    /** {@code KeyBuilder.buildKey(byte, short, boolean)}. */
    public static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) throws CryptoException {
        CardPlatform platform = CardPlatform.currentPlatform();
        boolean aes = keyType == KeyBuilder.TYPE_AES || keyType == KeyBuilder.TYPE_AES_TRANSIENT_RESET
                || keyType == KeyBuilder.TYPE_AES_TRANSIENT_DESELECT;
        if (aes && keyLength == KeyBuilder.LENGTH_AES_256 && !platform.aes256Keys()) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        // Transient EC private keys: jcardsim has none, on any platform (its own NO_SUCH_ALGORITHM).
        return KeyBuilder.jcardsimBuildKey(keyType, keyLength, keyEncryption);
    }

    // ------------------------------------------------------------------ transient memory

    /** {@code JCSystem.makeTransientByteArray}. */
    public static byte[] transientByteArray(short length, byte event) throws SystemException {
        book(length, 1, event);
        return JCSystem.jcardsimMakeTransientByteArray(length, event);
    }

    /** {@code JCSystem.makeTransientShortArray}. */
    public static short[] transientShortArray(short length, byte event) throws SystemException {
        book(length, 2, event);
        return JCSystem.jcardsimMakeTransientShortArray(length, event);
    }

    /** {@code JCSystem.makeTransientBooleanArray}. */
    public static boolean[] transientBooleanArray(short length, byte event) throws SystemException {
        book(length, 1, event);
        return JCSystem.jcardsimMakeTransientBooleanArray(length, event);
    }

    /** {@code JCSystem.makeTransientObjectArray}. */
    public static Object[] transientObjectArray(short length, byte event) throws SystemException {
        book(length, 2, event);
        return JCSystem.jcardsimMakeTransientObjectArray(length, event);
    }

    /** Books the array against the card's transient memory; a length or event jcardsim will refuse is left to it. */
    private static void book(short length, int bytesPerElement, byte event) {
        if (length > 0 && (event == JCSystem.CLEAR_ON_RESET || event == JCSystem.CLEAR_ON_DESELECT)) {
            CardPlatform.current().allocateTransient(length * bytesPerElement, event);
        }
    }
}

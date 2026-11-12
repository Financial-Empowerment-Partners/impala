package javacard.security;

import com.impala.jcardsim.jc31.Jc31;
import com.licel.jcardsim.crypto.KeyPairImpl;

/**
 * {@code javacard.security.KeyPair} for the simulated platform: jcardsim's own
 * class (a thin wrapper over its {@code KeyPairImpl}, kept as is for every
 * key type it knows) plus pairs of XEC keys from
 * {@code KeyBuilder.buildXECKey}, which the JavaCard 3.1 API creates through
 * the two-key constructor. Key generation on an elliptic curve that is not
 * one of the card's own follows the card's platform (see
 * {@code CardPlatform.CustomCurves}); the pair remembers the card it was made
 * on.
 */
public final class KeyPair {
    public static final byte ALG_RSA = 1;
    public static final byte ALG_RSA_CRT = 2;
    public static final byte ALG_DSA = 3;
    public static final byte ALG_EC_F2M = 4;
    public static final byte ALG_EC_FP = 5;
    public static final byte ALG_DH = 6;

    private final KeyPairImpl impl;      // null for an XEC pair
    private final PublicKey xecPublic;
    private final PrivateKey xecPrivate;
    private final Object curves;         // how this card treats custom curves (opaque to this class)

    public KeyPair(byte algorithm, short keyLength) throws CryptoException {
        impl = new KeyPairImpl(algorithm, keyLength);
        xecPublic = null;
        xecPrivate = null;
        curves = Jc31.customCurvesOfThisCard();
    }

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) throws CryptoException {
        if (Jc31.isXecKey(publicKey) || Jc31.isXecKey(privateKey)) {
            Jc31.checkXecPair(publicKey, privateKey);
            impl = null;
            xecPublic = publicKey;
            xecPrivate = privateKey;
        } else {
            impl = new KeyPairImpl(publicKey, privateKey);
            xecPublic = null;
            xecPrivate = null;
        }
        curves = Jc31.customCurvesOfThisCard();
    }

    public final void genKeyPair() throws CryptoException {
        if (impl != null) {
            Jc31.generateEcPair(impl, curves);
        } else {
            Jc31.generateXecPair(xecPublic, xecPrivate);
        }
    }

    /** JavaCard 3.1: null behaves as {@link #genKeyPair()}; no parameter set is supported. */
    public final void genKeyPair(AlgorithmParameterSpec params) throws CryptoException {
        if (params != null) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        genKeyPair();
    }

    public PublicKey getPublic() {
        return impl != null ? impl.getPublic() : xecPublic;
    }

    public PrivateKey getPrivate() {
        return impl != null ? impl.getPrivate() : xecPrivate;
    }
}

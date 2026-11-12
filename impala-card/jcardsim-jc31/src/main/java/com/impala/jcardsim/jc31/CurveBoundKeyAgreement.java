package com.impala.jcardsim.jc31;

import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.PrivateKey;

/**
 * Key agreement on a card that does not really compute on curves other than
 * its own: jcardsim's engine, with the two ways such a card answers a key on
 * a custom curve. {@link CardPlatform.CustomCurves#REFUSED} refuses the key;
 * {@link CardPlatform.CustomCurves#WRONG_MATH} takes it and returns the
 * negative of the right point from {@code ALG_EC_SVDP_DH_PLAIN_XY}, which is
 * what the same card's key generation makes of that curve too (see
 * {@code KeyPair}), so the two agree with each other and are both wrong.
 */
final class CurveBoundKeyAgreement extends KeyAgreement {
    private final KeyAgreement inner;
    private final CardPlatform.CustomCurves behaviour;
    private byte[] wrongField;

    CurveBoundKeyAgreement(KeyAgreement inner, CardPlatform.CustomCurves behaviour) {
        this.inner = inner;
        this.behaviour = behaviour;
    }

    @Override
    public void init(PrivateKey privateKey) throws CryptoException {
        byte[] custom = Curves.customField(privateKey);
        if (custom != null && behaviour == CardPlatform.CustomCurves.REFUSED) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        wrongField = custom;
        inner.init(privateKey);
    }

    @Override
    public byte getAlgorithm() {
        return inner.getAlgorithm();
    }

    @Override
    public short generateSecret(byte[] publicData, short publicOffset, short publicLength,
            byte[] secret, short secretOffset) throws CryptoException {
        short length = inner.generateSecret(publicData, publicOffset, publicLength, secret, secretOffset);
        if (wrongField != null && inner.getAlgorithm() == ALG_EC_SVDP_DH_PLAIN_XY) {
            Curves.negate(secret, secretOffset, length, wrongField);
        }
        return length;
    }
}

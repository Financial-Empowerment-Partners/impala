package com.impala.jcardsim.jc31;

import javacard.security.CryptoException;
import javacard.security.NamedParameterSpec;
import javacard.security.XECPublicKey;

final class XecPublicKeyImpl extends XecKeyImpl implements XECPublicKey {
    XecPublicKeyImpl(NamedParameterSpec params, byte memoryType) {
        super(params, memoryType);
    }

    @Override
    void check(byte[] encoded) throws CryptoException {
        if (!Ed25519Jdk.isPublicKey(encoded)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }
}

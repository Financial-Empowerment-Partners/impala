package com.impala.jcardsim.jc31;

import javacard.security.CryptoException;
import javacard.security.NamedParameterSpec;
import javacard.security.XECPrivateKey;

final class XecPrivateKeyImpl extends XecKeyImpl implements XECPrivateKey {
    private final boolean importAllowed;

    /** {@code importAllowed}: whether this card lets an applet load a private key ({@link CardPlatform#xecPrivateKeyImport()}). */
    XecPrivateKeyImpl(NamedParameterSpec params, byte memoryType, boolean importAllowed) {
        super(params, memoryType);
        this.importAllowed = importAllowed;
    }

    @Override
    public void setEncoded(byte[] in, short offset, short length) throws CryptoException {
        if (!importAllowed) {
            // A card that only ever holds private keys it generated itself.
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        super.setEncoded(in, offset, length);
    }

    @Override
    void check(byte[] encoded) {
        // RFC 8032 section 5.1.5: every 32-byte string is a private key.
    }
}

package com.impala.jcardsim.jc31;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.NamedParameterSpec;
import javacard.security.XECKey;

/**
 * An Ed25519 key in its RFC 8032 encoding (32 bytes, public or private),
 * stored in the kind of card memory it was built for: a transient key loses
 * its value on reset or deselect, as on a card.
 */
abstract class XecKeyImpl implements XECKey, Key {
    static final short LENGTH = 32;

    private final NamedParameterSpec params;
    private final byte[] value;
    private final boolean[] initialized;

    XecKeyImpl(NamedParameterSpec params, byte memoryType) {
        this.params = params;
        if (memoryType == JCSystem.MEMORY_TYPE_PERSISTENT) {
            value = new byte[LENGTH];
            initialized = new boolean[1];
        } else {
            byte event = memoryType == JCSystem.MEMORY_TYPE_TRANSIENT_RESET
                    ? JCSystem.CLEAR_ON_RESET : JCSystem.CLEAR_ON_DESELECT;
            value = JCSystem.makeTransientByteArray(LENGTH, event);
            initialized = JCSystem.makeTransientBooleanArray((short) 1, event);
        }
    }

    /** Refuses an encoding that is not a key of this kind. */
    abstract void check(byte[] encoded) throws CryptoException;

    public boolean isInitialized() {
        return initialized[0];
    }

    public void clearKey() {
        Util.arrayFillNonAtomic(value, (short) 0, LENGTH, (byte) 0);
        initialized[0] = false;
    }

    public byte getType() {
        return KeyBuilder.TYPE_XEC;
    }

    public short getSize() {
        return 255;
    }

    public NamedParameterSpec getParams() {
        return params;
    }

    public short getEncodingLength() {
        return LENGTH;
    }

    public short getEncoded(byte[] out, short offset) {
        if (!initialized[0]) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        Util.arrayCopyNonAtomic(value, (short) 0, out, offset, LENGTH);
        return (short) (offset + LENGTH);
    }

    public void setEncoded(byte[] in, short offset, short length) throws CryptoException {
        if (length != LENGTH) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        byte[] encoded = new byte[LENGTH];
        Util.arrayCopyNonAtomic(in, offset, encoded, (short) 0, LENGTH);
        load(encoded);
    }

    /** Places a key the platform itself produced (key generation); {@link #setEncoded} is the applet's way in. */
    void load(byte[] encoded) throws CryptoException {
        if (encoded.length != LENGTH) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        check(encoded);
        Util.arrayCopyNonAtomic(encoded, (short) 0, value, (short) 0, LENGTH);
        initialized[0] = true;
    }

    /** A copy of the encoded key; the key must be initialized. */
    byte[] encoded() {
        if (!initialized[0]) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return value.clone();
    }
}

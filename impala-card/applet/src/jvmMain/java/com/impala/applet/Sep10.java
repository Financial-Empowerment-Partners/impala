package com.impala.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * The card's own check of a SEP-10 challenge transaction.
 *
 * <p>The Stellar key signs nothing but the hash of a transaction that passed
 * {@link #validate}: a Stellar {@code Transaction} (XDR, the {@code tx} of a v1
 * envelope) whose sequence number is zero, whose operations are all
 * {@code MANAGE_DATA}, and whose first operation is a {@code "<domain> auth"}
 * entry sourced by this card's key. A sequence number of zero is never valid
 * on any Stellar network, so the signature cannot authorize a payment or any
 * other ledger transaction, whatever the host intended. The card computes the
 * hash itself from these bytes; it never signs a hash handed to it.</p>
 *
 * <p>The accepted grammar is exact (see {@code docs/sep10-card-keys.md} §3.3):
 * anything else is refused with the status word that names the first rule it
 * broke. Every read is bounds-checked against the staged length first.</p>
 *
 * <p>The validator has no state and writes nothing: it reads the staged bytes
 * and this card's public key.</p>
 */
final class Sep10 {
    private static final short KEY_LENGTH = 32;
    private static final short MAX_DATA_LENGTH = 64;
    private static final byte OP_MANAGE_DATA = (byte) 10;
    private static final short MIN_AUTH_NAME_LENGTH = 6;      // one domain character + " auth"
    private static final short AUTH_SUFFIX_LENGTH = 5;
    private static final byte[] AUTH_SUFFIX = {
            (byte) 0x20, (byte) 0x61, (byte) 0x75, (byte) 0x74, (byte) 0x68 // " auth"
    };

    private Sep10() {
    }

    /**
     * Returns normally only for a challenge this card may sign.
     *
     * @param tx      the staged transaction bytes, {@code tx[txOff..txOff+txLen)}
     * @param cardKey this card's 32-byte Ed25519 public key at {@code cardKeyOff}
     */
    static void validate(byte[] tx, short txOff, short txLen, byte[] cardKey, short cardKeyOff) {
        short p = txOff;
        short end = (short) (txOff + txLen); // one past the last staged byte

        // sourceAccount: a plain ed25519 account that is not this card
        need(p, (short) 36, end);
        if (!isU32(tx, p, (byte) 0)) {
            malformed(); // muxed or unknown account type
        }
        p += 4;
        if (Util.arrayCompare(tx, p, cardKey, cardKeyOff, KEY_LENGTH) == 0) {
            ISOException.throwIt(Constants.SW_ERROR_SEP10_WRONG_ACCOUNT);
        }
        p += KEY_LENGTH;

        // fee: any value
        need(p, (short) 4, end);
        p += 4;

        // seqNum: zero, the property the whole design rests on
        need(p, (short) 8, end);
        if (!isZero(tx, p, (short) 8)) {
            ISOException.throwIt(Constants.SW_ERROR_SEP10_SEQUENCE_NOT_ZERO);
        }
        p += 8;

        // cond: PRECOND_TIME with an upper bound (the card has no clock; the
        // verifying server enforces the bound)
        need(p, (short) 4, end);
        if (!isU32(tx, p, (byte) 1)) {
            ISOException.throwIt(Constants.SW_ERROR_SEP10_NO_TIME_BOUNDS);
        }
        p += 4;
        need(p, (short) 16, end);
        if (isZero(tx, (short) (p + 8), (short) 8)) {
            ISOException.throwIt(Constants.SW_ERROR_SEP10_NO_TIME_BOUNDS);
        }
        p += 16;

        // memo: MEMO_NONE
        need(p, (short) 4, end);
        if (!isU32(tx, p, (byte) 0)) {
            malformed();
        }
        p += 4;

        // operations
        need(p, (short) 4, end);
        byte count = tx[(short) (p + 3)];
        if (tx[p] != 0 || tx[(short) (p + 1)] != 0 || tx[(short) (p + 2)] != 0
                || count < 1 || count > Constants.SEP10_MAX_OPERATIONS) {
            ISOException.throwIt(Constants.SW_ERROR_SEP10_NOT_MANAGE_DATA);
        }
        p += 4;
        for (short i = 0; i < count; i++) {
            // source account: present, plain ed25519
            need(p, (short) 40, end);
            if (!isU32(tx, p, (byte) 1) || !isU32(tx, (short) (p + 4), (byte) 0)) {
                malformed();
            }
            short source = (short) (p + 8);
            p += 40;

            need(p, (short) 4, end);
            if (!isU32(tx, p, OP_MANAGE_DATA)) {
                ISOException.throwIt(Constants.SW_ERROR_SEP10_NOT_MANAGE_DATA);
            }
            p += 4;

            // dataName: string64
            need(p, (short) 4, end);
            short nameLength = small(tx, p);
            if (nameLength < 1 || nameLength > MAX_DATA_LENGTH) {
                malformed();
            }
            p += 4;
            short name = p;
            p = skipPadded(tx, p, nameLength, end);

            // dataValue: optional opaque<64>
            need(p, (short) 4, end);
            short valueLength = -1;
            if (isU32(tx, p, (byte) 1)) {
                p += 4;
                need(p, (short) 4, end);
                valueLength = small(tx, p);
                if (valueLength > MAX_DATA_LENGTH) {
                    malformed();
                }
                p += 4;
                p = skipPadded(tx, p, valueLength, end);
            } else if (isU32(tx, p, (byte) 0)) {
                p += 4;
            } else {
                malformed();
            }

            boolean mine = Util.arrayCompare(tx, source, cardKey, cardKeyOff, KEY_LENGTH) == 0;
            if (i == 0) {
                if (!mine) {
                    ISOException.throwIt(Constants.SW_ERROR_SEP10_WRONG_ACCOUNT);
                }
                if (nameLength < MIN_AUTH_NAME_LENGTH || valueLength < 1
                        || Util.arrayCompare(tx, (short) (name + nameLength - AUTH_SUFFIX_LENGTH),
                                AUTH_SUFFIX, (short) 0, AUTH_SUFFIX_LENGTH) != 0) {
                    ISOException.throwIt(Constants.SW_ERROR_SEP10_NOT_AUTH_CHALLENGE);
                }
            } else if (mine) {
                ISOException.throwIt(Constants.SW_ERROR_SEP10_WRONG_ACCOUNT);
            }
        }

        // ext: v0 (no Soroban data), then nothing
        need(p, (short) 4, end);
        if (!isU32(tx, p, (byte) 0)) {
            malformed();
        }
        p += 4;
        if (p != end) {
            malformed();
        }
    }

    private static void malformed() {
        ISOException.throwIt(Constants.SW_ERROR_SEP10_MALFORMED);
    }

    /** Refuses unless {@code n} more bytes exist at {@code p}, before {@code end}. */
    private static void need(short p, short n, short end) {
        if ((short) (end - p) < n) {
            malformed();
        }
    }

    /** True when the big-endian uint32 at {@code off} equals the small value {@code v}. */
    private static boolean isU32(byte[] b, short off, byte v) {
        return b[off] == 0 && b[(short) (off + 1)] == 0 && b[(short) (off + 2)] == 0
                && b[(short) (off + 3)] == v;
    }

    /** The big-endian uint32 at {@code off}, which must be below 2^15. */
    private static short small(byte[] b, short off) {
        if (b[off] != 0 || b[(short) (off + 1)] != 0 || (b[(short) (off + 2)] & 0x80) != 0) {
            malformed();
        }
        return Util.getShort(b, (short) (off + 2));
    }

    /** Steps over {@code n} bytes and their zero padding to a multiple of four. */
    private static short skipPadded(byte[] b, short p, short n, short end) {
        short padded = (short) ((short) (n + 3) & (short) 0xFFFC);
        need(p, padded, end);
        for (short i = n; i < padded; i++) {
            if (b[(short) (p + i)] != 0) {
                malformed();
            }
        }
        return (short) (p + padded);
    }

    private static boolean isZero(byte[] b, short off, short n) {
        for (short i = 0; i < n; i++) {
            if (b[(short) (off + i)] != 0) {
                return false;
            }
        }
        return true;
    }
}

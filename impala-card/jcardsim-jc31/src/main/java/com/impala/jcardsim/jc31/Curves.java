package com.impala.jcardsim.jc31;

import java.math.BigInteger;
import java.util.Arrays;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;

/**
 * Which elliptic curves a simulated card has "built in", for the platforms
 * that do not compute on any other ({@link CardPlatform.CustomCurves}). Here
 * that is NIST P-256, the one standard curve the Impala applet uses; a curve
 * of another size is never judged.
 */
final class Curves {
    private static final byte[] P256_FIELD = {
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

    private Curves() {
    }

    /**
     * The field prime of {@code key} when it is a 256-bit EC key on a curve
     * that is not built in; null for any other key, and for one whose
     * parameters are not set yet (there is nothing to judge).
     */
    static byte[] customField(Key key) {
        if (!(key instanceof ECKey)) {
            return null;
        }
        byte[] buffer = new byte[80];
        short length;
        try {
            length = ((ECKey) key).getField(buffer, (short) 0);
        } catch (CryptoException e) {
            return null;
        }
        if (length != P256_FIELD.length) {
            return null;
        }
        byte[] field = Arrays.copyOf(buffer, length);
        return Arrays.equals(field, P256_FIELD) ? null : field;
    }

    /**
     * Replaces the point at {@code point[offset..offset+length)}, given as
     * {@code 04 || X || Y} or {@code X || Y}, by its negative: the wrong
     * answer of a {@link CardPlatform.CustomCurves#WRONG_MATH} card. It is a
     * point of the same curve, so nothing downstream can tell by its form.
     */
    static void negate(byte[] point, short offset, short length, byte[] field) {
        int coordinate = length / 2;
        int y = offset + length - coordinate;
        BigInteger p = new BigInteger(1, field);
        BigInteger value = new BigInteger(1, Arrays.copyOfRange(point, y, y + coordinate));
        byte[] negated = p.subtract(value).mod(p).toByteArray();
        Arrays.fill(point, y, y + coordinate, (byte) 0);
        int copy = Math.min(negated.length, coordinate);
        System.arraycopy(negated, negated.length - copy, point, y + coordinate - copy, copy);
    }

    /** {@link #negate} for the point a public key holds. */
    static void negate(ECPublicKey publicKey, byte[] field) {
        byte[] w = new byte[1 + 2 * field.length];
        short length = publicKey.getW(w, (short) 0);
        negate(w, (short) 0, length, field);
        publicKey.setW(w, (short) 0, length);
    }
}

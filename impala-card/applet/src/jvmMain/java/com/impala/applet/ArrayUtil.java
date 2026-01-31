package com.impala.applet;

import javacard.framework.Util;

import static com.impala.applet.Constants.INT32_LENGTH;
import static com.impala.applet.Constants.ZERO;

/**
 * Utility methods for big-endian byte array arithmetic and comparison.
 * Used for counter and balance operations where JavaCard lacks native
 * multi-byte integer support.
 */
public class ArrayUtil {
    /** Increments a big-endian unsigned integer stored as a byte array by one, with overflow propagation. */
    public static void incNumber(byte[] addend1) {
        short i = (short) (addend1.length - 1);

        short v = (short) ((addend1[i] & 0xff) + 1);
        addend1[i] = (byte) v;
        short overflow = (short) (v >>> 8);

        for (i--; i >= 0; i--) {
            v = (short) ((addend1[i] & 0xff) + overflow);
            addend1[i] = (byte) v;
            overflow = (short) (v >>> 8);
        }
    }

    /*
     * compares unsigned byte values
     */
    public static byte unsignedByteArrayCompare(byte[] src, short srcOff,
            byte[] dest, short destOff,
            short length) {
        if (length < 0) {
            throw new ArrayIndexOutOfBoundsException();
        } else {
            for (short i = 0; i < length; ++i) {
                if (src[(short) (srcOff + i)] != dest[(short) (destOff + i)]) {
                    short thisSrc = (short) (src[(short) (srcOff + i)] & 0xff);
                    short thisDest = (short) (dest[(short) (destOff + i)] & 0xff);
                    return (byte) (thisSrc >= thisDest ? 1 : -1);
                }
            }

            return 0;
        }
    }

    /** Returns true if the 4-byte signed integer is negative (MSB sign bit set). */
    public static boolean isNegative(byte[] counter) {
        // ! verifyTransfer().isNegative() | counter: {counter}
        // True if first bit of the first byte is 1
        return (counter[0] & 1 << 8) != 0;
    }

    /** Returns true if all 4 bytes of the counter are zero. */
    public static boolean isZero(byte[] counter) {
        return counter[0] == 0 && counter[1] == 0 && counter[2] == 0 && counter[3] == 0;
    }

    /** Returns true if the counter is strictly positive (not negative and not zero). */
    public static boolean isPositive(byte[] counter) {
        return !isNegative(counter) && !isZero(counter);
    }

    /** Returns true if counter <= compareTo, treating both as signed 4-byte integers. */
    public static boolean isSmallerOrEqual(byte[] counter, byte[] compareTo) {
        if (isNegative(counter) && isZero(compareTo)) {
            return true;
        }
        if (isZero(counter) && isNegative(compareTo)) {
            return false;
        }
        return Util.arrayCompare(counter, ZERO, compareTo, ZERO, INT32_LENGTH) <= 0;
    }
}

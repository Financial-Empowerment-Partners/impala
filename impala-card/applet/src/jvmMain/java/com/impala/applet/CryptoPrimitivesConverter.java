package com.impala.applet;

import javacard.framework.Util;

/**
 * Converts JavaCard cryptographic primitives (DER-encoded ECDSA signatures and
 * uncompressed EC public keys) to fixed-size raw byte format (64 bytes each)
 * suitable for on-card storage and hash computation.
 */
public class CryptoPrimitivesConverter {

    /**
     * Converts an uncompressed EC public key (0x04 || X || Y, 65 bytes) to raw
     * 64-byte format by stripping the 0x04 prefix.
     */
    public static void convertPublicKeyToRawBytes(byte[] inBuff, short inOffset, byte[] outBuff, short outOffset) {
        // ! convertPublicKeyToRawBytes | {inBuff}
        Util.arrayCopyNonAtomic(inBuff, (short) (inOffset + 1), outBuff, outOffset, (short) 64);
    }

    /**
     * Converts a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
     * to a fixed 64-byte raw format (r[32] || s[32]). Handles variable-length
     * DER integers by padding short values or trimming leading zero bytes.
     */
    public static void convertSignatureToRawBytes(byte[] inBuff, short inOffset, byte[] outBuff, short outOffset) {
        // ! convertSignatureToRawBytes | {inBuff}

        // Validate minimum DER structure: 30 LEN 02 rLen r 02 sLen s (at least 8 bytes)
        if ((short)(inOffset + 7) >= (short) inBuff.length) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // the output buffer may have garbage in it and must be zeroed out
        Util.arrayFillNonAtomic(outBuff, outOffset, (short) 64, (byte) 0);

        short rLengthOffset = (short) (inOffset + 3);
        short rOffset = (short) (rLengthOffset + 1);
        byte rLength = inBuff[rLengthOffset];

        // Validate rLength is within secp256r1 bounds (32 or 33, rarely 31)
        if (rLength < 0 || rLength > 33) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short sLengthOffset = (short) (rOffset + rLength + 1);
        short sOffset = (short) (sLengthOffset + 1);

        // Bounds check before reading sLength
        if (sLengthOffset >= (short) inBuff.length) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte sLength = inBuff[sLengthOffset];

        // Validate sLength and total structure fits in buffer
        if (sLength < 0 || sLength > 33 ||
            (short)(sOffset + sLength) > (short) inBuff.length) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short rDiff = (short) (32 - rLength);
        short sDiff = (short) (32 - sLength);

        if (rLength == 33) { // remove first byte from r
            Util.arrayCopyNonAtomic(inBuff, (short) (rOffset + 1),
                    outBuff, outOffset,
                    (short) 32);
        } else if (rDiff > 0) {
            // Add rDiff bytes to r
            Util.arrayCopyNonAtomic(inBuff, rOffset,
                    outBuff, (short) (outOffset + rDiff),
                    (short) (32 - rDiff));
        } else { // rLength == 32
            // Just copy r
            Util.arrayCopyNonAtomic(inBuff, rOffset,
                    outBuff, outOffset,
                    (short) 32);
        }

        if (sLength == 33) {
            Util.arrayCopyNonAtomic(inBuff, (short) (sOffset + 1),
                    outBuff, (short) (outOffset + 32),
                    (short) 32);
        } else if (sDiff > 0) {
            Util.arrayCopyNonAtomic(inBuff, sOffset,
                    outBuff, (short) (outOffset + 32 + sDiff),
                    (short) (32 - sDiff));
        } else { // sLength == 32
            Util.arrayCopyNonAtomic(inBuff, sOffset,
                    outBuff, (short) (outOffset + 32),
                    (short) 32);
        }
    }
}

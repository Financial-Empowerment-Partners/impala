package com.impala.applet;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;

/**
 * AES-CMAC implementation per NIST SP 800-38B.
 * Used by SCP03 for key derivation, cryptogram computation, and command/response MAC.
 */
public class AESCMAC {

    private static final short BLOCK_SIZE = 16;
    private static final byte CONST_RB = (byte) 0x87;

    private final Cipher cipherECB;
    private final byte[] k1;
    private final byte[] k2;
    private final byte[] state;

    /**
     * Allocates a new AES-CMAC engine.
     * Buffers are persistent (EEPROM) — allocated once in the applet constructor.
     */
    public AESCMAC() {
        cipherECB = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        k1 = new byte[BLOCK_SIZE];
        k2 = new byte[BLOCK_SIZE];
        state = new byte[BLOCK_SIZE];
    }

    /**
     * Computes the full 16-byte AES-CMAC over the given data.
     *
     * @param key       AES key to use
     * @param data      input data
     * @param offset    offset into data
     * @param length    length of data
     * @param mac       output buffer for 16-byte MAC
     * @param macOffset offset into mac buffer
     */
    public void sign(AESKey key, byte[] data, short offset, short length,
                     byte[] mac, short macOffset) {
        // Initialize cipher with key
        cipherECB.init(key, Cipher.MODE_ENCRYPT);

        // Generate subkeys
        generateSubkeys(key);

        // Number of complete blocks
        short n = (short) (length / BLOCK_SIZE);
        boolean lastBlockComplete;
        if (n == 0) {
            n = 1;
            lastBlockComplete = false;
        } else {
            lastBlockComplete = ((short) (length % BLOCK_SIZE) == 0);
            if (!lastBlockComplete) {
                n++;
            }
        }

        // Clear state (CBC accumulator)
        Util.arrayFillNonAtomic(state, (short) 0, BLOCK_SIZE, (byte) 0);

        // Process all blocks except the last
        short blockOffset = offset;
        for (short i = 0; i < (short) (n - 1); i++) {
            // XOR block into state
            xorBlock(state, (short) 0, data, blockOffset, BLOCK_SIZE);
            // Encrypt state in place
            cipherECB.init(key, Cipher.MODE_ENCRYPT);
            cipherECB.doFinal(state, (short) 0, BLOCK_SIZE, state, (short) 0);
            blockOffset += BLOCK_SIZE;
        }

        // Process last block
        short remaining = (short) (length - (short) (blockOffset - offset));
        if (lastBlockComplete && length > 0) {
            // XOR last complete block with K1
            xorBlock(state, (short) 0, data, blockOffset, BLOCK_SIZE);
            xorBlock(state, (short) 0, k1, (short) 0, BLOCK_SIZE);
        } else {
            // Pad last block: copy remaining bytes, then 0x80, then zeros
            // Use mac buffer temporarily for padded block
            Util.arrayFillNonAtomic(mac, macOffset, BLOCK_SIZE, (byte) 0);
            if (remaining > 0) {
                Util.arrayCopyNonAtomic(data, blockOffset, mac, macOffset, remaining);
            }
            mac[(short) (macOffset + remaining)] = (byte) 0x80;
            // XOR padded block with K2
            xorBlock(state, (short) 0, mac, macOffset, BLOCK_SIZE);
            xorBlock(state, (short) 0, k2, (short) 0, BLOCK_SIZE);
        }

        // Final encryption
        cipherECB.init(key, Cipher.MODE_ENCRYPT);
        cipherECB.doFinal(state, (short) 0, BLOCK_SIZE, mac, macOffset);
    }

    /**
     * Generates CMAC subkeys K1 and K2 from the cipher key.
     * L = AES(K, 0^128), then K1 = L << 1 (with conditional XOR),
     * K2 = K1 << 1 (with conditional XOR).
     */
    private void generateSubkeys(AESKey key) {
        // L = AES-ECB(K, 0^128)
        Util.arrayFillNonAtomic(k1, (short) 0, BLOCK_SIZE, (byte) 0);
        cipherECB.init(key, Cipher.MODE_ENCRYPT);
        cipherECB.doFinal(k1, (short) 0, BLOCK_SIZE, k1, (short) 0);

        // K1 = L << 1; if MSB(L)==1 then K1 ^= Rb
        boolean msbSet = (k1[0] & 0x80) != 0;
        shiftLeft(k1);
        if (msbSet) {
            k1[(short) (BLOCK_SIZE - 1)] ^= CONST_RB;
        }

        // K2 = K1 << 1; if MSB(K1)==1 then K2 ^= Rb
        Util.arrayCopyNonAtomic(k1, (short) 0, k2, (short) 0, BLOCK_SIZE);
        msbSet = (k2[0] & 0x80) != 0;
        shiftLeft(k2);
        if (msbSet) {
            k2[(short) (BLOCK_SIZE - 1)] ^= CONST_RB;
        }
    }

    /**
     * Left-shifts a 16-byte block by 1 bit.
     */
    private static void shiftLeft(byte[] block) {
        byte carry = 0;
        for (short i = (short) (BLOCK_SIZE - 1); i >= 0; i--) {
            byte b = block[i];
            block[i] = (byte) (((b & 0xFF) << 1) | carry);
            carry = (byte) ((b >> 7) & 1);
        }
    }

    /**
     * XORs src into dst: dst[dstOff..dstOff+len] ^= src[srcOff..srcOff+len].
     */
    private static void xorBlock(byte[] dst, short dstOff, byte[] src, short srcOff, short len) {
        for (short i = 0; i < len; i++) {
            dst[(short) (dstOff + i)] ^= src[(short) (srcOff + i)];
        }
    }
}

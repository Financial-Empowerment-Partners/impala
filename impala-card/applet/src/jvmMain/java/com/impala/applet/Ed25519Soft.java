package com.impala.applet;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

/**
 * Ed25519 for JavaCard 3.0.5 platforms, which have no EdDSA API.
 *
 * <p>The expensive step of a signature, the scalar multiplication of the base
 * point, runs in the card's own elliptic-curve engine: Curve25519 has a short
 * Weierstrass form ("Wei25519"), so a private key on that curve fed to
 * {@code ALG_EC_SVDP_DH_PLAIN_XY} with the base point yields {@code scalar * G}
 * as affine coordinates. The applet then maps that point to the Edwards form
 * (one field inversion and six multiplications modulo 2^255 - 19) and does the
 * arithmetic modulo the group order L itself. SHA-512 is the card's.</p>
 *
 * <p>Signatures are RFC 8032 Ed25519: {@code R = r * B},
 * {@code k = SHA-512(R || A || M) mod L}, {@code S = (r + k * a) mod L}. The
 * secret scalar {@code a} comes from the platform's own key generation on
 * Wei25519 (uniform in [1, L - 1]) and the prefix from the platform RNG;
 * neither is derived from a seed, and neither can be loaded or read through
 * any command.</p>
 *
 * <p>The nonce is hedged: {@code r = SHA-512(prefix || Z || M) mod L} with 32
 * fresh random bytes {@code Z} per signature, where RFC 8032 has
 * {@code SHA-512(prefix || M)}. A verifier cannot tell the difference (any
 * {@code r} gives a valid signature), a failed RNG leaves the RFC's
 * deterministic nonce, and signing the same message twice no longer repeats
 * {@code r}, which is what the fault attacks on deterministic EdDSA need.
 * {@link #hedged} exists so tests can reproduce the RFC's vectors.</p>
 *
 * <p>All numbers are 32-byte big-endian (the JavaCard key API's order); the
 * RFC's little-endian encodings are produced at the edges. Code that touches
 * {@code r} or {@code a} has no secret-dependent branch or index; the point
 * conversion works on public values and is variable-time.</p>
 *
 * <p>Requires: custom prime-field curves for 256-bit EC keys,
 * {@code ALG_EC_SVDP_DH_PLAIN_XY}, {@code ALG_SHA_512}, a 256-bit AES key
 * object, and about 500 bytes of transient memory. {@link #create()} returns
 * null where any of those is missing.</p>
 */
final class Ed25519Soft extends Ed25519 {
    /** The field prime p = 2^255 - 19. */
    static final byte[] P = {
            (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xED
    };
    /** The group order L = 2^252 + 27742317777372353535851937790883648493. */
    static final byte[] L = {
            (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x14, (byte) 0xDE, (byte) 0xF9, (byte) 0xDE, (byte) 0xA2, (byte) 0xF7, (byte) 0x9C, (byte) 0xD6,
            (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1A, (byte) 0x5C, (byte) 0xF5, (byte) 0xD3, (byte) 0xED
    };
    /** Wei25519 a = (3 - A^2) / 3 for A = 486662. */
    static final byte[] WEI_A = {
            (byte) 0x2A, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0x98, (byte) 0x49, (byte) 0x14, (byte) 0xA1, (byte) 0x44
    };
    /** Wei25519 b = (2 A^3 - 9 A) / 27. */
    static final byte[] WEI_B = {
            (byte) 0x7B, (byte) 0x42, (byte) 0x5E, (byte) 0xD0, (byte) 0x97, (byte) 0xB4, (byte) 0x25, (byte) 0xED,
            (byte) 0x09, (byte) 0x7B, (byte) 0x42, (byte) 0x5E, (byte) 0xD0, (byte) 0x97, (byte) 0xB4, (byte) 0x25,
            (byte) 0xED, (byte) 0x09, (byte) 0x7B, (byte) 0x42, (byte) 0x5E, (byte) 0xD0, (byte) 0x97, (byte) 0xB4,
            (byte) 0x26, (byte) 0x0B, (byte) 0x5E, (byte) 0x9C, (byte) 0x77, (byte) 0x10, (byte) 0xC8, (byte) 0x64
    };
    /** The base point on Wei25519 (04 || X || Y); it maps to the RFC 8032 base point B. */
    static final byte[] WEI_G = {
            (byte) 0x04, (byte) 0x2A, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAD, (byte) 0x24,
            (byte) 0x5A, (byte) 0x20, (byte) 0xAE, (byte) 0x19, (byte) 0xA1, (byte) 0xB8, (byte) 0xA0, (byte) 0x86,
            (byte) 0xB4, (byte) 0xE0, (byte) 0x1E, (byte) 0xDD, (byte) 0x2C, (byte) 0x77, (byte) 0x48, (byte) 0xD1,
            (byte) 0x4C, (byte) 0x92, (byte) 0x3D, (byte) 0x4D, (byte) 0x7E, (byte) 0x6D, (byte) 0x7C, (byte) 0x61,
            (byte) 0xB2, (byte) 0x29, (byte) 0xE9, (byte) 0xC5, (byte) 0xA2, (byte) 0x7E, (byte) 0xCE, (byte) 0xD3,
            (byte) 0xD9
    };
    /** A / 3: the shift between the Weierstrass X and the Montgomery u. */
    static final byte[] DELTA = {
            (byte) 0x2A, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAD, (byte) 0x24, (byte) 0x51
    };
    /** sqrt(-486664), the constant of the Montgomery-to-Edwards map (RFC 7748). */
    static final byte[] SQRT_M486664 = {
            (byte) 0x70, (byte) 0xD9, (byte) 0x12, (byte) 0x0B, (byte) 0x9F, (byte) 0x5F, (byte) 0xF9, (byte) 0x44,
            (byte) 0x2D, (byte) 0x84, (byte) 0xF7, (byte) 0x23, (byte) 0xFC, (byte) 0x03, (byte) 0xB0, (byte) 0x81,
            (byte) 0x3A, (byte) 0x5E, (byte) 0x2C, (byte) 0x2E, (byte) 0xB4, (byte) 0x82, (byte) 0xE5, (byte) 0x7D,
            (byte) 0x33, (byte) 0x91, (byte) 0xFB, (byte) 0x55, (byte) 0x00, (byte) 0xBA, (byte) 0x81, (byte) 0xE7
    };

    /**
     * Known-answer test: the secret scalar of RFC 8032 section 7.1 TEST 1
     * (SHA-512 of the seed, clamped) reduced modulo L, big-endian, and the
     * public key the RFC gives for it.
     */
    static final byte[] KAT_SCALAR = {
            (byte) 0x0F, (byte) 0xE9, (byte) 0x4D, (byte) 0x90, (byte) 0x06, (byte) 0xF0, (byte) 0x20, (byte) 0xA5,
            (byte) 0xA3, (byte) 0xC0, (byte) 0x80, (byte) 0xD9, (byte) 0x68, (byte) 0x27, (byte) 0xFF, (byte) 0xFC,
            (byte) 0xE8, (byte) 0x85, (byte) 0x23, (byte) 0x46, (byte) 0x65, (byte) 0x50, (byte) 0x06, (byte) 0xE9,
            (byte) 0x6A, (byte) 0xE9, (byte) 0x9B, (byte) 0xE6, (byte) 0x12, (byte) 0xAC, (byte) 0x2C, (byte) 0x7C
    };
    static final byte[] KAT_PUBLIC = {
            (byte) 0xD7, (byte) 0x5A, (byte) 0x98, (byte) 0x01, (byte) 0x82, (byte) 0xB1, (byte) 0x0A, (byte) 0xB7,
            (byte) 0xD5, (byte) 0x4B, (byte) 0xFE, (byte) 0xD3, (byte) 0xC9, (byte) 0x64, (byte) 0x07, (byte) 0x3A,
            (byte) 0x0E, (byte) 0xE1, (byte) 0x72, (byte) 0xF3, (byte) 0xDA, (byte) 0xA6, (byte) 0x23, (byte) 0x25,
            (byte) 0xAF, (byte) 0x02, (byte) 0x1A, (byte) 0x68, (byte) 0xF7, (byte) 0x07, (byte) 0x51, (byte) 0x1A
    };

    static final short N = 32;

    // Layout of the transient work area.
    static final short W_HP = 0;        // 64: SHA-512 output, then 64-byte products
    static final short W_RT = 64;       // 128: scalar reduction (2 x 32) or inversion (4 x 32)
    static final short W_NONCE = 192;   // 32: r
    static final short W_K = 224;       // 32: k, or a short-lived secret on its way into a key object
    static final short W_F = 256;       // 160: five field temporaries; the first holds a while S is computed
    static final short W_EC = 416;      // 65: ECDH output 04 || X || Y
    static final short W_LENGTH = 481;

    private static final short F0 = W_F;
    private static final short F1 = (short) (W_F + 32);
    private static final short F2 = (short) (W_F + 64);
    private static final short F3 = (short) (W_F + 96);
    private static final short F4 = (short) (W_F + 128);

    private static final short INVERSION_STEP_LIMIT = 2048;

    final ECPrivateKey scalarKey;       // a: the long-term secret scalar, as a Wei25519 private key
    final AESKey prefixKey;             // the 32-byte nonce-derivation secret
    private final ECPublicKey pointKey; // the public point of the generated pair
    private final ECPrivateKey nonceKey;// per-signature r (a transient key object where the platform has one)
    private final KeyPair keyPair;
    private final KeyAgreement ecdh;
    private final MessageDigest sha512;
    private final RandomData random;
    private final byte[] pub;           // RFC 8032 public key
    private final byte[] w;
    private boolean generated;          // pub holds a public key
    private boolean ready;              // the private half is present
    /** Mix fresh randomness into every nonce. Only tests turn this off. */
    boolean hedged;

    private Ed25519Soft() {
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        scalarKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                KeyBuilder.LENGTH_EC_FP_256, false);
        pointKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                KeyBuilder.LENGTH_EC_FP_256, false);
        ECPrivateKey nk = null;
        try {
            nk = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                    KeyBuilder.LENGTH_EC_FP_256, false);
        } catch (CryptoException e) {
            // no transient EC keys on this platform
        } catch (SystemException e) {
            // no transient memory left for one
        }
        if (nk == null) {
            // A persistent object instead, cleared after every use.
            nk = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                    KeyBuilder.LENGTH_EC_FP_256, false);
        }
        nonceKey = nk;
        prefixKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        keyPair = new KeyPair(pointKey, scalarKey);
        pub = new byte[N];
        w = JCSystem.makeTransientByteArray(W_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        generated = false;
        ready = false;
        hedged = true;
    }

    /** The engine, or null when the platform lacks one of the primitives it needs. */
    static Ed25519 create() {
        try {
            return new Ed25519Soft();
        } catch (CryptoException e) {
            return null;
        } catch (SystemException e) {
            return null;
        }
    }

    byte engineId() {
        return ENGINE_SOFT;
    }

    boolean hasPublicKey() {
        return generated;
    }

    boolean isKeyReady() {
        return ready;
    }

    void getPublicKey(byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(pub, (short) 0, out, outOff, N);
    }

    boolean generateKeyPair() {
        ready = false;
        generated = false;
        try {
            setCurve(pointKey);
            setCurve(scalarKey);
            if (!knownAnswer()) {
                return false;
            }
            keyPair.genKeyPair();
            if (pointKey.getW(w, W_EC) != (short) 65 || w[W_EC] != (byte) 0x04) {
                return false;
            }
            // The signer depends on the ECDH path returning scalar * G in the same
            // form: prove it once, here, against the platform's own public point.
            Util.arrayCopyNonAtomic(w, W_EC, w, W_RT, (short) 65);
            loadScalar(W_NONCE);
            mulBase(W_NONCE);
            if (Util.arrayCompare(w, W_EC, w, W_RT, (short) 65) != 0) {
                return false;
            }
            return finishKey();
        } catch (CryptoException e) {
            return false;
        } finally {
            wipe();
        }
    }

    /**
     * Known-answer test of the whole public-key path: the card's ECDH on
     * Wei25519 with a fixed scalar, mapped to the Edwards form, must give that
     * scalar's RFC 8032 public key. The comparison with the platform's own
     * public point in {@link #generateKeyPair()} only shows that key generation
     * and ECDH agree with each other; an engine that is wrong in a consistent
     * way (one that assumes a = -3 for every curve, say) passes it and would
     * hand out a public key and signatures nobody can verify. Such a card gets
     * no Stellar key instead and works as a legacy card.
     */
    private boolean knownAnswer() {
        Util.arrayCopyNonAtomic(KAT_SCALAR, (short) 0, w, W_NONCE, N);
        mulBase(W_NONCE);
        encodePoint(w, w, W_K);
        return Util.arrayCompare(w, W_K, KAT_PUBLIC, (short) 0, N) == 0;
    }

    /**
     * Derives the public key from the point in the work area, draws the nonce
     * secret and marks the key usable.
     */
    private boolean finishKey() {
        encodePoint(w, pub, (short) 0);
        random.generateData(w, W_K, N);
        prefixKey.setKey(w, W_K);
        generated = true;
        ready = true;
        return true;
    }

    /**
     * Recomputes the public key from {@link #scalarKey} and marks the key
     * usable; {@link #prefixKey} must already be set. Used by tests that place
     * RFC 8032 vectors in the two key objects; no command reaches it.
     */
    void derivePublicKey() {
        try {
            loadScalar(W_NONCE);
            mulBase(W_NONCE);
            encodePoint(w, pub, (short) 0);
            generated = true;
            ready = true;
        } finally {
            wipe();
        }
    }

    short sign(byte[] msg, short msgOff, short msgLen, byte[] sig, short sigOff) {
        if (!ready) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        try {
            // r = SHA-512(prefix || Z || M) mod L (Z: fresh randomness, see the class comment)
            prefixKey.getKey(w, W_K);
            sha512.reset();
            sha512.update(w, W_K, N);
            if (hedged) {
                random.generateData(w, W_NONCE, N);
                sha512.update(w, W_NONCE, N);
            }
            sha512.doFinal(msg, msgOff, msgLen, w, W_HP);
            reverse(w, W_HP, (short) 64);
            scReduce(w, W_HP, w, W_NONCE);

            // R = r * B
            mulBase(W_NONCE);
            encodePoint(w, sig, sigOff);

            // k = SHA-512(R || A || M) mod L
            sha512.reset();
            sha512.update(sig, sigOff, N);
            sha512.update(pub, (short) 0, N);
            sha512.doFinal(msg, msgOff, msgLen, w, W_HP);
            reverse(w, W_HP, (short) 64);
            scReduce(w, W_HP, w, W_K);

            // S = (r + k * a) mod L
            loadScalar(F0);
            mul32(w, W_K, w, F0, w, W_HP);
            short carry = add(w, (short) (W_HP + N), w, W_NONCE, w, (short) (W_HP + N), N);
            for (short i = (short) (N - 1); i >= 0; i--) {
                short t = (short) ((short) (w[(short) (W_HP + i)] & 0xFF) + carry);
                w[(short) (W_HP + i)] = (byte) t;
                carry = (short) ((t >> 8) & 1);
            }
            scReduce(w, W_HP, sig, (short) (sigOff + N));
            reverse(sig, (short) (sigOff + N), N);
            return SIGNATURE_LENGTH;
        } finally {
            wipe();
        }
    }

    void clearKey() {
        ready = false;
        scalarKey.clearKey();
        prefixKey.clearKey();
        nonceKey.clearKey();
    }

    private void wipe() {
        Util.arrayFillNonAtomic(w, (short) 0, W_LENGTH, (byte) 0);
        nonceKey.clearKey();
    }

    private static void setCurve(ECKey key) {
        key.setFieldFP(P, (short) 0, N);
        key.setA(WEI_A, (short) 0, N);
        key.setB(WEI_B, (short) 0, N);
        key.setG(WEI_G, (short) 0, (short) 65);
        key.setR(L, (short) 0, N);
        key.setK((short) 8);
    }

    /** w[off..off+32) := the secret scalar a, right-aligned. */
    private void loadScalar(short off) {
        short n = scalarKey.getS(w, off);
        if (n < N) {
            short pad = (short) (N - n);
            Util.arrayCopyNonAtomic(w, off, w, (short) (off + pad), n);
            Util.arrayFillNonAtomic(w, off, pad, (byte) 0);
        }
    }

    /** w[W_EC..W_EC+65) := 04 || X || Y of w[scalarOff..+32) * G, from the card's ECDH engine. */
    private void mulBase(short scalarOff) {
        setCurve(nonceKey);
        nonceKey.setS(w, scalarOff, N);
        ecdh.init(nonceKey);
        short n = ecdh.generateSecret(WEI_G, (short) 0, (short) 65, w, W_EC);
        if (n == (short) 64) {
            // Some platforms return X || Y without the point-format byte.
            Util.arrayCopyNonAtomic(w, W_EC, w, (short) (W_EC + 1), (short) 64);
            w[W_EC] = (byte) 0x04;
        } else if (n != (short) 65 || w[W_EC] != (byte) 0x04) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
    }

    /**
     * Maps the Wei25519 point at wk[W_EC..] to its RFC 8032 encoding:
     * {@code u = X - A/3}, {@code y = (u - 1) / (u + 1)},
     * {@code x = sqrt(-486664) * u / Y}; 32 bytes little-endian y with the low
     * bit of x in the top bit. One inversion serves both quotients.
     */
    static void encodePoint(byte[] wk, byte[] out, short outOff) {
        short x = (short) (W_EC + 1);
        short y = (short) (W_EC + 1 + N);
        feSub(wk, wk, x, DELTA, (short) 0, F0);                 // F0 = u
        Util.arrayFillNonAtomic(wk, F4, N, (byte) 0);
        wk[(short) (F4 + N - 1)] = (byte) 1;
        feAdd(wk, wk, F0, wk, F4, F1);                          // F1 = u + 1
        feSub(wk, wk, F0, wk, F4, F4);                          // F4 = u - 1
        feMul(wk, wk, y, wk, F1, F2);                           // F2 = Y * (u + 1)
        if (isZero(wk, F2)) {
            // Only a point of order 1, 2 or 4 has Y = 0 or u = -1; never a multiple of G.
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        feInv(wk, F2, F3);                                      // F3 = 1 / (Y * (u + 1))
        feMul(wk, wk, F3, wk, y, F2);                           // F2 = 1 / (u + 1)
        feMul(wk, wk, F4, wk, F2, F4);                          // F4 = y
        feMul(wk, wk, F3, wk, F1, F3);                          // F3 = 1 / Y
        feMul(wk, wk, F0, wk, F3, F3);                          // F3 = u / Y
        feMul(wk, SQRT_M486664, (short) 0, wk, F3, F3);         // F3 = x
        // Finish in the work area: out may be persistent memory, written once.
        reverse(wk, F4, N);
        wk[(short) (F4 + N - 1)] |= (byte) ((wk[(short) (F3 + N - 1)] & 1) << 7);
        Util.arrayCopyNonAtomic(wk, F4, out, outOff, N);
    }

    // ------------------------------------------------------------------
    // Arithmetic modulo p = 2^255 - 19 (public values; variable time)
    // ------------------------------------------------------------------

    /** wk[r..] := (a + b) mod p for canonical a, b. */
    static void feAdd(byte[] wk, byte[] a, short aOff, byte[] b, short bOff, short r) {
        add(a, aOff, b, bOff, wk, r, N);        // a + b < 2p < 2^256: no carry out
        feCanon(wk, r);
    }

    /** wk[r..] := (a - b) mod p for canonical a, b. */
    static void feSub(byte[] wk, byte[] a, short aOff, byte[] b, short bOff, short r) {
        if (sub(a, aOff, b, bOff, wk, r, N) != 0) {
            add(wk, r, P, (short) 0, wk, r, N); // the wrapped difference plus p, modulo 2^256
        }
    }

    /** wk[r..] := (a * b) mod p. Uses wk[W_HP..+64); r may be a or b. */
    static void feMul(byte[] wk, byte[] a, short aOff, byte[] b, short bOff, short r) {
        mul32(a, aOff, b, bOff, wk, W_HP);
        // hi * 2^256 + lo == hi * 38 + lo (mod p)
        short carry = 0;
        for (short i = (short) (N - 1); i >= 0; i--) {
            short t = (short) ((short) ((short) (wk[(short) (W_HP + i)] & 0xFF) * (short) 38)
                    + (short) (wk[(short) (W_HP + N + i)] & 0xFF) + carry);
            wk[(short) (r + i)] = (byte) t;
            carry = (short) (t >> 8);           // t < 10240: never negative
        }
        if (addSmall(wk, r, (short) (carry * (short) 38)) != 0) {
            addSmall(wk, r, (short) 38);
        }
        feCanon(wk, r);
    }

    /** Adds a 16-bit value to wk[off..+32); returns the carry out. */
    private static short addSmall(byte[] wk, short off, short v) {
        short t = (short) ((short) (wk[(short) (off + 31)] & 0xFF) + (short) (v & 0xFF));
        wk[(short) (off + 31)] = (byte) t;
        short carry = (short) (t >> 8);
        t = (short) ((short) (wk[(short) (off + 30)] & 0xFF) + (short) ((v >> 8) & 0xFF) + carry);
        wk[(short) (off + 30)] = (byte) t;
        carry = (short) (t >> 8);
        for (short i = 29; i >= 0 && carry != 0; i--) {
            t = (short) ((short) (wk[(short) (off + i)] & 0xFF) + carry);
            wk[(short) (off + i)] = (byte) t;
            carry = (short) (t >> 8);
        }
        return carry;
    }

    /** Brings wk[off..+32) (any value below 2^256) into [0, p). */
    private static void feCanon(byte[] wk, short off) {
        if (cmp(wk, off, P, (short) 0, N) >= 0) {
            sub(wk, off, P, (short) 0, wk, off, N);
        }
        if (cmp(wk, off, P, (short) 0, N) >= 0) {
            sub(wk, off, P, (short) 0, wk, off, N);
        }
    }

    /**
     * wk[r..] := 1 / wk[a..] mod p by the binary extended Euclidean algorithm
     * (about ten times cheaper here than an exponentiation). a must be
     * non-zero and canonical. Uses wk[W_RT..+128).
     */
    static void feInv(byte[] wk, short a, short r) {
        short u = W_RT;
        short v = (short) (W_RT + 32);
        short x1 = (short) (W_RT + 64);
        short x2 = (short) (W_RT + 96);
        Util.arrayCopyNonAtomic(wk, a, wk, u, N);
        Util.arrayCopyNonAtomic(P, (short) 0, wk, v, N);
        Util.arrayFillNonAtomic(wk, x1, (short) 64, (byte) 0);
        wk[(short) (x1 + N - 1)] = (byte) 1;
        short steps = INVERSION_STEP_LIMIT;
        while (!isOne(wk, u) && !isOne(wk, v)) {
            while ((wk[(short) (u + N - 1)] & 1) == 0) {
                halve(wk, u, x1);
                if (--steps < 0) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
            }
            while ((wk[(short) (v + N - 1)] & 1) == 0) {
                halve(wk, v, x2);
                if (--steps < 0) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
            }
            if (cmp(wk, u, wk, v, N) >= 0) {
                sub(wk, u, wk, v, wk, u, N);
                feSub(wk, wk, x1, wk, x2, x1);
            } else {
                sub(wk, v, wk, u, wk, v, N);
                feSub(wk, wk, x2, wk, x1, x2);
            }
            if (--steps < 0) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
        }
        Util.arrayCopyNonAtomic(wk, isOne(wk, u) ? x1 : x2, wk, r, N);
    }

    /** val := val / 2 and coeff := coeff / 2 mod p (val is even). */
    private static void halve(byte[] wk, short val, short coeff) {
        shr1(wk, val, (short) 0);
        short carry = 0;
        if ((wk[(short) (coeff + N - 1)] & 1) != 0) {
            carry = add(wk, coeff, P, (short) 0, wk, coeff, N);
        }
        shr1(wk, coeff, carry);
    }

    // ------------------------------------------------------------------
    // Arithmetic modulo L (secret values; no secret-dependent branch or index)
    // ------------------------------------------------------------------

    /**
     * out[outOff..+32) := x mod L for the 64-byte big-endian x at wk[xOff..].
     * Restoring division: the top 248 bits are already below L; each further
     * bit doubles the remainder and subtracts L when that does not borrow.
     * Uses wk[W_RT..+64).
     */
    static void scReduce(byte[] wk, short xOff, byte[] out, short outOff) {
        short rem = W_RT;
        short trial = (short) (W_RT + N);
        wk[rem] = (byte) 0;
        Util.arrayCopyNonAtomic(wk, xOff, wk, (short) (rem + 1), (short) 31);
        for (short byteIndex = 31; byteIndex < (short) 64; byteIndex++) {
            short cur = (short) (wk[(short) (xOff + byteIndex)] & 0xFF);
            for (short bit = 7; bit >= 0; bit--) {
                short in = (short) ((cur >> bit) & 1);
                short borrow = 0;
                for (short i = (short) (N - 1); i >= 0; i--) {
                    short v = (short) (wk[(short) (rem + i)] & 0xFF);
                    short s = (short) (((short) (v << 1) & 0xFF) | in);
                    in = (short) (v >> 7);
                    wk[(short) (rem + i)] = (byte) s;
                    short t = (short) (s - (short) (L[i] & 0xFF) - borrow);
                    wk[(short) (trial + i)] = (byte) t;
                    borrow = (short) ((t >> 8) & 1);
                }
                // keep the trial difference when it did not borrow
                byte keep = (byte) (borrow - 1);
                for (short i = 0; i < N; i++) {
                    wk[(short) (rem + i)] = (byte) ((wk[(short) (rem + i)] & ~keep)
                            | (wk[(short) (trial + i)] & keep));
                }
            }
        }
        Util.arrayCopyNonAtomic(wk, rem, out, outOff, N);
    }

    // ------------------------------------------------------------------
    // Fixed-length big-endian helpers
    // ------------------------------------------------------------------

    /** r := a + b over len bytes; returns the carry out (0 or 1). r may be a or b. */
    static short add(byte[] a, short aOff, byte[] b, short bOff, byte[] r, short rOff, short len) {
        short carry = 0;
        for (short i = (short) (len - 1); i >= 0; i--) {
            short t = (short) ((short) (a[(short) (aOff + i)] & 0xFF)
                    + (short) (b[(short) (bOff + i)] & 0xFF) + carry);
            r[(short) (rOff + i)] = (byte) t;
            carry = (short) ((t >> 8) & 1);
        }
        return carry;
    }

    /** r := a - b over len bytes; returns the borrow out (0 or 1). r may be a or b. */
    static short sub(byte[] a, short aOff, byte[] b, short bOff, byte[] r, short rOff, short len) {
        short borrow = 0;
        for (short i = (short) (len - 1); i >= 0; i--) {
            short t = (short) ((short) (a[(short) (aOff + i)] & 0xFF)
                    - (short) (b[(short) (bOff + i)] & 0xFF) - borrow);
            r[(short) (rOff + i)] = (byte) t;
            borrow = (short) ((t >> 8) & 1);
        }
        return borrow;
    }

    /** Unsigned comparison: negative, zero or positive as a is below, equal to or above b. */
    static short cmp(byte[] a, short aOff, byte[] b, short bOff, short len) {
        for (short i = 0; i < len; i++) {
            short x = (short) (a[(short) (aOff + i)] & 0xFF);
            short y = (short) (b[(short) (bOff + i)] & 0xFF);
            if (x != y) {
                return (short) (x - y);
            }
        }
        return 0;
    }

    /** r[rOff..+64) := a * b for 32-byte a and b. r must not overlap a or b. */
    static void mul32(byte[] a, short aOff, byte[] b, short bOff, byte[] r, short rOff) {
        Util.arrayFillNonAtomic(r, rOff, (short) 64, (byte) 0);
        for (short i = (short) (N - 1); i >= 0; i--) {
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short carry = 0;
            for (short j = (short) (N - 1); j >= 0; j--) {
                short k = (short) (rOff + i + j + 1);
                // 255 * 255 + 255 + 255 = 65535: exact in 16 bits
                short t = (short) ((short) (ai * (short) (b[(short) (bOff + j)] & 0xFF))
                        + (short) (r[k] & 0xFF) + carry);
                r[k] = (byte) t;
                carry = (short) ((t >> 8) & 0xFF);
            }
            r[(short) (rOff + i)] = (byte) carry;
        }
    }

    /** Shifts wk[off..+32) right by one bit; top becomes the new most significant bit. */
    private static void shr1(byte[] wk, short off, short top) {
        for (short i = 0; i < N; i++) {
            short v = (short) (wk[(short) (off + i)] & 0xFF);
            wk[(short) (off + i)] = (byte) ((short) (top << 7) | (short) (v >> 1));
            top = (short) (v & 1);
        }
    }

    private static boolean isZero(byte[] wk, short off) {
        byte acc = 0;
        for (short i = 0; i < N; i++) {
            acc |= wk[(short) (off + i)];
        }
        return acc == 0;
    }

    private static boolean isOne(byte[] wk, short off) {
        byte acc = (byte) (wk[(short) (off + N - 1)] ^ 1);
        for (short i = 0; i < (short) (N - 1); i++) {
            acc |= wk[(short) (off + i)];
        }
        return acc == 0;
    }

    static void reverse(byte[] a, short off, short len) {
        short i = off;
        short j = (short) (off + len - 1);
        while (i < j) {
            byte t = a[i];
            a[i] = a[j];
            a[j] = t;
            i++;
            j--;
        }
    }
}

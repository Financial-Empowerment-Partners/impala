package com.impala.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * A diagnostic applet: asks a card, one primitive per command, for what the
 * Impala applet's Ed25519 engine needs, and says which request the card
 * refuses and how. It holds no secret and no state, and is meant to be
 * uninstalled after the run.
 *
 * <p>Every probe command answers {@code 9000} with
 * {@code kind(1) || code(2) || stage(1) || data}: kind 0 is success, otherwise
 * the exception the platform threw ({@link #KIND_CRYPTO} and the others, code
 * = its reason) and the step of the command it threw at. Nothing is decided
 * on the card; the host compares the data with values it computes itself.</p>
 *
 * <p>Algorithms and key types travel as numbers in the command, so the CAP
 * converts against an old API (JavaCard 3.0.1) and still asks for the newer
 * ones (ALG_EC_SVDP_DH_PLAIN_XY is 6): a card answers NO_SUCH_ALGORITHM for
 * what it does not have.</p>
 */
public class ProbeApplet extends Applet {
    static final byte CLA_PROBE = (byte) 0x80;

    /** JCSystem version, free memory, object deletion, protocol. */
    static final byte INS_INFO = (byte) 0x50;
    /** P1 = MessageDigest algorithm; data = message. Answers the digest. */
    static final byte INS_DIGEST = (byte) 0x51;
    /** P1 = class (GI_*), P2 = algorithm: getInstance only. */
    static final byte INS_GET_INSTANCE = (byte) 0x52;
    /** P1 = key type; data = length in bits (2). buildKey only. */
    static final byte INS_BUILD_KEY = (byte) 0x53;
    /**
     * P1 = KeyAgreement algorithm, P2 = curve (CURVE_*, | NO_COFACTOR);
     * data = private key type (1) || scalar (32) || point (65).
     * Answers the secret. Stages: 1 buildKey, 2 setFieldFP, 3 setA, 4 setB,
     * 5 setG, 6 setR, 7 setK, 8 setS, 9 getInstance, 10 init, 11 generateSecret.
     */
    static final byte INS_ECDH = (byte) 0x54;
    /**
     * P1 = KeyAgreement algorithm for the cross-check (0: none), P2 = curve.
     * Generates a key pair on the curve and answers W (65) and, with P1, the
     * key agreement of the new private key with the base point.
     * Stages: 1 buildKey public, 2 buildKey private, 3-8 the public key's
     * curve (as INS_ECDH 2-7), 9-14 the private key's, 15 KeyPair,
     * 16 genKeyPair, 17 getW, 18 getS, 19 getInstance, 20 init,
     * 21 generateSecret.
     */
    static final byte INS_KEYGEN = (byte) 0x55;
    /** data = 32 bytes: an AES-256 key object is built, set and read back. Stages: 1 buildKey, 2 setKey, 3 getKey. */
    static final byte INS_AES_KEY = (byte) 0x56;
    /**
     * P1 = Cipher algorithm; data = bits (2) || expLen (1) || exponent ||
     * modulus (bits / 8) || message (bits / 8). Answers message^exponent mod
     * modulus. Stages: 1 buildKey, 2 setModulus, 3 setExponent, 4 getInstance,
     * 5 init, 6 doFinal.
     */
    static final byte INS_RSA = (byte) 0x57;
    /** P1 = repetitions; data = a (32) || b (32). Answers a * b (64), computed P1 times in bytecode. */
    static final byte INS_MUL = (byte) 0x58;

    /**
     * data = allocations, each kind (1) || size (2): kind 1 a transient byte
     * array cleared on reset, 2 one cleared on deselect, 3 a transient
     * (deselect) 256-bit EC private key. They are made in order and all held
     * until the command ends. Answers the free transient memory afterwards,
     * reset (2) || deselect (2); the stage is the allocation that failed.
     */
    static final byte INS_MEMORY = (byte) 0x59;

    static final byte GI_KEY_AGREEMENT = 1;
    static final byte GI_SIGNATURE = 2;
    static final byte GI_CIPHER = 3;
    static final byte GI_RANDOM = 4;
    static final byte GI_DIGEST = 5;

    static final byte CURVE_P256 = 0;
    static final byte CURVE_WEI25519 = 1;
    static final byte CURVE_MASK = 0x0F;
    /** Leave the cofactor unset (Wei25519 has cofactor 8; some cards refuse setK, or anything but 1). */
    static final byte NO_COFACTOR = 0x10;
    /** Declare the cofactor as 1 whatever the curve (a card may accept only that for some algorithms). */
    static final byte COFACTOR_ONE = 0x20;

    static final byte KIND_OK = 0;
    static final byte KIND_CRYPTO = 1;
    static final byte KIND_SYSTEM = 2;
    static final byte KIND_ISO = 3;
    static final byte KIND_CARD_RUNTIME = 4;
    /** A Java runtime exception; code 1 null pointer, 2 index, 3 security, 4 arithmetic, 0 other. */
    static final byte KIND_RUNTIME = 5;

    static final short N = 32;
    static final short POINT = 65;
    static final short IN_LENGTH = 160;
    static final short OUT_LENGTH = 140;
    static final short HEADER = 4;

    private final byte[] in;
    private final byte[] out;
    private final byte[] stage;

    private ProbeApplet() {
        in = JCSystem.makeTransientByteArray(IN_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        out = JCSystem.makeTransientByteArray(OUT_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        stage = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        ProbeApplet applet = new ProbeApplet();
        if (bLength > 0 && bArray[bOffset] > 0) {
            applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        } else {
            applet.register();
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA_PROBE) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc = 0;
        if (ins == INS_INFO) {
            // no command data
        } else if (ins == INS_GET_INSTANCE || ins == INS_KEYGEN) {
            // no command data
        } else if (ins >= INS_DIGEST && ins <= INS_MEMORY) {
            lc = receive(apdu, buf);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte kind = KIND_OK;
        short code = 0;
        short len = 0;
        stage[0] = 0;
        try {
            len = run(ins, p1, p2, lc);
        } catch (CryptoException e) {
            kind = KIND_CRYPTO;
            code = e.getReason();
        } catch (SystemException e) {
            kind = KIND_SYSTEM;
            code = e.getReason();
        } catch (ISOException e) {
            kind = KIND_ISO;
            code = e.getReason();
        } catch (CardRuntimeException e) {
            kind = KIND_CARD_RUNTIME;
            code = e.getReason();
        } catch (NullPointerException e) {
            kind = KIND_RUNTIME;
            code = 1;
        } catch (IndexOutOfBoundsException e) {
            kind = KIND_RUNTIME;
            code = 2;
        } catch (SecurityException e) {
            kind = KIND_RUNTIME;
            code = 3;
        } catch (ArithmeticException e) {
            kind = KIND_RUNTIME;
            code = 4;
        } catch (RuntimeException e) {
            kind = KIND_RUNTIME;
            code = 0;
        }
        if (kind != KIND_OK) {
            len = 0;
        }
        // Each probe builds its own objects: give the memory back where the card can.
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
        Util.arrayFillNonAtomic(in, (short) 0, IN_LENGTH, (byte) 0);

        buf[0] = kind;
        Util.setShort(buf, (short) 1, code);
        buf[3] = stage[0];
        Util.arrayCopyNonAtomic(out, (short) 0, buf, HEADER, len);
        apdu.setOutgoingAndSend((short) 0, (short) (HEADER + len));
    }

    /** Copies the command data to {@link #in} and returns its length. */
    private short receive(APDU apdu, byte[] buf) {
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        if (lc > IN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short read = apdu.setIncomingAndReceive();
        short off = 0;
        while (true) {
            if ((short) (off + read) > lc) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, in, off, read);
            off += read;
            if (off >= lc) {
                break;
            }
            read = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        return lc;
    }

    private void step() {
        stage[0]++;
    }

    private short run(byte ins, byte p1, byte p2, short lc) {
        switch (ins) {
            case INS_INFO:
                return info();
            case INS_DIGEST:
                return digest(p1, lc);
            case INS_GET_INSTANCE:
                return getInstance(p1, p2);
            case INS_BUILD_KEY:
                return buildKey(p1, lc);
            case INS_ECDH:
                return ecdh(p1, p2, lc);
            case INS_KEYGEN:
                return keygen(p1, p2);
            case INS_AES_KEY:
                return aesKey(lc);
            case INS_RSA:
                return rsa(p1, lc);
            case INS_MUL:
                return mul(p1, lc);
            default:
                return memory(lc);
        }
    }

    private short memory(short lc) {
        // Held in locals: the objects stay referenced until the command returns.
        Object[] held = new Object[(short) (lc / 3)];
        for (short off = 0; (short) (off + 3) <= lc; off += 3) {
            step();
            short size = Util.getShort(in, (short) (off + 1));
            Object o;
            switch (in[off]) {
                case 1:
                    o = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_RESET);
                    break;
                case 2:
                    o = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
                    break;
                default:
                    o = KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                            KeyBuilder.LENGTH_EC_FP_256, false);
            }
            held[(short) (off / 3)] = o;
        }
        Util.setShort(out, (short) 0, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        Util.setShort(out, (short) 2, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        return 4;
    }

    private short info() {
        Util.setShort(out, (short) 0, JCSystem.getVersion());
        Util.setShort(out, (short) 2, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
        Util.setShort(out, (short) 4, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        Util.setShort(out, (short) 6, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        out[8] = JCSystem.isObjectDeletionSupported() ? (byte) 1 : (byte) 0;
        out[9] = APDU.getProtocol();
        return (short) 10;
    }

    private short digest(byte alg, short lc) {
        step();
        MessageDigest md = MessageDigest.getInstance(alg, false);
        step();
        return md.doFinal(in, (short) 0, lc, out, (short) 0);
    }

    private short getInstance(byte cls, byte alg) {
        step();
        switch (cls) {
            case GI_KEY_AGREEMENT:
                KeyAgreement.getInstance(alg, false);
                break;
            case GI_SIGNATURE:
                Signature.getInstance(alg, false);
                break;
            case GI_CIPHER:
                Cipher.getInstance(alg, false);
                break;
            case GI_RANDOM:
                RandomData.getInstance(alg);
                break;
            case GI_DIGEST:
                MessageDigest.getInstance(alg, false);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return 0;
    }

    private short buildKey(byte type, short lc) {
        if (lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        step();
        KeyBuilder.buildKey(type, Util.getShort(in, (short) 0), false);
        return 0;
    }

    /** Six stages: the domain parameters of {@code curve} on {@code key}. */
    private void setCurve(ECKey key, byte curve) {
        boolean wei = (byte) (curve & CURVE_MASK) == CURVE_WEI25519;
        step();
        key.setFieldFP(wei ? ProbeCurves.WEI_P : ProbeCurves.P256_P, (short) 0, N);
        step();
        key.setA(wei ? ProbeCurves.WEI_A : ProbeCurves.P256_A, (short) 0, N);
        step();
        key.setB(wei ? ProbeCurves.WEI_B : ProbeCurves.P256_B, (short) 0, N);
        step();
        key.setG(wei ? ProbeCurves.WEI_G : ProbeCurves.P256_G, (short) 0, POINT);
        step();
        key.setR(wei ? ProbeCurves.WEI_R : ProbeCurves.P256_R, (short) 0, N);
        step();
        if ((byte) (curve & COFACTOR_ONE) != 0) {
            key.setK((short) 1);
        } else if ((byte) (curve & NO_COFACTOR) == 0) {
            key.setK(wei ? (short) 8 : (short) 1);
        }
    }

    private short ecdh(byte alg, byte curve, short lc) {
        if (lc != (short) (1 + N + POINT)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        step();
        ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(in[0], KeyBuilder.LENGTH_EC_FP_256, false);
        setCurve(key, curve);
        step();
        key.setS(in, (short) 1, N);
        step();
        KeyAgreement ka = KeyAgreement.getInstance(alg, false);
        step();
        ka.init(key);
        step();
        short n = ka.generateSecret(in, (short) (1 + N), POINT, out, (short) 0);
        key.clearKey();
        return n;
    }

    private short keygen(byte alg, byte curve) {
        step();
        ECPublicKey pub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                KeyBuilder.LENGTH_EC_FP_256, false);
        step();
        ECPrivateKey priv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                KeyBuilder.LENGTH_EC_FP_256, false);
        setCurve(pub, curve);
        setCurve(priv, curve);
        step();
        KeyPair pair = new KeyPair(pub, priv);
        step();
        pair.genKeyPair();
        step();
        short n = pub.getW(out, (short) 0);
        if (alg == 0) {
            priv.clearKey();
            return n;
        }
        // The engine's own check: the key agreement of the new scalar with the
        // base point must be the public point the card generated.
        step();
        short s = priv.getS(in, (short) 0);
        short pad = (short) (N - s);
        if (pad > 0) {
            Util.arrayCopyNonAtomic(in, (short) 0, in, pad, s);
            Util.arrayFillNonAtomic(in, (short) 0, pad, (byte) 0);
        }
        priv.setS(in, (short) 0, N);
        step();
        KeyAgreement ka = KeyAgreement.getInstance(alg, false);
        step();
        ka.init(priv);
        step();
        boolean wei = (byte) (curve & CURVE_MASK) == CURVE_WEI25519;
        n += ka.generateSecret(wei ? ProbeCurves.WEI_G : ProbeCurves.P256_G, (short) 0, POINT, out, n);
        priv.clearKey();
        return n;
    }

    private short aesKey(short lc) {
        if (lc != N) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        step();
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        step();
        key.setKey(in, (short) 0);
        step();
        short n = key.getKey(out, (short) 0);
        key.clearKey();
        return n;
    }

    private short rsa(byte alg, short lc) {
        short bits = Util.getShort(in, (short) 0);
        short size = (short) (bits / 8);
        short expLen = (short) (in[2] & 0xFF);
        short expOff = 3;
        short modOff = (short) (expOff + expLen);
        short msgOff = (short) (modOff + size);
        if (size <= 0 || size > OUT_LENGTH || lc != (short) (msgOff + size)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        step();
        RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, bits, false);
        step();
        key.setModulus(in, modOff, size);
        step();
        key.setExponent(in, expOff, expLen);
        step();
        Cipher cipher = Cipher.getInstance(alg, false);
        step();
        cipher.init(key, Cipher.MODE_ENCRYPT);
        step();
        return cipher.doFinal(in, msgOff, size, out, (short) 0);
    }

    private short mul(byte times, short lc) {
        if (lc != (short) (2 * N)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short n = (short) (times & 0xFF);
        for (short i = 0; i < n; i++) {
            mul32(in, (short) 0, in, N, out, (short) 0);
        }
        return (short) (2 * N);
    }

    /** r[rOff..+64) := a[aOff..+32) * b[bOff..+32), big-endian, schoolbook, bytes in 16-bit arithmetic. */
    private static void mul32(byte[] a, short aOff, byte[] b, short bOff, byte[] r, short rOff) {
        Util.arrayFillNonAtomic(r, rOff, (short) (2 * N), (byte) 0);
        for (short i = (short) (N - 1); i >= 0; i--) {
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short carry = 0;
            for (short j = (short) (N - 1); j >= 0; j--) {
                short k = (short) (rOff + i + j + 1);
                // at most 255 * 255 + 255 + 255 = 65535: fits 16 bits, read back unsigned
                short t = (short) (ai * (short) (b[(short) (bOff + j)] & 0xFF));
                t = (short) (t + (short) (r[k] & 0xFF));
                t = (short) (t + carry);
                r[k] = (byte) t;
                carry = (short) ((t >> 8) & 0xFF);
            }
            r[(short) (rOff + i)] = (byte) carry;
        }
    }
}

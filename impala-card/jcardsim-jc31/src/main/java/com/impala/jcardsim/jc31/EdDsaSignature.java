package com.impala.jcardsim.jc31;

import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * EdDSA over Ed25519 keys from {@code KeyBuilder.buildXECKey}: pure EdDSA
 * (RFC 8032), 64-byte signatures, as the generic JavaCard 3.1 cipher
 * {@code Signature.SIG_CIPHER_EDDSA} or the JavaCard 3.2 per-curve cipher
 * {@code SIG_CIPHER_EDDSA_ED25519}. Which of the two a card has, under which
 * message digest constant, and whether the result really is pure Ed25519,
 * follows its {@link CardPlatform}.
 */
final class EdDsaSignature extends Signature {
    private static final short SIGNATURE_LENGTH = 64;

    private final byte messageDigestAlgorithm;
    private final byte cipherAlgorithm;
    private final boolean pureSign;
    private final boolean pureVerify;
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private XecKeyImpl key;
    private byte mode;

    private EdDsaSignature(byte messageDigestAlgorithm, byte cipherAlgorithm, boolean pureSign, boolean pureVerify) {
        this.messageDigestAlgorithm = messageDigestAlgorithm;
        this.cipherAlgorithm = cipherAlgorithm;
        this.pureSign = pureSign;
        this.pureVerify = pureVerify;
    }

    /**
     * The instance a card of {@code platform} gives for this request, or
     * {@code NO_SUCH_ALGORITHM}. The JavaCard 3.2 API specifies both ciphers
     * with {@code MessageDigest.ALG_NULL}; the 3.1 text left the digest
     * constant of the generic cipher open, so a platform may take
     * {@code ALG_SHA_512} there instead.
     */
    static Signature create(CardPlatform platform, byte messageDigestAlgorithm, byte cipherAlgorithm,
            byte paddingAlgorithm) throws CryptoException {
        boolean isNull = messageDigestAlgorithm == MessageDigest.ALG_NULL;
        boolean isSha512 = messageDigestAlgorithm == MessageDigest.ALG_SHA_512;
        boolean accepted;
        if (cipherAlgorithm == SIG_CIPHER_EDDSA) {
            accepted = (isNull && platform.edDsaGenericNull()) || (isSha512 && platform.edDsaGenericSha512());
        } else if (cipherAlgorithm == Jc31.SIG_CIPHER_EDDSA_ED25519) {
            accepted = isNull && platform.edDsaPerCurve();
        } else {
            accepted = false;
        }
        if (!accepted || paddingAlgorithm != Cipher.PAD_NULL) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return new EdDsaSignature(messageDigestAlgorithm, cipherAlgorithm,
                platform.edDsaPureSign(), platform.edDsaPureVerify());
    }

    @Override
    public void init(Key theKey, byte theMode) throws CryptoException {
        boolean fits = (theMode == MODE_SIGN && theKey instanceof XecPrivateKeyImpl)
                || (theMode == MODE_VERIFY && theKey instanceof XecPublicKeyImpl);
        if (!fits) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        key = (XecKeyImpl) theKey;
        mode = theMode;
        message.reset();
    }

    @Override
    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        // Pure Ed25519 takes no parameters (no context, no initial vector).
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    @Override
    public void setInitialDigest(byte[] state, short stateOffset, short stateLength,
            byte[] digestedLen, short digestedLenOffset, short digestedLenLength) throws CryptoException {
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }

    @Override
    public byte getAlgorithm() {
        return 0;
    }

    @Override
    public byte getMessageDigestAlgorithm() {
        return messageDigestAlgorithm;
    }

    @Override
    public byte getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    @Override
    public byte getPaddingAlgorithm() {
        return Cipher.PAD_NULL;
    }

    @Override
    public short getLength() throws CryptoException {
        return SIGNATURE_LENGTH;
    }

    @Override
    public void update(byte[] inBuff, short inOffset, short inLength) throws CryptoException {
        require((byte) 0);
        append(inBuff, inOffset, inLength);
    }

    @Override
    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset)
            throws CryptoException {
        require(MODE_SIGN);
        append(inBuff, inOffset, inLength);
        byte[] privateKey = key.encoded();
        byte[] signature;
        try {
            signature = Ed25519Jdk.sign(privateKey, takeMessage(pureSign));
        } finally {
            java.util.Arrays.fill(privateKey, (byte) 0);
        }
        Util.arrayCopyNonAtomic(signature, (short) 0, sigBuff, sigOffset, SIGNATURE_LENGTH);
        return SIGNATURE_LENGTH;
    }

    @Override
    public boolean verify(byte[] inBuff, short inOffset, short inLength,
            byte[] sigBuff, short sigOffset, short sigLength) throws CryptoException {
        require(MODE_VERIFY);
        append(inBuff, inOffset, inLength);
        byte[] m = takeMessage(pureVerify);
        if (sigLength != SIGNATURE_LENGTH) {
            return false;
        }
        byte[] signature = new byte[SIGNATURE_LENGTH];
        Util.arrayCopyNonAtomic(sigBuff, sigOffset, signature, (short) 0, SIGNATURE_LENGTH);
        return Ed25519Jdk.verify(key.encoded(), m, signature);
    }

    @Override
    public short signPreComputedHash(byte[] hashBuff, short hashOffset, short hashLength,
            byte[] sigBuff, short sigOffset) throws CryptoException {
        // Pure EdDSA has no separate message digest step.
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        return 0;
    }

    @Override
    public boolean verifyPreComputedHash(byte[] hashBuff, short hashOffset, short hashLength,
            byte[] sigBuff, short sigOffset, short sigLength) throws CryptoException {
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        return false;
    }

    /** INVALID_INIT unless initialized, and for this mode when one is given. */
    private void require(byte wanted) {
        if (key == null || (wanted != 0 && mode != wanted)) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
    }

    private void append(byte[] in, short offset, short length) {
        if (offset < 0 || length < 0 || offset + length > in.length) {
            throw new ArrayIndexOutOfBoundsException();
        }
        message.write(in, offset, length);
    }

    /** The accumulated message, as the scheme of this profile handles it in this direction; resets the accumulator. */
    private byte[] takeMessage(boolean pure) {
        byte[] m = message.toByteArray();
        message.reset();
        if (pure) {
            return m;
        }
        try {
            return java.security.MessageDigest.getInstance("SHA-512").digest(m);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

package com.impala.applet;

/**
 * The card's Stellar key: an Ed25519 (RFC 8032) key pair generated on the card
 * and a signer over it, behind one applet-internal API.
 *
 * <p>Two engines implement it and exactly one is compiled into a CAP (see
 * {@code Ed25519Provider} and the {@code applet.ed25519} build option):
 * {@code Ed25519Soft} for JavaCard 3.0.5 platforms and {@code Ed25519Native}
 * for JavaCard 3.1+ platforms with EdDSA. Both produce standard Ed25519
 * signatures; the rest of the applet cannot tell them apart.</p>
 *
 * <p>The key is generate-only: there is no way to load or read the private
 * key through this API.</p>
 */
abstract class Ed25519 {
    /** Engine ids reported by GET_STELLAR_KEY. */
    static final byte ENGINE_SOFT = Constants.ED25519_ENGINE_SOFT;
    static final byte ENGINE_NATIVE = Constants.ED25519_ENGINE_NATIVE;

    static final short PUBLIC_KEY_LENGTH = Constants.ED25519_PUB_KEY_LENGTH;
    static final short SIGNATURE_LENGTH = Constants.ED25519_SIG_LENGTH;

    /** {@link #ENGINE_SOFT} or {@link #ENGINE_NATIVE}. */
    abstract byte engineId();

    /**
     * Generates a fresh key pair. Returns false, leaving no usable key, when
     * the platform refuses any step; the card then behaves as a legacy card.
     */
    abstract boolean generateKeyPair();

    /** True once a key pair has been generated; stays true after {@link #clearKey()}. */
    abstract boolean hasPublicKey();

    /** True while the key can sign: generated and not cleared. */
    abstract boolean isKeyReady();

    /**
     * Copies the 32-byte RFC 8032 public key to {@code out[outOff..outOff+32)}.
     * Meaningful only when {@link #hasPublicKey()}.
     */
    abstract void getPublicKey(byte[] out, short outOff);

    /**
     * Signs {@code msg[msgOff..msgOff+msgLen)} (pure Ed25519) and writes the
     * 64-byte signature to {@code sig[sigOff..sigOff+64)}. The two ranges must
     * not overlap. Returns 64. Throws {@code CryptoException} when there is no
     * usable key or the platform refuses.
     */
    abstract short sign(byte[] msg, short msgOff, short msgLen, byte[] sig, short sigOff);

    /** Destroys the private key. The public key stays readable. */
    abstract void clearKey();
}

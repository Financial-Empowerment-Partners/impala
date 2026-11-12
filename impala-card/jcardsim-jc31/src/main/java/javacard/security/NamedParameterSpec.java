package javacard.security;

import com.impala.jcardsim.jc31.Jc31;

/**
 * JavaCard 3.1: algorithm parameters identified by a standard name. The
 * constants are the JavaCard 3.1 API's; this layer implements {@link #ED25519}
 * only and answers {@code CryptoException.NO_SUCH_ALGORITHM} for the rest, as
 * a card without those curves would.
 */
public class NamedParameterSpec implements AlgorithmParameterSpec {
    public static final short ED25519 = 257;
    public static final short ED448 = 514;
    public static final short X25519 = 259;
    public static final short X448 = 516;
    public static final short FRP256V1 = 1025;
    public static final short SM2 = 768;
    public static final short SECP192R1 = 4097;
    public static final short SECP224R1 = 4098;
    public static final short SECP256R1 = 4099;
    public static final short SECP384R1 = 4100;
    public static final short SECP521R1 = 4101;
    public static final short BRAINPOOLP192R1 = 8195;
    public static final short BRAINPOOLP192T1 = 8196;
    public static final short BRAINPOOLP224R1 = 8197;
    public static final short BRAINPOOLP224T1 = 8198;
    public static final short BRAINPOOLP256R1 = 8199;
    public static final short BRAINPOOLP256T1 = 8200;
    public static final short BRAINPOOLP320R1 = 8201;
    public static final short BRAINPOOLP320T1 = 8202;
    public static final short BRAINPOOLP384R1 = 8203;
    public static final short BRAINPOOLP384T1 = 8204;
    public static final short BRAINPOOLP512R1 = 8205;
    public static final short BRAINPOOLP512T1 = 8206;

    private static final NamedParameterSpec ED25519_SPEC = new NamedParameterSpec(ED25519);

    private final short name;

    private NamedParameterSpec(short name) {
        this.name = name;
    }

    public static final NamedParameterSpec getInstance(short stdName) throws CryptoException {
        if (stdName != ED25519 || !Jc31.edDsaAvailable()) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        return ED25519_SPEC;
    }

    public final short getName() {
        return name;
    }
}

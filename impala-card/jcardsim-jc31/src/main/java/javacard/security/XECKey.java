package javacard.security;

/** JavaCard 3.1: a key on a named curve with a predefined encoding. */
public interface XECKey {
    NamedParameterSpec getParams();

    short getEncodingLength();

    /** Copies the encoded key to {@code value[offset..]}; returns the offset after the last byte. */
    short getEncoded(byte[] value, short offset);

    void setEncoded(byte[] value, short offset, short length) throws CryptoException;
}

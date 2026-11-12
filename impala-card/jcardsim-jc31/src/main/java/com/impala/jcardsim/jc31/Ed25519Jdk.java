package com.impala.jcardsim.jc31;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

/** Ed25519 from the JDK (15+), on the RFC 8032 byte encodings JavaCard uses. */
final class Ed25519Jdk {
    private Ed25519Jdk() {
    }

    /** A fresh key pair: { private key (the 32-byte seed), public key }. */
    static byte[][] generate() {
        try {
            KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            byte[] seed = ((EdECPrivateKey) pair.getPrivate()).getBytes()
                    .orElseThrow(() -> new IllegalStateException("the JDK did not expose the private key"));
            return new byte[][] {seed, encode(((EdECPublicKey) pair.getPublic()).getPoint())};
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("this JVM has no Ed25519 (needs JDK 15 or later)", e);
        }
    }

    static byte[] sign(byte[] privateKey, byte[] message) {
        try {
            PrivateKey key = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, privateKey));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(message);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(decode(publicKey));
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** True when the 32 bytes decode to a point the JDK accepts as a public key. */
    static boolean isPublicKey(byte[] encoded) {
        try {
            Signature.getInstance("Ed25519").initVerify(decode(encoded));
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static PublicKey decode(byte[] encoded) throws GeneralSecurityException {
        byte[] bigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            bigEndian[i] = encoded[31 - i];
        }
        boolean xOdd = (bigEndian[0] & 0x80) != 0;
        bigEndian[0] &= 0x7F;
        EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, bigEndian));
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
    }

    private static byte[] encode(EdECPoint point) {
        byte[] bigEndian = point.getY().toByteArray();
        byte[] encoded = new byte[32];
        for (int i = 0; i < bigEndian.length && i < 32; i++) {
            encoded[i] = bigEndian[bigEndian.length - 1 - i];
        }
        if (point.isXOdd()) {
            encoded[31] |= (byte) 0x80;
        }
        return encoded;
    }
}

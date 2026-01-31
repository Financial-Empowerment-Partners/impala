package com.impala.applet;

/**
 * A transaction record consisting of its raw contents and their SHA-256 hash.
 * Contents layout (252 bytes): [signable (60B) | signature (64B) | pubKey (64B) | pubKeySig (64B)].
 * Stored in the on-card Repository for offline transaction tracking.
 */
public class Hashable {
    /** SHA-256 hash of contents (32 bytes). Used as the transaction identifier. */
    public final byte[] hash;
    /** Raw transaction data (252 bytes): signable + signature + pubKey + pubKeySig. */
    public final byte[] contents;

    public Hashable(byte[] hash, byte[] contents) {
        this.hash = hash;
        this.contents = contents;
    }
}

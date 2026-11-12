package com.impala.applet;

/**
 * Engine choice of the default CAP ({@code -Papplet.ed25519=soft}, JavaCard
 * 3.0.5): Ed25519 through the card's ECDH engine. See {@link Ed25519Soft}.
 */
final class Ed25519Provider {
    private Ed25519Provider() {
    }

    /** The engine, or null where the platform lacks a primitive it needs. */
    static Ed25519 create() {
        return Ed25519Soft.create();
    }
}

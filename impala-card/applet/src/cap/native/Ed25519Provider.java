package com.impala.applet;

/**
 * Engine choice of the JavaCard 3.1 CAP ({@code -Papplet.ed25519=native}): the
 * platform's own EdDSA. See {@link Ed25519Native}.
 */
final class Ed25519Provider {
    private Ed25519Provider() {
    }

    /** The engine, or null where the platform has no pure Ed25519. */
    static Ed25519 create() {
        return Ed25519Native.create();
    }
}

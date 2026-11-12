package com.impala.applet;

/**
 * Engine choice of the legacy CAP ({@code -Papplet.ed25519=none}): no Stellar
 * key. GET_STELLAR_KEY and SIGN_SEP10 answer 0x623C and the card signs in with
 * SIGN_AUTH only.
 */
final class Ed25519Provider {
    private Ed25519Provider() {
    }

    static Ed25519 create() {
        return null;
    }
}

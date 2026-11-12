package com.impala.applet;

/**
 * Chooses the Ed25519 engine of a card (see {@link Ed25519}).
 *
 * <p>This is the simulator's provider: on a JVM (jcardsim) every engine is
 * present and the system property {@code impala.ed25519} picks one when the
 * applet is installed: {@code soft} (the default), {@code native} or
 * {@code none}. It is never part of a CAP file. A CAP contains exactly one
 * engine, fixed at build time by {@code -Papplet.ed25519=soft|native|none},
 * and its provider is the matching file under {@code applet/src/cap/}.</p>
 */
final class Ed25519Provider {
    static final String ENGINE_PROPERTY = "impala.ed25519";

    private Ed25519Provider() {
    }

    /** The engine, or null for a card without a Stellar key. */
    static Ed25519 create() {
        String engine = System.getProperty(ENGINE_PROPERTY, "soft");
        if (engine.equals("soft")) {
            return Ed25519Soft.create();
        }
        if (engine.equals("native")) {
            return Ed25519Native.create();
        }
        if (engine.equals("none")) {
            return null;
        }
        throw new IllegalArgumentException(ENGINE_PROPERTY + " must be soft, native or none, not " + engine);
    }
}

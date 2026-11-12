package com.impala.jcardsim.jc31;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;

/**
 * A simulated card product: the JavaCard Classic API level it implements and
 * which of the optional algorithms an applet may ask for it really has.
 *
 * <p>jcardsim on its own is one card: JavaCard 3.0.5 with every algorithm
 * present and no limit on memory. Real cards differ in exactly the places the
 * Impala applet depends on: whether the platform has EdDSA at all (JavaCard
 * 3.1 and later), under which constants it offers it (the generic
 * {@code SIG_CIPHER_EDDSA} of 3.1, the per-curve
 * {@code SIG_CIPHER_EDDSA_ED25519} that 3.2 adds), and, on a JavaCard 3.0.5
 * card, whether the primitives of the software Ed25519 engine are there (ECDH
 * that returns both coordinates, custom curve parameters, SHA-512, a 256-bit
 * AES key object, enough transient memory). A {@code CardPlatform} says which
 * of those a simulated card has, and the patched jcardsim classes of this
 * module ask it before they answer an applet.</p>
 *
 * <p>One thing no card of this simulator has: transient EC private keys
 * ({@code KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT}). jcardsim does
 * not implement them, so there is nothing to switch off, and an applet that
 * prefers one always runs its fallback here.</p>
 *
 * <p>The presets ({@link #JC305}, {@link #JC32} and their variants, see
 * {@link #presets()}) are the card models the simulator integrations name:
 * {@code SimulatorBibo(platform = …)}, {@code :simulator:serve --platform},
 * {@code impala.platform} in a vpcd cfg. A platform is immutable; the state of
 * one simulated card (what it has allocated) lives in a {@link Card}.</p>
 *
 * <p>Nothing here is a model of a named product. Which real cards behave like
 * which preset is what fleet testing on hardware finds out.</p>
 */
public final class CardPlatform {

    /**
     * A JavaCard Classic API level, with the minor versions of the three API
     * packages a card of that level exports (the major version is 1
     * throughout). A card loads a CAP only if it has every imported package at
     * the imported version or a later one.
     */
    public enum Level {
        JC305("3.0.5", 6, 6, 6),
        JC31("3.1", 8, 7, 7),
        JC32("3.2", 9, 8, 8);

        private final String label;
        private final int framework;
        private final int security;
        private final int crypto;

        Level(String label, int framework, int security, int crypto) {
            this.label = label;
            this.framework = framework;
            this.security = security;
            this.crypto = crypto;
        }

        /** {@code 3.0.5}, {@code 3.1} or {@code 3.2}. */
        public String label() {
            return label;
        }

        /** Minor version of {@code javacard.framework} (1.x). */
        public int frameworkMinor() {
            return framework;
        }

        /** Minor version of {@code javacard.security} (1.x). */
        public int securityMinor() {
            return security;
        }

        /** Minor version of {@code javacardx.crypto} (1.x). */
        public int cryptoMinor() {
            return crypto;
        }

        public boolean atLeast(Level other) {
            return ordinal() >= other.ordinal();
        }

        /** Whether a card of this level has the three API packages at these minor versions or later. */
        public boolean exports(int frameworkMinor, int securityMinor, int cryptoMinor) {
            return framework >= frameworkMinor && security >= securityMinor && crypto >= cryptoMinor;
        }
    }

    /** What a card does with elliptic-curve domain parameters that are not one of its own curves. */
    public enum CustomCurves {
        /** Computes on the curve it is given. */
        SUPPORTED,
        /** Refuses a key on such a curve when it is used ({@code CryptoException.ILLEGAL_VALUE}). */
        REFUSED,
        /**
         * Accepts the parameters and computes something else, the same wrong
         * way in key generation and in ECDH (a card whose arithmetic assumes
         * its own curve family). The two agree with each other, so only a
         * known-answer test can tell.
         */
        WRONG_MATH
    }

    private final String name;
    private final String description;
    private final Level level;
    private final boolean edDsaGenericNull;
    private final boolean edDsaGenericSha512;
    private final boolean edDsaPerCurve;
    private final boolean edDsaPureSign;
    private final boolean edDsaPureVerify;
    private final boolean xecPrivateKeyImport;
    private final boolean ecdhPlainXy;
    private final CustomCurves customCurves;
    private final boolean sha512;
    private final boolean aes256Keys;
    private final int transientResetBytes;
    private final int transientDeselectBytes;

    private CardPlatform(Builder b) {
        name = b.name;
        description = b.description;
        level = b.level;
        edDsaGenericNull = b.edDsaGenericNull;
        edDsaGenericSha512 = b.edDsaGenericSha512;
        edDsaPerCurve = b.edDsaPerCurve;
        edDsaPureSign = b.edDsaPureSign;
        edDsaPureVerify = b.edDsaPureVerify;
        xecPrivateKeyImport = b.xecPrivateKeyImport;
        ecdhPlainXy = b.ecdhPlainXy;
        customCurves = b.customCurves;
        sha512 = b.sha512;
        aes256Keys = b.aes256Keys;
        transientResetBytes = b.transientResetBytes;
        transientDeselectBytes = b.transientDeselectBytes;
    }

    // ------------------------------------------------------------------ what the platform has

    /** The name the integrations use ({@code jc305}, {@code jc32-per-curve}, …). */
    public String name() {
        return name;
    }

    /** One line for a help text or a log. */
    public String description() {
        return description;
    }

    public Level level() {
        return level;
    }

    /** Pure Ed25519 as {@code SIG_CIPHER_EDDSA} with {@code MessageDigest.ALG_NULL} (JavaCard 3.1+). */
    public boolean edDsaGenericNull() {
        return edDsaGenericNull;
    }

    /** Pure Ed25519 as {@code SIG_CIPHER_EDDSA} with {@code MessageDigest.ALG_SHA_512} (JavaCard 3.1+). */
    public boolean edDsaGenericSha512() {
        return edDsaGenericSha512;
    }

    /** Pure Ed25519 as {@code SIG_CIPHER_EDDSA_ED25519} with {@code MessageDigest.ALG_NULL} (JavaCard 3.2). */
    public boolean edDsaPerCurve() {
        return edDsaPerCurve;
    }

    /** Whether the platform has Ed25519 keys and signatures in any form. */
    public boolean edDsaOffered() {
        return edDsaGenericNull || edDsaGenericSha512 || edDsaPerCurve;
    }

    /** False: what the platform calls EdDSA hashes the message first when it signs (not pure Ed25519). */
    public boolean edDsaPureSign() {
        return edDsaPureSign;
    }

    /** False: the same when it verifies. */
    public boolean edDsaPureVerify() {
        return edDsaPureVerify;
    }

    /** Whether an Ed25519 private key can be loaded ({@code XECPrivateKey.setEncoded}). */
    public boolean xecPrivateKeyImport() {
        return xecPrivateKeyImport;
    }

    /** {@code KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY}. */
    public boolean ecdhPlainXy() {
        return ecdhPlainXy;
    }

    public CustomCurves customCurves() {
        return customCurves;
    }

    /** {@code MessageDigest.ALG_SHA_512}. */
    public boolean sha512() {
        return sha512;
    }

    /** A 256-bit AES key object from {@code KeyBuilder.buildKey}. */
    public boolean aes256Keys() {
        return aes256Keys;
    }

    /** Bytes of {@code CLEAR_ON_RESET} transient memory one applet instance may take; -1 for no limit. */
    public int transientResetBytes() {
        return transientResetBytes;
    }

    /** The same for {@code CLEAR_ON_DESELECT}; -1 for no limit. */
    public int transientDeselectBytes() {
        return transientDeselectBytes;
    }

    @Override
    public String toString() {
        return name + " (JavaCard " + level.label + ")";
    }

    // ------------------------------------------------------------------ building one

    /** A platform of {@code level} with every optional algorithm of that level present and no memory limit. */
    public static Builder builder(String name, Level level) {
        return new Builder(name, level);
    }

    /** A copy to change, under a new name. */
    public Builder toBuilder(String newName) {
        Builder b = new Builder(newName, level);
        b.description = description;
        b.edDsaGenericNull = edDsaGenericNull;
        b.edDsaGenericSha512 = edDsaGenericSha512;
        b.edDsaPerCurve = edDsaPerCurve;
        b.edDsaPureSign = edDsaPureSign;
        b.edDsaPureVerify = edDsaPureVerify;
        b.xecPrivateKeyImport = xecPrivateKeyImport;
        b.ecdhPlainXy = ecdhPlainXy;
        b.customCurves = customCurves;
        b.sha512 = sha512;
        b.aes256Keys = aes256Keys;
        b.transientResetBytes = transientResetBytes;
        b.transientDeselectBytes = transientDeselectBytes;
        return b;
    }

    public static final class Builder {
        private final String name;
        private final Level level;
        private String description = "";
        private boolean edDsaGenericNull;
        private boolean edDsaGenericSha512;
        private boolean edDsaPerCurve;
        private boolean edDsaPureSign = true;
        private boolean edDsaPureVerify = true;
        private boolean xecPrivateKeyImport = true;
        private boolean ecdhPlainXy = true;
        private CustomCurves customCurves = CustomCurves.SUPPORTED;
        private boolean sha512 = true;
        private boolean aes256Keys = true;
        private int transientResetBytes = -1;
        private int transientDeselectBytes = -1;

        private Builder(String name, Level level) {
            if (name == null || !name.matches("[a-z0-9][a-z0-9-]{0,39}")) {
                throw new IllegalArgumentException("a platform name is lowercase letters, digits and dashes, not " + name);
            }
            if (level == null) {
                throw new IllegalArgumentException("a platform needs a JavaCard level");
            }
            this.name = name;
            this.level = level;
            // What a card of this level has when its maker implemented all of it.
            this.edDsaGenericNull = level.atLeast(Level.JC31);
            this.edDsaPerCurve = level.atLeast(Level.JC32);
        }

        public Builder description(String text) {
            description = text == null ? "" : text;
            return this;
        }

        /**
         * How the platform offers pure Ed25519: as {@code SIG_CIPHER_EDDSA}
         * with {@code ALG_NULL}, as {@code SIG_CIPHER_EDDSA} with
         * {@code ALG_SHA_512}, as the JavaCard 3.2
         * {@code SIG_CIPHER_EDDSA_ED25519}. All false: no Ed25519.
         */
        public Builder edDsa(boolean genericNull, boolean genericSha512, boolean perCurve) {
            edDsaGenericNull = genericNull;
            edDsaGenericSha512 = genericSha512;
            edDsaPerCurve = perCurve;
            return this;
        }

        public Builder noEdDsa() {
            return edDsa(false, false, false);
        }

        /** A platform whose "EdDSA" hashes the message first, when signing and, unless {@code pureVerify}, when verifying. */
        public Builder edDsaNotPure(boolean pureVerify) {
            edDsaPureSign = false;
            edDsaPureVerify = pureVerify;
            return this;
        }

        public Builder xecPrivateKeyImport(boolean allowed) {
            xecPrivateKeyImport = allowed;
            return this;
        }

        public Builder ecdhPlainXy(boolean present) {
            ecdhPlainXy = present;
            return this;
        }

        public Builder customCurves(CustomCurves behaviour) {
            customCurves = behaviour;
            return this;
        }

        public Builder sha512(boolean present) {
            sha512 = present;
            return this;
        }

        public Builder aes256Keys(boolean present) {
            aes256Keys = present;
            return this;
        }

        /** Transient memory one applet instance may take, in bytes per clearing event; -1 for no limit. */
        public Builder transientMemory(int resetBytes, int deselectBytes) {
            transientResetBytes = resetBytes;
            transientDeselectBytes = deselectBytes;
            return this;
        }

        public CardPlatform build() {
            boolean edDsa = edDsaGenericNull || edDsaGenericSha512 || edDsaPerCurve;
            if (edDsa && !level.atLeast(Level.JC31)) {
                throw new IllegalArgumentException(name + ": a JavaCard " + level.label + " card has no EdDSA API");
            }
            if (edDsaPerCurve && !level.atLeast(Level.JC32)) {
                throw new IllegalArgumentException(name + ": SIG_CIPHER_EDDSA_ED25519 is JavaCard 3.2 API, not " + level.label);
            }
            if (customCurves == null) {
                throw new IllegalArgumentException(name + ": customCurves must be set");
            }
            if (transientResetBytes < -1 || transientDeselectBytes < -1) {
                throw new IllegalArgumentException(name + ": a memory limit is a number of bytes, or -1 for none");
            }
            return new CardPlatform(this);
        }
    }

    // ------------------------------------------------------------------ the card models

    /** A JavaCard 3.0.5 card with everything the software Ed25519 engine needs. No EdDSA API. */
    public static final CardPlatform JC305 = builder("jc305", Level.JC305)
            .description("JavaCard 3.0.5 card: no EdDSA API; ECDH (plain XY), custom curves, SHA-512 and AES-256 keys present")
            .build();

    /** JavaCard 3.0.5 without {@code ALG_EC_SVDP_DH_PLAIN_XY}. */
    public static final CardPlatform JC305_NO_XY = JC305.toBuilder("jc305-no-xy")
            .description("JavaCard 3.0.5 card without KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY")
            .ecdhPlainXy(false).build();

    /** JavaCard 3.0.5 that only computes on its own curves and refuses any other parameters. */
    public static final CardPlatform JC305_FIXED_CURVES = JC305.toBuilder("jc305-fixed-curves")
            .description("JavaCard 3.0.5 card that refuses elliptic-curve parameters other than its own curves")
            .customCurves(CustomCurves.REFUSED).build();

    /** JavaCard 3.0.5 that accepts custom curve parameters and computes on them wrongly, consistently. */
    public static final CardPlatform JC305_WRONG_CURVE_MATH = JC305.toBuilder("jc305-wrong-curve-math")
            .description("JavaCard 3.0.5 card that accepts custom curve parameters but computes on them wrongly (consistently)")
            .customCurves(CustomCurves.WRONG_MATH).build();

    /** JavaCard 3.0.5 without SHA-512. */
    public static final CardPlatform JC305_NO_SHA512 = JC305.toBuilder("jc305-no-sha512")
            .description("JavaCard 3.0.5 card without MessageDigest.ALG_SHA_512")
            .sha512(false).build();

    /** JavaCard 3.0.5 without 256-bit AES key objects. */
    public static final CardPlatform JC305_NO_AES256 = JC305.toBuilder("jc305-no-aes256")
            .description("JavaCard 3.0.5 card without 256-bit AES key objects")
            .aes256Keys(false).build();

    /**
     * JavaCard 3.0.5 with little transient memory: the legacy functions fit
     * (179 bytes cleared on deselect), the software engine's work area (481
     * more) does not.
     */
    public static final CardPlatform JC305_SMALL_RAM = JC305.toBuilder("jc305-small-ram")
            .description("JavaCard 3.0.5 card with 512 bytes of deselect-transient memory: the legacy functions fit, the Ed25519 engine does not")
            .transientMemory(-1, 512).build();

    /**
     * JavaCard 3.0.5 where the software engine fits (179 + 481 bytes) and the
     * SEP-10 challenge stage (676 more) does not.
     */
    public static final CardPlatform JC305_TIGHT_RAM = JC305.toBuilder("jc305-tight-ram")
            .description("JavaCard 3.0.5 card with 1024 bytes of deselect-transient memory: the Ed25519 engine fits, the SEP-10 challenge stage does not")
            .transientMemory(-1, 1024).build();

    /** A JavaCard 3.1 card: EdDSA as {@code SIG_CIPHER_EDDSA} with {@code ALG_NULL}, and all of JC305. */
    public static final CardPlatform JC31 = builder("jc31", Level.JC31)
            .description("JavaCard 3.1 card: EdDSA as SIG_CIPHER_EDDSA with MessageDigest.ALG_NULL")
            .build();

    /** A JavaCard 3.1 card that takes {@code ALG_SHA_512}, not {@code ALG_NULL}, with {@code SIG_CIPHER_EDDSA}. */
    public static final CardPlatform JC31_SHA512 = JC31.toBuilder("jc31-sha512")
            .description("JavaCard 3.1 card whose SIG_CIPHER_EDDSA wants MessageDigest.ALG_SHA_512")
            .edDsa(false, true, false).build();

    /**
     * A JavaCard 3.2 card: EdDSA both as {@code SIG_CIPHER_EDDSA} and as the
     * per-curve {@code SIG_CIPHER_EDDSA_ED25519} of 3.2, and all of JC305.
     */
    public static final CardPlatform JC32 = builder("jc32", Level.JC32)
            .description("JavaCard 3.2 card: EdDSA as SIG_CIPHER_EDDSA and as SIG_CIPHER_EDDSA_ED25519")
            .build();

    /** A JavaCard 3.2 card that offers Ed25519 only under the 3.2 constant. */
    public static final CardPlatform JC32_PER_CURVE = JC32.toBuilder("jc32-per-curve")
            .description("JavaCard 3.2 card that offers Ed25519 only as SIG_CIPHER_EDDSA_ED25519 (the 3.2 constant)")
            .edDsa(false, false, true).build();

    /** A JavaCard 3.2 card without EdDSA (it is an optional algorithm at every level). */
    public static final CardPlatform JC32_NO_EDDSA = JC32.toBuilder("jc32-no-eddsa")
            .description("JavaCard 3.2 card without EdDSA (an optional algorithm); everything JavaCard 3.0.5 has is present")
            .noEdDsa().build();

    /** A JavaCard 3.2 card that will not load an Ed25519 private key. */
    public static final CardPlatform JC32_NO_KEY_IMPORT = JC32.toBuilder("jc32-no-key-import")
            .description("JavaCard 3.2 card that generates Ed25519 keys but refuses to load a private one")
            .xecPrivateKeyImport(false).build();

    private static final Map<String, CardPlatform> PRESETS;

    static {
        Map<String, CardPlatform> all = new LinkedHashMap<>();
        for (CardPlatform p : new CardPlatform[] {
                JC305, JC305_NO_XY, JC305_FIXED_CURVES, JC305_WRONG_CURVE_MATH, JC305_NO_SHA512,
                JC305_NO_AES256, JC305_SMALL_RAM, JC305_TIGHT_RAM,
                JC31, JC31_SHA512,
                JC32, JC32_PER_CURVE, JC32_NO_EDDSA, JC32_NO_KEY_IMPORT}) {
            all.put(p.name, p);
        }
        PRESETS = Collections.unmodifiableMap(all);
    }

    /** Every card model with a name, in the order they are documented. */
    public static List<CardPlatform> presets() {
        return Collections.unmodifiableList(new ArrayList<>(PRESETS.values()));
    }

    /** The card model called {@code name} (case does not matter); an unknown name lists the known ones. */
    public static CardPlatform byName(String name) {
        CardPlatform p = name == null ? null : PRESETS.get(name.trim().toLowerCase(Locale.ROOT));
        if (p == null) {
            throw new IllegalArgumentException("unknown card platform '" + name + "'; one of: "
                    + String.join(", ", PRESETS.keySet()));
        }
        return p;
    }

    // ------------------------------------------------------------------ one simulated card

    private static final ThreadLocal<Card> CURRENT = new ThreadLocal<>();

    /** A new card of this platform, with nothing allocated yet. */
    public Card newCard() {
        return new Card(this);
    }

    /**
     * One simulated card: its platform and how much transient memory its
     * applet has taken. The simulated API calls made inside {@link #execute} and
     * {@link #call} are answered for this card; the objects they create (a key
     * agreement, a key pair, a signature) remember it.
     */
    public static final class Card {
        private final CardPlatform platform;
        private int resetBytes;
        private int deselectBytes;

        private Card(CardPlatform platform) {
            this.platform = platform;
        }

        public CardPlatform platform() {
            return platform;
        }

        /** Transient bytes this card's applet holds that are cleared on reset. */
        public synchronized int transientResetBytesUsed() {
            return resetBytes;
        }

        /** The same for memory cleared on deselect. */
        public synchronized int transientDeselectBytesUsed() {
            return deselectBytes;
        }

        /**
         * Runs {@code body} as this card. (Not called {@code run}: from Kotlin,
         * {@code card.run { … }} would be the standard library's scope
         * function, which runs the block without making the card current.)
         */
        public void execute(Runnable body) {
            Card before = CURRENT.get();
            CURRENT.set(this);
            try {
                body.run();
            } finally {
                restore(before);
            }
        }

        /** Runs {@code body} as this card and returns its result. */
        public <T> T call(Callable<T> body) throws Exception {
            Card before = CURRENT.get();
            CURRENT.set(this);
            try {
                return body.call();
            } finally {
                restore(before);
            }
        }

        private static void restore(Card before) {
            if (before == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(before);
            }
        }

        /** Books {@code bytes} of transient memory, or refuses as a card with none left does. */
        synchronized void allocateTransient(int bytes, byte event) {
            boolean reset = event == JCSystem.CLEAR_ON_RESET;
            int limit = reset ? platform.transientResetBytes : platform.transientDeselectBytes;
            int used = reset ? resetBytes : deselectBytes;
            if (limit >= 0 && (bytes > limit || used > limit - bytes)) {
                SystemException.throwIt(SystemException.NO_TRANSIENT_SPACE);
            }
            if (reset) {
                resetBytes = used + bytes;
            } else {
                deselectBytes = used + bytes;
            }
        }
    }

    /**
     * The card the calling thread is acting as. Outside {@link Card#execute} that
     * is a card of the platform the {@value Jc31#EDDSA_PROPERTY} system
     * property describes (see {@link Jc31}): every optional algorithm
     * present, no memory limit.
     */
    static Card current() {
        Card card = CURRENT.get();
        return card != null ? card : Jc31.defaultPlatform().newCard();
    }

    /** The platform of {@link #current()}. */
    static CardPlatform currentPlatform() {
        Card card = CURRENT.get();
        return card != null ? card.platform : Jc31.defaultPlatform();
    }
}

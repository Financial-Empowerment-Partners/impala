package com.impala.simulator

import com.impala.applet.ImpalaApplet
import com.impala.jcardsim.jc31.CardPlatform
import com.impala.sdk.Constants
import com.impala.sdk.apdu4j.ApduTrace
import com.impala.sdk.apdu4j.ApduTraceHook
import com.impala.sdk.apdu4j.BIBO
import com.licel.jcardsim.smartcardio.CardSimulator
import com.licel.jcardsim.base.Simulator
import com.licel.jcardsim.base.SimulatorRuntime
import com.licel.jcardsim.utils.AIDUtil
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey as JcaECPrivateKey
import java.security.interfaces.ECPublicKey as JcaECPublicKey
import java.security.SecureRandom
import javacard.framework.AID
import javacard.security.AESKey
import javacard.security.ECPrivateKey
import javacard.security.ECPublicKey

/**
 * [BIBO] backed by the jcardsim [CardSimulator]: installs [ImpalaApplet] under
 * the applet-instance AID from `applet/build.xml` (`applet.aid.app`) and selects
 * it, so SDK tests exercise the real applet end-to-end without hardware.
 *
 * [installParams] is the applet data (the GlobalPlatform "C9" parameter value,
 * `gp --params`); when non-null it is wrapped in the standard JavaCard install
 * parameter array `[aidLen][aid][ciLen][ci][adLen][appletData]` exactly as a
 * real card's JCRE would present it to `ImpalaApplet.install`.
 *
 * jcardsim is the interop oracle for SCP03 and ECDSA — its crypto engines are an
 * independent implementation of the SDK's pure-Kotlin primitives.
 *
 * Lives in `com.impala:simulator` so impala-lib and the Android demo can drive
 * the real applet from their test source sets. [debugTrace] sees every
 * exchange with PIN/key bytes masked ([ApduTrace.mask]); nothing is logged.
 *
 * **Key entropy.** jcardsim's `KeyPair` generates with a null `SecureRandom`,
 * so every simulated card would get the SAME P-256 key (a bridge then refuses
 * the second registration: `card.ec_pubkey` is unique). A physical card draws
 * keygen entropy from its own RNG. To match that, after a successful
 * INITIALIZE the card's key pair is re-set from a fresh JCA key through the
 * standard `ECPrivateKey.setS` / `ECPublicKey.setW` API ([distinctKeys]). The
 * same goes for the Stellar key of a card with the JavaCard 3.0.5 Ed25519
 * engine, whose scalar comes from that `KeyPair` too (the JavaCard 3.1 engine
 * of the simulated platform already draws real randomness).
 *
 * **A card is a CAP on hardware.** Two things are chosen for a simulated card,
 * as for a real one:
 *
 * - [ed25519], the CAP it was loaded with. A CAP file holds one Ed25519
 *   engine, fixed at build time (`-Papplet.ed25519=soft|native|none`); the
 *   simulator holds all of them and [ed25519] says which this card got:
 *   `"soft"` (the default CAP, converted for JavaCard 3.0.5), `"native"` (the
 *   platform's EdDSA, converted for JavaCard 3.1) or `"none"` (a legacy card
 *   without a Stellar key). See [CapVariant].
 * - [platform], the hardware: a [CardPlatform] says which JavaCard level the
 *   card implements and which optional algorithms it really has
 *   ([CardPlatform.JC305], [CardPlatform.JC32] and their variants). The
 *   applet then meets what it would meet on such a card: an algorithm that is
 *   not there, a curve the card will not compute on, no memory left.
 *
 * Name either and the other follows: a CAP alone runs on the lowest hardware
 * that loads it with every optional algorithm present (`soft` and `none` on
 * [CardPlatform.JC305], `native` on [CardPlatform.JC31]); hardware alone gets
 * the CAP an operator would load on it ([CapVariant.preferredFor]). With
 * neither, the JVM's `impala.ed25519` and `impala.platform` system properties
 * are followed, and without those it is the default CAP on a JavaCard 3.0.5
 * card. A CAP that such hardware does not load is refused before anything is
 * installed ([CapNotLoadableException]), as a card's loader would.
 */
class SimulatorBibo @JvmOverloads constructor(
    aidHex: String = APPLET_INSTANCE_AID,
    installParams: ByteArray? = null,
    var debugTrace: ApduTraceHook? = null,
    private val distinctKeys: Boolean = true,
    ed25519: String? = null,
    platform: CardPlatform? = null
) : BIBO {
    /** The CAP this card was loaded with. */
    val capVariant: CapVariant

    /** The simulated hardware. */
    val platform: CardPlatform

    /** This card on that hardware: what its applet has allocated so far. */
    private val card: CardPlatform.Card

    private val simulator = CardSimulator()
    private val aid: AID = AIDUtil.create(aidHex)

    init {
        val (variant, hardware) = resolve(ed25519, platform)
        if (!variant.loadsOn(hardware)) throw CapNotLoadableException(variant, hardware)
        capVariant = variant
        this.platform = hardware
        card = hardware.newCard()
        withEngine(variant.id) {
            card.execute {
                if (installParams == null) {
                    simulator.installApplet(aid, ImpalaApplet::class.java)
                } else {
                    val bArray = buildInstallArray(aidHex, installParams)
                    simulator.installApplet(aid, ImpalaApplet::class.java, bArray, 0.toShort(), bArray.size.toByte())
                }
            }
        }
        card.execute { simulator.selectApplet(aid) }
    }

    /** Transient memory the applet took at install, in bytes: cleared on reset, cleared on deselect. */
    val transientMemoryUsed: Pair<Int, Int> get() = card.transientResetBytesUsed() to card.transientDeselectBytesUsed()

    override fun transceive(bytes: ByteArray?): ByteArray {
        requireNotNull(bytes) { "APDU bytes must not be null" }
        // The command runs on this card's hardware: whatever the applet asks the
        // platform for now (INITIALIZE builds keys) is answered for this card.
        val resp = card.call {
            val out = simulator.transmitCommand(bytes)
            if (distinctKeys && isInitialize(bytes) && out.size >= 2 &&
                out[out.size - 2] == 0x90.toByte() && out[out.size - 1] == 0x00.toByte()
            ) {
                reseedCardKey()
            }
            out
        }
        debugTrace?.invoke(ApduTrace.mask(bytes), resp)
        return resp
    }

    private fun isInitialize(cmd: ByteArray) = cmd.size >= 2 && cmd[0] == 0x00.toByte() && cmd[1] == Constants.INS_INITIALIZE

    /** Replaces the applet's freshly generated (deterministic) key pair with a random one. */
    private fun reseedCardKey() {
        val runtime = Simulator::class.java.getDeclaredField("runtime").apply { isAccessible = true }.get(simulator)
        val applet = SimulatorRuntime::class.java.getDeclaredMethod("getApplet", AID::class.java)
            .apply { isAccessible = true }.invoke(runtime, aid)
        fun field(name: String) = ImpalaApplet::class.java.getDeclaredField(name).apply { isAccessible = true }.get(applet)
        val priv = field("cardECPrivateKey") as ECPrivateKey
        val pub = field("cardECPublicKey") as ECPublicKey
        val fresh = Jca.genP256()
        val d = (fresh.private as JcaECPrivateKey).s.toFixed32()
        val w = Jca.uncompressedPoint(fresh.public as JcaECPublicKey)
        priv.setS(d, 0, d.size.toShort())
        pub.setW(w, 0, w.size.toShort())
        d.fill(0)
        reseedStellarKey(field("stellarKey"))
    }

    /**
     * Gives a card with the JavaCard 3.0.5 Ed25519 engine a random Stellar key:
     * a scalar in [1, L - 1] and a nonce secret, placed in the engine's key
     * objects through the standard key API, then its public key recomputed by
     * the engine's own (test-only) `derivePublicKey`. Nothing to do for a card
     * without a Stellar key or with the JavaCard 3.1 engine.
     */
    private fun reseedStellarKey(engine: Any?) {
        if (engine == null || engine.javaClass.name != SOFT_ENGINE_CLASS) return
        fun member(name: String) = engine.javaClass.getDeclaredField(name).apply { isAccessible = true }.get(engine)
        val order = BigInteger(1, engine.javaClass.getDeclaredField("L").apply { isAccessible = true }.get(null) as ByteArray)
        val random = SecureRandom()
        val scalar = (BigInteger(order.bitLength() + 64, random).mod(order - BigInteger.ONE) + BigInteger.ONE).toFixed32()
        val prefix = ByteArray(32).also { random.nextBytes(it) }
        (member("scalarKey") as ECPrivateKey).setS(scalar, 0, 32)
        (member("prefixKey") as AESKey).setKey(prefix, 0)
        engine.javaClass.getDeclaredMethod("derivePublicKey").apply { isAccessible = true }.invoke(engine)
        scalar.fill(0)
        prefix.fill(0)
    }

    private fun BigInteger.toFixed32(): ByteArray {
        val raw = toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return ByteArray(32 - raw.size) + raw
    }

    override fun close() {}

    /** The simulated card's ATR (served to vpcd clients such as scardutil). */
    val atr: ByteArray get() = simulator.atr

    /** Card reset: clears transient state and the current selection, keeps the applet and its persistent state. */
    fun reset() {
        card.execute { simulator.reset() }
    }

    companion object {
        /** Applet-instance AID (`applet.aid.app` in applet/build.xml). */
        const val APPLET_INSTANCE_AID = "01020304050607080102"

        /** The system property the simulator's `Ed25519Provider` reads when the applet is installed. */
        const val ED25519_PROPERTY = "impala.ed25519"
        const val ED25519_SOFT = "soft"
        const val ED25519_NATIVE = "native"
        const val ED25519_NONE = "none"

        /**
         * The system property that names the hardware of cards created
         * without a [CardPlatform]: a preset name (`jc305`, `jc32`,
         * `jc32-per-curve`, … see [CardPlatform.presets]).
         */
        const val PLATFORM_PROPERTY = "impala.platform"

        /**
         * The CAP and the hardware of a new card, from what the caller named
         * and, for what it did not, the two system properties (see the class
         * comment for the rule).
         */
        internal fun resolve(ed25519: String?, platform: CardPlatform?): Pair<CapVariant, CardPlatform> {
            val variant = (ed25519 ?: System.getProperty(ED25519_PROPERTY)?.takeIf { it.isNotBlank() })?.let { CapVariant.byId(it) }
            val hardware = platform ?: System.getProperty(PLATFORM_PROPERTY)?.takeIf { it.isNotBlank() }?.let { CardPlatform.byName(it) }
            return when {
                variant != null && hardware != null -> variant to hardware
                variant != null -> variant to CapVariant.defaultPlatformFor(variant)
                hardware != null -> CapVariant.preferredFor(hardware) to hardware
                else -> CapVariant.SOFT to CardPlatform.JC305
            }
        }

        private const val SOFT_ENGINE_CLASS = "com.impala.applet.Ed25519Soft"
        private val installLock = Any()

        /**
         * Runs an applet install with [engine] as the Ed25519 engine. The choice
         * travels in a JVM-wide system property, so installs are serialized and
         * the property is restored afterwards.
         */
        private fun withEngine(engine: String, install: () -> Unit) {
            synchronized(installLock) {
                val before = System.getProperty(ED25519_PROPERTY)
                System.setProperty(ED25519_PROPERTY, engine)
                try {
                    install()
                } finally {
                    if (before == null) System.clearProperty(ED25519_PROPERTY) else System.setProperty(ED25519_PROPERTY, before)
                }
            }
        }

        /**
         * Builds the JavaCard install parameter array:
         * [instanceAIDLength][instanceAID][controlInfoLength(=0)][appletDataLength][appletData].
         */
        private fun buildInstallArray(aidHex: String, appletData: ByteArray): ByteArray {
            val aidBytes = aidHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            return byteArrayOf(aidBytes.size.toByte()) + aidBytes +
                byteArrayOf(0x00) + // empty control info
                byteArrayOf(appletData.size.toByte()) + appletData
        }
    }
}

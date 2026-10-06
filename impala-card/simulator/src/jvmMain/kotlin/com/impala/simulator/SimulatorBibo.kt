package com.impala.simulator

import com.impala.applet.ImpalaApplet
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
import javacard.framework.AID
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
 * standard `ECPrivateKey.setS` / `ECPublicKey.setW` API ([distinctKeys]).
 */
class SimulatorBibo @JvmOverloads constructor(
    aidHex: String = APPLET_INSTANCE_AID,
    installParams: ByteArray? = null,
    var debugTrace: ApduTraceHook? = null,
    private val distinctKeys: Boolean = true
) : BIBO {
    private val simulator = CardSimulator()
    private val aid: AID = AIDUtil.create(aidHex)

    init {
        if (installParams == null) {
            simulator.installApplet(aid, ImpalaApplet::class.java)
        } else {
            val bArray = buildInstallArray(aidHex, installParams)
            simulator.installApplet(aid, ImpalaApplet::class.java, bArray, 0.toShort(), bArray.size.toByte())
        }
        simulator.selectApplet(aid)
    }

    override fun transceive(bytes: ByteArray?): ByteArray {
        requireNotNull(bytes) { "APDU bytes must not be null" }
        val resp = simulator.transmitCommand(bytes)
        if (distinctKeys && isInitialize(bytes) && resp.size >= 2 &&
            resp[resp.size - 2] == 0x90.toByte() && resp[resp.size - 1] == 0x00.toByte()
        ) {
            reseedCardKey()
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
    }

    private fun BigInteger.toFixed32(): ByteArray {
        val raw = toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return ByteArray(32 - raw.size) + raw
    }

    override fun close() {}

    companion object {
        /** Applet-instance AID (`applet.aid.app` in applet/build.xml). */
        const val APPLET_INSTANCE_AID = "01020304050607080102"

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

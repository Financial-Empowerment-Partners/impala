package com.impala.sdk

import com.impala.applet.ImpalaApplet
import com.impala.sdk.apdu4j.BIBO
import com.licel.jcardsim.smartcardio.CardSimulator
import com.licel.jcardsim.utils.AIDUtil

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
 */
class SimulatorBibo(
    aidHex: String = APPLET_INSTANCE_AID,
    installParams: ByteArray? = null
) : BIBO {
    private val simulator = CardSimulator()

    init {
        val aid = AIDUtil.create(aidHex)
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
        return simulator.transmitCommand(bytes)
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

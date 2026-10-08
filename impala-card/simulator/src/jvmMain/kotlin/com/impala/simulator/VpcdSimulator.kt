package com.impala.simulator

import com.impala.sdk.models.PersonalizationProtocol
import com.licel.jcardsim.remote.VSmartCardTCPProtocol
import java.io.File
import java.io.IOException
import java.util.Properties

/**
 * Serves one simulated Impala card over the vsmartcard "vpcd" protocol — the
 * transport scardutil's `--sim` / `--sim-cfg` / fleet simulator targets speak.
 *
 * Why not jCardSim's own `VSmartCard`: its config-driven start only LOADS the
 * applet class and leaves instantiation to the GlobalPlatform extension, so
 * `ImpalaApplet` is never created and every SELECT answers 6999. This host
 * installs the applet explicitly (the path the SDK tests use), with the real
 * install-parameter TLV when the cfg provides one, so the same dispatch checks
 * run unchanged against a real card and against this simulator.
 *
 * Wire protocol (jCardSim's `VSmartCardTCPProtocol`): the simulator CONNECTS
 * to the vpcd listener; frames are `len(2, BE) ‖ payload`; a 1-byte payload is
 * a control command (0 power off, 1 power on, 2 reset, 4 get ATR), anything
 * longer is an APDU answered with a response frame.
 */
class VpcdSimulator(
    private val card: SimulatorBibo,
    private val host: String,
    private val port: Int,
    private val notice: (String) -> Unit = { System.err.println(it) }
) {
    /** Serves connections until the listener stays away for [reconnectForMs]. */
    fun serve(reconnectForMs: Long = 60_000) {
        var lastSeen = System.currentTimeMillis()
        while (true) {
            val proto = VSmartCardTCPProtocol()
            try {
                proto.connect(host, port)
                notice("vpcd: connected to $host:$port")
                lastSeen = System.currentTimeMillis()
                session(proto)
                lastSeen = System.currentTimeMillis()
            } catch (e: IOException) {
                if (System.currentTimeMillis() - lastSeen > reconnectForMs) {
                    notice("vpcd: no listener on $host:$port for ${reconnectForMs / 1000}s; exiting")
                    return
                }
                Thread.sleep(500)
            } finally {
                proto.disconnect()
            }
        }
    }

    /** One connection: dispatch control commands and APDUs until the peer closes. */
    internal fun session(proto: VSmartCardTCPProtocol) {
        while (true) {
            when (val cmd = proto.readCommand()) {
                VSmartCardTCPProtocol.POWER_ON, VSmartCardTCPProtocol.RESET -> card.reset()
                VSmartCardTCPProtocol.POWER_OFF -> Unit
                VSmartCardTCPProtocol.GET_ATR -> proto.writeData(card.atr)
                VSmartCardTCPProtocol.APDU -> proto.writeData(card.transceive(proto.readData()))
                else -> notice("vpcd: unknown command $cmd ignored")
            }
        }
    }

    companion object {
        const val KEY_HOST = "com.licel.jcardsim.vsmartcard.host"
        const val KEY_PORT = "com.licel.jcardsim.vsmartcard.port"
        const val KEY_AID = "com.licel.jcardsim.card.applet.0.AID"
        /** Our key: the applet install-parameter TLV as hex (docs/apdu.md "Install parameters"). */
        const val KEY_INSTALL_PARAMS = "impala.install.params"

        /** Builds the card described by a jcardsim-style cfg (host/port, AID, optional install params). */
        fun fromConfig(props: Properties): Triple<SimulatorBibo, String, Int> {
            val host = props.getProperty(KEY_HOST) ?: "localhost"
            val port = props.getProperty(KEY_PORT)?.toIntOrNull() ?: 35963
            val aid = props.getProperty(KEY_AID) ?: SimulatorBibo.APPLET_INSTANCE_AID
            val params = props.getProperty(KEY_INSTALL_PARAMS)?.trim()?.takeIf { it.isNotEmpty() }
                ?.let { hex -> ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() } }
            return Triple(SimulatorBibo(aidHex = aid, installParams = params), host, port)
        }

        /** The TLV for a factory-style install: ENFORCE on, GP default SCP03 keys, no program binding. */
        fun factoryInstallParams(): ByteArray =
            PersonalizationProtocol.installParams(enforce = true, keys = null, pins = null, program = null)
    }
}

/**
 * `vpcd-sim.sh <jcardsim.cfg>`: scardutil writes the cfg (with the vpcd
 * host/port it listens on) and passes it as the last argument.
 */
fun main(args: Array<String>) {
    val cfgPath = args.lastOrNull { !it.startsWith("--") }
        ?: run { System.err.println("usage: VpcdSimulator <jcardsim.cfg>"); kotlin.system.exitProcess(2) }
    val props = Properties().apply { File(cfgPath).inputStream().use { load(it) } }
    val (card, host, port) = VpcdSimulator.fromConfig(props)
    System.err.println("vpcd: serving ImpalaApplet 0.2 (${props.getProperty(VpcdSimulator.KEY_AID) ?: SimulatorBibo.APPLET_INSTANCE_AID}) to $host:$port")
    VpcdSimulator(card, host, port).serve()
}

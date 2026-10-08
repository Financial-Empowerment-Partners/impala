package com.impala.simulator

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Plays the vpcd listener (what scardutil does) against [VpcdSimulator]. */
class VpcdSimulatorTest {
    private fun frame(out: DataOutputStream, payload: ByteArray) {
        out.writeShort(payload.size); out.write(payload); out.flush()
    }
    private fun read(input: DataInputStream): ByteArray = ByteArray(input.readUnsignedShort()).also { input.readFully(it) }

    @Test
    fun `serves ATR, SELECT and applet commands over vpcd and honours reset`() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { listener ->
            val props = Properties().apply {
                setProperty(VpcdSimulator.KEY_HOST, "127.0.0.1")
                setProperty(VpcdSimulator.KEY_PORT, listener.localPort.toString())
            }
            val (card, host, port) = VpcdSimulator.fromConfig(props)
            val server = Thread { VpcdSimulator(card, host, port, notice = {}).serve(reconnectForMs = 2_000) }.apply { isDaemon = true; start() }
            listener.accept().use { socket ->
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                frame(output, byteArrayOf(1))                       // power on: no reply
                frame(output, byteArrayOf(4))                       // ATR
                assertTrue(read(input).isNotEmpty())
                frame(output, byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2))
                assertContentEquals(byteArrayOf(0x90.toByte(), 0x00), read(input).takeLast(2).toByteArray())
                frame(output, byteArrayOf(0x00, 0x64, 0x00, 0x00, 0x00))
                val version = read(input)
                assertEquals(12, version.size)
                assertEquals(2, version[3].toInt())                 // 0.2
                frame(output, byteArrayOf(0x00, 0x2C, 0x00, 0x00, 0x04, 1, 2, 3, 4)) // INITIALIZE
                assertContentEquals(byteArrayOf(0x90.toByte(), 0x00), read(input))
                frame(output, byteArrayOf(2))                       // reset: selection cleared, state kept
                frame(output, byteArrayOf(0x00, 0x64, 0x00, 0x00, 0x00))
                assertEquals(0x6986, sw(read(input)))               // nothing selected after reset
                frame(output, byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2))
                read(input)
                frame(output, byteArrayOf(0x00, 0x2C, 0x00, 0x00, 0x04, 1, 2, 3, 4))
                assertEquals(0x6686, sw(read(input)))               // already initialized: persistent state survived the reset
            }
            server.join(5_000)
        }
    }

    @Test
    fun `install parameters from the cfg reach the applet`() {
        val props = Properties().apply { setProperty(VpcdSimulator.KEY_INSTALL_PARAMS, "0101") } // ENFORCE
        val (card, _, _) = VpcdSimulator.fromConfig(props)
        val sdk = com.impala.sdk.ImpalaSDK(card)
        assertTrue(sdk.getPersonalization().provisioningEnforced)
    }

    private fun sw(r: ByteArray) = ((r[r.size - 2].toInt() and 0xFF) shl 8) or (r[r.size - 1].toInt() and 0xFF)
}

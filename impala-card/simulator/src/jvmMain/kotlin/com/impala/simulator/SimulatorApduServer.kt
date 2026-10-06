package com.impala.simulator

import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Serves one simulated card over TCP so a client without NFC (the Android
 * emulator, through `adb reverse tcp:9443 tcp:9443`) can drive the real applet.
 *
 * Framing, both directions: `len(2, big-endian) ‖ bytes`. The card persists for
 * the server's lifetime across connections, so it can be issued once (the
 * issuance tool's `--transport tcp:host:port`) and then used by the app.
 * Binds to loopback only: this is a test fixture, never a network service.
 */
class SimulatorApduServer(
    private val card: BIBO = SimulatorBibo(),
    port: Int = DEFAULT_PORT
) : AutoCloseable {
    private val server = ServerSocket().apply {
        reuseAddress = true
        bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port))
    }
    val port: Int get() = server.localPort

    @Volatile
    private var running = true

    /** Accepts connections until [close]; one client at a time (a card has one reader). */
    fun serve() {
        while (running) {
            val socket = try {
                server.accept()
            } catch (e: IOException) {
                if (!running) return
                throw e
            }
            socket.use { handle(it) }
        }
    }

    /** Runs [serve] on a daemon thread. */
    fun start(): SimulatorApduServer {
        Thread({ serve() }, "simulator-apdu-server").apply { isDaemon = true }.start()
        return this
    }

    private fun handle(socket: Socket) {
        val input = DataInputStream(socket.getInputStream().buffered())
        val output = DataOutputStream(socket.getOutputStream().buffered())
        while (running) {
            val len = try {
                input.readUnsignedShort()
            } catch (_: EOFException) {
                return
            }
            val command = ByteArray(len)
            input.readFully(command)
            val response = synchronized(card) {
                try {
                    card.transceive(command) ?: byteArrayOf(0x6F, 0x00)
                } catch (_: BIBOException) {
                    byteArrayOf(0x6F, 0x00)
                }
            }
            output.writeShort(response.size)
            output.write(response)
            output.flush()
        }
    }

    override fun close() {
        running = false
        server.close()
    }

    companion object {
        const val DEFAULT_PORT = 9443
    }
}

/** A JVM client for [SimulatorApduServer] (the issuance tool's `--transport tcp:host:port`). */
class TcpApduClient(host: String, port: Int, timeoutMs: Int = 10_000) : BIBO {
    private val socket = Socket().apply {
        soTimeout = timeoutMs
        connect(InetSocketAddress(host, port), timeoutMs)
    }
    private val input = DataInputStream(socket.getInputStream().buffered())
    private val output = DataOutputStream(socket.getOutputStream().buffered())

    override fun transceive(bytes: ByteArray?): ByteArray {
        requireNotNull(bytes) { "APDU bytes must not be null" }
        try {
            output.writeShort(bytes.size)
            output.write(bytes)
            output.flush()
            val out = ByteArray(input.readUnsignedShort())
            input.readFully(out)
            return out
        } catch (e: IOException) {
            throw BIBOException("TCP APDU exchange failed: ${e.message}", e)
        }
    }

    override fun close() {
        try { socket.close() } catch (_: IOException) { }
    }
}

/** `./gradlew :simulator:serve --args="--port 9443"` */
fun main(args: Array<String>) {
    var port = SimulatorApduServer.DEFAULT_PORT
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--port" -> port = args.getOrNull(++i)?.toIntOrNull() ?: run { System.err.println("--port needs a number"); kotlin.system.exitProcess(2) }
            "-h", "--help" -> { System.err.println("usage: serve [--port 9443]"); return }
            else -> { System.err.println("unknown argument: ${args[i]}"); kotlin.system.exitProcess(2) }
        }
        i++
    }
    // A factory-installed card: ENFORCE, GP default SCP03 keys (the issuance
    // tool's default transport keys), no program binding.
    val server = SimulatorApduServer(SimulatorBibo(installParams = com.impala.sdk.models.PersonalizationProtocol.installParams(
        enforce = true, keys = null, pins = null, program = null
    )), port)
    System.err.println("simulated ImpalaApplet listening on 127.0.0.1:${server.port} (adb reverse tcp:${server.port} tcp:${server.port})")
    System.err.println("issue it with the issuance tool: --transport tcp:127.0.0.1:${server.port}")
    server.serve()
}

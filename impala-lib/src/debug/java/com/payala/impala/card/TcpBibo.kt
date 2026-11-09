package com.payala.impala.card

import android.annotation.SuppressLint
import com.impala.sdk.apdu4j.ApduExchangeHook
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * DEBUG BUILDS ONLY. A [BIBO] over TCP to impala-card's `SimulatorApduServer`
 * (`./gradlew :simulator:serve`), so the emulator — which has no NFC — can
 * drive the real applet on jcardsim. Framing: `len(2, BE) ‖ bytes` both ways.
 * Release builds contain neither this class nor [DebugCardTransport] (CI checks
 * the release AAR).
 *
 * The constructor connects; a failed connect closes the socket before the
 * exception propagates.
 */
class TcpBibo(host: String, port: Int, timeoutMs: Int = 10_000) : BIBO {
    private val socket = Socket().apply {
        try {
            soTimeout = timeoutMs
            connect(InetSocketAddress(host, port), timeoutMs)
        } catch (e: IOException) {
            closeQuietly()
            throw e
        } catch (e: RuntimeException) {
            closeQuietly()
            throw e
        }
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

    override fun close() = socket.closeQuietly()
}

private fun Socket.closeQuietly() {
    try {
        close()
    } catch (_: IOException) {
    }
}

/** A session over an injected transport (instrumented tests, the emulator lane). */
@SuppressLint("VisibleForTests") // debug source set only: this IS the test entry point
fun ImpalaCardSession.Companion.openForTest(bibo: BIBO): ImpalaCardSession = ImpalaCardSession.fromBibo(bibo)

/**
 * DEBUG BUILDS ONLY. The simulated card at [endpoint] (`host:port`) could not
 * be reached: nothing listens there, the connection timed out, or the
 * transport is blocked. Delivered unwrapped so the app can say exactly that.
 */
class SimulatorUnreachableException(val endpoint: String, cause: Throwable) :
    IOException("Simulated card at $endpoint is unreachable", cause)

/**
 * DEBUG BUILDS ONLY. The result of one simulator probe: [State.READY] (it
 * answered a NOP), [State.BUSY] (it accepted the connection but is serving
 * another client), or [State.DOWN] (no connection). [millis] is the probe's
 * wall time.
 */
class SimProbe(val endpoint: String, val state: State, val millis: Long) {
    enum class State { READY, BUSY, DOWN }

    override fun toString(): String = "SimProbe($endpoint ${state.name} ${millis}ms)"
}

/**
 * DEBUG BUILDS ONLY. The simulated-card transport is selected exclusively by
 * `adb shell setprop debug.impala.tcp_card host:port` — never from the UI.
 */
object DebugCardTransport {
    const val PROPERTY = "debug.impala.tcp_card"
    private const val TAG = "ImpalaSimCard"

    /** NOP (`00 02 00 00`): answered by any Impala applet, changes nothing. */
    private val NOP = byteArrayOf(0x00, 0x02, 0x00, 0x00)

    /** How long a BUSY probe keeps its queued connection open so the simulator can answer it cleanly. */
    private const val BUSY_DRAIN_MS = 60_000

    /** The configured `host:port`, or null when the property is unset or malformed. */
    @JvmStatic
    fun configuredEndpoint(): Pair<String, Int>? = parseEndpoint(systemProperty(PROPERTY))

    /** The configured endpoint as `host:port`, or null. */
    @JvmStatic
    fun endpointText(): String? = configuredEndpoint()?.let { (host, port) -> "$host:$port" }

    internal fun parseEndpoint(value: String?): Pair<String, Int>? {
        if (value.isNullOrBlank()) return null
        val idx = value.lastIndexOf(':')
        if (idx <= 0) return null
        val port = value.substring(idx + 1).toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return value.substring(0, idx) to port
    }

    /**
     * Opens a session to the configured simulator, or null when none is
     * configured. Off the main thread only.
     *
     * @throws SimulatorUnreachableException when the simulator cannot be reached
     */
    @JvmStatic
    @JvmOverloads
    fun openConfiguredSession(trace: ApduExchangeHook? = null, readOnly: Boolean = false): ImpalaCardSession? {
        requireBackgroundThread("Opening a TCP card session")
        val (host, port) = configuredEndpoint() ?: return null
        return openSession(host, port, trace, readOnly)
    }

    /**
     * Opens a session to the simulator at [host]:[port] (no SELECT: the
     * simulator's applet is selected by default). Off the main thread only.
     *
     * @throws SimulatorUnreachableException when the connection fails
     */
    @JvmStatic
    @JvmOverloads
    @SuppressLint("VisibleForTests") // debug source set only: the emulator lane's injected transport
    fun openSession(
        host: String,
        port: Int,
        trace: ApduExchangeHook? = null,
        readOnly: Boolean = false,
        timeoutMs: Int = 10_000
    ): ImpalaCardSession {
        requireBackgroundThread("Opening a TCP card session")
        val bibo = try {
            TcpBibo(host, port, timeoutMs)
        } catch (e: IOException) {
            ImpalaLibLog.w(TAG, "Simulated card at $host:$port unreachable: ${e.javaClass.simpleName}")
            throw SimulatorUnreachableException("$host:$port", e)
        }
        return try {
            ImpalaCardSession.fromBibo(bibo, null, trace, readOnly)
        } catch (e: RuntimeException) {
            bibo.close()
            throw e
        }
    }

    /**
     * Probes the simulator at [host]:[port] with one NOP. A connection the
     * simulator accepted but does not answer within [timeoutMs] means it is
     * serving another client (BUSY); that connection is then kept open on a
     * daemon thread until the simulator answers it, so the one-client
     * simulator never writes into a socket that was abandoned mid-command.
     * Off the main thread only; never throws.
     */
    @JvmStatic
    @JvmOverloads
    fun probe(host: String, port: Int, timeoutMs: Int = 2_000): SimProbe {
        requireBackgroundThread("Probing the simulated card")
        val endpoint = "$host:$port"
        val start = System.nanoTime()
        fun result(state: SimProbe.State) = SimProbe(endpoint, state, (System.nanoTime() - start) / 1_000_000L)
        val socket = Socket()
        try {
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(host, port), timeoutMs)
        } catch (_: Exception) {
            socket.closeQuietly()
            return result(SimProbe.State.DOWN)
        }
        val input: DataInputStream
        try {
            input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())
            output.writeShort(NOP.size)
            output.write(NOP)
            output.flush()
        } catch (_: Exception) {
            socket.closeQuietly()
            return result(SimProbe.State.DOWN)
        }
        return try {
            val len = input.readUnsignedShort()
            input.readFully(ByteArray(len))
            socket.closeQuietly()
            result(if (len >= 2) SimProbe.State.READY else SimProbe.State.DOWN)
        } catch (_: SocketTimeoutException) {
            drainLater(socket, input)
            result(SimProbe.State.BUSY)
        } catch (_: Exception) {
            socket.closeQuietly()
            result(SimProbe.State.DOWN)
        }
    }

    /** Probes the configured simulator, or returns null when none is configured. Off the main thread only. */
    @JvmStatic
    fun probeConfigured(): SimProbe? {
        val (host, port) = configuredEndpoint() ?: return null
        return probe(host, port)
    }

    private fun drainLater(socket: Socket, input: DataInputStream) {
        Thread({
            try {
                socket.soTimeout = BUSY_DRAIN_MS
                val len = input.readUnsignedShort()
                input.readFully(ByteArray(len))
            } catch (_: Exception) {
            } finally {
                socket.closeQuietly()
            }
        }, "impala-sim-probe-drain").apply { isDaemon = true }.start()
    }

    // Debug builds only: reads the `debug.*` property adb sets; there is no
    // public API for system properties. Any failure means "not configured".
    @SuppressLint("PrivateApi")
    private fun systemProperty(key: String): String? = try {
        Class.forName("android.os.SystemProperties").getMethod("get", String::class.java).invoke(null, key) as? String
    } catch (_: Exception) {
        null
    }
}

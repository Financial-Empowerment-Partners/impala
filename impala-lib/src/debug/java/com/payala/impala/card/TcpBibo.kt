package com.payala.impala.card

import android.annotation.SuppressLint
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * DEBUG BUILDS ONLY. A [BIBO] over TCP to impala-card's `SimulatorApduServer`
 * (`./gradlew :simulator:serve`), so the emulator — which has no NFC — can
 * drive the real applet on jcardsim. Framing: `len(2, BE) ‖ bytes` both ways.
 * Release builds contain neither this class nor [DebugCardTransport] (CI checks
 * the release AAR).
 */
class TcpBibo(host: String, port: Int, timeoutMs: Int = 10_000) : BIBO {
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
        try {
            socket.close()
        } catch (_: IOException) {
        }
    }
}

/** A session over an injected transport (instrumented tests, the emulator lane). */
@SuppressLint("VisibleForTests") // debug source set only: this IS the test entry point
fun ImpalaCardSession.Companion.openForTest(bibo: BIBO): ImpalaCardSession = ImpalaCardSession.fromBibo(bibo)

/**
 * DEBUG BUILDS ONLY. The simulated-card transport is selected exclusively by
 * `adb shell setprop debug.impala.tcp_card host:port` — never from the UI.
 */
object DebugCardTransport {
    const val PROPERTY = "debug.impala.tcp_card"

    /** The configured `host:port`, or null when the property is unset or malformed. */
    @JvmStatic
    fun configuredEndpoint(): Pair<String, Int>? = parseEndpoint(systemProperty(PROPERTY))

    internal fun parseEndpoint(value: String?): Pair<String, Int>? {
        if (value.isNullOrBlank()) return null
        val idx = value.lastIndexOf(':')
        if (idx <= 0) return null
        val port = value.substring(idx + 1).toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return value.substring(0, idx) to port
    }

    /** Opens a session to the configured simulator, or null when none is configured. Off the main thread only. */
    @JvmStatic
    fun openConfiguredSession(): ImpalaCardSession? {
        requireBackgroundThread("Opening a TCP card session")
        val (host, port) = configuredEndpoint() ?: return null
        return ImpalaCardSession.openForTest(TcpBibo(host, port))
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

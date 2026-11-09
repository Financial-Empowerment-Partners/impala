package com.payala.impala.demo.card

import com.impala.sdk.apdu4j.ApduExchangeHook
import com.payala.impala.card.DebugCardTransport
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.card.SimProbe
import com.payala.impala.card.SimulatorUnreachableException

/**
 * DEBUG BUILDS ONLY: the emulator has no NFC, so with
 * `adb shell setprop debug.impala.tcp_card 10.0.2.2:9443` (or `127.0.0.1:9443`
 * after `adb reverse`) every card request is served by impala-card's
 * `SimulatorApduServer` instead. The release source set has a stub that is
 * never configured; there is no UI switch.
 */
object DebugCards {
    fun isConfigured(): Boolean = DebugCardTransport.configuredEndpoint() != null

    /** The configured simulator endpoint (`host:port`), or null. */
    fun endpointText(): String? = DebugCardTransport.endpointText()

    /**
     * Opens a session to the configured simulator, or null when none is
     * configured. Off the main thread only (opens a socket).
     *
     * @throws java.io.IOException when the simulator is unreachable (render it with [describeFailure])
     */
    fun openSession(trace: ApduExchangeHook? = null, readOnly: Boolean = false): ImpalaCardSession? =
        DebugCardTransport.openConfiguredSession(trace, readOnly)

    /** Probes the configured simulator with one NOP, or null when none is configured. Off the main thread only. */
    fun probe(): SimulatorStatus? = DebugCardTransport.probeConfigured()?.let {
        val state = when (it.state) {
            SimProbe.State.READY -> SimulatorStatus.State.READY
            SimProbe.State.BUSY -> SimulatorStatus.State.BUSY
            SimProbe.State.DOWN -> SimulatorStatus.State.DOWN
        }
        SimulatorStatus(it.endpoint, state, it.millis)
    }

    /** The user-facing text for a simulated-card failure in [e]'s cause chain, or null when it is not one. */
    fun describeFailure(e: Throwable): String? =
        generateSequence(e) { it.cause }.filterIsInstance<SimulatorUnreachableException>().firstOrNull()?.let {
            "Simulated card at ${it.endpoint} is unreachable — is :simulator:serve running?"
        }
}

package com.payala.impala.demo.card

/**
 * The simulated card's reachability, as the debug build's [DebugCards.probe]
 * reports it: [State.READY] (it answered a NOP), [State.BUSY] (another client
 * holds it), [State.DOWN] (nothing answered). [millis] is the probe's wall
 * time. Release builds never produce one (their probe returns null).
 */
class SimulatorStatus(val endpoint: String, val state: State, val millis: Long) {
    enum class State { READY, BUSY, DOWN }

    override fun toString(): String = "SimulatorStatus($endpoint ${state.name} ${millis}ms)"
}

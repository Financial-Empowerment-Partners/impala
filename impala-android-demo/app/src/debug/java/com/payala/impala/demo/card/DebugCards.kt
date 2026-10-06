package com.payala.impala.demo.card

import com.payala.impala.card.DebugCardTransport
import com.payala.impala.card.ImpalaCardSession

/**
 * DEBUG BUILDS ONLY: the emulator has no NFC, so with
 * `adb shell setprop debug.impala.tcp_card 10.0.2.2:9443` (or `127.0.0.1:9443`
 * after `adb reverse`) every card request is served by impala-card's
 * `SimulatorApduServer` instead. The release source set has a stub that is
 * never configured; there is no UI switch.
 */
object DebugCards {
    fun isConfigured(): Boolean = DebugCardTransport.configuredEndpoint() != null

    /** Off the main thread only (opens a socket). */
    fun openSession(): ImpalaCardSession? = DebugCardTransport.openConfiguredSession()
}

package com.payala.impala.demo.card

import com.impala.sdk.apdu4j.ApduExchangeHook
import com.payala.impala.card.ImpalaCardSession

/** Release builds: no simulated-card transport exists (see the debug source set). */
object DebugCards {
    fun isConfigured(): Boolean = false

    fun endpointText(): String? = null

    @Suppress("UNUSED_PARAMETER")
    fun openSession(trace: ApduExchangeHook? = null, readOnly: Boolean = false): ImpalaCardSession? = null

    fun probe(): SimulatorStatus? = null

    @Suppress("UNUSED_PARAMETER")
    fun describeFailure(e: Throwable): String? = null
}

package com.payala.impala.demo.card

import com.payala.impala.card.ImpalaCardSession

/** Release builds: no simulated-card transport exists (see the debug source set). */
object DebugCards {
    fun isConfigured(): Boolean = false

    fun openSession(): ImpalaCardSession? = null
}

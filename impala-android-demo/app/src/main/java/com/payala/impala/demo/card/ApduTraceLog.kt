package com.payala.impala.demo.card

import com.impala.sdk.apdu4j.ApduExchange
import com.payala.impala.demo.BuildConfig

/**
 * DEBUG BUILDS ONLY (a no-op in release): the header-only card exchanges of the
 * last [MAX_TAPS] production taps, for the Card Lab's Trace tab. The records
 * are [ApduExchange]s, which carry no command or response bytes, so nothing
 * secret can be retained here.
 *
 * A tap is bracketed by [beginTap] and [endTap]; an exchange recorded with no
 * open tap opens one (source `tap`), and a [beginTap] while one is open closes
 * it as `abandoned`. Thread-safe: the trace hook records on the card I/O
 * thread while the UI reads [taps] on main.
 */
object ApduTraceLog {
    const val MAX_TAPS = 20

    /** Bounds one tap's record (a production flow sends well under this). */
    const val MAX_EXCHANGES_PER_TAP = 64

    class TapRecord(
        val startedAtMs: Long,
        val source: String,
        val exchanges: List<ApduExchange>,
        val outcome: String
    ) {
        override fun toString(): String = "TapRecord($source, ${exchanges.size} exchanges, $outcome)"
    }

    /** Outcome of a tap that is still open when [taps] is read. */
    const val OUTCOME_IN_PROGRESS = "in progress"

    private class OpenTap(val startedAtMs: Long, val source: String) {
        val exchanges = ArrayList<ApduExchange>()
    }

    private val lock = Any()
    private val finished = ArrayDeque<TapRecord>()
    private var open: OpenTap? = null

    /** Overridable for tests; production follows the build type. */
    @Volatile
    internal var enabled: Boolean = BuildConfig.DEBUG

    @Volatile
    internal var clock: () -> Long = System::currentTimeMillis

    fun beginTap(source: String) {
        if (!enabled) return
        synchronized(lock) {
            closeOpen("abandoned")
            open = OpenTap(clock(), source)
        }
    }

    fun record(e: ApduExchange) {
        if (!enabled) return
        synchronized(lock) {
            val tap = open ?: OpenTap(clock(), "tap").also { open = it }
            if (tap.exchanges.size < MAX_EXCHANGES_PER_TAP) tap.exchanges += e
        }
    }

    /**
     * A production trace hook's recording step: the first exchange of a card
     * session ([ApduExchange.sequence] 1) opens a tap labelled [source]
     * (asked only then, on the card I/O thread), and every exchange is
     * recorded. Hosts label a tap with the flow it serves (`register`,
     * `sign-in`, …), or `idle` for a card tapped with nothing asked.
     */
    fun trace(e: ApduExchange, source: () -> String) {
        if (!enabled) return
        if (e.sequence == 1) beginTap(source())
        record(e)
    }

    fun endTap(outcome: String) {
        if (!enabled) return
        synchronized(lock) { closeOpen(outcome) }
    }

    /** Finished taps, oldest first, then the open one (outcome [OUTCOME_IN_PROGRESS]) if any. */
    fun taps(): List<TapRecord> {
        if (!enabled) return emptyList()
        synchronized(lock) {
            val current = open?.let { TapRecord(it.startedAtMs, it.source, it.exchanges.toList(), OUTCOME_IN_PROGRESS) }
            return finished.toList() + listOfNotNull(current)
        }
    }

    fun clear() {
        synchronized(lock) {
            finished.clear()
            open = null
        }
    }

    private fun closeOpen(outcome: String) {
        val tap = open ?: return
        open = null
        finished.addLast(TapRecord(tap.startedAtMs, tap.source, tap.exchanges.toList(), outcome))
        while (finished.size > MAX_TAPS) finished.removeFirst()
    }
}

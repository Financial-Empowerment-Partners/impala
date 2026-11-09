package com.payala.impala.demo.card

/** Non-card progress steps a tap reports while the card is still in the field. */
enum class TapStep {
    /** The tap is waiting on the bridge (e.g. the card-login challenge request). */
    CONTACTING_BRIDGE
}

/**
 * Lets code running inside a card tap's `onTap` (the NFC binder thread, or the
 * debug-tap thread) report a progress step to whoever armed the tap, without
 * that code knowing about any UI. The tap wrapper installs a sink for exactly
 * the duration of one `onTap` with [withSink]; [report] outside a sink is a
 * no-op.
 *
 * The sink is thread-confined (a [ThreadLocal]): `onTap` runs synchronously on
 * one thread, so a report from that thread reaches that tap's sink only, and
 * the sink is always removed in `finally`, so a later tap on the same thread
 * never sees an earlier tap's sink. A sink that throws never breaks the tap.
 * Steps carry no data: nothing secret can travel through here.
 */
object TapProgress {
    private val sink = ThreadLocal<((TapStep) -> Unit)?>()

    /** Reports [step] to the current thread's sink, if a tap installed one. */
    fun report(step: TapStep) {
        val current = sink.get() ?: return
        try {
            current(step)
        } catch (_: Exception) {
            // Progress is advisory; the card operation must not fail because a UI sink did.
        }
    }

    /** Runs [block] with [sink] installed on this thread, restoring the previous sink afterwards. */
    fun <T> withSink(sink: (TapStep) -> Unit, block: () -> T): T {
        val previous = this.sink.get()
        this.sink.set(sink)
        try {
            return block()
        } finally {
            if (previous == null) this.sink.remove() else this.sink.set(previous)
        }
    }
}

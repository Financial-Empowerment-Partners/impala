package com.impala.sdk.apdu4j

/**
 * Field-quality figures over a list of [ApduExchange]s: totals, outcome counts
 * and per-instruction timing. [perIns] is keyed by [ApduExchange.insName] in
 * order of first appearance.
 *
 * [cardErrors] counts status words that mean the card refused or failed a
 * command. A documented normal answer ([ApduNames.isExpectedStatus], e.g.
 * GET_LAST_TRANSFER's `6A83` on a card that never signed) is counted in
 * [expectedStatuses] instead, so a healthy card never reports a card error.
 */
class ApduStats(
    val count: Int,
    val totalNanos: Long,
    val tagLosses: Int,
    val refusals: Int,
    val transportFailures: Int,
    val cardErrors: Int,
    val perIns: Map<String, InsStats>,
    val expectedStatuses: Int = 0
) {
    class InsStats(val count: Int, val minNanos: Long, val maxNanos: Long, val totalNanos: Long) {
        /** Integer mean (0 when [count] is 0). */
        val avgNanos: Long get() = if (count == 0) 0L else totalNanos / count
    }

    /** The slowest exchange's elapsed time, or 0 when there were none. */
    val maxNanos: Long get() = perIns.values.maxOfOrNull { it.maxNanos } ?: 0L

    companion object {
        fun of(exchanges: List<ApduExchange>): ApduStats {
            var total = 0L
            var tagLosses = 0
            var refusals = 0
            var transport = 0
            var cardErrors = 0
            var expected = 0
            val acc = LinkedHashMap<String, LongArray>() // count, min, max, total
            for (e in exchanges) {
                total += e.elapsedNanos
                when (e.outcome) {
                    ApduExchange.Outcome.TAG_LOST -> tagLosses++
                    ApduExchange.Outcome.REFUSED -> refusals++
                    ApduExchange.Outcome.TRANSPORT_FAILURE -> transport++
                    ApduExchange.Outcome.CARD_ERROR ->
                        if (ApduNames.isExpectedStatus(e.cla, e.ins, e.sw)) expected++ else cardErrors++
                    ApduExchange.Outcome.OK -> {}
                }
                val a = acc.getOrPut(e.insName) { longArrayOf(0L, Long.MAX_VALUE, Long.MIN_VALUE, 0L) }
                a[0] += 1
                a[1] = minOf(a[1], e.elapsedNanos)
                a[2] = maxOf(a[2], e.elapsedNanos)
                a[3] += e.elapsedNanos
            }
            val perIns = LinkedHashMap<String, InsStats>()
            for ((name, a) in acc) perIns[name] = InsStats(a[0].toInt(), a[1], a[2], a[3])
            return ApduStats(exchanges.size, total, tagLosses, refusals, transport, cardErrors, perIns, expected)
        }
    }
}

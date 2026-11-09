package com.payala.impala.demo.log

/**
 * What the Activity Log shows: the entries whose level is in [levels] and
 * whose tag or message contains [query] (case-insensitive; blank matches
 * everything). Order is always chronological, oldest first, so "Follow"
 * means "stay at the bottom". Pure, so it is unit-tested without Android.
 */
data class LogFilter(
    val levels: Set<AppLogger.Level> = ALL_LEVELS,
    val query: String = ""
) {
    fun matches(entry: AppLogger.Entry): Boolean {
        if (entry.level !in levels) return false
        val q = query.trim()
        if (q.isEmpty()) return true
        return entry.tag.contains(q, ignoreCase = true) || entry.message.contains(q, ignoreCase = true)
    }

    /** The matching subset of [entries], in their (chronological) order. */
    fun apply(entries: List<AppLogger.Entry>): List<AppLogger.Entry> = entries.filter(::matches)

    /** True when nothing is filtered out. */
    val isIdentity: Boolean get() = levels.containsAll(ALL_LEVELS) && query.isBlank()

    fun withLevel(level: AppLogger.Level, shown: Boolean): LogFilter =
        copy(levels = if (shown) levels + level else levels - level)

    fun withQuery(text: String): LogFilter = copy(query = text)

    companion object {
        val ALL_LEVELS: Set<AppLogger.Level> = AppLogger.Level.entries.toSet()
    }
}

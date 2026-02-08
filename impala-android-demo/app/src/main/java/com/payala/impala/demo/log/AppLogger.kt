package com.payala.impala.demo.log

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-memory ring-buffer logger for capturing recent application activity.
 *
 * Thread-safe via [CopyOnWriteArrayList]. Entries beyond [MAX_ENTRIES] are
 * trimmed from the oldest end. Each entry includes a timestamp, severity
 * level, tag, and message.
 *
 * Accessible app-wide via the singleton [instance].
 */
object AppLogger {

    private const val MAX_ENTRIES = 500

    enum class Level { DEBUG, INFO, WARN, ERROR }

    data class Entry(
        val timestamp: String,
        val level: Level,
        val tag: String,
        val message: String
    ) {
        override fun toString(): String = "[$timestamp] ${level.name} [$tag] $message"
    }

    private val entries = CopyOnWriteArrayList<Entry>()
    private val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")

    fun d(tag: String, message: String) = log(Level.DEBUG, tag, message)
    fun i(tag: String, message: String) = log(Level.INFO, tag, message)
    fun w(tag: String, message: String) = log(Level.WARN, tag, message)
    fun e(tag: String, message: String) = log(Level.ERROR, tag, message)

    private fun log(level: Level, tag: String, message: String) {
        val entry = Entry(
            timestamp = LocalDateTime.now().format(formatter),
            level = level,
            tag = tag,
            message = message
        )
        entries.add(entry)
        // Trim from the front if we exceed the max
        while (entries.size > MAX_ENTRIES) {
            entries.removeAt(0)
        }
    }

    /** Returns a snapshot of all log entries, oldest first. */
    fun getEntries(): List<Entry> = entries.toList()

    /** Returns all log entries formatted as a single string. */
    fun getLogText(): String = entries.joinToString("\n") { it.toString() }

    /** Clears all log entries. */
    fun clear() = entries.clear()

    /** Returns the number of entries currently buffered. */
    fun size(): Int = entries.size
}

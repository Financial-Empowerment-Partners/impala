package com.payala.impala.demo.log

import android.os.Handler
import android.os.Looper
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-memory ring-buffer logger for the in-app Activity Log.
 *
 * The newest [MAX_ENTRIES] entries live in an [ArrayDeque] under one lock;
 * older ones fall off the front. Each entry carries its wall-clock instant
 * ([Entry.epochMs]) and an ISO-8601 UTC timestamp (`2026-11-08T09:41:07.123Z`),
 * so lines from different devices and the bridge's logs line up.
 *
 * [addListener] subscribers are told about every new entry and every [clear],
 * on the main thread. Nothing Android is touched while there are no listeners,
 * so plain JVM tests can log freely.
 *
 * Never log secrets or PII here: the log can be copied and shared
 * (`AppLogHygieneTest` pins the call sites).
 */
object AppLogger {

    const val MAX_ENTRIES = 1_000

    enum class Level { DEBUG, INFO, WARN, ERROR }

    /**
     * One log line. [seq] increases by one per entry for the life of the
     * process (it survives [clear]), so it is a stable list key.
     */
    data class Entry(
        val seq: Long,
        val epochMs: Long,
        val level: Level,
        val tag: String,
        val message: String
    ) {
        /** ISO-8601 UTC with milliseconds, e.g. `2026-11-08T09:41:07.123Z`. */
        val timestamp: String get() = iso(epochMs)

        override fun toString(): String = "[$timestamp] ${level.name} [$tag] $message"
    }

    /** Told about each new entry and each [clear]; always called on the main thread. */
    fun interface Listener {
        fun onEntry(entry: Entry)

        fun onCleared() {}
    }

    private val ISO: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)

    /** ISO-8601 UTC with milliseconds and a `Z` suffix. */
    fun iso(epochMs: Long): String = ISO.format(Instant.ofEpochMilli(epochMs))

    private val lock = Any()
    private val entries = ArrayDeque<Entry>(MAX_ENTRIES)
    private var nextSeq = 1L
    private val listeners = CopyOnWriteArrayList<Listener>()

    /** Wall clock; overridable for tests. */
    @Volatile
    internal var clock: () -> Long = System::currentTimeMillis

    /**
     * How listener notifications reach the main thread. The default posts to
     * the main looper (or runs inline when already on it); tests may run
     * notifications inline.
     */
    @Volatile
    internal var dispatcher: (Runnable) -> Unit = MainDispatcher

    fun d(tag: String, message: String) = log(Level.DEBUG, tag, message)
    fun i(tag: String, message: String) = log(Level.INFO, tag, message)
    fun w(tag: String, message: String) = log(Level.WARN, tag, message)
    fun e(tag: String, message: String) = log(Level.ERROR, tag, message)

    private fun log(level: Level, tag: String, message: String) {
        val entry: Entry
        synchronized(lock) {
            entry = Entry(nextSeq++, clock(), level, tag, message)
            entries.addLast(entry)
            while (entries.size > MAX_ENTRIES) entries.removeFirst()
        }
        if (listeners.isNotEmpty()) notify { it.onEntry(entry) }
    }

    /** Subscribes [listener] (idempotent). Remove it in the matching lifecycle callback. */
    fun addListener(listener: Listener) {
        listeners.addIfAbsent(listener)
    }

    fun removeListener(listener: Listener) {
        listeners.remove(listener)
    }

    /** Returns a snapshot of all log entries, oldest first. */
    fun getEntries(): List<Entry> = synchronized(lock) { entries.toList() }

    /** Returns all log entries formatted as a single string, oldest first. */
    fun getLogText(): String = getEntries().joinToString("\n") { it.toString() }

    /** Clears all log entries. */
    fun clear() {
        synchronized(lock) { entries.clear() }
        if (listeners.isNotEmpty()) notify { it.onCleared() }
    }

    /** Returns the number of entries currently buffered. */
    fun size(): Int = synchronized(lock) { entries.size }

    private inline fun notify(crossinline call: (Listener) -> Unit) {
        dispatcher(Runnable {
            for (l in listeners) {
                // One failing listener never starves the others, and never fails the log call.
                try {
                    call(l)
                } catch (_: Exception) {
                }
            }
        })
    }

    private object MainDispatcher : (Runnable) -> Unit {
        private val handler by lazy { Handler(Looper.getMainLooper()) }

        override fun invoke(r: Runnable) {
            if (Looper.myLooper() == Looper.getMainLooper()) r.run() else handler.post(r)
        }
    }
}

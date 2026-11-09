package com.payala.impala.demo.log

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** [AppLogger]: the 1 000-entry ring, ISO-8601 UTC timestamps, listeners, and the kept API. */
class AppLoggerTest {
    private val delivered = ArrayList<Runnable>()
    private val originalDispatcher = AppLogger.dispatcher

    @Before
    fun setUp() {
        AppLogger.clear()
        AppLogger.dispatcher = { delivered += it } // "main thread" = run when the test says so
    }

    @After
    fun tearDown() {
        AppLogger.clock = System::currentTimeMillis
        AppLogger.dispatcher = originalDispatcher
        AppLogger.clear()
    }

    private fun drain() {
        val pending = delivered.toList()
        delivered.clear()
        pending.forEach { it.run() }
    }

    @Test
    fun `the ring keeps the newest 1000 entries, oldest first`() {
        repeat(1_005) { AppLogger.i("T", "line $it") }
        val entries = AppLogger.getEntries()
        assertEquals(1_000, AppLogger.MAX_ENTRIES)
        assertEquals(1_000, entries.size)
        assertEquals(1_000, AppLogger.size())
        assertEquals("line 5", entries.first().message)
        assertEquals("line 1004", entries.last().message)
        assertTrue("seq is strictly increasing", entries.zipWithNext().all { (a, b) -> b.seq == a.seq + 1 })
    }

    @Test
    fun `timestamps are ISO-8601 UTC with milliseconds and a Z`() {
        AppLogger.clock = { 1_762_594_867_123L }
        AppLogger.w("Tag", "hello")
        val e = AppLogger.getEntries().single()
        assertEquals(1_762_594_867_123L, e.epochMs)
        assertEquals("2025-11-08T09:41:07.123Z", e.timestamp)
        assertEquals("1970-01-01T00:00:00.000Z", AppLogger.iso(0L))
        assertEquals("[2025-11-08T09:41:07.123Z] WARN [Tag] hello", e.toString())
        assertTrue(Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z""").matches(AppLogger.iso(System.currentTimeMillis())))
    }

    @Test
    fun `the d i w e getEntries getLogText clear size API is kept`() {
        AppLogger.clock = { 0L }
        AppLogger.d("A", "debug")
        AppLogger.i("B", "info")
        AppLogger.w("C", "warn")
        AppLogger.e("D", "error")
        assertEquals(listOf(AppLogger.Level.DEBUG, AppLogger.Level.INFO, AppLogger.Level.WARN, AppLogger.Level.ERROR), AppLogger.getEntries().map { it.level })
        assertEquals(
            "[1970-01-01T00:00:00.000Z] DEBUG [A] debug\n[1970-01-01T00:00:00.000Z] INFO [B] info\n" +
                "[1970-01-01T00:00:00.000Z] WARN [C] warn\n[1970-01-01T00:00:00.000Z] ERROR [D] error",
            AppLogger.getLogText()
        )
        assertEquals(4, AppLogger.size())
        AppLogger.clear()
        assertEquals(0, AppLogger.size())
        assertEquals("", AppLogger.getLogText())
    }

    @Test
    fun `listeners hear entries and clears through the dispatcher, until removed`() {
        val seen = ArrayList<String>()
        val listener = object : AppLogger.Listener {
            override fun onEntry(entry: AppLogger.Entry) { seen += entry.message }
            override fun onCleared() { seen += "<cleared>" }
        }
        AppLogger.addListener(listener)
        AppLogger.addListener(listener) // idempotent
        AppLogger.i("T", "one")
        assertTrue("delivery waits for the main thread", seen.isEmpty())
        drain()
        AppLogger.clear()
        drain()
        AppLogger.removeListener(listener)
        AppLogger.i("T", "two")
        drain()
        assertEquals(listOf("one", "<cleared>"), seen)
    }

    @Test
    fun `a failing listener neither breaks logging nor starves the others`() {
        val seen = ArrayList<String>()
        val bad = AppLogger.Listener { throw IllegalStateException("boom") }
        val good = AppLogger.Listener { seen += it.message }
        AppLogger.addListener(bad)
        AppLogger.addListener(good)
        try {
            AppLogger.e("T", "still logged")
            drain()
        } finally {
            AppLogger.removeListener(bad)
            AppLogger.removeListener(good)
        }
        assertEquals(listOf("still logged"), seen)
        assertEquals(1, AppLogger.size())
    }

    @Test
    fun `no listener means no dispatch at all (plain JVM callers never touch Android)`() {
        AppLogger.i("T", "quiet")
        assertTrue(delivered.isEmpty())
    }

    @Test
    fun `concurrent writers keep the cap and a gap-free sequence`() {
        val pool = Executors.newFixedThreadPool(4)
        val start = CountDownLatch(1)
        repeat(4) { t -> pool.execute { start.await(); repeat(600) { AppLogger.d("T$t", "m$it") } } }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS))
        val entries = AppLogger.getEntries()
        assertEquals(1_000, entries.size)
        assertTrue(entries.zipWithNext().all { (a, b) -> b.seq == a.seq + 1 })
    }
}

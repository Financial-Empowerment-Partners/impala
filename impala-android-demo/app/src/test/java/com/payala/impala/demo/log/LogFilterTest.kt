package com.payala.impala.demo.log

import com.payala.impala.demo.log.AppLogger.Level
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** [LogFilter]: level set plus a case-insensitive tag/message search, always chronological. */
class LogFilterTest {
    private fun entry(seq: Long, level: Level, tag: String, message: String) = AppLogger.Entry(seq, seq * 1000, level, tag, message)

    private val entries = listOf(
        entry(1, Level.DEBUG, "App", "Impala Demo started"),
        entry(2, Level.INFO, "lib.ImpalaCardSession", "SELECT ok"),
        entry(3, Level.WARN, "CardLab", "Stellar network mismatch"),
        entry(4, Level.ERROR, "Login", "Card sign-in refused (401)"),
        entry(5, Level.INFO, "CardLab", "Lab read complete: 9 commands")
    )

    @Test
    fun `the default filter shows everything in order`() {
        val f = LogFilter()
        assertTrue(f.isIdentity)
        assertEquals(entries, f.apply(entries))
    }

    @Test
    fun `levels are a set of shown levels`() {
        val f = LogFilter().withLevel(Level.DEBUG, false).withLevel(Level.INFO, false)
        assertFalse(f.isIdentity)
        assertEquals(listOf(3L, 4L), f.apply(entries).map { it.seq })
        assertEquals(listOf(2L, 3L, 4L, 5L), f.withLevel(Level.INFO, true).apply(entries).map { it.seq })
    }

    @Test
    fun `search matches tag or message, ignoring case and surrounding blanks`() {
        assertEquals(listOf(3L, 5L), LogFilter(query = "cardlab").apply(entries).map { it.seq })
        assertEquals(listOf(4L), LogFilter(query = "  REFUSED ").apply(entries).map { it.seq })
        assertEquals(listOf(2L), LogFilter(query = "lib.").apply(entries).map { it.seq })
        assertTrue(LogFilter(query = "   ").isIdentity)
        assertEquals(entries, LogFilter(query = "   ").apply(entries))
    }

    @Test
    fun `levels and search combine, and the order stays chronological`() {
        val f = LogFilter(levels = setOf(Level.INFO, Level.WARN), query = "card")
        assertEquals(listOf(2L, 3L, 5L), f.apply(entries).map { it.seq })
        assertEquals(listOf(5L, 3L, 2L).sorted(), f.apply(entries.reversed()).map { it.seq }.reversed())
    }

    @Test
    fun `no shown level shows nothing`() {
        assertTrue(LogFilter(levels = emptySet()).apply(entries).isEmpty())
    }
}

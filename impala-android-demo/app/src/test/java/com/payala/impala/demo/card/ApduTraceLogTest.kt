package com.payala.impala.demo.card

import com.impala.sdk.apdu4j.ApduExchange
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** [ApduTraceLog]: the debug-only ring of the last 20 production taps (header-only exchanges). */
class ApduTraceLogTest {
    private var now = 1_000L

    private fun ex(seq: Int, ins: Int = 0x02, sw: Int? = 0x9000) = ApduExchange(
        0x00, ins, 0, 0, 0, sw, 0, 1_000_000L,
        if (sw == 0x9000) ApduExchange.Outcome.OK else ApduExchange.Outcome.CARD_ERROR, seq
    )

    @Before
    fun setUp() {
        ApduTraceLog.enabled = true
        ApduTraceLog.clock = { now }
        ApduTraceLog.clear()
    }

    @After
    fun tearDown() {
        ApduTraceLog.clear()
        ApduTraceLog.enabled = com.payala.impala.demo.BuildConfig.DEBUG
        ApduTraceLog.clock = System::currentTimeMillis
    }

    @Test
    fun `a tap is bracketed by beginTap and endTap`() {
        ApduTraceLog.beginTap("login")
        ApduTraceLog.record(ex(1))
        ApduTraceLog.record(ex(2, ins = 0x25))
        ApduTraceLog.endTap("ok")
        val tap = ApduTraceLog.taps().single()
        assertEquals("login", tap.source)
        assertEquals("ok", tap.outcome)
        assertEquals(1_000L, tap.startedAtMs)
        assertEquals(listOf(1, 2), tap.exchanges.map { it.sequence })
    }

    @Test
    fun `the open tap is listed last as in progress`() {
        ApduTraceLog.beginTap("register")
        ApduTraceLog.endTap("ok")
        ApduTraceLog.beginTap("redeem")
        ApduTraceLog.record(ex(1))
        val taps = ApduTraceLog.taps()
        assertEquals(listOf("register", "redeem"), taps.map { it.source })
        assertEquals(ApduTraceLog.OUTCOME_IN_PROGRESS, taps.last().outcome)
    }

    @Test
    fun `a record without beginTap opens a tap, and a new beginTap abandons the open one`() {
        ApduTraceLog.record(ex(1))
        ApduTraceLog.beginTap("login")
        val taps = ApduTraceLog.taps()
        assertEquals("tap", taps[0].source)
        assertEquals("abandoned", taps[0].outcome)
        assertEquals("login", taps[1].source)
    }

    @Test
    fun `trace opens a tap labelled by the host on each session's first exchange`() {
        var asked = 0
        val label = { asked++; "register" }
        ApduTraceLog.trace(ex(1), label)
        ApduTraceLog.trace(ex(2), label)
        ApduTraceLog.trace(ex(3, ins = 0x36, sw = 0x6A83), label)
        ApduTraceLog.endTap("ok")
        ApduTraceLog.trace(ex(1)) { "idle" }
        ApduTraceLog.endTap("idle")
        val taps = ApduTraceLog.taps()
        assertEquals(listOf("register", "idle"), taps.map { it.source })
        assertEquals(listOf(1, 2, 3), taps[0].exchanges.map { it.sequence })
        assertEquals("the label is asked once per session, on its first exchange", 1, asked)
    }

    @Test
    fun `trace records nothing and asks for no label when disabled`() {
        ApduTraceLog.enabled = false
        ApduTraceLog.trace(ex(1)) { error("a release build never labels a tap") }
        ApduTraceLog.enabled = true
        assertTrue(ApduTraceLog.taps().isEmpty())
    }

    @Test
    fun `the production hosts label their taps by flow, not idle`() {
        // MainActivity labels a tap from the request running on the card thread, or the armed one,
        // so a session with no SELECT before onTap (the simulated card) is not labelled idle.
        val main = java.io.File("src/main/java/com/payala/impala/demo/ui/main/MainActivity.kt").readText()
        assertTrue(main.contains("runningTap.set(request.prompt.logName)"))
        assertTrue(main.contains("ApduTraceLog.trace(exchange) { traceSource() }"))
        // LoginActivity brackets its card-login taps too (sessions opened by its reader and its simulated tap).
        val login = java.io.File("src/main/java/com/payala/impala/demo/ui/login/LoginActivity.kt").readText()
        assertTrue(login.contains("ApduTraceLog.trace(exchange)"))
        assertTrue(login.contains("trace = traceHook)"))
        assertTrue(login.contains("DebugCards.openSession(trace = traceHook)"))
        assertTrue(Regex("""ApduTraceLog\.endTap\(""").findAll(login).count() >= 4)
    }

    @Test
    fun `only the last 20 taps and 64 exchanges per tap are kept`() {
        repeat(25) { i ->
            now = i.toLong()
            ApduTraceLog.beginTap("t$i")
            ApduTraceLog.endTap("ok")
        }
        val taps = ApduTraceLog.taps()
        assertEquals(ApduTraceLog.MAX_TAPS, taps.size)
        assertEquals("t5", taps.first().source)
        assertEquals("t24", taps.last().source)

        ApduTraceLog.clear()
        ApduTraceLog.beginTap("long")
        repeat(100) { ApduTraceLog.record(ex(it + 1)) }
        ApduTraceLog.endTap("ok")
        assertEquals(ApduTraceLog.MAX_EXCHANGES_PER_TAP, ApduTraceLog.taps().single().exchanges.size)
    }

    @Test
    fun `disabled (release builds) it records and returns nothing`() {
        ApduTraceLog.enabled = false
        ApduTraceLog.beginTap("login")
        ApduTraceLog.record(ex(1))
        ApduTraceLog.endTap("ok")
        assertTrue(ApduTraceLog.taps().isEmpty())
        ApduTraceLog.enabled = true
        assertTrue("nothing was retained while disabled", ApduTraceLog.taps().isEmpty())
    }

    @Test
    fun `clear drops finished and open taps`() {
        ApduTraceLog.beginTap("a")
        ApduTraceLog.endTap("ok")
        ApduTraceLog.beginTap("b")
        ApduTraceLog.clear()
        assertTrue(ApduTraceLog.taps().isEmpty())
    }

    @Test
    fun `the record type is header-only, so the log cannot retain bytes`() {
        val fields = ApduExchange::class.java.declaredFields.map { it.type }
        assertTrue(fields.none { it == ByteArray::class.java || it == String::class.java })
        assertTrue(ApduTraceLog.TapRecord(0, "s", emptyList(), "ok").toString().contains("0 exchanges"))
    }
}

package com.payala.impala.card

import android.util.Log
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ImpalaLibLogTest {
    @After
    fun tearDown() {
        ImpalaLibLog.sink = null
    }

    @Test
    fun `the sink receives every line with its priority and tag`() {
        val lines = mutableListOf<Triple<Int, String, String>>()
        ImpalaLibLog.sink = LibLogSink { p, t, m -> lines += Triple(p, t, m) }
        ImpalaLibLog.d("T", "one")
        ImpalaLibLog.i("T", "two")
        ImpalaLibLog.w("T", "three")
        ImpalaLibLog.e("T", "four")
        assertEquals(
            listOf(Triple(Log.DEBUG, "T", "one"), Triple(Log.INFO, "T", "two"), Triple(Log.WARN, "T", "three"), Triple(Log.ERROR, "T", "four")),
            lines
        )
    }

    @Test
    fun `no sink, or a throwing sink, is safe`() {
        ImpalaLibLog.sink = null
        ImpalaLibLog.e("T", "nobody listens")
        ImpalaLibLog.sink = LibLogSink { _, _, _ -> throw IllegalStateException("broken sink") }
        ImpalaLibLog.w("T", "still fine")
    }

    @Test
    fun `library call sites reach the sink`() {
        val tags = mutableListOf<String>()
        ImpalaLibLog.sink = LibLogSink { _, t, _ -> tags += t }
        ImpalaCardTapHandler.setCardTapListener(null)
        offMain { ImpalaCardTapHandler.readTap(ImpalaCardSession.fromBibo(ScriptedBibo(emptyMap()))) }
        assertEquals(listOf("ImpalaCardTap"), tags)
    }
}

package com.payala.impala.demo

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tripwire: the simulated-card transport is debug-only. Its types live in
 * impala-lib's debug source set (absent from the release AAR) and are reached
 * only through the app's debug `DebugCards`; `src/main` and `src/release`
 * never name them, so a release build cannot even compile against them.
 */
class DebugBoundaryTest {
    private val forbidden = Regex("""\b(TcpBibo|DebugCardTransport|SimulatorUnreachableException|SimProbe)\b""")

    private fun offenders(dir: String): List<String> {
        val root = File(dir)
        assertTrue("run from the app module directory ($dir missing)", root.isDirectory)
        return root.walkTopDown()
            .filter { it.isFile && it.extension in setOf("kt", "java", "xml") }
            .flatMap { f ->
                f.readLines().mapIndexedNotNull { i, line -> if (forbidden.containsMatchIn(line)) "${f.path}:${i + 1}: ${line.trim()}" else null }
            }.toList()
    }

    @Test
    fun `app sources compiled into release never name the debug-only card transport`() {
        // Every source set a release APK compiles: main, release, each flavour (tnet, live) and flavour+release.
        val releaseSets = File("src").listFiles()!!.map { it.name }
            .filter { it == "main" || it == "release" || it == "tnet" || it == "live" || it.endsWith("Release") }
        assertTrue(releaseSets.toString(), releaseSets.containsAll(listOf("main", "release", "tnet", "live")))
        val found = releaseSets.flatMap { offenders("src/$it") }
        assertTrue("debug-only card types referenced outside src/debug:\n" + found.joinToString("\n"), found.isEmpty())
    }

    @Test
    fun `the debug DebugCards is the one place that names them`() {
        val debug = File("src/debug/java/com/payala/impala/demo/card/DebugCards.kt").readText()
        assertTrue(forbidden.containsMatchIn(debug))
        assertTrue(forbidden.containsMatchIn("import com.payala.impala.card.DebugCardTransport"))
        assertTrue(!forbidden.containsMatchIn("SimulatorStatus"))
    }
}

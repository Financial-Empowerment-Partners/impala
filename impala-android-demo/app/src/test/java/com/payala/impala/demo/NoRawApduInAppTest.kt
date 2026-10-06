package com.payala.impala.demo

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tripwire: the app never speaks APDU itself. Card transport, sessions and
 * every instruction byte belong to impala-lib and the card SDK, so a new card
 * feature cannot fork the protocol a third time.
 */
class NoRawApduInAppTest {
    private val forbidden = listOf(
        Regex("""\bIsoDep\b"""), Regex("""\bCommandAPDU\b"""), Regex("""\btransceive\("""), Regex("""\bINS_[A-Z_0-9]+""")
    )

    @Test
    fun `app main sources contain no APDU or IsoDep references`() {
        val root = File("src/main")
        assertTrue("run from the app module directory", root.isDirectory)
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.extension in setOf("kt", "java", "xml") }
            .flatMap { f ->
                f.readLines().mapIndexedNotNull { i, line ->
                    if (forbidden.any { it.containsMatchIn(line) }) "${f.path}:${i + 1}: ${line.trim()}" else null
                }
            }.toList()
        assertTrue("raw APDU/IsoDep references in app sources:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }
}

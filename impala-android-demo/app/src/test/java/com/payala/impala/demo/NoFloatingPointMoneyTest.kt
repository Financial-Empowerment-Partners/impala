package com.payala.impala.demo

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Tripwire: integer minor units only — no floating point anywhere money is handled. */
class NoFloatingPointMoneyTest {
    private val forbidden = Regex("""\b(Double|Float)\b|\.toDouble\(|\.toFloat\(|\b\d+\.\d+[fFdD]?\b""")

    @Test
    fun `transfer package sources contain no Double or Float`() {
        val roots = listOf(
            "src/main/java/com/payala/impala/demo/transfer",
            "src/main/java/com/payala/impala/demo/ui/transfer",
            "src/main/java/com/payala/impala/demo/ui/fragments/TransfersFragment.kt",
            "src/main/java/com/payala/impala/demo/model/OfflineModels.kt"
        ).map(::File)
        roots.forEach { assertTrue("missing ${it.path}", it.exists()) }
        val offenders = roots.flatMap { r -> r.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
            .flatMap { f ->
                f.readLines().mapIndexedNotNull { i, line ->
                    val code = line.substringBefore("//").trimStart()
                    val comment = code.startsWith("*") || code.startsWith("/*")
                    if (!comment && forbidden.containsMatchIn(code)) "${f.path}:${i + 1}: ${line.trim()}" else null
                }
            }
        assertTrue("floating point in money code:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }
}

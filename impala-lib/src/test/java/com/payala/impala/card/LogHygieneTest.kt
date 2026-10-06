package com.payala.impala.card

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tripwire: no log call in the module's main sources may reference a PIN,
 * challenge, signature or key material. Tracing is the caller's choice,
 * through the masked `debugTrace` hooks only.
 */
class LogHygieneTest {
    private val logCall = Regex("""\bLog\.(v|d|i|w|e|wtf)\s*\(""")
    private val secret = Regex("""(?i)(pin|challenge|signature|\bsig\b|seed|private|secret|scp03|\bkey\b|keyBytes|pubKey|tuple|tail209)""")

    @Test
    fun `no log call in the module's main source references pin, challenge, signature or key material`() {
        val root = File("src/main/java")
        assertTrue("run from the impala-lib module directory", root.isDirectory)
        val offenders = root.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
            .flatMap { f -> f.readLines().mapIndexedNotNull { i, line -> if (logCall.containsMatchIn(line) && secret.containsMatchIn(line)) "${f.path}:${i + 1}: ${line.trim()}" else null } }
            .toList()
        assertTrue("log calls reference secret material:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }
}

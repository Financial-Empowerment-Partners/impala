package com.payala.impala.card

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tripwire: no log call in the module's main sources (`android.util.Log` or
 * the [ImpalaLibLog] sink, which reaches the app's exportable log) may
 * reference a PIN, challenge, signature or key material. Tracing is the
 * caller's choice, through header-only trace hooks only.
 */
class LogHygieneTest {
    private val logCall = Regex("""\b(Log|ImpalaLibLog)\.(v|d|i|w|e|wtf|println)\s*\(|\bsink\s*\??\.\s*log\s*\(""")
    private val secret = Regex("""(?i)(pin|challenge|signature|\bsig\b|seed|private|secret|scp03|\bkey\b|keyBytes|pubKey|tuple|tail209|fullName|holderName|displayName|email|phone|balance|amount|recipient|lastTransfer|latitude|longitude)""")

    /** Every log call in [text] as (line, whole call): the call runs to its closing parenthesis, across lines. */
    private fun logCalls(text: String): List<Pair<Int, String>> = logCall.findAll(text).map { m ->
        var depth = 0
        var end = text.length
        var i = m.range.last
        while (i < text.length) {
            when (text[i]) {
                '(' -> depth++
                ')' -> if (--depth == 0) { end = i + 1; break }
            }
            i++
        }
        (text.substring(0, m.range.first).count { it == '\n' } + 1) to text.substring(m.range.first, end)
    }.toList()

    @Test
    fun `no log call in the module's main or debug source references pin, challenge, signature, key material or PII`() {
        // src/debug lines reach the app's exportable log through the same ImpalaLibLog sink.
        val roots = listOf(File("src/main/java"), File("src/debug/java"))
        assertTrue("run from the impala-lib module directory", roots.all { it.isDirectory })
        val offenders = roots.flatMap { root -> root.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "java") }.toList() }
            .flatMap { f -> logCalls(f.readText()).filter { secret.containsMatchIn(it.second) }.map { (line, call) -> "${f.path}:$line: ${call.replace(Regex("""\s+"""), " ")}" } }
        assertTrue("log calls reference secret material:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }

    @Test
    fun `the log-call pattern covers the ImpalaLibLog sink`() {
        assertTrue(logCall.containsMatchIn("ImpalaLibLog.d(TAG, \"x\")"))
        assertTrue(logCall.containsMatchIn("Log.e(TAG, \"x\")"))
        assertTrue(secret.containsMatchIn("ImpalaLibLog.w(TAG, \"pin=\" + pin)"))
        assertTrue(logCall.containsMatchIn("Log.println(Log.WARN, TAG, \"x\")"))
        assertTrue(logCall.containsMatchIn("ImpalaLibLog.sink?.log(Log.WARN, TAG, \"x\")"))
        assertTrue(logCalls("ImpalaLibLog.w(\n    TAG, \"holder \$fullName\")").single().second.contains("fullName"))
    }

    @Test
    fun `GeoUpdateReceiver never logs coordinates`() {
        val src = File("src/main/java/com/payala/impala/GeoUpdateReceiver.java").readText()
        assertTrue(!Regex("""getLatitude|getLongitude""").containsMatchIn(src.lines().filter { logCall.containsMatchIn(it) }.joinToString("\n")))
        assertTrue(!src.contains("lat=") && !src.contains("lon="))
    }
}

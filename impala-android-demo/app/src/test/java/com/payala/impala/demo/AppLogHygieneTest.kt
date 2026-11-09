package com.payala.impala.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Tripwire: no app log call interpolates a secret, a piece of PII, or a whole
 * container object whose toString() could carry either. The in-app Activity
 * Log can be copied and shared, and logcat is readable over adb, so the rule
 * is structural rather than "remember not to".
 *
 * Every `AppLogger.d/i/w/e(` and `Log.v/d/i/w/e/wtf(` call in app/src/main,
 * src/debug and src/release is extracted (across lines, up to its closing
 * parenthesis) and each value it interpolates or passes is reduced to the
 * identifier actually rendered (the last segment of `a.b.c`, looking through
 * string-slicing calls such as `take`/`substring`, which still reveal the
 * value). That identifier must not name a secret or PII ([SENSITIVE], [PIN])
 * and must not be a container ([CONTAINER]); `${identity.wireCardId}` is fine,
 * `$identity` is not. `${e.message}` and response `message` fields are allowed.
 */
class AppLogHygieneTest {

    companion object {
        val SENSITIVE = Regex(
            "(?i)(token|password|secret|seed|signature|challenge|tuple|signable|tail|email|phone|fullName|holderName|displayName|accountId)"
        )
        val PIN = Regex("""(?<![A-Za-z])pin(?![a-z])|Pin(?=[A-Z_0-9]|$)""")
        val CONTAINER = Regex("(?i)(snapshot|pending|redemption|credit|inspection|identity|exchange)")

        /** Calls that still render (part of) their receiver: looked through when finding the rendered identifier. */
        val TRANSPARENT = setOf(
            "take", "takeLast", "drop", "dropLast", "substring", "subSequence", "slice", "chunked", "windowed",
            "lowercase", "uppercase", "trim", "trimEnd", "trimStart", "toString", "orEmpty", "padStart", "padEnd",
            "joinToString", "contentToString", "toHex", "encodeHex", "reversed"
        )

        private val CALL = Regex("""\b(AppLogger\.(d|i|w|e)|Log\.(v|d|i|w|e|wtf))\s*\(""")
        private val CHAIN = Regex("""[A-Za-z_][A-Za-z0-9_]*(?:\s*\??\.\s*[A-Za-z_][A-Za-z0-9_]*)*""")

        /** The argument text of the call whose "(" is at [open], up to its matching ")". */
        fun callArguments(src: String, open: Int): String {
            var depth = 0
            var i = open
            var inString = false
            var templateDepth = 0
            while (i < src.length) {
                val c = src[i]
                if (inString && templateDepth == 0) {
                    when {
                        c == '\\' -> i++
                        c == '"' -> inString = false
                        c == '$' && i + 1 < src.length && src[i + 1] == '{' -> { templateDepth = 1; i++ }
                    }
                } else if (inString) { // inside ${ ... } of a string template
                    if (c == '{') templateDepth++ else if (c == '}') templateDepth--
                } else {
                    when (c) {
                        '"' -> inString = true
                        '(' -> depth++
                        ')' -> { depth--; if (depth == 0) return src.substring(open + 1, i) }
                    }
                }
                i++
            }
            return src.substring(open + 1)
        }

        /** Expressions a log call renders: `$x` / `${...}` templates and non-literal arguments. */
        fun renderedExpressions(args: String): List<String> {
            val out = ArrayList<String>()
            val outside = StringBuilder()
            var i = 0
            while (i < args.length) {
                val c = args[i]
                if (c == '"') {
                    i++
                    while (i < args.length && args[i] != '"') {
                        when {
                            args[i] == '\\' -> i++
                            args[i] == '$' && i + 1 < args.length && args[i + 1] == '{' -> {
                                var depth = 1
                                val start = i + 2
                                i += 2
                                while (i < args.length && depth > 0) {
                                    if (args[i] == '{') depth++ else if (args[i] == '}') depth--
                                    i++
                                }
                                out += args.substring(start, (i - 1).coerceAtLeast(start))
                                continue
                            }
                            args[i] == '$' && i + 1 < args.length && (args[i + 1].isLetter() || args[i + 1] == '_') -> {
                                val m = Regex("""[A-Za-z_][A-Za-z0-9_]*""").find(args, i + 1)!!
                                out += m.value
                                i = m.range.last + 1
                                continue
                            }
                        }
                        i++
                    }
                    i++
                    outside.append(' ')
                } else {
                    outside.append(c)
                    i++
                }
            }
            out += outside.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            return out
        }

        /** The identifier an expression chain actually renders, looking through [TRANSPARENT] calls. */
        fun renderedIdentifier(chain: String): String {
            val segments = chain.split(Regex("""\s*\??\.\s*""")).filter { it.isNotEmpty() }
            var k = segments.size - 1
            while (k > 0 && segments[k] in TRANSPARENT) k--
            return segments[k]
        }

        /** Why [expression] may not be logged, or null when it is fine. */
        fun violation(expression: String): String? {
            // Masked.reveal() exists for the Lab screen only; a log line never renders a revealed value.
            if (Regex("""\breveal\s*\(""").containsMatchIn(expression)) return "a revealed Masked value"
            for (m in CHAIN.findAll(expression)) {
                val id = renderedIdentifier(m.value)
                if (SENSITIVE.containsMatchIn(id) || PIN.containsMatchIn(id)) return "sensitive value '$id'"
                if (CONTAINER.containsMatchIn(id)) return "whole container '$id' (log a non-sensitive field instead)"
            }
            return null
        }

        /** All offending log calls in [src], as "line: reason: call". */
        fun offenders(src: String): List<String> = CALL.findAll(src).mapNotNull { call ->
            val open = call.range.last
            val args = callArguments(src, open)
            val reasons = renderedExpressions(args).mapNotNull(::violation)
            if (reasons.isEmpty()) null
            else "${src.substring(0, call.range.first).count { it == '\n' } + 1}: ${reasons.first()}: ${call.value}$args)"
        }.toList()
    }

    @Test
    fun `the rule catches secrets, PII and containers and allows plain fields`() {
        val bad = listOf(
            """AppLogger.i("Auth", "Google login attempt for: ${'$'}email")""",
            """AppLogger.d("Auth", "sig ${'$'}{tap.signatureHex}")""",
            """AppLogger.i("Cards", "read ${'$'}identity")""",
            """AppLogger.i("Cards", "read ${'$'}{event.identity}")""",
            """AppLogger.w("Auth", "tok ${'$'}{token.take(6)}")""",
            """AppLogger.w("Card", "pin ${'$'}userPin")""",
            """AppLogger.w("Card", "pin ${'$'}{pin}")""",
            """Log.d(TAG, "pending: " + pending)""",
            """AppLogger.e("Redeem",
                   "tuple ${'$'}{prepared.tuple}")""",
            """Log.i(TAG, "name ${'$'}{identity.fullName.lowercase()}")""",
            """AppLogger.i("Lab", "inspection=${'$'}{lastInspection}")""",
            """AppLogger.i("Auth", challengeHex)""",
            // Federated (Google, Okta) account ids are the verified e-mail address.
            """AppLogger.i("MFA", "TOTP enrollment successful for: ${'$'}accountId")""",
            """AppLogger.i("Lab", "holder ${'$'}{inspection.holderName?.reveal()}")""",
            """AppLogger.i("Lab", "balance ${'$'}{read.inspection?.balanceMinor?.reveal()}")"""
        )
        for (line in bad) assertEquals("must be flagged: $line", 1, offenders(line).size)

        val good = listOf(
            """AppLogger.w("Auth", "Token request failed: ${'$'}{tokenResponse.message}")""",
            """AppLogger.i("Cards", "Card registered: ${'$'}{identity.wireCardId}")""",
            """AppLogger.i("App", "provider: ${'$'}{tokenManager.getAuthProvider() ?: "unknown"})")""",
            """AppLogger.e("MFA", "TOTP enrollment failed: ${'$'}{e.message}")""",
            """AppLogger.w("Auth", "${'$'}provider login timed out after ${'$'}{LOGIN_TIMEOUT_MS / 1000}s")""",
            """AppLogger.i("Redeem", "Card ${'$'}{prepared.cardId} signed a redemption")""",
            """Log.d(TAG, "spinner shown (pinned=${'$'}pinned)")"""
        )
        for (line in good) assertEquals("must pass: $line", emptyList<String>(), offenders(line))
    }

    @Test
    fun `no app log call renders a secret, PII or a container`() {
        val roots = listOf("src/main", "src/debug", "src/release").map(::File)
        assertTrue("run from the app module directory", roots[0].isDirectory)
        val found = roots.filter { it.isDirectory }.flatMap { root ->
            root.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java") }.flatMap { f ->
                offenders(f.readText()).map { "${f.path}:$it" }
            }.toList()
        }
        assertTrue("log calls that render secrets, PII or containers:\n" + found.joinToString("\n"), found.isEmpty())
    }
}

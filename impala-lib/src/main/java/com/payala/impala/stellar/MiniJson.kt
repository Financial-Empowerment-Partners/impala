package com.payala.impala.stellar

/**
 * Just enough JSON for the SEP-10 exchanges, without a dependency (org.json is
 * a stub in plain JVM unit tests): [stringFields] reads the top-level string
 * members of one JSON object, validating the whole document (RFC 8259, nesting
 * bounded); [quote] writes a JSON string.
 */
internal object MiniJson {
    private const val MAX_DEPTH = 32

    class JsonException(message: String) : Exception(message)

    /** The top-level members of the object [text] whose values are strings. Duplicate keys are malformed. */
    @Throws(JsonException::class)
    fun stringFields(text: String): Map<String, String> {
        val p = Parser(text)
        p.ws()
        val out = p.topObject()
        p.ws()
        if (p.i != text.length) throw JsonException("trailing characters at ${p.i}")
        return out
    }

    fun quote(s: String): String {
        val b = StringBuilder(s.length + 2).append('"')
        for (c in s) {
            when {
                c == '"' -> b.append("\\\"")
                c == '\\' -> b.append("\\\\")
                c < ' ' -> b.append("\\u").append(c.code.toString(16).padStart(4, '0'))
                else -> b.append(c)
            }
        }
        return b.append('"').toString()
    }

    private class Parser(val s: String) {
        var i = 0

        fun fail(what: String): Nothing = throw JsonException("$what at $i")

        fun ws() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        fun expect(c: Char) {
            if (i >= s.length || s[i] != c) fail("expected '$c'")
            i++
        }

        fun topObject(): Map<String, String> {
            val out = LinkedHashMap<String, String>()
            val seen = HashSet<String>()
            expect('{')
            ws()
            if (i < s.length && s[i] == '}') { i++; return out }
            while (true) {
                ws()
                val key = string()
                if (!seen.add(key)) fail("duplicate key")
                ws(); expect(':'); ws()
                if (i < s.length && s[i] == '"') out[key] = string() else value(1)
                ws()
                if (i < s.length && s[i] == ',') { i++; continue }
                expect('}')
                return out
            }
        }

        fun value(depth: Int) {
            if (depth > MAX_DEPTH) fail("nesting too deep")
            if (i >= s.length) fail("unexpected end")
            when (s[i]) {
                '"' -> string()
                '{' -> container('}', depth, keyed = true)
                '[' -> container(']', depth, keyed = false)
                't' -> literal("true")
                'f' -> literal("false")
                'n' -> literal("null")
                else -> number()
            }
        }

        fun container(close: Char, depth: Int, keyed: Boolean) {
            i++
            ws()
            if (i < s.length && s[i] == close) { i++; return }
            while (true) {
                ws()
                if (keyed) { string(); ws(); expect(':'); ws() }
                value(depth + 1)
                ws()
                if (i < s.length && s[i] == ',') { i++; continue }
                expect(close)
                return
            }
        }

        fun literal(word: String) {
            if (!s.startsWith(word, i)) fail("bad literal")
            i += word.length
        }

        fun number() {
            val m = NUMBER.find(s.substring(i, minOf(s.length, i + 64))) ?: fail("bad value")
            if (m.range.first != 0) fail("bad value")
            i += m.value.length
        }

        fun string(): String {
            expect('"')
            val b = StringBuilder()
            while (true) {
                if (i >= s.length) fail("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return b.toString()
                    c == '\\' -> {
                        if (i >= s.length) fail("unterminated escape")
                        when (val e = s[i++]) {
                            '"' -> b.append('"')
                            '\\' -> b.append('\\')
                            '/' -> b.append('/')
                            'b' -> b.append('\b')
                            'f' -> b.append('\u000C')
                            'n' -> b.append('\n')
                            'r' -> b.append('\r')
                            't' -> b.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) fail("short unicode escape")
                                val hex = s.substring(i, i + 4)
                                if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) fail("bad unicode escape")
                                b.append(hex.toInt(16).toChar())
                                i += 4
                            }
                            else -> fail("bad escape '\\$e'")
                        }
                    }
                    c < ' ' -> fail("control character in string")
                    else -> b.append(c)
                }
            }
        }

        companion object {
            val NUMBER = Regex("""-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?""")
        }
    }
}

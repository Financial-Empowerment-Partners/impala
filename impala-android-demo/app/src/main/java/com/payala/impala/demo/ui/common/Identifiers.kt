package com.payala.impala.demo.ui.common

/**
 * Display helpers for identifiers (UUIDs, URLs, `host:port` endpoints).
 *
 * Android's line breaker follows the Unicode rules, under which a hyphen
 * followed by a digit (`-0000`) and a slash or colon followed by a digit
 * (`//10.0.2.2:8080`) are not break opportunities. A UUID or a URL is then one
 * unbreakable word, and when it does not fit (large font scales) the text view
 * breaks it wherever the line ends: `…-8000-0000` / `00000006`. [breakable]
 * inserts zero-width spaces after each `-`, after a run of `/`, and before a
 * port's `:` (fingerprints' colons are left alone), so an identifier wraps
 * only at its own separators.
 *
 * Display only: the zero-width spaces must never reach a clipboard, a log or
 * an export. Copy actions use the original value, and text views showing a
 * breakable value are not selectable.
 */
object Identifiers {
    const val ZERO_WIDTH_SPACE = '\u200B'

    /** [value] with break opportunities at its separators (see [Identifiers]). */
    fun breakable(value: String): String {
        val out = StringBuilder(value.length + 8)
        for (i in value.indices) {
            val c = value[i]
            val next = value.getOrNull(i + 1)
            if (c == ':' && i > 0 && isPort(value, i + 1)) out.append(ZERO_WIDTH_SPACE)
            out.append(c)
            when {
                c == '-' && next != null -> out.append(ZERO_WIDTH_SPACE)
                c == '/' && next != null && next != '/' -> out.append(ZERO_WIDTH_SPACE)
            }
        }
        return out.toString()
    }

    /**
     * True when the colon before [from] starts a URL or endpoint port: 1 to 5
     * digits up to the end or a `/`, and the only colon besides a scheme's
     * `://` (a fingerprint's colons are not ports).
     */
    private fun isPort(value: String, from: Int): Boolean {
        val colons = value.indices.count { value[it] == ':' && !value.startsWith("//", it + 1) }
        if (colons != 1) return false
        var end = from
        while (end < value.length && value[end].isDigit()) end++
        return end - from in 1..5 && (end == value.length || value[end] == '/')
    }

    /** [text] without the zero-width spaces [breakable] added. */
    fun plain(text: CharSequence): String = text.toString().replace(ZERO_WIDTH_SPACE.toString(), "")
}

package com.payala.impala.stellar

/** A stellar.toml that this strict reader refuses (too large, a malformed or duplicated needed key). */
class StellarTomlException(message: String) : Exception(message)

/**
 * The three SEP-1 keys SEP-10 needs, read strictly from a stellar.toml.
 *
 * Only root-table lines (before the first `[table]` or `[[array]]` header)
 * count, and a needed key must be a bare-key line `KEY = "value"`: a basic
 * double-quoted string without escapes or control characters, optionally
 * followed by a `#` comment. Each needed key may appear at most once. Every
 * other line (other keys, comments, multi-line arrays and strings) is
 * skipped. A missing key is `null` here; the client decides what it needs.
 */
class StellarToml private constructor(
    val signingKey: String?,
    val webAuthEndpoint: String?,
    val networkPassphrase: String?,
) {
    companion object {
        /** SEP-1 caps stellar.toml at 100 KB. */
        const val MAX_LENGTH = 100 * 1024
        const val SIGNING_KEY = "SIGNING_KEY"
        const val WEB_AUTH_ENDPOINT = "WEB_AUTH_ENDPOINT"
        const val NETWORK_PASSPHRASE = "NETWORK_PASSPHRASE"
        private val NEEDED = setOf(SIGNING_KEY, WEB_AUTH_ENDPOINT, NETWORK_PASSPHRASE)
        private val KEY_LINE = Regex("""^([A-Za-z0-9_-]+)[ \t]*=(.*)$""")
        private val HEADER = Regex("""^\[\[?[ \t]*[A-Za-z0-9_."' \t-]+[ \t]*]]?[ \t]*(#.*)?$""")
        private val VALUE = Regex("""^[ \t]*"([^"\\\u0000-\u001F\u007F]*)"[ \t]*(#.*)?$""")

        @JvmStatic
        @Throws(StellarTomlException::class)
        fun parse(text: String): StellarToml {
            if (text.length > MAX_LENGTH) throw StellarTomlException("stellar.toml longer than $MAX_LENGTH characters")
            val found = HashMap<String, String>()
            var multiline: String? = null
            for ((index, raw) in text.split('\n').withIndex()) {
                val line = raw.removeSuffix("\r")
                if (multiline != null) {
                    if (line.contains(multiline)) multiline = null
                    continue
                }
                val trimmed = line.trim()
                if (HEADER.matches(trimmed)) break // the root table ends at the first header
                val m = KEY_LINE.find(trimmed)
                if (m == null) continue
                val key = m.groupValues[1]
                val rest = m.groupValues[2]
                if (key !in NEEDED) {
                    // skip another key's multi-line string so its content cannot pose as a key line
                    val v = rest.trimStart()
                    for (delim in listOf("\"\"\"", "'''")) {
                        if (v.startsWith(delim) && !v.substring(3).contains(delim)) { multiline = delim; break }
                    }
                    continue
                }
                val value = VALUE.find(rest)?.groupValues?.get(1)
                    ?: throw StellarTomlException("line ${index + 1}: $key must be a plain double-quoted string")
                if (found.put(key, value) != null) throw StellarTomlException("line ${index + 1}: $key appears more than once")
            }
            return StellarToml(found[SIGNING_KEY], found[WEB_AUTH_ENDPOINT], found[NETWORK_PASSPHRASE])
        }
    }
}

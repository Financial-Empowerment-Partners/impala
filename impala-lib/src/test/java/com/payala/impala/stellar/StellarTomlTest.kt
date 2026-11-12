package com.payala.impala.stellar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class StellarTomlTest {
    /** The root table of https://testanchor.stellar.org/.well-known/stellar.toml (2026-11-12), plus its first tables. */
    private val testAnchor = """
        ACCOUNTS = ["GCSGSR6KQQ5BP2FXVPWRL6SWPUSFWLVONLIBJZUKTVQB5FYJFVL6XOXE"]
        VERSION = "0.1.0"
        SIGNING_KEY = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR"
        NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"

        WEB_AUTH_ENDPOINT = "https://testanchor.stellar.org/auth"
        KYC_SERVER = "https://testanchor.stellar.org/sep12"
        WEB_AUTH_FOR_CONTRACTS_ENDPOINT = "https://testanchor.stellar.org/sep45/auth"

        [[CURRENCIES]]
        code = "SRT"
        issuer = "GCDNJUBQSX7AJWLJACMJ7I4BC3Z47BQUTMHEICZLE6MU4KQBRYG5JY6B"

        [DOCUMENTATION]
        ORG_NAME = "Stellar Development Foundation"
    """.trimIndent()

    @Test
    fun `the reference anchor's toml yields its three keys`() {
        val t = StellarToml.parse(testAnchor)
        assertEquals("GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR", t.signingKey)
        assertEquals("https://testanchor.stellar.org/auth", t.webAuthEndpoint)
        assertEquals("Test SDF Network ; September 2015", t.networkPassphrase)
    }

    @Test
    fun `comments, spacing, CRLF and trailing comments are fine, missing keys are null`() {
        val t = StellarToml.parse("# hi\r\n  SIGNING_KEY=\"G1\"   # the key\r\nWEB_AUTH_ENDPOINT\t =  \"https://a/b\"\r\n")
        assertEquals("G1", t.signingKey)
        assertEquals("https://a/b", t.webAuthEndpoint)
        assertNull(t.networkPassphrase)
        val empty = StellarToml.parse("")
        assertNull(empty.signingKey)
    }

    @Test
    fun `keys inside tables do not count`() {
        val t = StellarToml.parse("VERSION = \"1\"\n[DOCUMENTATION]\nSIGNING_KEY = \"GX\"\n[[PRINCIPALS]]\nWEB_AUTH_ENDPOINT = \"https://evil\"\n")
        assertNull(t.signingKey)
        assertNull(t.webAuthEndpoint)
        val t2 = StellarToml.parse("[ DOCUMENTATION ] # c\nSIGNING_KEY = \"GX\"\n")
        assertNull(t2.signingKey)
    }

    @Test
    fun `a multi-line string or array in another key cannot pose as a key line`() {
        val t = StellarToml.parse("DESC = \"\"\"\nSIGNING_KEY = \"GEVIL\"\n\"\"\"\nNOTE = '''\nWEB_AUTH_ENDPOINT = \"https://evil\"\n'''\nSIGNING_KEY = \"GOOD\"\n")
        assertEquals("GOOD", t.signingKey)
        assertNull(t.webAuthEndpoint)
        val arr = StellarToml.parse("ACCOUNTS = [\n  \"GA\",\n  [\"nested\"],\n]\nSIGNING_KEY = \"GOOD\"\n")
        assertEquals("GOOD", arr.signingKey)
    }

    @Test
    fun `needed keys must be plain double-quoted strings, once`() {
        for (bad in listOf(
            "SIGNING_KEY = GABC",
            "SIGNING_KEY = 'GABC'",
            "SIGNING_KEY = \"GA\\u0042\"",
            "SIGNING_KEY = \"GA\\\"BC\"",
            "SIGNING_KEY = \"\"\"GABC\"\"\"",
            "SIGNING_KEY = \"GABC\" extra",
            "SIGNING_KEY = \"GABC",
            "SIGNING_KEY = \"GA\tBC\"",
            "SIGNING_KEY = [\"GABC\"]",
            "SIGNING_KEY = \"A\"\nSIGNING_KEY = \"A\"",
            "NETWORK_PASSPHRASE = \"x\"\nNETWORK_PASSPHRASE = \"y\"",
            "WEB_AUTH_ENDPOINT = \"https://a\"\n  WEB_AUTH_ENDPOINT = \"https://a\"",
        )) {
            assertThrows(bad, StellarTomlException::class.java) { StellarToml.parse(bad) }
        }
    }

    @Test
    fun `size is bounded`() {
        StellarToml.parse("#".repeat(StellarToml.MAX_LENGTH))
        assertThrows(StellarTomlException::class.java) { StellarToml.parse("#".repeat(StellarToml.MAX_LENGTH + 1)) }
    }
}

package com.payala.impala.stellar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class MiniJsonTest {
    @Test
    fun `top-level string members are read and other values validated and skipped`() {
        val m = MiniJson.stringFields(
            """ { "transaction" : "AAAA+/=", "network_passphrase":"Test SDF Network ; September 2015",
                 "n": -1.5e3, "o": {"a": [1, true, null, {"b": "c"}]}, "e": "\"\\\/\b\f\n\r\t\u00e9" } """
        )
        assertEquals("AAAA+/=", m["transaction"])
        assertEquals("Test SDF Network ; September 2015", m["network_passphrase"])
        assertEquals("\"\\/\b\u000C\n\r\t\u00e9", m["e"])
        assertEquals(setOf("transaction", "network_passphrase", "e"), m.keys)
        assertEquals(emptyMap<String, String>(), MiniJson.stringFields("{}"))
    }

    @Test
    fun `malformed documents are refused`() {
        for (bad in listOf(
            "", "[]", "\"x\"", "{", "}", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "{\"a\":1}x", "{\"a\":\"b\",\"a\":\"c\"}",
            "{'a':'b'}", "{\"a\":\"\u0001\"}", "{\"a\":\"\\x\"}", "{\"a\":\"\\u12\"}", "{\"a\":01}", "{\"a\":tru}",
            "{\"a\":" + "[".repeat(100) + "]".repeat(100) + "}", "{\"a\":\"unterminated}",
        )) {
            assertThrows(bad, MiniJson.JsonException::class.java) { MiniJson.stringFields(bad) }
        }
    }

    @Test
    fun `quote escapes what JSON requires and round-trips`() {
        val s = "a\"b\\c\nd\u0001e/é"
        assertEquals("\"a\\\"b\\\\c\\u000ad\\u0001e/é\"", MiniJson.quote(s))
        assertEquals(s, MiniJson.stringFields("{\"k\":${MiniJson.quote(s)}}")["k"])
    }
}

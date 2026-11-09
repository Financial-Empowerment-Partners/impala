package com.payala.impala.demo.ui

import com.payala.impala.demo.ui.common.Identifiers
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [Identifiers.breakable]: break opportunities only at an identifier's own
 * separators (a UUID's hyphens, a URL's slashes and port colon), so a large
 * font scale never wraps one mid-token; [Identifiers.plain] undoes it.
 */
class IdentifiersTest {
    private val z = Identifiers.ZERO_WIDTH_SPACE

    @Test
    fun `a UUID may break after each hyphen and nowhere else`() {
        val uuid = "10000000-0000-4000-8000-000000000006"
        assertEquals("10000000-${z}0000-${z}4000-${z}8000-${z}000000000006", Identifiers.breakable(uuid))
        assertEquals(uuid, Identifiers.plain(Identifiers.breakable(uuid)))
    }

    @Test
    fun `a URL may break after its slashes and before its port`() {
        assertEquals("http://${z}10.0.2.2${z}:8080", Identifiers.breakable("http://10.0.2.2:8080"))
        assertEquals("https://${z}api.impala.example.com/${z}v1", Identifiers.breakable("https://api.impala.example.com/v1"))
        assertEquals("127.0.0.1${z}:9444", Identifiers.breakable("127.0.0.1:9444"))
        assertEquals("http://${z}10.0.2.2${z}:8080/${z}api", Identifiers.breakable("http://10.0.2.2:8080/api"))
    }

    @Test
    fun `hex ids and fingerprints are unchanged`() {
        for (v in listOf("65264cbf522d444d3d360e7741db0dc8", "e0:c8:fa:01:02:03:04:05:06:07", "01020304050607080102", "", "-", "a-")) {
            assertEquals(v, Identifiers.breakable(v))
        }
        assertEquals("e0:c8:fa", Identifiers.breakable("e0:c8:fa")) // a colon before a letter is not a port
    }
}

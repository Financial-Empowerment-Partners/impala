package com.impala.sdk

import com.impala.sdk.scp03.SCP03Constants
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Doc tripwire: pins `docs/apdu.md` to the SDK constants. Reads the file named
 * by the `impala.apdu.doc` system property (set in `sdk/build.gradle.kts`),
 * parses its command tables and asserts the INS sets and every row's name
 * resolve to the expected constants. Complements [ApduDocDriftTest], which also
 * cross-checks the applet source and jcardsim.
 */
class ApduDocTest {

    private companion object {
        // The application INS the applet dispatches at CLA 0x00 (applet 0.2).
        val DISPATCHED_APP_INS = setOf(
            0x02, 0x04, 0x16, 0x18, 0x19, 0x1E, 0x1F, 0x20, 0x21, 0x22,
            0x24, 0x25, 0x2C, 0x2E, 0x30, 0x31, 0x34, 0x35, 0x36, 0x64
        )
        val SCP03_INS = setOf(0x50, 0x82, 0x70, 0x71, 0x72, 0x73)
        val RETIRED_INS = setOf(0x06, 0x14)
        val UNDISPATCHED_INS = setOf(0x07, 0x23, 0x26, 0x2B, 0x2D)
        val REQUIRED_SW = listOf(
            "6233", "6234", "6235", "6236", "6237", "6238", "6239", "623A", "623B",
            "6A80", "6984", "6A83", "6E00", "0022", "6677", "6683", "6684", "6688", "6A86"
        )
    }

    private val docPath: String = System.getProperty("impala.apdu.doc")
        ?: fail("system property impala.apdu.doc is unset — set it in sdk/build.gradle.kts")
    private val lines = File(docPath).readLines()

    private val rowRe = Regex("""^\|\s*`0x([0-9A-Fa-f]{2})`\s*\|\s*([A-Z0-9_ ]+?)\s*\|""")
    private val headingRe = Regex("""^#{1,6}\s+(.*)$""")

    private data class Section(val rows: LinkedHashMap<Int, String> = LinkedHashMap(), val text: StringBuilder = StringBuilder())
    private val sections: Map<String, Section> = run {
        val out = LinkedHashMap<String, Section>()
        var current = ""
        for (line in lines) {
            headingRe.find(line)?.let { current = it.groupValues[1].trim(); out.getOrPut(current) { Section() }; return@let }
            val sec = out.getOrPut(current) { Section() }
            sec.text.append(line).append('\n')
            rowRe.find(line)?.let { sec.rows[it.groupValues[1].toInt(16)] = it.groupValues[2].trim() }
        }
        out
    }

    private fun section(startsWith: String): Section =
        sections.entries.firstOrNull { it.key.startsWith(startsWith) }?.value
            ?: fail("no section heading starting with '$startsWith' in apdu.md")

    private fun resolveInsByte(name: String): Int {
        val field = "INS_" + name.replace(' ', '_')
        for (cls in listOf(Constants::class.java, SCP03Constants::class.java)) {
            runCatching { cls.getField(field) }.getOrNull()?.let { return it.getByte(null).toInt() and 0xFF }
        }
        fail("row name '$name' does not resolve to an INS constant ($field)")
    }

    @Test
    fun `application table is exactly the dispatched application INS`() {
        assertEquals(DISPATCHED_APP_INS, section("Application commands").rows.keys)
    }

    @Test
    fun `SCP03 table is exactly the six secure-channel INS`() {
        assertEquals(SCP03_INS, section("SCP03 secure channel").rows.keys)
    }

    @Test
    fun `retired table is exactly the removed INS`() {
        assertEquals(RETIRED_INS, section("Retired").rows.keys)
    }

    @Test
    fun `declared-but-not-dispatched table is exactly the undispatched INS`() {
        assertEquals(UNDISPATCHED_INS, section("Declared but not dispatched").rows.keys)
    }

    @Test
    fun `every application and SCP03 row name resolves to its hex`() {
        for (sec in listOf("Application commands", "SCP03 secure channel")) {
            section(sec).rows.forEach { (hex, name) ->
                assertEquals(hex, resolveInsByte(name), "row 0x%02X names '$name'".format(hex))
            }
        }
    }

    @Test
    fun `common status words section documents every transfer-protocol code`() {
        val text = section("Common status words").text.toString().uppercase()
        for (sw in REQUIRED_SW) {
            assertTrue(text.contains("0X${sw.uppercase()}"), "apdu.md status-word table is missing 0x$sw")
        }
    }
}

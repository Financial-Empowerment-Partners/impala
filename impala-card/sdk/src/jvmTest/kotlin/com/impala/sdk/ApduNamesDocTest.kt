package com.impala.sdk

import com.impala.sdk.apdu4j.ApduNames
import com.impala.sdk.models.ImpalaException
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Pins [ApduNames] to `docs/apdu.md`: every documented INS has exactly the
 * documented name, every documented status word has a name (and an
 * [ImpalaException] arm), and the read-only allow-list is the pinned literal,
 * disjoint from the mutating set, and together they classify every dispatched
 * application INS.
 *
 * Documented exceptions: `6A82` and `6999` are answered by the card platform
 * (JCRE / jcardsim), not by the applet, so `apdu.md`'s status-word table does
 * not list them. They are pinned here instead, as [ApduNames.PLATFORM_STATUS_WORDS].
 */
class ApduNamesDocTest {
    private val docLines: List<String> = File(resolveRoot(), "docs/apdu.md").readLines()

    private fun resolveRoot(): File {
        System.getProperty("impala.card.root")?.let { return File(it) }
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        var hops = 0
        while (dir != null && hops < 4) {
            if (File(dir, "docs/apdu.md").isFile && File(dir, "settings.gradle.kts").isFile) return dir
            dir = dir.parentFile; hops++
        }
        fail("cannot locate impala-card root from ${System.getProperty("user.dir")}")
    }

    private val rowRe = Regex("""^\|\s*`0x([0-9A-Fa-f]{2})`\s*\|\s*([^|]+?)\s*\|""")
    private val rangeRe = Regex("""`?(0x[0-9A-Fa-f]{4})`?\s*[–-]\s*`?(0x[0-9A-Fa-f]{4})`?""")
    private val swRe = Regex("""0x[0-9A-Fa-f]{4}""")

    private fun table(heading: (String) -> Boolean): Map<Int, String> {
        var section = ""
        val out = LinkedHashMap<Int, String>()
        for (line in docLines) {
            if (line.startsWith("#")) { section = line.trim(); continue }
            if (heading(section)) rowRe.find(line)?.let { out[it.groupValues[1].toInt(16)] = it.groupValues[2].trim() }
        }
        return out
    }

    private val app = table { it == "## Application commands (CLA 0x00)" }
    private val undispatched = table { it == "### Declared but not dispatched" }
    private val retired = table { it.startsWith("### Retired") }
    private val scp03 = table { it == "## SCP03 secure channel" }

    private val documentedSws: Set<Int> = run {
        var section = ""
        val sw = HashSet<Int>()
        for (line in docLines) {
            if (line.startsWith("#")) { section = line.trim(); continue }
            if (section == "## Common status words" && line.startsWith("|")) {
                rangeRe.findAll(line).forEach { r -> (r.groupValues[1].drop(2).toInt(16)..r.groupValues[2].drop(2).toInt(16)).forEach { sw += it } }
                swRe.findAll(line).forEach { sw += it.value.drop(2).toInt(16) }
            }
        }
        sw
    }

    @Test
    fun `application command names equal apdu_md`() {
        assertEquals(25, app.size, "application table parse drift")
        app.forEach { (ins, name) -> assertEquals(name, ApduNames.ins(0x00, ins), "INS 0x%02X".format(ins)) }
    }

    @Test
    fun `undispatched and retired constants are named without the INS_ prefix`() {
        assertEquals(5, undispatched.size)
        assertEquals(2, retired.size)
        (undispatched + retired).forEach { (ins, constant) ->
            assertEquals(constant, "INS_" + ApduNames.ins(0x00, ins), "INS 0x%02X".format(ins))
        }
    }

    @Test
    fun `secure-channel command names equal apdu_md`() {
        assertEquals(setOf(0x50, 0x82, 0x70, 0x71, 0x72, 0x73), scp03.keys)
        scp03.forEach { (ins, name) ->
            assertEquals(name, ApduNames.ins(0x80, ins))
            assertEquals(name, ApduNames.ins(0x84, ins))
        }
        assertEquals("SELECT", ApduNames.ins(0x00, ApduNames.SELECT_INS))
        assertEquals("INS 0x99", ApduNames.ins(0x00, 0x99))
    }

    @Test
    fun `every documented status word is named and has an ImpalaException arm`() {
        assertTrue(documentedSws.size > 40, "status-word parse found only ${documentedSws.size}")
        assertEquals("OK", ApduNames.sw(0x9000))
        for (sw in documentedSws) {
            val hex = "%04X".format(sw)
            assertTrue(ApduNames.sw(sw) != "UNKNOWN", "0x$hex has no ApduNames.sw name")
            if (sw == 0x9000) continue
            val msg = ImpalaException.fromStatusWord(sw).message!!
            assertTrue(!msg.startsWith("Unknown status word"), "0x$hex has no ImpalaException arm: $msg")
            // PIN failures carry the tries count (ImpalaPinException.triesRemaining) instead of the hex.
            if (sw !in 0x69C0..0x69C9) assertTrue(msg.uppercase().contains(hex), "0x$hex message '$msg' must carry the status word")
        }
        assertEquals("WRONG_PIN_3", ApduNames.sw(0x69C3))
        assertEquals("PIN_BLOCKED", ApduNames.sw(0x69C0))
        assertEquals("UNKNOWN", ApduNames.sw(0xABCD))
    }

    @Test
    fun `platform status words are the documented exceptions, named but absent from apdu_md`() {
        assertEquals(setOf(0x6A82, 0x6999), ApduNames.PLATFORM_STATUS_WORDS)
        for (sw in ApduNames.PLATFORM_STATUS_WORDS) {
            assertTrue(sw !in documentedSws, "0x%04X is now in apdu.md; drop it from the exceptions".format(sw))
            assertTrue(ApduNames.sw(sw) != "UNKNOWN")
        }
    }

    @Test
    fun `READ_ONLY_INS is the pinned literal, disjoint from MUTATING_INS, and both cover the dispatched table`() {
        assertEquals(setOf(0x02, 0x04, 0x16, 0x1E, 0x20, 0x21, 0x24, 0x2E, 0x34, 0x35, 0x36, 0x37, 0x39, 0x64), ApduNames.READ_ONLY_INS)
        // SIGN_SEP10 (0x38) produces a signature; SET_SIGN_IN_POLICY (0x3A) and
        // CHANGE_USER_PIN (0x3B) change card state: a read-only session refuses them.
        assertEquals(setOf(0x18, 0x19, 0x1F, 0x22, 0x25, 0x2C, 0x30, 0x31, 0x38, 0x3A, 0x3B), ApduNames.MUTATING_INS)
        assertTrue(ApduNames.READ_ONLY_INS.intersect(ApduNames.MUTATING_INS).isEmpty())
        assertEquals(app.keys, ApduNames.READ_ONLY_INS + ApduNames.MUTATING_INS, "every dispatched INS must be classified")
        for (ins in ApduNames.READ_ONLY_INS) {
            assertTrue(ApduNames.isReadOnly(0x00, ins))
            assertTrue(!ApduNames.isReadOnly(0x84, ins), "secured CLA is never read-only")
        }
        for (ins in ApduNames.MUTATING_INS + scp03.keys) assertTrue(!ApduNames.isReadOnly(0x00, ins))
        assertTrue(ApduNames.isReadOnly(0x00, ApduNames.SELECT_INS))
    }
}

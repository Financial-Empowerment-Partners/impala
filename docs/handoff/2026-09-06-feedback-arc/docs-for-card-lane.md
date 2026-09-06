## 3. Drift guards

### 3.1 `ApduDocDriftTest.kt` (runs inside the existing `./gradlew :sdk:jvmTest`, CI job `test` of `impala-card.yml`, path filter `impala-card/**` already covers `impala-card/docs/apdu.md`)

Add to `impala-card/sdk/build.gradle.kts` inside the existing `jvm { testRuns["test"].executionTask.configure { … } }` block (lines 53-62): `systemProperty("impala.card.root", rootProject.projectDir.absolutePath)`.

File content:

```kotlin
package com.impala.sdk

import com.impala.applet.Constants as AppletConstants
import com.impala.applet.ImpalaApplet
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Docs-drift guard. Pins `docs/apdu.md` (the only APDU command table in the repository) to the
 * applet's dispatch switch, its declared constants, the SDK's constants and the status words the
 * applet actually throws. Two oracles: a regex parse of ImpalaApplet.java and a behavioural sweep
 * of every INS against jcardsim. No hardware, no network; < 1 s.
 */
class ApduDocDriftTest {
    private val root: File = resolveRoot()
    private val appletDir = File(root, "applet/src/jvmMain/java/com/impala/applet")
    private val appletSrc = File(appletDir, "ImpalaApplet.java").readText()
    private val docLines = File(root, "docs/apdu.md").readLines()

    private fun resolveRoot(): File {
        System.getProperty("impala.card.root")?.let { return File(it) }
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        var hops = 0
        while (dir != null && hops < 4) {
            if (File(dir, "docs/apdu.md").isFile && File(dir, "settings.gradle.kts").isFile) return dir
            dir = dir.parentFile; hops++
        }
        fail("cannot locate impala-card root (docs/apdu.md + settings.gradle.kts) from ${System.getProperty("user.dir")}")
    }

    // --- constants by reflection (values never re-parsed from source) ---
    private fun byteFields(c: Class<*>): Map<String, Int> = c.fields
        .filter { it.name.startsWith("INS_") && it.type == java.lang.Byte.TYPE }
        .associate { it.name to (it.getByte(null).toInt() and 0xFF) }
    private fun shortField(c: Class<*>, name: String): Int? = c.fields
        .firstOrNull { it.name == name && it.type == java.lang.Short.TYPE }?.getShort(null)?.toInt()?.and(0xFFFF)

    private val appletIns = byteFields(AppletConstants::class.java)
    private val sdkIns = byteFields(Constants::class.java)

    // --- dispatch parse (oracle 1) ---
    private val dispatchedNames = Regex("""case\s+(INS_[A-Z0-9_]+)\s*:""").findAll(appletSrc).map { it.groupValues[1] }.toSet()
    private val scp03Names = Regex("""ins\s*==\s*(INS_SCP03_[A-Z_]+)""").findAll(appletSrc).map { it.groupValues[1] }.toSet()
    private val cla80Literals = Regex("""case\s*\(byte\)\s*0x([0-9A-Fa-f]{2})\s*:""").findAll(appletSrc).map { it.groupValues[1].toInt(16) }.toSet()
    private val defaultBranches = Regex("""default:\s*\{?\s*ISOException\.throwIt\(ISO7816\.SW_INS_NOT_SUPPORTED\)""").findAll(appletSrc).count()
    private val dispatched: Set<Int> = dispatchedNames.map { appletIns[it] ?: fail("dispatch case $it has no constant") }.toSet()
    private val scp03Secured: Set<Int> = scp03Names.map { appletIns[it] ?: fail("$it has no constant") }.toSet()

    // --- doc parse ---
    private data class Doc(val app: Map<Int, String>, val undispatched: Map<Int, String>, val scp03: Map<Int, String>, val sw: Set<Int>, val claimCount: Map<String, Int>)
    private val rowRe = Regex("""^\|\s*`0x([0-9A-Fa-f]{2})`\s*\|\s*([^|]+?)\s*\|""")
    private val rangeRe = Regex("""`?(0x[0-9A-Fa-f]{4})`?\s*[–-]\s*`?(0x[0-9A-Fa-f]{4})`?""")
    private val swRe = Regex("""0x[0-9A-Fa-f]{4}""")
    private val countRe = Regex("""<!--\s*claim-count:\s*([^>]*?)\s*-->""")
    private val doc: Doc = run {
        var section = ""
        val app = LinkedHashMap<Int, String>(); val und = LinkedHashMap<Int, String>(); val scp = LinkedHashMap<Int, String>()
        val sw = HashSet<Int>(); val counts = HashMap<String, Int>()
        for (line in docLines) {
            countRe.find(line)?.groupValues?.get(1)?.split(Regex("\\s+"))?.forEach { kv ->
                val (k, v) = kv.split("="); counts[k] = v.toInt()
            }
            if (line.startsWith("#")) { section = line.trim(); continue }
            val m = rowRe.find(line)
            when (section) {
                "## Application commands (CLA 0x00)" -> m?.let { app[it.groupValues[1].toInt(16)] = it.groupValues[2].trim() }
                "### Declared but not dispatched" -> m?.let { und[it.groupValues[1].toInt(16)] = it.groupValues[2].trim() }
                "## SCP03 secure channel" -> m?.let { scp[it.groupValues[1].toInt(16)] = it.groupValues[2].trim() }
                "## Common status words" -> if (line.startsWith("|")) {
                    rangeRe.findAll(line).forEach { r -> (r.groupValues[1].drop(2).toInt(16)..r.groupValues[2].drop(2).toInt(16)).forEach { sw += it } }
                    swRe.findAll(line).forEach { sw += it.value.drop(2).toInt(16) }
                }
            }
        }
        Doc(app, und, scp, sw, counts)
    }

    // --- status words thrown (every *.java in the applet package) ---
    private val throwRe = Regex("""ISOException\.throwIt\(\s*([^;]+?)\s*\)\s*;""")
    private fun resolveThrown(arg: String, file: String): Set<Int> {
        Regex("""^ISO7816\.(SW_[A-Z0-9_]+)$""").find(arg)?.let { return setOf(shortField(javacard.framework.ISO7816::class.java, it.groupValues[1]) ?: fail("$file: unknown ISO7816.${it.groupValues[1]}")) }
        Regex("""^Constants\.(SW_[A-Z0-9_]+)$""").find(arg)?.let { return setOf(shortField(AppletConstants::class.java, it.groupValues[1]) ?: fail("$file: unknown Constants.${it.groupValues[1]}")) }
        Regex("""^\(short\)\s*0x([0-9A-Fa-f]{4})$""").find(arg)?.let { return setOf(it.groupValues[1].toInt(16)) }
        Regex("""^\(short\)\s*\(\s*(SW_[A-Z0-9_]+)\s*\+\s*\w+\s*\)$""").find(arg)?.let { m ->
            val base = shortField(ImpalaApplet::class.java, m.groupValues[1]) ?: shortField(AppletConstants::class.java, m.groupValues[1]) ?: fail("$file: unknown ${m.groupValues[1]}")
            return (base..base + 9).toSet() // PIN retry counters: at most 10 tries
        }
        Regex("""^(SW_[A-Z0-9_]+)$""").find(arg)?.let { m ->
            return setOf(shortField(ImpalaApplet::class.java, m.groupValues[1]) ?: shortField(AppletConstants::class.java, m.groupValues[1]) ?: fail("$file: unknown ${m.groupValues[1]}"))
        }
        fail("$file: unrecognised throwIt argument '$arg' — extend resolveThrown")
    }
    private val thrown: Set<Int> = appletDir.listFiles { f -> f.name.endsWith(".java") }!!.flatMap { f ->
        throwRe.findAll(f.readText()).flatMap { resolveThrown(it.groupValues[1].trim(), f.name).asSequence() }.toList()
    }.toSet()

    // --- behavioural sweep (oracle 2): dispatched <=> SW != 6D00 on a fresh simulator per CLA ---
    private fun probe(cla: Int): Set<Int> {
        val bibo = SimulatorBibo()
        val hit = HashSet<Int>()
        for (ins in 0..255) {
            if (ins == 0xA4 || ins == 0xC0) continue // SELECT / GET RESPONSE are consumed by the JCRE, never by process()
            val resp = bibo.transceive(byteArrayOf(cla.toByte(), ins.toByte(), 0, 0))
            val sw = ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)
            if (sw != 0x6D00) hit += ins
        }
        return hit
    }

    private fun hex(s: Set<Int>) = s.sorted().joinToString { "0x%02X".format(it) }

    @Test
    fun `apdu.md application table lists exactly the INS dispatched at CLA 00`() {
        assertTrue(dispatched.isNotEmpty(), "dispatch parse found nothing — regex drift")
        assertEquals(dispatched, doc.app.keys, "doc − code: ${hex(doc.app.keys - dispatched)}; code − doc: ${hex(dispatched - doc.app.keys)}")
        doc.app.forEach { (ins, name) -> assertEquals(ins, appletIns["INS_$name"], "row 0x%02X names $name but INS_$name is ${appletIns["INS_$name"]}".format(ins)) }
    }

    @Test
    fun `apdu.md declared-but-not-dispatched table is exactly the undispatched INS constants`() {
        val expected = appletIns.filterKeys { !it.startsWith("INS_SCP03_") }.filterValues { it !in dispatched }
        assertEquals(expected.values.toSet(), doc.undispatched.keys, "expected ${hex(expected.values.toSet())}, doc ${hex(doc.undispatched.keys)}")
        doc.undispatched.forEach { (ins, constant) -> assertEquals(ins, appletIns[constant], "row 0x%02X names $constant".format(ins)) }
    }

    @Test
    fun `apdu.md SCP03 table is exactly the four secure-channel INS and the dispatch pins them`() {
        assertEquals(setOf(0x50, 0x82), cla80Literals, "CLA 0x80 literal cases")
        assertEquals(setOf(0x70, 0x71), scp03Secured, "CLA 0x84 secured INS")
        assertEquals(setOf(0x50, 0x82, 0x70, 0x71), doc.scp03.keys, "doc SCP03 rows ${hex(doc.scp03.keys)}")
        assertTrue(defaultBranches >= 2, "both switch defaults must throw SW_INS_NOT_SUPPORTED (found $defaultBranches)")
    }

    @Test
    fun `every status word the applet throws is in the apdu.md status-word table`() {
        assertTrue(thrown.size > 20, "thrown-SW parse found only ${thrown.size} values — regex drift")
        val missing = thrown - doc.sw
        assertTrue(missing.isEmpty(), "thrown but undocumented: " + missing.sorted().joinToString { "0x%04X".format(it) })
    }

    @Test
    fun `SDK Constants kt and applet Constants java agree on every application INS`() {
        assertEquals(appletIns.filterKeys { !it.startsWith("INS_SCP03_") }, sdkIns)
    }

    @Test
    fun `the simulated applet answers 6D00 for exactly the INS the doc says are not dispatched`() {
        assertEquals(doc.app.keys, probe(0x00), "CLA 00 sweep")
        assertEquals(setOf(0x50, 0x82), probe(0x80), "CLA 80 sweep")
    }

    @Test
    fun `apdu.md claim-count marker matches the tables and the dispatch switch`() {
        assertEquals(mapOf("apdu-app-ins" to doc.app.size, "apdu-scp03-ins" to doc.scp03.size, "apdu-undispatched" to doc.undispatched.size), doc.claimCount)
        assertEquals(dispatched.size, doc.claimCount["apdu-app-ins"])
    }
}
```

Expected values on the current tree after §4 lands: app = 17, undispatched = 5, scp03 = 4, thrown = 35 distinct values with 0 missing. Without §4 test 4 fails listing `0x6227 0x6230 0x6233 0x6984 0x6A80` — land them together.

## 4. `impala-card/docs/apdu.md` deltas (docs-only; describe existing behaviour)
1. After the intro paragraph (line 11) insert: `<!-- claim-count: apdu-app-ins=17 apdu-scp03-ins=4 apdu-undispatched=5 -->`.
2. `VERIFY_TRANSFER` row, Data column: append " — P1=0x01: counter must be > 0 and strictly greater than the last accepted receive counter (gaps allowed), else `0x6233`; the credit and the stored counter update are one JavaCard transaction; `pubKeySig` is **not** verified".
3. New note under the Notes list: "**Sender-key trust.** `VERIFY_TRANSFER` verifies the transfer signature against the public key carried in the tail; the `pubKeySig` slot is never read and no issuer key is stored on the card, so any secp256r1 key is accepted (`impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/AppletInteropTest.kt::verifyTransfer credits and signTransfer debits with a JCA-verifiable signature` funds a card from an ad-hoc host key with an all-zero `pubKeySig`). `SW_ERROR_KEY_VERIFICATION_FAILED` (`0x0022`) is declared and never thrown. See `../../docs/known-limitations.md` KL-C2."
4. New subsection `### Transfer counter` after the Notes: "One strictly increasing counter stream per **receiving** card, allocated off-card by the transfer coordinator; the sender persists no counter. Gaps are accepted, repeats and lower values are rejected (`0x6233`), zero is never accepted, the maximum is `0x7FFFFFFF`, and there is no command to read the current value (KL-C3)."
5. Status-word table: add rows `| \`0x6227\` | Signer initialization failed (SIGN_TRANSFER / SIGN_AUTH: the ECDSA engine refused the card key) |`, `| \`0x6230\` | Card EC key missing (SIGN_TRANSFER / SIGN_AUTH before INITIALIZE) |`, `| \`0x6233\` | Transfer counter invalid (VERIFY_TRANSFER phase 2: zero, negative, or not strictly greater than the last accepted receive counter) |`, `| \`0x6984\` | Data invalid (SIGN_TRANSFER: negative counter; VERIFY_TRANSFER: malformed DER signature, or a credit that would overflow the 8-byte balance) |`, `| \`0x6A80\` | Wrong data (install parameters: unknown flag bits, wrong TLV shape or a bad key/PIN block — the install fails) |`; change the `0x6688 / 0x6689` row meaning to "Internal null-pointer / bounds error; `0x6688` is also the SCP03 C-MAC verification failure on a secured (CLA 0x84) command".
6. "Writing new APDUs" step 5 → "Add a row to this document and bump the `claim-count` marker — `ApduDocDriftTest` (`sdk/src/jvmTest`) fails until this table, `Constants.java`, `Constants.kt` and the dispatch switch agree, and `scripts/check-doc-claims.py` checks the marker."
Do not add any command the dispatch switch lacks; the INS tables are unchanged.


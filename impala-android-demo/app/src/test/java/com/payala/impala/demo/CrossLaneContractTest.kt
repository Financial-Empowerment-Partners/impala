package com.payala.impala.demo

import android.content.Context
import android.view.View
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.tabs.TabLayout
import com.payala.impala.demo.lab.CannedBridge
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.lab.LabViewModel
import com.payala.impala.demo.ui.nfc.NfcDebugActivity
import com.payala.impala.demo.ui.tap.TapPrompt
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import java.io.File

/**
 * Contracts that cross lane boundaries, where each side compiles and passes
 * its own tests while the seam between them drifts:
 *
 * - the string files never name a transport class or an instruction constant
 *   (user copy says "ISO 14443-4" and "card", never `IsoDep`);
 * - every [TapPrompt] subtype has a title the tap sheet renders from a string;
 * - the Card Lab reads [LabIntents.EXTRA_TAB] and [LabIntents.EXTRA_CARD_ID] and
 *   maps [LabIntents.TABS] onto its TabLayout in the order Inspector, Doctor,
 *   Trace, Device (Cards, Login and the Main overflow open it by tab name);
 * - no string name is defined twice across the four `values/strings*.xml`
 *   files, each owned by a different lane.
 */
@RunWith(RobolectricTestRunner::class)
class CrossLaneContractTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private var controller: ActivityController<NfcDebugActivity>? = null

    @After
    fun tearDown() {
        controller?.pause()?.stop()?.destroy()
        controller = null
        LabViewModel.probeClient = null
    }

    private fun source(path: String): File =
        File(path).also { assertTrue("run from the app module directory: $path", it.isFile) }

    // ---- string files ----

    private val forbiddenCopy = listOf(
        Regex("""\bIsoDep\b"""), Regex("""\bCommandAPDU\b"""), Regex("""\btransceive\("""), Regex("""\bINS_[A-Z_0-9]+""")
    )

    /** Every strings*.xml of every source set (main, debug, release, the flavours). */
    private fun stringFiles(): List<File> {
        val src = File("src")
        assertTrue("run from the app module directory", src.isDirectory)
        return src.walkTopDown()
            .filter { it.isFile && it.name.startsWith("strings") && it.extension == "xml" && it.parentFile?.name?.startsWith("values") == true }
            .toList()
    }

    @Test
    fun `no string file names a transport class or an instruction constant`() {
        val files = stringFiles()
        assertTrue(
            "the lane string files are found",
            files.map { it.name }.containsAll(listOf("strings_foundation.xml", "strings_flows.xml", "strings_lab.xml"))
        )
        val offenders = files.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line ->
                if (forbiddenCopy.any { it.containsMatchIn(line) }) "${f.path}:${i + 1}: ${line.trim()}" else null
            }
        }
        assertTrue("forbidden copy in string resources (write \"ISO 14443-4\", \"card\"):\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }

    private val nameAttr = Regex("""<(string|plurals|string-array)\s+name="([^"]+)"""")

    @Test
    fun `no string name is defined twice across the lane string files`() {
        val dir = File("src/main/res/values")
        val owners = listOf("strings.xml", "strings_foundation.xml", "strings_flows.xml", "strings_lab.xml")
        val seen = LinkedHashMap<String, MutableList<String>>()
        for (name in owners) {
            val f = File(dir, name)
            assertTrue("missing ${f.path}", f.isFile)
            nameAttr.findAll(f.readText()).forEach { m -> seen.getOrPut(m.groupValues[2]) { ArrayList() } += name }
        }
        assertTrue("the four files define strings", seen.size > 100)
        val duplicates = seen.filterValues { it.size > 1 }
        assertTrue("string names defined more than once: $duplicates", duplicates.isEmpty())
    }

    // ---- tap prompts ----

    @Test
    fun `every TapPrompt subtype has a title string the sheet renders`() {
        // Runtime truth: the sealed hierarchy's nested subtypes (no kotlin-reflect needed).
        val subtypes = TapPrompt::class.java.declaredClasses
            .filter { TapPrompt::class.java.isAssignableFrom(it) && it != TapPrompt::class.java }
            .map { it.simpleName }
            .sorted()
        assertEquals(listOf("Apply", "Read", "Register", "Sign", "SignIn"), subtypes)

        val sheet = source("src/main/java/com/payala/impala/demo/ui/tap/CardTapSheet.kt").readText()
        val titleFn = Regex("""private fun title\(p: TapPrompt\): String = when \(p\) \{(.*?)\n    }""", RegexOption.DOT_MATCHES_ALL)
            .find(sheet)?.groupValues?.get(1) ?: error("CardTapSheet.title(TapPrompt) not found")
        val declared = nameAttr.findAll(File("src/main/res/values/strings_flows.xml").readText()).map { it.groupValues[2] }.toSet()

        for (name in subtypes) {
            val branch = titleFn.lines().firstOrNull { Regex("""^\s*(is\s+)?TapPrompt\.$name\s*->""").containsMatchIn(it) }
                ?: error("CardTapSheet.title has no branch for TapPrompt.$name")
            val titles = Regex("""R\.string\.(tap_title_[a-z_]+)""").findAll(branch).map { it.groupValues[1] }.toList()
            assertTrue("TapPrompt.$name has no tap_title_* string: $branch", titles.isNotEmpty())
            for (t in titles) {
                assertTrue("$t is not defined in strings_flows.xml", t in declared)
                val id = R.string::class.java.getField(t).getInt(null)
                assertTrue("$t resolves to empty text", ctx.getString(id, "abcd").isNotBlank())
            }
        }
    }

    // ---- the Card Lab's tabs ----

    @Test
    fun `the Lab reads both LabIntents extras and indexes TABS`() {
        val lab = source("src/main/java/com/payala/impala/demo/ui/nfc/NfcDebugActivity.kt").readText()
        assertTrue(lab.contains("getStringExtra(LabIntents.EXTRA_TAB)"))
        assertTrue(lab.contains("getStringExtra(LabIntents.EXTRA_CARD_ID)"))
        assertTrue(lab.contains("LabIntents.TABS.indexOf("))
        assertEquals(
            listOf(LabIntents.TAB_INSPECTOR, LabIntents.TAB_DOCTOR, LabIntents.TAB_TRACE, LabIntents.TAB_DEVICE),
            LabIntents.TABS
        )
        assertEquals(listOf("inspector", "doctor", "trace", "device"), LabIntents.TABS)
    }

    @Test
    fun `the Lab's TabLayout lists the tabs in LabIntents order`() {
        val layout = source("src/main/res/layout/activity_nfc_debug.xml").readText()
        val tabTexts = Regex("""<com\.google\.android\.material\.tabs\.TabItem[^>]*?android:text="@string/([a-z_]+)"""", RegexOption.DOT_MATCHES_ALL)
            .findAll(layout).map { it.groupValues[1] }.toList()
        assertEquals(LabIntents.TABS.map { "lab_tab_$it" }, tabTexts)
    }

    @Test
    fun `each LabIntents tab opens its own pane`() {
        LabViewModel.probeClient = CannedBridge.healthy(network = BuildConfig.STELLAR_NETWORK).client
        val panes = listOf(R.id.paneInspector, R.id.paneDoctor, R.id.rvTrace, R.id.paneDevice)
        val labels = listOf(R.string.lab_tab_inspector, R.string.lab_tab_doctor, R.string.lab_tab_trace, R.string.lab_tab_device)
        LabIntents.TABS.forEachIndexed { index, tab ->
            val c = Robolectric.buildActivity(NfcDebugActivity::class.java, LabIntents.open(ctx, tab, "00112233445566778899aabbccddeeff")).setup()
            controller = c
            val lab = c.get()
            val tabs = lab.findViewById<TabLayout>(R.id.tabs)
            assertEquals("tab '$tab'", index, tabs.selectedTabPosition)
            assertEquals("tab '$tab' label", ctx.getString(labels[index]), tabs.getTabAt(index)?.text?.toString())
            panes.forEachIndexed { p, id ->
                assertEquals("tab '$tab', pane $p", if (p == index) View.VISIBLE else View.GONE, lab.findViewById<View>(id).visibility)
            }
            assertEquals("00112233445566778899aabbccddeeff", lab.viewModel.expectedCardId)
            c.pause().stop().destroy()
            controller = null
        }
    }
}

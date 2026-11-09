package com.payala.impala.demo.theme

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Source-level pins on how the theme is wired (no Android needed):
 * - the three theme names the manifest uses exist in BOTH values/ and
 *   values-night/themes.xml, with identical items (a night style replaces the
 *   day style wholesale, so drift silently changes dark mode);
 * - the generated role themes set the same items in day and night, and every
 *   custom attribute in attrs_impala.xml is set there (an unset ?attr in a
 *   drawable or layout resolves to nothing at runtime);
 * - layouts consume colour only through theme attributes: no raw hex and no
 *   direct reference to the generated @color/m3_* (or legacy md_theme_*)
 *   values, so dark mode and the generated palette always apply.
 */
class ThemeWiringTest {
    private val res = File("src/main/res")

    private fun styles(file: File): Map<String, Map<String, String>> {
        assertTrue("missing $file", file.isFile)
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val out = LinkedHashMap<String, Map<String, String>>()
        val nodes = doc.getElementsByTagName("style")
        for (i in 0 until nodes.length) {
            val style = nodes.item(i) as Element
            val items = LinkedHashMap<String, String>()
            val children = style.getElementsByTagName("item")
            for (j in 0 until children.length) {
                val item = children.item(j) as Element
                items[item.getAttribute("name")] = item.textContent.trim()
            }
            val parent = if (style.hasAttribute("parent")) style.getAttribute("parent") else null
            out[style.getAttribute("name")] = items + ("@parent" to (parent ?: "<implicit>"))
        }
        return out
    }

    @Test
    fun `manifest theme names exist in day and night with identical items`() {
        val day = styles(File(res, "values/themes.xml"))
        val night = styles(File(res, "values-night/themes.xml"))
        for (name in listOf("Theme.ImpalaDemo", "Theme.ImpalaDemo.NoActionBar", "Theme.ImpalaDemo.Translucent")) {
            assertTrue("$name missing from values/themes.xml", name in day)
            assertTrue("$name missing from values-night/themes.xml", name in night)
        }
        assertEquals("values/ and values-night/themes.xml must define the same styles and items", day, night)
        assertEquals("Base.Theme.ImpalaDemo.Roles", day.getValue("Theme.ImpalaDemo")["@parent"])
    }

    @Test
    fun `generated role themes set the same items in day and night and every custom attribute`() {
        val day = styles(File(res, "values/themes_roles.xml")).getValue("Base.Theme.ImpalaDemo.Roles")
        val night = styles(File(res, "values-night/themes_roles.xml")).getValue("Base.Theme.ImpalaDemo.Roles")
        assertEquals(day.keys, night.keys)
        day.forEach { (attr, value) ->
            if (attr != "@parent") assertTrue("$attr -> $value must use a light colour", value.startsWith("@color/m3_light_"))
        }
        night.forEach { (attr, value) ->
            if (attr != "@parent") assertTrue("$attr -> $value must use a dark colour", value.startsWith("@color/m3_dark_"))
        }
        val declared = Regex("""<attr name="([A-Za-z]+)"""")
            .findAll(File(res, "values/attrs_impala.xml").readText()).map { it.groupValues[1] }.toList()
        assertTrue("attrs_impala.xml declares no attributes?", declared.isNotEmpty())
        for (attr in declared) assertTrue("custom attribute $attr is never set by the role theme", attr in day.keys)
    }

    @Test
    fun `layouts use theme attributes, never raw hex or generated colour names`() {
        val rawHex = Regex("""="#[0-9A-Fa-f]{3,8}"""")
        val generated = Regex("""@color/(m3_|md_theme_)""")
        val layouts = File(res, "layout").listFiles { f -> f.extension == "xml" }.orEmpty()
        assertTrue("no layouts found", layouts.isNotEmpty())
        val offenders = layouts.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line ->
                if (rawHex.containsMatchIn(line) || generated.containsMatchIn(line)) "${f.name}:${i + 1}: ${line.trim()}" else null
            }
        }
        assertTrue("layouts must use ?attr/ colours:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }

    @Test
    fun `the launcher icon has adaptive, monochrome and legacy forms`() {
        for (name in listOf("ic_launcher", "ic_launcher_round")) {
            val adaptive = File(res, "mipmap-anydpi-v26/$name.xml").readText()
            assertTrue("$name: adaptive foreground", "@drawable/ic_launcher_foreground" in adaptive)
            assertTrue("$name: themed-icon monochrome layer", "<monochrome" in adaptive)
            assertTrue("$name: legacy (API 24-25) fallback", File(res, "mipmap-anydpi/$name.xml").isFile)
        }
    }
}

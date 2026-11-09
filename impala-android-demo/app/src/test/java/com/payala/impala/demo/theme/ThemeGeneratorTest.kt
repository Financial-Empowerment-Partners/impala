package com.payala.impala.demo.theme

import android.annotation.SuppressLint
import com.google.android.material.color.utilities.Blend
import com.google.android.material.color.utilities.DynamicColor
import com.google.android.material.color.utilities.DynamicScheme
import com.google.android.material.color.utilities.Hct
import com.google.android.material.color.utilities.MaterialDynamicColors
import com.google.android.material.color.utilities.SchemeTonalSpot
import com.google.android.material.color.utilities.TonalPalette
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Locale
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

/**
 * The demo's colour system is a derived artefact: every Material 3 role and
 * every custom family (status, brand header, card face) comes from ONE seed
 * through MDC 1.14.0's material-color-utilities port, so no hex is ever
 * hand-picked. This test renders the three generated resource files and
 * asserts they are byte-equal to the committed ones, then pins the contrast
 * of every pair the UI draws text or the FAB on.
 *
 * Regenerate (after changing [SEED], a tone or a family):
 * `IMPALA_THEME_WRITE=1 ./gradlew :app:testTnetDebugUnitTest --tests '*ThemeGeneratorTest*' --rerun`
 * (app/build.gradle.kts forwards the variable to the test JVM).
 *
 * The utilities are `@RestrictTo(LIBRARY_GROUP)` (a lint annotation only) and
 * pure Java; they run on the host JVM without Robolectric. If MDC ever moves
 * them this test fails loudly at compile time.
 */
@SuppressLint("RestrictedApi")
class ThemeGeneratorTest {

    companion object {
        /** Brand seed: deep teal, SchemeTonalSpot, standard contrast. */
        const val SEED: Int = 0xFF00696B.toInt()
        const val SEED_HEX = "#00696B"
        const val SCHEME = "SchemeTonalSpot"
        const val CONTRAST_LEVEL = 0.0

        /** MaterialDynamicColors method -> theme attribute (null: colour only, no theme item). */
        val ROLES: List<Pair<String, String?>> = listOf(
            "primary" to "colorPrimary", "onPrimary" to "colorOnPrimary",
            "primaryContainer" to "colorPrimaryContainer", "onPrimaryContainer" to "colorOnPrimaryContainer",
            "primaryFixed" to "colorPrimaryFixed", "primaryFixedDim" to "colorPrimaryFixedDim",
            "onPrimaryFixed" to "colorOnPrimaryFixed", "onPrimaryFixedVariant" to "colorOnPrimaryFixedVariant",
            "secondary" to "colorSecondary", "onSecondary" to "colorOnSecondary",
            "secondaryContainer" to "colorSecondaryContainer", "onSecondaryContainer" to "colorOnSecondaryContainer",
            "secondaryFixed" to "colorSecondaryFixed", "secondaryFixedDim" to "colorSecondaryFixedDim",
            "onSecondaryFixed" to "colorOnSecondaryFixed", "onSecondaryFixedVariant" to "colorOnSecondaryFixedVariant",
            "tertiary" to "colorTertiary", "onTertiary" to "colorOnTertiary",
            "tertiaryContainer" to "colorTertiaryContainer", "onTertiaryContainer" to "colorOnTertiaryContainer",
            "tertiaryFixed" to "colorTertiaryFixed", "tertiaryFixedDim" to "colorTertiaryFixedDim",
            "onTertiaryFixed" to "colorOnTertiaryFixed", "onTertiaryFixedVariant" to "colorOnTertiaryFixedVariant",
            "error" to "colorError", "onError" to "colorOnError",
            "errorContainer" to "colorErrorContainer", "onErrorContainer" to "colorOnErrorContainer",
            "background" to "android:colorBackground", "onBackground" to "colorOnBackground",
            "surface" to "colorSurface", "onSurface" to "colorOnSurface",
            "surfaceVariant" to "colorSurfaceVariant", "onSurfaceVariant" to "colorOnSurfaceVariant",
            "surfaceDim" to "colorSurfaceDim", "surfaceBright" to "colorSurfaceBright",
            "surfaceContainerLowest" to "colorSurfaceContainerLowest",
            "surfaceContainerLow" to "colorSurfaceContainerLow",
            "surfaceContainer" to "colorSurfaceContainer",
            "surfaceContainerHigh" to "colorSurfaceContainerHigh",
            "surfaceContainerHighest" to "colorSurfaceContainerHighest",
            "inverseSurface" to "colorSurfaceInverse", "inverseOnSurface" to "colorOnSurfaceInverse",
            "inversePrimary" to "colorPrimaryInverse",
            "outline" to "colorOutline", "outlineVariant" to "colorOutlineVariant",
            // MDC 1.14.0 has no scrim theme attribute (scrimBackground is a different, translucent thing).
            "scrim" to null
        )

        /** Status families: design hue in HCT degrees, harmonized toward the seed. */
        val STATUS: List<Pair<String, Double>> = listOf("Success" to 145.0, "Warning" to 70.0, "Info" to 250.0)
        const val STATUS_CHROMA = 48.0
        /** M3 custom-colour tones: colour, on-colour, container, on-container. */
        val STATUS_TONES_LIGHT = listOf(40, 100, 90, 10)
        val STATUS_TONES_DARK = listOf(80, 20, 30, 90)

        /** Brand header: primary-palette tones (start, end), white text in both modes. */
        val HEADER_TONES_LIGHT = 40 to 30
        val HEADER_TONES_DARK = 30 to 20
        const val ON_HEADER_TONE = 100

        /** Card face end stop: primaryContainer blended this far toward primary (CAM16-UCS); stays in the container band. */
        const val CARD_FACE_BLEND = 0.12

        const val COLORS_FILE = "src/main/res/values/colors_m3.xml"
        const val ROLES_DAY_FILE = "src/main/res/values/themes_roles.xml"
        const val ROLES_NIGHT_FILE = "src/main/res/values-night/themes_roles.xml"
        const val ATTRS_FILE = "src/main/res/values/attrs_impala.xml"
        const val ROLES_STYLE = "Base.Theme.ImpalaDemo.Roles"
        const val ROLES_PARENT = "Theme.Material3.DayNight"

        // WCAG 2.x thresholds.
        const val TEXT_MIN = 4.5
        const val NON_TEXT_MIN = 3.0

        /** WCAG relative luminance of an sRGB colour. */
        fun luminance(argb: Int): Double {
            fun channel(v: Int): Double {
                val s = v / 255.0
                return if (s <= 0.04045) s / 12.92 else ((s + 0.055) / 1.055).pow(2.4)
            }
            return 0.2126 * channel((argb shr 16) and 0xFF) +
                0.7152 * channel((argb shr 8) and 0xFF) +
                0.0722 * channel(argb and 0xFF)
        }

        /** WCAG contrast ratio of two opaque colours (1.0..21.0). */
        fun contrast(a: Int, b: Int): Double {
            val la = luminance(a)
            val lb = luminance(b)
            return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
        }

        fun hex(argb: Int): String = String.format(Locale.ROOT, "#%06X", argb and 0xFFFFFF)
    }

    /** One mode's generated colours, in emission order: colour-name suffix -> ARGB, plus the theme items. */
    private class ModeOutput(val mode: String) {
        val colors = LinkedHashMap<String, Int>()
        val items = ArrayList<Pair<String, String>>() // attr -> colour suffix
        fun put(suffix: String, argb: Int, attr: String?) {
            colors[suffix] = argb or 0xFF000000.toInt()
            if (attr != null) items += attr to suffix
        }
        fun color(suffix: String): Int = colors[suffix] ?: error("no generated colour $suffix")
        fun colorName(suffix: String) = "m3_${mode}_$suffix"
    }

    private fun generate(dark: Boolean): ModeOutput {
        val out = ModeOutput(if (dark) "dark" else "light")
        val scheme: DynamicScheme = SchemeTonalSpot(Hct.fromInt(SEED), dark, CONTRAST_LEVEL)
        val mdc = MaterialDynamicColors()
        for ((method, attr) in ROLES) {
            val dc = MaterialDynamicColors::class.java.getMethod(method).invoke(mdc) as DynamicColor
            out.put(method, dc.getArgb(scheme), attr)
        }

        val (c, on, cont, onCont) = if (dark) STATUS_TONES_DARK else STATUS_TONES_LIGHT
        for ((name, hue) in STATUS) {
            val design = Hct.from(hue, STATUS_CHROMA, 50.0).toInt()
            val harmonized = Hct.fromInt(Blend.harmonize(design, SEED))
            val palette = TonalPalette.fromHueAndChroma(harmonized.hue, STATUS_CHROMA)
            val key = name.lowercase(Locale.ROOT)
            out.put("status_$key", palette.tone(c), "colorStatus$name")
            out.put("on_status_$key", palette.tone(on), "colorOnStatus$name")
            out.put("status_${key}_container", palette.tone(cont), "colorStatus${name}Container")
            out.put("on_status_${key}_container", palette.tone(onCont), "colorOnStatus${name}Container")
        }

        val (hs, he) = if (dark) HEADER_TONES_DARK else HEADER_TONES_LIGHT
        out.put("brand_header_start", scheme.primaryPalette.tone(hs), "colorBrandHeaderStart")
        out.put("brand_header_end", scheme.primaryPalette.tone(he), "colorBrandHeaderEnd")
        out.put("on_brand_header", scheme.primaryPalette.tone(ON_HEADER_TONE), "colorOnBrandHeader")

        val container = out.color("primaryContainer")
        out.put("card_face_start", container, "colorCardFaceStart")
        out.put("card_face_end", Blend.cam16Ucs(container, out.color("primary"), CARD_FACE_BLEND), "colorCardFaceEnd")
        out.put("on_card_face", out.color("onPrimaryContainer"), "colorOnCardFace")
        return out
    }

    private val light = generate(dark = false)
    private val dark = generate(dark = true)

    private val provenance =
        "seed $SEED_HEX, $SCHEME, contrast $CONTRAST_LEVEL; status hues " +
            STATUS.joinToString(",") { it.second.toInt().toString() } +
            " chroma ${STATUS_CHROMA.toInt()}; material-color-utilities from MDC 1.14.0"

    private val generatedNotice =
        "    GENERATED by app/src/test/java/com/payala/impala/demo/theme/ThemeGeneratorTest.kt\n" +
            "    ($provenance).\n" +
            "    Do not edit by hand: change the generator and run it with IMPALA_THEME_WRITE=1."

    private fun renderColors(): String {
        val sb = StringBuilder()
        sb.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!--\n").append(generatedNotice).append("\n-->\n<resources>\n")
        for (m in listOf(light, dark)) {
            sb.append("    <!-- ${m.mode} -->\n")
            for ((suffix, argb) in m.colors) {
                sb.append("    <color name=\"${m.colorName(suffix)}\">${hex(argb)}</color>\n")
            }
        }
        sb.append("    <!-- Launcher icon background (a literal: adaptive-icon layers cannot use theme attributes). -->\n")
        sb.append("    <color name=\"launcher_background\">${hex(light.color("brand_header_end"))}</color>\n")
        sb.append("</resources>\n")
        return sb.toString()
    }

    private fun renderRoles(m: ModeOutput): String {
        val sb = StringBuilder()
        sb.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!--\n").append(generatedNotice).append("\n")
        sb.append("    values/ and values-night/ carry the same item list by construction: a night\n")
        sb.append("    style replaces the day style wholesale, so an omitted item would fall back\n")
        sb.append("    to the Material 3 baseline colour.\n-->\n<resources>\n")
        sb.append("    <style name=\"$ROLES_STYLE\" parent=\"$ROLES_PARENT\">\n")
        for ((attr, suffix) in m.items) {
            sb.append("        <item name=\"$attr\">@color/${m.colorName(suffix)}</item>\n")
        }
        sb.append("    </style>\n</resources>\n")
        return sb.toString()
    }

    private fun checkOrWrite(path: String, expected: String) {
        val file = File(path)
        assertTrue("run from the app module directory ($path)", file.parentFile?.isDirectory == true)
        if (System.getenv("IMPALA_THEME_WRITE") == "1") file.writeText(expected)
        assertTrue("$path is missing; run ThemeGeneratorTest with IMPALA_THEME_WRITE=1", file.isFile)
        assertEquals(
            "$path differs from the generator output; run ThemeGeneratorTest with IMPALA_THEME_WRITE=1",
            expected, file.readText()
        )
    }

    @Test
    fun `committed colours and role themes equal the generator output`() {
        checkOrWrite(COLORS_FILE, renderColors())
        checkOrWrite(ROLES_DAY_FILE, renderRoles(light))
        checkOrWrite(ROLES_NIGHT_FILE, renderRoles(dark))
    }

    @Test
    fun `day and night set the same items and every custom attribute is declared`() {
        assertEquals(light.items.map { it.first }, dark.items.map { it.first })
        val declared = Regex("""<attr name="([A-Za-z]+)"""").findAll(File(ATTRS_FILE).readText()).map { it.groupValues[1] }.toSet()
        val m3Attrs = ROLES.mapNotNull { it.second }.toSet()
        val custom = light.items.map { it.first }.filter { it !in m3Attrs }.toSet()
        assertEquals("attrs_impala.xml declares exactly the generated custom attributes", custom, declared)
    }

    @Test
    fun `seed is the light primary`() {
        // TonalSpot reproduces a T40, chroma-34 seed exactly: no brand drift.
        assertEquals(SEED_HEX, hex(light.color("primary")))
    }

    private fun assertContrast(m: ModeOutput, fg: String, bg: String, min: Double) {
        val r = contrast(m.color(fg), m.color(bg))
        assertTrue(
            String.format(Locale.ROOT, "%s: %s %s on %s %s is %.2f:1, needs %.1f:1",
                m.mode, fg, hex(m.color(fg)), bg, hex(m.color(bg)), r, min),
            r >= min
        )
    }

    @Test
    fun `text and FAB contrast holds in both modes`() {
        for (m in listOf(light, dark)) {
            // Login header: white wordmark and status-bar icons over both gradient stops.
            assertContrast(m, "on_brand_header", "brand_header_start", TEXT_MIN)
            assertContrast(m, "on_brand_header", "brand_header_end", TEXT_MIN)
            // Card face: identifiers and chips over both face stops.
            assertContrast(m, "on_card_face", "card_face_start", TEXT_MIN)
            assertContrast(m, "on_card_face", "card_face_end", TEXT_MIN)
            // Status chips and banners.
            for ((name, _) in STATUS) {
                val key = name.lowercase(Locale.ROOT)
                assertContrast(m, "on_status_${key}_container", "status_${key}_container", TEXT_MIN)
                assertContrast(m, "on_status_$key", "status_$key", TEXT_MIN)
                assertContrast(m, "status_$key", "surface", TEXT_MIN)
            }
            // Pending (tertiary) and danger (error) chips.
            assertContrast(m, "onTertiaryContainer", "tertiaryContainer", TEXT_MIN)
            assertContrast(m, "onErrorContainer", "errorContainer", TEXT_MIN)
            // FAB (Widget.ImpalaDemo.Fab): the container against the bottom bar, and its icon.
            assertContrast(m, "primary", "surfaceContainer", NON_TEXT_MIN)
            assertContrast(m, "onPrimary", "primary", TEXT_MIN)
            // Body text and quiet text buttons (the login "Card Lab" link).
            assertContrast(m, "onSurface", "surface", TEXT_MIN)
            assertContrast(m, "onSurfaceVariant", "surface", TEXT_MIN)
            assertContrast(m, "onSurfaceVariant", "surfaceContainerLow", TEXT_MIN)
        }
    }

    @Test
    fun `brand header and card face stay in their tone bands`() {
        for (m in listOf(light, dark)) {
            val faceStart = Hct.fromInt(m.color("card_face_start")).tone
            val faceEnd = Hct.fromInt(m.color("card_face_end")).tone
            val primary = Hct.fromInt(m.color("primary")).tone
            val container = Hct.fromInt(m.color("primaryContainer")).tone
            // The end stop moves toward primary but by at most CARD_FACE_BLEND of the gap (plus rounding).
            val gap = kotlin.math.abs(primary - container)
            assertTrue("${m.mode} card face end tone $faceEnd leaves the container band",
                kotlin.math.abs(faceEnd - faceStart) <= gap * CARD_FACE_BLEND + 1.0)
            // The header is dark in both modes: forced light status-bar icons stay legible.
            assertTrue("${m.mode} header start must be dark", luminance(m.color("brand_header_start")) < 0.18)
            assertTrue("${m.mode} header end must be dark", luminance(m.color("brand_header_end")) < 0.18)
        }
        assertEquals("#FFFFFF", hex(light.color("on_brand_header")))
        assertEquals("#FFFFFF", hex(dark.color("on_brand_header")))
    }

    @Test
    fun `contrast helper matches known WCAG values`() {
        assertEquals(21.0, contrast(0xFF000000.toInt(), 0xFFFFFFFF.toInt()), 1e-9)
        assertEquals(1.0, contrast(0xFF777777.toInt(), 0xFF777777.toInt()), 1e-9)
        // #767676 on white is the classic 4.54:1 grey.
        assertEquals(4.54, contrast(0xFF767676.toInt(), 0xFFFFFFFF.toInt()), 0.01)
    }
}

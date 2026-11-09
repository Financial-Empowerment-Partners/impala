package com.payala.impala.demo

import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.view.WindowManager
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * The merged manifest's shape. Background NFC processing is gone:
 * system-dispatched taps go to impala-lib's identity-only NfcContactActivity,
 * which SELECTs the flavour's applet AID from resource-typed meta-data. Only
 * the launcher and the two OAuth redirect targets are exported.
 */
@RunWith(RobolectricTestRunner::class)
class ManifestTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()

    @Suppress("DEPRECATION")
    private fun activities(): List<ActivityInfo> =
        ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_ACTIVITIES).activities.orEmpty().toList()

    private fun activity(simpleName: String): ActivityInfo =
        activities().singleOrNull { it.name.endsWith(".$simpleName") } ?: error("$simpleName is not declared")

    @Test
    fun `no foreground service and no NfcDispatchActivity are declared`() {
        @Suppress("DEPRECATION")
        val info = ctx.packageManager.getPackageInfo(
            ctx.packageName,
            PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or PackageManager.GET_PERMISSIONS
        )
        val activities = info.activities.orEmpty().map { it.name }
        val services = info.services.orEmpty().map { it.name }
        val permissions = info.requestedPermissions.orEmpty().toList()
        assertFalse(activities.any { it.endsWith("NfcDispatchActivity") })
        assertTrue("impala-lib's system-dispatch activity is merged", activities.contains("com.payala.impala.NfcContactActivity"))
        assertFalse(services.any { it.endsWith("NfcWatcherService") })
        assertFalse(permissions.any { it.startsWith("android.permission.FOREGROUND_SERVICE") })
        assertFalse("impala-lib location permissions are stripped", permissions.contains("android.permission.ACCESS_FINE_LOCATION"))
    }

    @Test
    fun `only the launcher and the OAuth redirects are exported`() {
        val exportedAllowed = setOf(
            "com.payala.impala.demo.ui.login.LoginActivity",
            "com.payala.impala.demo.auth.GitHubRedirectActivity",
            "com.payala.impala.demo.auth.OktaRedirectActivity"
        )
        val app = activities().filter { it.name.startsWith("com.payala.impala.demo.") }
        assertTrue("the app's activities are visible", app.size >= exportedAllowed.size + 3)
        for (a in app) {
            if (a.name in exportedAllowed) assertTrue("${a.name} must stay exported", a.exported)
            else assertFalse("${a.name} must be exported=false", a.exported)
        }
    }

    @Test
    fun `every activity in the app manifest declares android exported explicitly`() {
        val manifest = File("src/main/AndroidManifest.xml")
        assertTrue("run from the app module directory", manifest.isFile)
        val elements = Regex("""<activity\b[^>]*>""").findAll(manifest.readText()).map { it.value }.toList()
        assertTrue(elements.isNotEmpty())
        for (e in elements) assertTrue("android:exported missing on: $e", "android:exported=" in e)
    }

    @Test
    fun `the applet AID meta-data is a string resource equal to BuildConfig CARD_APPLET_AID`() {
        @Suppress("DEPRECATION")
        val meta = ctx.packageManager.getApplicationInfo(ctx.packageName, PackageManager.GET_META_DATA).metaData
        val key = "com.payala.impala.CARD_APPLET_AID"
        assertTrue("meta-data $key is declared", meta != null && meta.containsKey(key))
        // android:resource stores a resource id (an Int), never a Float as android:value="0102..." would.
        val raw = meta!!.get(key)
        assertTrue("meta-data must be resource-typed, was ${raw?.javaClass}", raw is Int)
        val resId = meta.getInt(key)
        assertNotEquals(0, resId)
        assertEquals(R.string.impala_card_applet_aid, resId)
        assertEquals(BuildConfig.CARD_APPLET_AID, ctx.getString(resId))
    }

    @Test
    fun `the OAuth redirects use the translucent theme`() {
        for (name in listOf("GitHubRedirectActivity", "OktaRedirectActivity")) {
            assertEquals("$name theme", R.style.Theme_ImpalaDemo_Translucent, activity(name).themeResource)
        }
    }

    @Test
    fun `the Card Lab activity is declared, not exported, under its kept class name`() {
        val lab = activity("NfcDebugActivity")
        assertEquals("com.payala.impala.demo.ui.nfc.NfcDebugActivity", lab.name)
        assertFalse(lab.exported)
    }

    @Test
    fun `login resizes for the keyboard`() {
        val mode = activity("LoginActivity").softInputMode and WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST
        assertEquals(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE, mode)
    }
}

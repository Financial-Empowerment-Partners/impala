package com.payala.impala.demo

import android.content.Context
import android.graphics.drawable.LayerDrawable
import android.util.TypedValue
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * API 24-25 have no adaptive icons, so `mipmap-anydpi-v26` does not apply and
 * the launcher icon must come from the `mipmap-anydpi` layer-list fallbacks.
 * Without them (impala-lib's template mipmaps are gone), `@mipmap/ic_launcher`
 * and the round icon resolve to nothing on minSdk devices. The push small icon
 * is a plain vector and must resolve there too.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [24])
class LauncherIconApi24Test {
    private val ctx: Context = ApplicationProvider.getApplicationContext()

    private fun resolvedPath(id: Int): String {
        val value = TypedValue()
        ctx.resources.getValue(id, value, true)
        return value.string?.toString().orEmpty()
    }

    @Test
    fun `launcher icons resolve to the legacy layer lists on API 24`() {
        for ((name, id) in listOf("ic_launcher" to R.mipmap.ic_launcher, "ic_launcher_round" to R.mipmap.ic_launcher_round)) {
            val icon = ContextCompat.getDrawable(ctx, id)
            assertNotNull("@mipmap/$name does not resolve on API 24", icon)
            assertTrue("@mipmap/$name is not the legacy layer list: ${icon!!::class.java.name}", icon is LayerDrawable)
            assertTrue("@mipmap/$name has no size", icon.intrinsicWidth > 0 && icon.intrinsicHeight > 0)
            val path = resolvedPath(id)
            assertFalse("@mipmap/$name resolved to the adaptive icon on API 24: $path", path.contains("-v26"))
        }
    }

    @Test
    fun `the manifest's application icon is the launcher mipmap and loads`() {
        assertEquals(R.mipmap.ic_launcher, ctx.applicationInfo.icon)
        assertNotNull(ctx.packageManager.getApplicationIcon(ctx.applicationInfo))
    }

    @Test
    fun `the push small icon resolves on API 24`() {
        val push = File("src/main/java/com/payala/impala/demo/push/ImpalaPushService.kt")
        assertTrue("run from the app module directory", push.isFile)
        assertTrue("ImpalaPushService uses ic_stat_impala", push.readText().contains("setSmallIcon(R.drawable.ic_stat_impala)"))
        val icon = ContextCompat.getDrawable(ctx, R.drawable.ic_stat_impala)
        assertNotNull("@drawable/ic_stat_impala does not resolve on API 24", icon)
        assertTrue(icon!!.intrinsicWidth > 0 && icon.intrinsicHeight > 0)
    }
}

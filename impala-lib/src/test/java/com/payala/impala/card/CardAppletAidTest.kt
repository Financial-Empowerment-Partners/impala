package com.payala.impala.card

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Resources
import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class CardAppletAidTest {
    private val testnet = ImpalaCardSession.TESTNET_APPLET_AID
    private val resId = 0x7f0e0042

    /** A context whose manifest declares the AID as `android:resource="@string/…"` resolving to [value]. */
    private fun resourceBacked(value: String?): Context {
        val meta = Bundle().apply { if (value != null) putInt(CardAppletAid.META_DATA_KEY, resId) }
        val info = ApplicationInfo().apply { metaData = meta }
        val pm = mock(PackageManager::class.java)
        `when`(pm.getApplicationInfo(eq("com.example.app"), any(PackageManager.ApplicationInfoFlags::class.java))).thenReturn(info)
        `when`(pm.getApplicationInfo(eq("com.example.app"), anyInt())).thenReturn(info)
        val res = mock(Resources::class.java)
        if (value != null) `when`(res.getString(resId)).thenReturn(value)
        val ctx = mock(Context::class.java)
        `when`(ctx.packageName).thenReturn("com.example.app")
        `when`(ctx.packageManager).thenReturn(pm)
        `when`(ctx.resources).thenReturn(res)
        return ctx
    }

    @Test
    fun `a resource-backed empty AID means no SELECT`() {
        assertNull(CardAppletAid.forApp(resourceBacked("")))
        assertNull(CardAppletAid.forApp(resourceBacked("   ")))
    }

    @Test
    fun `a resource-backed custom AID is used as declared`() {
        assertEquals("A0000006472F0001", CardAppletAid.forApp(resourceBacked("A0000006472F0001")))
        assertEquals("01020304050607080103", CardAppletAid.forApp(resourceBacked(" 01020304050607080103 ")))
    }

    @Test
    fun `absent meta-data falls back to the testnet AID`() {
        assertEquals(testnet, CardAppletAid.forApp(resourceBacked(null)))
        val app: Application = ApplicationProvider.getApplicationContext()
        shadowOf(app.packageManager).getInternalMutablePackageInfo(app.packageName).applicationInfo!!.metaData = null
        assertEquals(testnet, CardAppletAid.forApp(app))
    }

    @Test
    fun `malformed or float-typed values fall back to the testnet AID`() {
        assertEquals(testnet, CardAppletAid.forApp(resourceBacked("not hex at all")))
        assertEquals(testnet, CardAppletAid.forApp(resourceBacked("0102")))            // too short
        assertEquals(testnet, CardAppletAid.forApp(resourceBacked("010203040506070801020")))  // odd length
        val app: Application = ApplicationProvider.getApplicationContext()
        val info = shadowOf(app.packageManager).getInternalMutablePackageInfo(app.packageName).applicationInfo!!
        // What AAPT2 makes of android:value="01020304050607080102": a float.
        info.metaData = Bundle().apply { putFloat(CardAppletAid.META_DATA_KEY, 1.0203041E18f) }
        assertEquals(testnet, CardAppletAid.forApp(app))
        // A literal android:value string is accepted.
        info.metaData = Bundle().apply { putString(CardAppletAid.META_DATA_KEY, "A0000006472F0001") }
        assertEquals("A0000006472F0001", CardAppletAid.forApp(app))
        info.metaData = Bundle().apply { putString(CardAppletAid.META_DATA_KEY, "") }
        assertNull(CardAppletAid.forApp(app))
    }

    @Test
    fun `an unreadable package manager falls back to the testnet AID`() {
        val ctx = mock(Context::class.java)
        `when`(ctx.packageName).thenReturn("com.example.app")
        `when`(ctx.packageManager).thenThrow(IllegalStateException("no package manager"))
        assertEquals(testnet, CardAppletAid.forApp(ctx))
    }
}

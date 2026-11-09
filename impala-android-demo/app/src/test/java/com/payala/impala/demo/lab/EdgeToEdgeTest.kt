package com.payala.impala.demo.lab

import android.content.Context
import androidx.core.view.WindowCompat
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ui.common.applyEdgeToEdge
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.lab.LabViewModel
import com.payala.impala.demo.ui.nfc.NfcDebugActivity
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config

/**
 * `applyEdgeToEdge` sets the system-bar icon appearance from the night mode
 * (the transparent bars no longer take it from the theme): dark icons on the
 * light theme's near-white surfaces, light icons in dark mode, and light
 * status-bar icons whenever a screen asks for them (the login header). Driven
 * through the Card Lab, an activity that calls `applyEdgeToEdge()` and runs
 * with no session.
 */
@RunWith(RobolectricTestRunner::class)
class EdgeToEdgeTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private var controller: ActivityController<NfcDebugActivity>? = null

    @Before
    fun setUp() {
        LabViewModel.probeClient = CannedBridge.healthy(network = BuildConfig.STELLAR_NETWORK).client
    }

    @After
    fun tearDown() {
        controller?.pause()?.stop()?.destroy()
        LabViewModel.probeClient = null
    }

    private fun launch(): NfcDebugActivity =
        Robolectric.buildActivity(NfcDebugActivity::class.java, LabIntents.open(ctx)).setup().also { controller = it }.get()

    private fun NfcDebugActivity.bars() = WindowCompat.getInsetsController(window, window.decorView)

    @Test
    fun `light mode gets dark status and navigation bar icons`() {
        val lab = launch()
        assertTrue("light theme: dark status-bar icons", lab.bars().isAppearanceLightStatusBars)
        assertTrue("light theme: dark navigation-bar icons", lab.bars().isAppearanceLightNavigationBars)
    }

    @Test
    @Config(qualifiers = "+night")
    fun `dark mode gets light status and navigation bar icons`() {
        val lab = launch()
        assertFalse("dark theme: light status-bar icons", lab.bars().isAppearanceLightStatusBars)
        assertFalse("dark theme: light navigation-bar icons", lab.bars().isAppearanceLightNavigationBars)
    }

    @Test
    fun `a dark header keeps light status-bar icons in light mode`() {
        val lab = launch()
        lab.applyEdgeToEdge(lightStatusBarIcons = true)
        assertFalse("forced light status-bar icons", lab.bars().isAppearanceLightStatusBars)
        assertTrue("the navigation bar still follows the theme", lab.bars().isAppearanceLightNavigationBars)
    }

    @Test
    @Config(qualifiers = "+night")
    fun `a dark header keeps light status-bar icons in dark mode`() {
        val lab = launch()
        lab.applyEdgeToEdge(lightStatusBarIcons = true)
        assertFalse(lab.bars().isAppearanceLightStatusBars)
        assertFalse(lab.bars().isAppearanceLightNavigationBars)
    }
}

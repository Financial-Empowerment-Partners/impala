package com.payala.impala.demo.lab

import android.content.Context
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import com.impala.simulator.SimulatorApduServer
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.ui.lab.LabIntents
import com.payala.impala.demo.ui.lab.LabViewModel
import com.payala.impala.demo.ui.nfc.NfcDebugActivity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.android.controller.ActivityController
import org.robolectric.shadows.ShadowSystemProperties

/**
 * Debug builds: the Card Lab's Doctor tab (where Cards → Inspect in Card Lab
 * lands) has its own read action for the simulated card, so the checks can be
 * run without switching to the Inspector. Uses an ephemeral simulator (port
 * 0); nothing touches a long-running one.
 */
@RunWith(RobolectricTestRunner::class)
class LabDoctorReadTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val property = "debug.impala.tcp_card"
    private var controller: ActivityController<NfcDebugActivity>? = null

    @Before
    fun setUp() {
        LabViewModel.probeClient = CannedBridge.healthy(network = BuildConfig.STELLAR_NETWORK).client
    }

    @After
    fun tearDown() {
        controller?.pause()?.stop()?.destroy()
        LabViewModel.probeClient = null
        ShadowSystemProperties.override(property, "")
    }

    private fun launchDoctor(): NfcDebugActivity =
        Robolectric.buildActivity(NfcDebugActivity::class.java, LabIntents.open(ctx, LabIntents.TAB_DOCTOR, "00112233445566778899aabbccddeeff"))
            .setup().also { controller = it }.get()

    @Test
    fun `the Doctor tab reads the simulated card itself and runs the checks`() {
        SimulatorApduServer(port = 0).start().use { server ->
            ShadowSystemProperties.override(property, "127.0.0.1:${server.port}")
            val lab = launchDoctor()
            val read = lab.findViewById<View>(R.id.btnDoctorRead)
            assertEquals(View.VISIBLE, lab.findViewById<View>(R.id.doctorActions).visibility)
            assertEquals(View.VISIBLE, read.visibility)
            assertEquals(ctx.getString(R.string.lab_doctor_intro_simulated), lab.findViewById<TextView>(R.id.tvDoctorSummary).text.toString())

            read.performClick()
            idleMainUntil { lab.viewModel.phase.value == LabViewModel.Phase.DONE || lab.viewModel.phase.value == LabViewModel.Phase.FAILED }
            assertEquals(LabViewModel.Phase.DONE, lab.viewModel.phase.value)
            idleMainUntil { lab.findViewById<TextView>(R.id.tvDoctorSummary).text.contains("passed") }
            val summary = lab.findViewById<TextView>(R.id.tvDoctorSummary).text.toString()
            assertTrue(summary, Regex("""^\d+ passed · \d+ failed · \d+ warnings? · \d+ skipped$""").matches(summary))
        }
    }

    @Test
    fun `without a simulator or NFC there is no Doctor read button`() {
        ShadowSystemProperties.override(property, "")
        val lab = launchDoctor()
        assertEquals(View.GONE, lab.findViewById<View>(R.id.btnDoctorRead).visibility)
        assertEquals(View.GONE, lab.findViewById<View>(R.id.doctorActions).visibility)
        assertEquals(ctx.getString(R.string.lab_doctor_intro), lab.findViewById<TextView>(R.id.tvDoctorSummary).text.toString())
    }
}

package com.payala.impala.demo.lab

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.ui.lab.BuildInfo
import com.payala.impala.demo.ui.lab.ReaderState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.time.Instant
import java.time.ZoneId
import java.util.Locale

/** [BuildInfo]: the Device tab's public build facts, never anything from the session store. */
@RunWith(RobolectricTestRunner::class)
class BuildInfoTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()

    private fun rows(reader: ReaderState = ReaderState.NFC_ENABLED, zone: ZoneId = ZoneId.of("UTC")) =
        BuildInfo.rows(ctx, reader, Instant.parse("2026-11-08T09:41:07Z"), zone, Locale.UK)
            .associate { ctx.getString(it.labelRes) to it.value }

    @Test
    fun `rows carry flavor, network, AID and the build identity`() {
        val r = rows()
        assertEquals(BuildConfig.FLAVOR, r["Flavor"])
        assertEquals(BuildConfig.BUILD_TYPE, r["Build type"])
        assertEquals(BuildConfig.STELLAR_NETWORK, r["Stellar network"])
        assertEquals(BuildConfig.BRIDGE_BASE_URL, r["Bridge URL"])
        assertEquals(ctx.packageName, r["Application ID"])
        assertEquals("${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})", r["App version"])
        val aid = BuildConfig.CARD_APPLET_AID
        assertEquals(if (aid.isEmpty()) ctx.getString(R.string.lab_default_selection) else aid, r["Applet AID"])
        assertTrue(r.getValue("SDK").matches(Regex("min \\d+ · target \\d+")))
        assertTrue(r.getValue("Android").contains("API "))
    }

    @Test
    fun `locale and UTC offset are explicit`() {
        assertEquals("en-GB · UTC+00:00", rows()["Locale"])
        assertEquals("en-GB · UTC+05:30", rows(zone = ZoneId.of("Asia/Kolkata"))["Locale"])
    }

    @Test
    fun `the NFC row names the reader state`() {
        assertEquals("Enabled", rows(ReaderState.NFC_ENABLED)["NFC"])
        assertEquals("Disabled", rows(ReaderState.NFC_DISABLED)["NFC"])
        assertEquals("Not present", rows(ReaderState.NFC_ABSENT)["NFC"])
    }

    @Test
    fun `the AID row is copyable only when there is an AID`() {
        val aidRow = BuildInfo.rows(ctx, ReaderState.NFC_ENABLED).single { it.labelRes == R.string.lab_build_aid }
        assertEquals(BuildConfig.CARD_APPLET_AID.isNotEmpty(), aidRow.copyable)
    }

    @Test
    fun `BuildInfo never reads the session store`() {
        val src = File("src/main/java/com/payala/impala/demo/ui/lab/BuildInfo.kt").readText()
        for (forbidden in listOf("TokenManager", "tokenManager", "ImpalaApp", "getAccountId", "getCardId", "getSharedPreferences")) {
            assertFalse("BuildInfo.kt mentions $forbidden", src.contains(forbidden))
        }
    }
}

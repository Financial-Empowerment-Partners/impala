package com.payala.impala.demo.tap

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.payala.impala.demo.R
import com.payala.impala.demo.ui.tap.TapCopy
import com.payala.impala.demo.ui.tap.TapPrompt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The sheet's outcome copy: a Done sheet says what happens next instead of
 * repeating the prompt, and a Failed title keeps the flow it belongs to
 * (an ambiguous outcome keeps the fixed "do not repeat" title).
 */
@RunWith(RobolectricTestRunner::class)
class TapCopyTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val res = ctx.resources

    @Test
    fun `every Done summary has an outcome line that is not a prompt title`() {
        val titles = listOf(
            R.string.tap_title_register, R.string.tap_title_sign_in, R.string.tap_title_read
        ).map(ctx::getString)
        for (summary in listOf(
            R.string.tap_done_registered, R.string.tap_done_signed_in, R.string.tap_done_sent,
            R.string.tap_done_loaded, R.string.tap_done_load_created, R.string.tap_done_nothing_signed
        )) {
            val detail = TapCopy.doneDetail(summary)
            assertNotNull(ctx.getString(summary), detail)
            val text = ctx.getString(detail!!)
            assertTrue(text.isNotBlank())
            assertTrue("$text repeats a prompt", text !in titles)
            assertNotEquals(ctx.getString(summary), text)
        }
        assertEquals(null, TapCopy.doneDetail(R.string.tap_action_done))
    }

    @Test
    fun `a Failed title names its flow`() {
        assertEquals("Couldn't register the card", TapCopy.failedTitle(res, TapPrompt.Register, warning = false))
        assertEquals("Couldn't sign in with the card", TapCopy.failedTitle(res, TapPrompt.SignIn, warning = false))
        assertEquals("Couldn't read the card", TapCopy.failedTitle(res, TapPrompt.Read(null), warning = false))
        assertEquals("Couldn't read card ····eeff", TapCopy.failedTitle(res, TapPrompt.Read("eeff"), warning = false))
        assertEquals("Couldn't sign on card ····eeff", TapCopy.failedTitle(res, TapPrompt.Sign("eeff"), warning = false))
        assertEquals("Couldn't apply the credit to card ····eeff", TapCopy.failedTitle(res, TapPrompt.Apply("eeff"), warning = false))
    }

    @Test
    fun `an ambiguous outcome keeps the do-not-repeat title for every prompt`() {
        for (p in listOf(TapPrompt.Register, TapPrompt.SignIn, TapPrompt.Read(null), TapPrompt.Sign("eeff"), TapPrompt.Apply("eeff"))) {
            assertEquals(ctx.getString(R.string.tap_failed_warning_title), TapCopy.failedTitle(res, p, warning = true))
        }
    }
}

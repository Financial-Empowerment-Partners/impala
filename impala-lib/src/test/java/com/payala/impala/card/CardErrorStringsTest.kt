package com.payala.impala.card

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.impala.sdk.flows.CardError
import com.payala.impala.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CardErrorStringsTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `every CardError userMessageKey has a string resource`() {
        for (key in CardError.ALL_MESSAGE_KEYS) {
            val byName = context.resources.getIdentifier(key, "string", context.packageName)
            assertNotEquals("missing string resource $key", 0, byName)
            assertEquals(key, byName, CardErrorMessages.resId(key))
        }
        assertEquals(R.string.card_error_other, CardErrorMessages.resId("card_error_unknown_future_key"))
    }

    @Test
    fun `messages format their arguments and append the SW only on request`() {
        assertEquals("Wrong PIN. Tries left: 4.", CardErrorMessages.message(context, CardError.WrongPin(4)))
        assertTrue(CardErrorMessages.message(context, CardError.CounterInvalid, includeStatusWord = true).endsWith("(SW 6233)"))
        assertTrue(!CardErrorMessages.message(context, CardError.CounterInvalid).contains("6233"))
    }
}

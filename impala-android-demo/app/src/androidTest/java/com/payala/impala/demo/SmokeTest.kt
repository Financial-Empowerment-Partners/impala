package com.payala.impala.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SmokeTest {

    @Test
    fun targetContext_packageName_matches_applicationId() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("com.payala.impala.demo", context.packageName)
    }
}

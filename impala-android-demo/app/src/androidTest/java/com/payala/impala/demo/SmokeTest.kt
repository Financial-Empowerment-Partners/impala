package com.payala.impala.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SmokeTest {

    /**
     * The installed package is the variant's application id: the tnet flavour
     * adds the `.testnet` suffix, so a hard-coded base package fails
     * `connectedTnetDebugAndroidTest`.
     */
    @Test
    fun targetContext_packageName_matches_applicationId() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(BuildConfig.APPLICATION_ID, context.packageName)
    }
}

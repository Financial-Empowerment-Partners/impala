package com.payala.impala.demo

import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Background NFC processing is gone: system-dispatched taps go to impala-lib's identity-only NfcContactActivity. */
@RunWith(RobolectricTestRunner::class)
class ManifestTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()

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
}

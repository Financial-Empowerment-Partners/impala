package com.payala.impala.demo.ui.lab

import android.content.Context
import android.os.Build
import androidx.annotation.StringRes
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import java.time.Instant
import java.time.ZoneId
import java.util.Locale

/**
 * The Device tab's build and environment facts. Public configuration only:
 * nothing from the session store, and no secret (the build has none to show).
 */
object BuildInfo {

    /** One fact: a label and its value. [copyable] values are identifiers worth pasting into a bug report. */
    class Row(@StringRes val labelRes: Int, val value: String, val copyable: Boolean = false) {
        override fun toString(): String = "Row($labelRes=$value)"
    }

    /** The applet AID this build SELECTs, or null for the card's default selection. */
    val appletAid: String? get() = BuildConfig.CARD_APPLET_AID.ifEmpty { null }

    fun rows(
        context: Context,
        reader: ReaderState,
        now: Instant = Instant.now(),
        zone: ZoneId = ZoneId.systemDefault(),
        locale: Locale = Locale.getDefault()
    ): List<Row> {
        val res = context.resources
        val info = context.applicationInfo
        val offset = zone.rules.getOffset(now).id.let { if (it == "Z") "+00:00" else it }
        return listOf(
            Row(R.string.lab_build_version, "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"),
            Row(R.string.lab_build_flavor, BuildConfig.FLAVOR),
            Row(R.string.lab_build_type, BuildConfig.BUILD_TYPE),
            Row(R.string.lab_build_application_id, context.packageName, copyable = true),
            Row(R.string.lab_build_network, BuildConfig.STELLAR_NETWORK),
            Row(R.string.lab_build_bridge_url, BuildConfig.BRIDGE_BASE_URL, copyable = true),
            Row(R.string.lab_build_aid, appletAid ?: res.getString(R.string.lab_default_selection), copyable = appletAid != null),
            Row(R.string.lab_build_sdk, res.getString(R.string.lab_build_sdk_value, info.minSdkVersion, info.targetSdkVersion)),
            Row(R.string.lab_build_device, "${Build.MANUFACTURER} ${Build.MODEL}"),
            Row(
                R.string.lab_build_android,
                res.getString(R.string.lab_build_android_value, Build.VERSION.RELEASE ?: "?", Build.VERSION.SDK_INT, Build.VERSION.SECURITY_PATCH ?: "?")
            ),
            Row(R.string.lab_build_locale, res.getString(R.string.lab_build_locale_value, locale.toLanguageTag(), offset)),
            Row(R.string.lab_build_nfc, res.getString(readerText(reader)))
        )
    }

    @StringRes
    fun readerText(reader: ReaderState): Int = when (reader) {
        ReaderState.NFC_ENABLED -> R.string.lab_nfc_enabled
        ReaderState.NFC_DISABLED -> R.string.lab_nfc_disabled
        ReaderState.NFC_ABSENT -> R.string.lab_nfc_absent
        ReaderState.SIMULATED -> R.string.lab_nfc_simulated
    }
}

package com.payala.impala.card

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * The applet AID the consuming app selects for system-dispatched taps
 * ([com.payala.impala.NfcContactActivity]), declared by the app in its
 * manifest as a **string resource**:
 *
 * ```xml
 * <meta-data android:name="com.payala.impala.CARD_APPLET_AID"
 *            android:resource="@string/impala_card_applet_aid" />
 * ```
 *
 * `android:value` would let AAPT2 type an all-digit AID as a float, so the
 * resource form is the contract. The resolved string decides:
 * - empty → null: no SELECT, the card's default-selected applet answers;
 * - 10..32 hex digits (5..16 bytes) → that AID;
 * - meta-data absent → [ImpalaCardSession.TESTNET_APPLET_AID] (the behaviour
 *   before this meta-data existed);
 * - anything unreadable or malformed → [ImpalaCardSession.TESTNET_APPLET_AID],
 *   with a warning.
 *
 * A plain-string `android:value` is accepted too, for consumers that cannot
 * declare a resource.
 */
object CardAppletAid {
    const val META_DATA_KEY = "com.payala.impala.CARD_APPLET_AID"
    private const val TAG = "ImpalaCardAid"
    private val HEX_AID = Regex("^[0-9A-Fa-f]{10,32}$")

    @JvmStatic
    fun forApp(context: Context): String? {
        val meta = try {
            applicationInfo(context).metaData
        } catch (e: Exception) {
            ImpalaLibLog.w(TAG, "Manifest meta-data unreadable (${e.javaClass.simpleName}); using the testnet AID")
            return ImpalaCardSession.TESTNET_APPLET_AID
        }
        if (meta == null || !meta.containsKey(META_DATA_KEY)) return ImpalaCardSession.TESTNET_APPLET_AID
        val raw: String? = when (val v = readValue(meta)) {
            is Int -> if (v == 0) null else try {
                context.resources.getString(v)
            } catch (e: Exception) {
                ImpalaLibLog.w(TAG, "AID resource unreadable (${e.javaClass.simpleName}); using the testnet AID")
                return ImpalaCardSession.TESTNET_APPLET_AID
            }
            is String -> v
            else -> null
        }
        if (raw == null) {
            ImpalaLibLog.w(TAG, "AID meta-data is not a string resource; using the testnet AID")
            return ImpalaCardSession.TESTNET_APPLET_AID
        }
        val aid = raw.trim()
        if (aid.isEmpty()) return null
        if (aid.length % 2 != 0 || !HEX_AID.matches(aid)) {
            ImpalaLibLog.w(TAG, "AID meta-data is not 5..16 bytes of hex; using the testnet AID")
            return ImpalaCardSession.TESTNET_APPLET_AID
        }
        return aid
    }

    @Suppress("DEPRECATION") // Bundle.get: the value's type is what is being checked
    private fun readValue(meta: android.os.Bundle): Any? = meta.get(META_DATA_KEY)

    private fun applicationInfo(context: Context): ApplicationInfo {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= 33) {
            pm.getApplicationInfo(context.packageName, PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)
        }
    }
}

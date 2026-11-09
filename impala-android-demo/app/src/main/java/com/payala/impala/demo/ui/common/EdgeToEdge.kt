package com.payala.impala.demo.ui.common

import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.view.View
import android.view.Window
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.fragment.app.DialogFragment

/**
 * Edge-to-edge helpers. The app targets API 37, so Android 15+ already draws
 * every window edge to edge; [applyEdgeToEdge] makes API 24-34 behave the
 * same (transparent bars, content under them) so insets are handled once,
 * the same way, on every device.
 */

/**
 * Call in `onCreate` before `setContentView`. The status- and navigation-bar
 * icons follow the current night mode: dark icons on the light surfaces of
 * the light theme, light icons in dark mode. (The windows are transparent
 * edge to edge, so the theme's own bar colours no longer decide this, and
 * `WindowCompat.enableEdgeToEdge` leaves the icon appearance alone.)
 * [lightStatusBarIcons] forces light status-bar icons for screens whose top
 * edge is a dark surface in both modes (the login header).
 */
fun Activity.applyEdgeToEdge(lightStatusBarIcons: Boolean = false) {
    WindowCompat.enableEdgeToEdge(window)
    applySystemBarAppearance(window, isNightMode(this), lightStatusBarIcons)
}

/** True when [context]'s configuration is in night mode (the app's DayNight theme is dark). */
fun isNightMode(context: Context): Boolean =
    (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES

/**
 * Sets the system-bar icon appearance for [window]: dark icons ("light
 * appearance") on a light theme, light icons on a dark one; the status-bar
 * icons stay light when [lightStatusBarIcons] (a dark surface under them).
 */
internal fun applySystemBarAppearance(window: Window, night: Boolean, lightStatusBarIcons: Boolean = false) {
    val controller = WindowCompat.getInsetsController(window, window.decorView)
    controller.isAppearanceLightStatusBars = !night && !lightStatusBarIcons
    controller.isAppearanceLightNavigationBars = !night
}

/**
 * Pads this view by the system-bar (and display-cutout) insets on the chosen
 * edges, on top of the padding it was inflated with, and by the IME when [ime]
 * is set. Left and right insets are always applied (landscape cutouts).
 * Re-applies whenever the insets change; returns the insets unconsumed so
 * siblings still see them.
 */
fun View.padForSystemBars(top: Boolean = false, bottom: Boolean = true, ime: Boolean = false) {
    val start = paddingLeft
    val initialTop = paddingTop
    val end = paddingRight
    val initialBottom = paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(this) { v, insets ->
        var types = WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
        if (ime) types = types or WindowInsetsCompat.Type.ime()
        val i = insets.getInsets(types)
        v.updatePadding(
            left = start + i.left,
            top = initialTop + if (top) i.top else 0,
            right = end + i.right,
            bottom = initialBottom + if (bottom) i.bottom else 0
        )
        insets
    }
    if (isAttachedToWindow) {
        ViewCompat.requestApplyInsets(this)
    } else {
        addOnAttachStateChangeListener(object : View.OnAttachStateChangeListener {
            override fun onViewAttachedToWindow(v: View) {
                v.removeOnAttachStateChangeListener(this)
                ViewCompat.requestApplyInsets(v)
            }
            override fun onViewDetachedFromWindow(v: View) = Unit
        })
    }
}

/**
 * Call from a sheet's `onStart`: its dialog window draws edge to edge like the
 * activity behind it, with the same night-mode icon appearance.
 */
fun DialogFragment.enableSheetEdgeToEdge() {
    val window = dialog?.window ?: return
    WindowCompat.enableEdgeToEdge(window)
    applySystemBarAppearance(window, isNightMode(requireContext()))
}

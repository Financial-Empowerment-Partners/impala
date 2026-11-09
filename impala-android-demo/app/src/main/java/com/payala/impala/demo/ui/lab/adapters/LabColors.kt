package com.payala.impala.demo.ui.lab.adapters

import android.content.Context
import android.content.res.ColorStateList
import android.view.View
import androidx.annotation.AttrRes
import androidx.annotation.ColorInt
import com.google.android.material.chip.Chip
import com.google.android.material.color.MaterialColors
import com.google.android.material.shape.MaterialShapeDrawable
import com.google.android.material.shape.RelativeCornerSize
import com.google.android.material.shape.ShapeAppearanceModel
import com.payala.impala.demo.R
import com.payala.impala.demo.ui.lab.CheckStatus

/**
 * Status colours for Lab rows, resolved from theme attributes only (the
 * generated `colorStatus*` families plus the M3 error and neutral roles), so
 * light and dark come from the theme and no colour is hard-coded.
 */
object LabColors {

    @ColorInt
    fun attr(context: Context, @AttrRes attr: Int): Int = MaterialColors.getColor(context, attr, "Card Lab colour")

    /** Container / on-container attribute pair for a verdict chip. */
    private fun chipAttrs(status: CheckStatus): Pair<Int, Int> = when (status) {
        CheckStatus.PASS -> R.attr.colorStatusSuccessContainer to R.attr.colorOnStatusSuccessContainer
        CheckStatus.FAIL -> com.google.android.material.R.attr.colorErrorContainer to com.google.android.material.R.attr.colorOnErrorContainer
        CheckStatus.WARN -> R.attr.colorStatusWarningContainer to R.attr.colorOnStatusWarningContainer
        CheckStatus.INFO -> R.attr.colorStatusInfoContainer to R.attr.colorOnStatusInfoContainer
        CheckStatus.SKIP -> com.google.android.material.R.attr.colorSurfaceContainerHighest to com.google.android.material.R.attr.colorOnSurfaceVariant
    }

    /** Tints a `Widget.ImpalaDemo.Chip.Status` chip for [status]. */
    fun tintChip(chip: Chip, status: CheckStatus) {
        val (bg, fg) = chipAttrs(status)
        chip.chipBackgroundColor = ColorStateList.valueOf(attr(chip.context, bg))
        chip.setTextColor(attr(chip.context, fg))
    }

    /** Foreground colour for a value or line that carries a verdict (readable on the surface). */
    @ColorInt
    fun foreground(context: Context, status: CheckStatus?): Int = attr(
        context,
        when (status) {
            CheckStatus.PASS -> R.attr.colorStatusSuccess
            CheckStatus.FAIL -> androidx.appcompat.R.attr.colorError
            CheckStatus.WARN -> R.attr.colorStatusWarning
            CheckStatus.INFO -> R.attr.colorStatusInfo
            CheckStatus.SKIP, null -> com.google.android.material.R.attr.colorOnSurfaceVariant
        }
    )

    /** A fully rounded background (status dot or tag pill) in [color], with no drawable resource. */
    fun rounded(view: View, @ColorInt color: Int) {
        val model = ShapeAppearanceModel.builder().setAllCornerSizes(RelativeCornerSize(HALF)).build()
        view.background = MaterialShapeDrawable(model).apply { fillColor = ColorStateList.valueOf(color) }
    }

    private const val HALF = 0.5f
}

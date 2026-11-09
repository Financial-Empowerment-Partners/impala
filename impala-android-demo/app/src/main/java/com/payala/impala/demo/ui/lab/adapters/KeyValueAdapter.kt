package com.payala.impala.demo.ui.lab.adapters

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.TextViewCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ItemLabRowBinding
import com.payala.impala.demo.ui.common.Identifiers
import com.payala.impala.demo.ui.lab.LabRow

/**
 * Labelled values in groups (Inspector and Device tabs). Identifier rows get a
 * 48 dp copy button whose content description names the row and the start of
 * the value ("Copy Card ID 8d7d…"); masked and personal rows never do. Only
 * identifier values are set in monospace; the copy button copies the value
 * itself, never the displayed text (which carries break opportunities).
 */
class KeyValueAdapter(
    private val onCopy: (label: String, value: String) -> Unit
) : ListAdapter<LabRow, KeyValueAdapter.Holder>(Diff) {

    class Holder(val binding: ItemLabRowBinding) : RecyclerView.ViewHolder(binding.root)

    override fun getItemViewType(position: Int): Int = if (getItem(position) is LabRow.Header) HEADER else ITEM

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(ItemLabRowBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val b = holder.binding
        when (val row = getItem(position)) {
            is LabRow.Header -> {
                b.tvHeader.visibility = View.VISIBLE
                b.tvHeader.text = row.title
                b.rowBody.visibility = View.GONE
            }
            is LabRow.Item -> {
                b.tvHeader.visibility = View.GONE
                b.rowBody.visibility = View.VISIBLE
                b.tvLabel.text = row.label
                val ctx = b.root.context
                // Monospace for identifiers only (wrapping at their separators); prose reads in the body face.
                val ident = row.identifier && !row.masked && !row.personal
                TextViewCompat.setTextAppearance(
                    b.tvValue,
                    if (ident) R.style.TextAppearance_ImpalaDemo_MonoSmall else R.style.TextAppearance_ImpalaDemo_LabValue
                )
                b.tvValue.text = if (ident) Identifiers.breakable(row.value) else row.value
                if (row.masked) b.tvValue.setTypeface(b.tvValue.typeface, Typeface.ITALIC)
                b.tvValue.setTextColor(
                    when {
                        row.masked -> LabColors.attr(ctx, com.google.android.material.R.attr.colorOnSurfaceVariant)
                        row.tone != null -> LabColors.foreground(ctx, row.tone)
                        else -> LabColors.attr(ctx, com.google.android.material.R.attr.colorOnSurface)
                    }
                )
                val copy = row.copyable && !row.masked && !row.personal
                b.btnCopy.visibility = if (copy) View.VISIBLE else View.GONE
                if (copy) {
                    b.btnCopy.contentDescription = ctx.getString(R.string.lab_copy_description, row.label, preview(row.value))
                    b.btnCopy.setOnClickListener { onCopy(row.label, row.value) }
                } else {
                    b.btnCopy.setOnClickListener(null)
                }
            }
        }
    }

    private fun preview(value: String): String = if (value.length <= 8) value else value.take(4) + "…"

    private object Diff : DiffUtil.ItemCallback<LabRow>() {
        override fun areItemsTheSame(oldItem: LabRow, newItem: LabRow): Boolean = when {
            oldItem is LabRow.Header && newItem is LabRow.Header -> oldItem.title == newItem.title
            oldItem is LabRow.Item && newItem is LabRow.Item -> oldItem.label == newItem.label
            else -> false
        }

        override fun areContentsTheSame(oldItem: LabRow, newItem: LabRow): Boolean = oldItem == newItem
    }

    private companion object {
        const val HEADER = 0
        const val ITEM = 1
    }
}

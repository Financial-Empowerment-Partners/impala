package com.payala.impala.demo.ui.lab.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ItemLabCheckBinding
import com.payala.impala.demo.ui.lab.CheckAction
import com.payala.impala.demo.ui.lab.CheckStatus
import com.payala.impala.demo.ui.lab.DoctorCheck

/** The Doctor's verdicts: a tonal status chip, the check, what was found, and the remedy. */
class DoctorAdapter(
    private val onAction: (CheckAction) -> Unit
) : ListAdapter<DoctorCheck, DoctorAdapter.Holder>(Diff) {

    class Holder(val binding: ItemLabCheckBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
        Holder(ItemLabCheckBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
        val b = holder.binding
        val check = getItem(position)
        val ctx = b.root.context
        b.chipStatus.text = check.status.name
        LabColors.tintChip(b.chipStatus, check.status)
        val title = ctx.getString(check.titleRes)
        b.tvCheckTitle.text = title
        b.tvCheckDetail.text = ctx.getString(check.detailRes, *check.detailArgs.toTypedArray())
        val remedy = check.remedyRes
        b.tvCheckRemedy.visibility = if (remedy != null) View.VISIBLE else View.GONE
        if (remedy != null) b.tvCheckRemedy.text = ctx.getString(remedy)
        val action = check.action
        b.btnCheckAction.visibility = if (action != null) View.VISIBLE else View.GONE
        if (action != null) {
            b.btnCheckAction.setText(
                when (action) {
                    CheckAction.OPEN_NFC_SETTINGS -> R.string.lab_open_nfc_settings
                }
            )
            b.btnCheckAction.setOnClickListener { onAction(action) }
        } else {
            b.btnCheckAction.setOnClickListener(null)
        }
        b.root.contentDescription = ctx.getString(R.string.lab_check_description, statusWord(ctx, check.status), title, b.tvCheckDetail.text)
    }

    private fun statusWord(ctx: android.content.Context, s: CheckStatus): String = ctx.getString(
        when (s) {
            CheckStatus.PASS -> R.string.lab_status_pass
            CheckStatus.FAIL -> R.string.lab_status_fail
            CheckStatus.WARN -> R.string.lab_status_warn
            CheckStatus.SKIP -> R.string.lab_status_skip
            CheckStatus.INFO -> R.string.lab_status_info
        }
    )

    private object Diff : DiffUtil.ItemCallback<DoctorCheck>() {
        override fun areItemsTheSame(oldItem: DoctorCheck, newItem: DoctorCheck) = oldItem.id == newItem.id
        override fun areContentsTheSame(oldItem: DoctorCheck, newItem: DoctorCheck) = oldItem == newItem
    }
}

package com.payala.impala.demo.ui.lab.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.core.widget.TextViewCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduNames
import com.impala.sdk.apdu4j.ApduStats
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ItemLabExchangeBinding
import com.payala.impala.demo.databinding.ItemLabRowBinding
import com.payala.impala.demo.databinding.ItemLabStatsBinding
import com.payala.impala.demo.ui.lab.CheckStatus

/** Trace tab content: section headers, a stats block, and header-only exchanges. */
sealed class TraceItem {
    abstract val key: String

    class Section(val title: String, val subtitle: String?, override val key: String) : TraceItem() {
        override fun equals(other: Any?) = other is Section && other.key == key && other.title == title && other.subtitle == subtitle
        override fun hashCode() = key.hashCode()
    }

    class Stats(val stats: ApduStats, override val key: String) : TraceItem() {
        override fun equals(other: Any?) = other is Stats && other.key == key && other.stats.count == stats.count &&
            other.stats.totalNanos == stats.totalNanos
        override fun hashCode() = key.hashCode()
    }

    class Exchange(val exchange: ApduExchange, override val key: String) : TraceItem() {
        override fun equals(other: Any?) = other is Exchange && other.key == key
        override fun hashCode() = key.hashCode()
    }
}

class TraceAdapter : ListAdapter<TraceItem, RecyclerView.ViewHolder>(Diff) {

    private class SectionHolder(val b: ItemLabRowBinding) : RecyclerView.ViewHolder(b.root)
    private class StatsHolder(val b: ItemLabStatsBinding) : RecyclerView.ViewHolder(b.root)
    private class ExchangeHolder(val b: ItemLabExchangeBinding) : RecyclerView.ViewHolder(b.root)

    override fun getItemViewType(position: Int): Int = when (getItem(position)) {
        is TraceItem.Section -> SECTION
        is TraceItem.Stats -> STATS
        is TraceItem.Exchange -> EXCHANGE
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            SECTION -> SectionHolder(ItemLabRowBinding.inflate(inflater, parent, false))
            STATS -> StatsHolder(ItemLabStatsBinding.inflate(inflater, parent, false))
            else -> ExchangeHolder(ItemLabExchangeBinding.inflate(inflater, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val item = getItem(position)) {
            is TraceItem.Section -> (holder as SectionHolder).b.let { b ->
                b.tvHeader.visibility = View.VISIBLE
                b.tvHeader.text = item.title
                if (item.subtitle != null) {
                    b.rowBody.visibility = View.VISIBLE
                    b.rowBody.minimumHeight = 0
                    b.tvLabel.visibility = View.GONE
                    // A prose line ("12:34:56 · 8 commands · headers only"), not an identifier.
                    TextViewCompat.setTextAppearance(b.tvValue, R.style.TextAppearance_ImpalaDemo_LabValue)
                    b.tvValue.text = item.subtitle
                    b.tvValue.setTextColor(LabColors.attr(b.root.context, com.google.android.material.R.attr.colorOnSurfaceVariant))
                    b.btnCopy.visibility = View.GONE
                } else {
                    b.rowBody.visibility = View.GONE
                }
            }
            is TraceItem.Stats -> bindStats((holder as StatsHolder).b, item.stats)
            is TraceItem.Exchange -> bindExchange((holder as ExchangeHolder).b, item.exchange)
        }
    }

    private fun bindStats(b: ItemLabStatsBinding, s: ApduStats) {
        val ctx = b.root.context
        reflow(b, StatsGrid.columns(ctx.resources.configuration.fontScale, ctx.resources.configuration.screenWidthDp))
        fun ms(nanos: Long) = ctx.getString(R.string.lab_ms, (nanos / 1_000_000L).toString())
        b.tvStatCount.text = s.count.toString()
        b.tvStatTotal.text = ms(s.totalNanos)
        b.tvStatAvg.text = ms(if (s.count == 0) 0L else s.totalNanos / s.count)
        b.tvStatMax.text = ms(s.maxNanos)
        b.tvStatTagLoss.text = s.tagLosses.toString()
        b.tvStatRefused.text = s.refusals.toString()
        b.tvStatTransport.text = s.transportFailures.toString()
        b.tvStatCardErrors.text = s.cardErrors.toString()
        val slowest = s.perIns.maxByOrNull { it.value.maxNanos }
        b.tvStatSlowest.visibility = if (slowest != null) View.VISIBLE else View.GONE
        if (slowest != null) {
            b.tvStatSlowest.text = ctx.getString(R.string.lab_stat_slowest_value, slowest.key, (slowest.value.maxNanos / 1_000_000L).toString())
        }
    }

    private fun bindExchange(b: ItemLabExchangeBinding, e: ApduExchange) {
        val ctx = b.root.context
        b.tvSeq.text = ctx.getString(R.string.lab_seq, e.sequence)
        b.tvIns.text = e.insName
        val sw = e.swHex?.let { hex -> e.swName?.let { "$hex $it" } ?: hex } ?: e.outcome.name
        b.tvDetail.text = ctx.getString(R.string.lab_exchange_detail, e.lc, sw, e.responseLength, e.elapsedMillis.toString())
        val tone = toneOf(e)
        LabColors.rounded(b.outcomeDot, LabColors.foreground(ctx, tone))
        b.root.contentDescription = "${e.insName}, ${b.tvDetail.text}"
    }

    /** Four columns (two pairs side by side) or two (each row's pairs stacked). */
    private fun reflow(b: ItemLabStatsBinding, columns: Int) {
        val stacked = columns == 2
        for ((row, pairs) in listOf(
            b.rowStatsTiming to listOf(b.pairStatsCount, b.pairStatsTime),
            b.rowStatsOutcomes to listOf(b.pairStatsLink, b.pairStatsErrors)
        )) {
            row.orientation = if (stacked) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
            pairs.forEachIndexed { i, pair ->
                val lp = pair.layoutParams as LinearLayout.LayoutParams
                lp.width = if (stacked) ViewGroup.LayoutParams.MATCH_PARENT else 0
                lp.weight = if (stacked) 0f else 1f
                lp.topMargin = if (stacked && i > 0) b.root.resources.getDimensionPixelSize(R.dimen.lab_stats_row_gap) else 0
                pair.layoutParams = lp
            }
        }
    }

    private object Diff : DiffUtil.ItemCallback<TraceItem>() {
        override fun areItemsTheSame(oldItem: TraceItem, newItem: TraceItem) = oldItem.key == newItem.key && oldItem::class == newItem::class
        override fun areContentsTheSame(oldItem: TraceItem, newItem: TraceItem) = oldItem == newItem
    }

    private companion object {
        const val SECTION = 0
        const val STATS = 1
        const val EXCHANGE = 2
    }
}

/**
 * The trace row's dot: OK passes; a documented normal answer (GET_LAST_TRANSFER's
 * `6A83` on a card that never signed, [ApduNames.isExpectedStatus]) is
 * informational, never an error; any other status word warns; a refusal,
 * tag loss or transport failure fails.
 */
internal fun toneOf(e: ApduExchange): CheckStatus = when (e.outcome) {
    ApduExchange.Outcome.OK -> CheckStatus.PASS
    ApduExchange.Outcome.CARD_ERROR -> if (ApduNames.isExpectedStatus(e.cla, e.ins, e.sw)) CheckStatus.INFO else CheckStatus.WARN
    else -> CheckStatus.FAIL
}

/** How many columns the Trace stats grid uses. */
internal object StatsGrid {
    /** Font scale from which the eight figures reflow to two columns (130 % in the verification matrix). */
    private const val LARGE_FONT_PERCENT = 115

    /** Below this width four columns of labels do not fit even at 100 %. */
    private const val NARROW_WIDTH_DP = 360

    fun columns(fontScale: Float, screenWidthDp: Int): Int =
        if ((fontScale * 100).toInt() >= LARGE_FONT_PERCENT || (screenWidthDp in 1 until NARROW_WIDTH_DP)) 2 else 4
}

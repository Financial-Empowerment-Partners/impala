package com.payala.impala.demo.ui.log

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import androidx.annotation.VisibleForTesting
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ActivityLogViewerBinding
import com.payala.impala.demo.databinding.ItemLogEntryBinding
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.log.LogFilter
import com.payala.impala.demo.ui.common.applyEdgeToEdge
import com.payala.impala.demo.ui.common.padForSystemBars
import com.payala.impala.demo.ui.lab.adapters.LabColors
import com.payala.impala.demo.ui.lab.CheckStatus

/**
 * The Activity Log: a live, filterable list of the in-memory [AppLogger]
 * ring (ISO-8601 UTC times, `lib.`-prefixed lines from impala-lib).
 *
 * Level chips and search filter ([LogFilter]); Follow keeps the newest entry
 * in view (the list is always chronological). Tapping an entry expands it
 * with its full timestamp and a Copy button. The overflow shares the log as
 * text, copies it all (the clip is marked sensitive on Android 13+), or
 * clears it after a confirmation. Reachable after login only.
 */
class LogViewerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLogViewerBinding
    private lateinit var adapter: LogAdapter
    private var filter = LogFilter()
    private val handler = Handler(Looper.getMainLooper())
    private var refreshPending = false

    /** Coalesces bursts of log lines into one list update. */
    private val listener = object : AppLogger.Listener {
        override fun onEntry(entry: AppLogger.Entry) = scheduleRefresh()
        override fun onCleared() = scheduleRefresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        applyEdgeToEdge()
        super.onCreate(savedInstanceState)
        binding = ActivityLogViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.title_activity_log)

        adapter = LogAdapter(::copyEntry)
        binding.rvLog.layoutManager = LinearLayoutManager(this)
        binding.rvLog.adapter = adapter
        binding.rvLog.itemAnimator = null
        binding.rvLog.padForSystemBars(bottom = true)
        binding.rvLog.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrollStateChanged(rv: RecyclerView, newState: Int) {
                // Dragging away from the bottom stops following; the switch says so.
                if (newState == RecyclerView.SCROLL_STATE_DRAGGING && rv.canScrollVertically(1)) {
                    binding.switchFollow.isChecked = false
                }
            }
        })

        savedInstanceState?.let { state ->
            val hidden = state.getStringArrayList(STATE_HIDDEN_LEVELS).orEmpty()
            filter = LogFilter(
                levels = LogFilter.ALL_LEVELS.filterNot { it.name in hidden }.toSet(),
                query = state.getString(STATE_QUERY).orEmpty()
            )
            binding.switchFollow.isChecked = state.getBoolean(STATE_FOLLOW, true)
        }
        bindLevelChip(binding.chipDebug, AppLogger.Level.DEBUG)
        bindLevelChip(binding.chipInfo, AppLogger.Level.INFO)
        bindLevelChip(binding.chipWarn, AppLogger.Level.WARN)
        bindLevelChip(binding.chipError, AppLogger.Level.ERROR)
        binding.etSearch.setText(filter.query)
        binding.etSearch.doAfterTextChanged {
            filter = filter.withQuery(it?.toString().orEmpty())
            refresh()
        }
        binding.switchFollow.setOnCheckedChangeListener { _, checked -> if (checked) scrollToEnd() }
        refresh()
    }

    override fun onStart() {
        super.onStart()
        AppLogger.addListener(listener)
        refresh()
    }

    override fun onStop() {
        AppLogger.removeListener(listener)
        handler.removeCallbacksAndMessages(null)
        refreshPending = false
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(STATE_HIDDEN_LEVELS, ArrayList(LogFilter.ALL_LEVELS.filterNot { it in filter.levels }.map { it.name }))
        outState.putString(STATE_QUERY, filter.query)
        outState.putBoolean(STATE_FOLLOW, binding.switchFollow.isChecked)
    }

    private fun bindLevelChip(chip: Chip, level: AppLogger.Level) {
        chip.isChecked = level in filter.levels
        chip.setOnCheckedChangeListener { _, checked ->
            filter = filter.withLevel(level, checked)
            refresh()
        }
    }

    private fun scheduleRefresh() {
        if (refreshPending) return
        refreshPending = true
        handler.postDelayed({
            refreshPending = false
            refresh()
        }, REFRESH_DELAY_MS)
    }

    @VisibleForTesting
    internal fun refresh() {
        val all = AppLogger.getEntries()
        val shown = filter.apply(all)
        val follow = binding.switchFollow.isChecked
        adapter.submitList(shown) { if (follow) scrollToEnd() }
        binding.tvLogCount.text = if (filter.isIdentity) getString(R.string.log_entry_count, all.size)
        else getString(R.string.logview_count, shown.size, all.size)
        binding.tvEmpty.visibility = if (shown.isEmpty()) View.VISIBLE else View.GONE
        binding.tvEmpty.setText(if (all.isEmpty()) R.string.log_empty else R.string.logview_no_match)
    }

    private fun scrollToEnd() {
        val n = adapter.itemCount
        if (n > 0) binding.rvLog.scrollToPosition(n - 1)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.log_viewer_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        android.R.id.home -> {
            finish()
            true
        }
        R.id.action_share_log -> {
            shareLog()
            true
        }
        R.id.action_copy_log -> {
            copyAll()
            true
        }
        R.id.action_clear_log -> {
            confirmClear()
            true
        }
        else -> super.onOptionsItemSelected(item)
    }

    private fun copyEntry(entry: AppLogger.Entry) {
        clipboard().setPrimaryClip(ClipData.newPlainText(getString(R.string.title_activity_log), entry.toString()))
        snackbar(getString(R.string.logview_entry_copied))
    }

    private fun copyAll() {
        val clip = ClipData.newPlainText(getString(R.string.title_activity_log), buildLogExport())
        // Android 13+: keep the log out of the clipboard preview and keyboard suggestions.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        clipboard().setPrimaryClip(clip)
        snackbar(getString(R.string.log_copied))
    }

    private fun shareLog() {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, getString(R.string.logview_share_subject, BuildConfig.VERSION_NAME))
            putExtra(Intent.EXTRA_TEXT, buildLogExport())
        }
        startActivity(Intent.createChooser(intent, getString(R.string.log_share_title)))
    }

    private fun confirmClear() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.logview_clear_title)
            .setMessage(R.string.logview_clear_message)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.logview_clear) { _, _ ->
                AppLogger.clear()
                refresh()
                snackbar(getString(R.string.log_cleared))
            }
            .show()
    }

    private fun clipboard() = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private fun snackbar(text: CharSequence) = Snackbar.make(binding.root, text, Snackbar.LENGTH_SHORT).show()

    private fun buildLogExport(): String = buildString {
        appendLine("=== Impala Demo Application Log ===")
        appendLine("Version: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("Build Type: ${BuildConfig.BUILD_TYPE}")
        appendLine("Flavor: ${BuildConfig.FLAVOR}")
        appendLine("Bridge URL: ${BuildConfig.BRIDGE_BASE_URL}")
        appendLine("Exported: ${AppLogger.iso(System.currentTimeMillis())}")
        appendLine("Entries: ${AppLogger.size()}")
        appendLine("===================================")
        appendLine()
        append(AppLogger.getLogText())
    }

    /** Rows of [AppLogger.Entry]; a tap expands one (full timestamp + Copy). */
    private class LogAdapter(private val onCopy: (AppLogger.Entry) -> Unit) :
        ListAdapter<AppLogger.Entry, LogAdapter.Holder>(Diff) {

        private val expanded = HashSet<Long>()

        class Holder(val b: ItemLogEntryBinding) : RecyclerView.ViewHolder(b.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            Holder(ItemLogEntryBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun onBindViewHolder(holder: Holder, position: Int) {
            val e = getItem(position)
            val b = holder.b
            val ctx = b.root.context
            val tone = toneOf(e.level)
            LabColors.rounded(b.levelDot, LabColors.foreground(ctx, tone))
            LabColors.rounded(b.tvTag, LabColors.attr(ctx, com.google.android.material.R.attr.colorSurfaceContainerHighest))
            b.tvTime.text = e.timestamp.substring(TIME_START)
            b.tvTag.text = e.tag
            b.tvLevel.text = e.level.name
            b.tvLevel.setTextColor(LabColors.foreground(ctx, tone))
            b.tvMessage.text = e.message
            val open = e.seq in expanded
            b.tvMessage.maxLines = if (open) Int.MAX_VALUE else COLLAPSED_LINES
            b.expanded.visibility = if (open) View.VISIBLE else View.GONE
            b.tvFullTime.text = e.timestamp
            b.btnCopyEntry.setOnClickListener { onCopy(e) }
            b.root.setOnClickListener {
                if (!expanded.remove(e.seq)) expanded.add(e.seq)
                notifyItemChanged(holder.bindingAdapterPosition)
            }
        }

        private fun toneOf(level: AppLogger.Level): CheckStatus? = when (level) {
            AppLogger.Level.DEBUG -> null
            AppLogger.Level.INFO -> CheckStatus.INFO
            AppLogger.Level.WARN -> CheckStatus.WARN
            AppLogger.Level.ERROR -> CheckStatus.FAIL
        }

        private object Diff : DiffUtil.ItemCallback<AppLogger.Entry>() {
            override fun areItemsTheSame(oldItem: AppLogger.Entry, newItem: AppLogger.Entry) = oldItem.seq == newItem.seq
            override fun areContentsTheSame(oldItem: AppLogger.Entry, newItem: AppLogger.Entry) = oldItem == newItem
        }

        private companion object {
            /** `2026-11-08T` is dropped in the row; the expanded row shows the full timestamp. */
            const val TIME_START = 11
            const val COLLAPSED_LINES = 3
        }
    }

    private companion object {
        const val REFRESH_DELAY_MS = 150L
        const val STATE_HIDDEN_LEVELS = "log.hiddenLevels"
        const val STATE_QUERY = "log.query"
        const val STATE_FOLLOW = "log.follow"
    }
}

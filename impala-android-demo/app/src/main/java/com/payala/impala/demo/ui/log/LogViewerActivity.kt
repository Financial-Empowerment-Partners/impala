package com.payala.impala.demo.ui.log

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ActivityLogViewerBinding
import com.payala.impala.demo.log.AppLogger

/**
 * Displays the in-memory application log buffer in a scrollable text view.
 *
 * Toolbar actions allow the user to copy the full log to the clipboard,
 * share it via email or another app, or clear the buffer. The log auto-scrolls
 * to the bottom on open so the most recent entries are visible.
 */
class LogViewerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLogViewerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLogViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.title_activity_log)

        refreshLog()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.log_viewer_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            R.id.action_copy_log -> {
                copyLogToClipboard()
                true
            }
            R.id.action_email_log -> {
                sendLogViaEmail()
                true
            }
            R.id.action_clear_log -> {
                AppLogger.clear()
                refreshLog()
                Snackbar.make(binding.root, R.string.log_cleared, Snackbar.LENGTH_SHORT).show()
                true
            }
            R.id.action_refresh_log -> {
                refreshLog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun refreshLog() {
        val entries = AppLogger.getEntries()
        if (entries.isEmpty()) {
            binding.tvLogContent.text = getString(R.string.log_empty)
            binding.tvLogCount.visibility = View.GONE
        } else {
            binding.tvLogContent.text = entries.joinToString("\n") { it.toString() }
            binding.tvLogCount.visibility = View.VISIBLE
            binding.tvLogCount.text = getString(R.string.log_entry_count, entries.size)
            // Scroll to bottom to show most recent entries
            binding.scrollView.post {
                binding.scrollView.fullScroll(View.FOCUS_DOWN)
            }
        }
    }

    private fun copyLogToClipboard() {
        val logText = buildLogExport()
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Impala Log", logText))
        Snackbar.make(binding.root, R.string.log_copied, Snackbar.LENGTH_SHORT).show()
    }

    private fun sendLogViaEmail() {
        val logText = buildLogExport()
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "Impala Demo Log - ${BuildConfig.VERSION_NAME}")
            putExtra(Intent.EXTRA_TEXT, logText)
        }
        startActivity(Intent.createChooser(intent, getString(R.string.log_share_title)))
    }

    private fun buildLogExport(): String {
        val header = buildString {
            appendLine("=== Impala Demo Application Log ===")
            appendLine("Version: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            appendLine("Build Type: ${BuildConfig.BUILD_TYPE}")
            appendLine("Bridge URL: ${BuildConfig.BRIDGE_BASE_URL}")
            appendLine("Entries: ${AppLogger.size()}")
            appendLine("===================================")
            appendLine()
        }
        return header + AppLogger.getLogText()
    }
}

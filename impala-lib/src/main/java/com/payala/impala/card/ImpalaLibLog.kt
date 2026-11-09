package com.payala.impala.card

import android.util.Log

/** Receives every line impala-lib logs (priority is an `android.util.Log` level). */
fun interface LibLogSink {
    fun log(priority: Int, tag: String, message: String)
}

/**
 * impala-lib's one logger: every line goes to `android.util.Log` and, when an
 * app installs a [sink], to the app's own log as well. Lines are terse and
 * never carry card data, credentials or coordinates (`LogHygieneTest` scans
 * every call). A sink that throws is ignored: logging never fails a card flow.
 */
object ImpalaLibLog {
    @Volatile
    @JvmStatic
    var sink: LibLogSink? = null

    @JvmStatic
    fun d(tag: String, msg: String) = emit(Log.DEBUG, tag, msg)

    @JvmStatic
    fun i(tag: String, msg: String) = emit(Log.INFO, tag, msg)

    @JvmStatic
    fun w(tag: String, msg: String) = emit(Log.WARN, tag, msg)

    @JvmStatic
    fun e(tag: String, msg: String) = emit(Log.ERROR, tag, msg)

    private fun emit(priority: Int, tag: String, msg: String) {
        try {
            Log.println(priority, tag, msg)
        } catch (_: RuntimeException) {
            // Plain JVM unit tests without android.util.Log.
        }
        val s = sink ?: return
        try {
            s.log(priority, tag, msg)
        } catch (_: Throwable) {
        }
    }
}

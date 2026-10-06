package com.payala.impala.card

import android.os.Looper

/**
 * Card I/O blocks for tens to hundreds of milliseconds per APDU; doing it on
 * the main thread risks an ANR. Every entry point that talks to a card calls
 * this first.
 */
internal fun requireBackgroundThread(what: String) {
    check(Looper.myLooper() != Looper.getMainLooper()) { "$what must not run on the main thread" }
}

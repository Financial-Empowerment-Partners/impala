package com.payala.impala.card

/**
 * A personal or financial value (holder name, balance, last transfer) that
 * renders as `••••` everywhere — `toString()`, string templates, logs, crash
 * reports — and is read only through an explicit [reveal]. Equality is
 * identity, so a masked value cannot be probed by comparison.
 */
class Masked<T>(private val value: T) {
    /** The value itself; callers reveal it only to its owner (a matching session). */
    fun reveal(): T = value

    override fun toString(): String = MASK

    companion object {
        const val MASK = "••••"
    }
}

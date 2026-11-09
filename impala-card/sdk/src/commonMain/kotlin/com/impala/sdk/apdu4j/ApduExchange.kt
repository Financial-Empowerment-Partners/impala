package com.impala.sdk.apdu4j

/** Receives one [ApduExchange] per traced command (see [TracingBibo]). */
fun interface ApduExchangeHook {
    fun onExchange(exchange: ApduExchange)
}

/**
 * One command/response exchange, **header only**: CLA, INS, P1, P2, the
 * command data length, the status word, the response data length and the
 * elapsed time. There is deliberately no byte field and no free-text field, so
 * PINs, challenges, signables, signatures and credit tails can never leave the
 * transport through a trace (`TracingBiboTest` pins this by reflection). The
 * derived names below are computed, not stored.
 *
 * @property lc command data length (Nc): 0 for header-only commands, decoded
 *   from the 3-byte form for extended-length commands
 * @property sw the status word, or null when no response arrived (tag loss,
 *   refusal, transport failure, or a response shorter than 2 bytes)
 * @property responseLength response data bytes, excluding the status word
 * @property sequence 1-based position of this exchange in its transport
 */
class ApduExchange(
    val cla: Int,
    val ins: Int,
    val p1: Int,
    val p2: Int,
    val lc: Int,
    val sw: Int?,
    val responseLength: Int,
    val elapsedNanos: Long,
    val outcome: Outcome,
    val sequence: Int
) {
    enum class Outcome {
        /** The card answered 9000. */
        OK,
        /** The card answered another status word. */
        CARD_ERROR,
        /** The card left the field mid-exchange. */
        TAG_LOST,
        /** A read-only session refused the command; nothing was sent. */
        REFUSED,
        /** The transport failed, or returned no usable response. */
        TRANSPORT_FAILURE
    }

    /** The instruction's name, e.g. `GET_VERSION` (see [ApduNames.ins]). */
    val insName: String get() = ApduNames.ins(cla, ins)

    /** The status word as 4 upper-case hex digits (`9000`), or null. */
    val swHex: String? get() = sw?.let { ApduNames.hex(it, 4) }

    /** The status word's name (see [ApduNames.sw]), or null. */
    val swName: String? get() = sw?.let { ApduNames.sw(it) }

    val elapsedMillis: Long get() = elapsedNanos / 1_000_000L

    /** `GET_VERSION 9000 12ms` — never any bytes. */
    override fun toString(): String = insName + " " + (swHex ?: outcome.name) + " " + elapsedMillis + "ms"
}

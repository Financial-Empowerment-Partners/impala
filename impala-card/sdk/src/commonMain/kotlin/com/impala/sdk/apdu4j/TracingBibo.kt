package com.impala.sdk.apdu4j

import kotlin.time.TimeSource

/**
 * A [BIBO] decorator that reports one header-only [ApduExchange] per command to
 * [hook]: header, Lc, status word, response length, elapsed time and outcome.
 * No command or response bytes ever reach the hook.
 *
 * The decorator never changes what the transport does:
 * - the command and the response pass through unchanged;
 * - a command that is null or shorter than the 4-byte header is forwarded
 *   untouched and not reported (there is no header to report);
 * - any [Throwable] from [inner] is reported (tag lost, refused, transport
 *   failure) and rethrown as the same instance;
 * - the hook runs inside `try/catch(Throwable)`, so a failing hook can neither
 *   replace the transport's exception nor fail a successful exchange.
 *
 * Wrap a read-only guard inside it, `TracingBibo(ReadOnlyBibo(transport))`, so
 * refusals appear in the trace as [ApduExchange.Outcome.REFUSED].
 *
 * Not thread-safe, like every [BIBO]: one card session drives one transport.
 */
class TracingBibo(
    private val inner: BIBO,
    private val hook: ApduExchangeHook,
    private val clock: TimeSource = TimeSource.Monotonic
) : BIBO {
    private var sequence = 0

    override fun transceive(bytes: ByteArray?): ByteArray? {
        if (bytes == null || bytes.size < 4) return inner.transceive(bytes)
        val cla = bytes[0].toInt() and 0xFF
        val ins = bytes[1].toInt() and 0xFF
        val p1 = bytes[2].toInt() and 0xFF
        val p2 = bytes[3].toInt() and 0xFF
        val lc = commandDataLength(bytes)
        val seq = ++sequence
        val mark = clock.markNow()
        val response: ByteArray?
        try {
            response = inner.transceive(bytes)
        } catch (t: Throwable) {
            val outcome = when (t) {
                is BIBOTagLostException -> ApduExchange.Outcome.TAG_LOST
                is ReadOnlyViolationException -> ApduExchange.Outcome.REFUSED
                else -> ApduExchange.Outcome.TRANSPORT_FAILURE
            }
            report(ApduExchange(cla, ins, p1, p2, lc, null, 0, mark.elapsedNow().inWholeNanoseconds, outcome, seq))
            throw t
        }
        val elapsed = mark.elapsedNow().inWholeNanoseconds
        val exchange = if (response == null || response.size < 2) {
            ApduExchange(cla, ins, p1, p2, lc, null, 0, elapsed, ApduExchange.Outcome.TRANSPORT_FAILURE, seq)
        } else {
            val sw = ((response[response.size - 2].toInt() and 0xFF) shl 8) or (response[response.size - 1].toInt() and 0xFF)
            val outcome = if (sw == 0x9000) ApduExchange.Outcome.OK else ApduExchange.Outcome.CARD_ERROR
            ApduExchange(cla, ins, p1, p2, lc, sw, response.size - 2, elapsed, outcome, seq)
        }
        report(exchange)
        return response
    }

    override fun close() = inner.close()

    private fun report(exchange: ApduExchange) {
        try {
            hook.onExchange(exchange)
        } catch (_: Throwable) {
            // A trace consumer must never change the card exchange's outcome.
        }
    }

    internal companion object {
        /** Nc from a command's length bytes (short or extended form); 0 when the command has no data. */
        fun commandDataLength(cmd: ByteArray): Int {
            if (cmd.size <= 5) return 0                      // case 1, case 2s
            val b4 = cmd[4].toInt() and 0xFF
            if (b4 != 0) return b4                           // case 3s, 4s
            if (cmd.size <= 7) return 0                      // case 2e (or malformed)
            return ((cmd[5].toInt() and 0xFF) shl 8) or (cmd[6].toInt() and 0xFF)  // case 3e, 4e
        }
    }
}

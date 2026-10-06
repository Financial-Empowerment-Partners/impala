package com.impala.sdk.apdu4j

import javax.smartcardio.Card
import javax.smartcardio.CardChannel
import javax.smartcardio.CardException
import javax.smartcardio.CardTerminal
import javax.smartcardio.CommandAPDU as JCommandAPDU
import javax.smartcardio.TerminalFactory

/**
 * [BIBO] over a PC/SC reader (`javax.smartcardio`), for the issuance tool and
 * physical-card evidence runs on a desktop.
 *
 * [connect] picks the first terminal with a card present whose name contains
 * [terminalNameFilter] (case-insensitive; any when null), connects T=1 when
 * available and selects the applet by [aidHex]. [close] disconnects without
 * resetting the card. Commands with more than 255 data bytes (or any
 * extended-length encoding) are refused before the terminal is touched: the
 * largest Impala command is VERIFY_TRANSFER_V2 P1=01 at 209 bytes, so a longer
 * one is a caller bug, never something to truncate.
 *
 * APDU bytes are never logged; [debugTrace] (PIN/key bytes masked by
 * [ApduTrace.mask]) is the only way to observe traffic.
 */
class PcscBibo internal constructor(
    private val terminalNameFilter: String?,
    private val aidHex: String,
    private val debugTrace: ApduTraceHook?,
    private val terminals: () -> List<CardTerminal>
) : BIBO {

    @JvmOverloads
    constructor(
        terminalNameFilter: String? = null,
        aidHex: String = DEFAULT_APPLET_AID,
        debugTrace: ApduTraceHook? = null
    ) : this(terminalNameFilter, aidHex, debugTrace, { TerminalFactory.getDefault().terminals().list() })

    private var card: Card? = null
    private var channel: CardChannel? = null

    /** The name of the connected terminal, or null before [connect]. */
    var terminalName: String? = null
        private set

    /** Connects to the reader and SELECTs the applet; idempotent while connected. */
    @Throws(BIBOException::class)
    fun connect(): PcscBibo {
        if (channel != null) return this
        try {
            val terminal = terminals().firstOrNull { t ->
                (terminalNameFilter == null || t.name.contains(terminalNameFilter, ignoreCase = true)) && t.isCardPresent
            } ?: throw BIBOException(
                if (terminalNameFilter == null) "no PC/SC reader with a card present"
                else "no PC/SC reader matching \"$terminalNameFilter\" with a card present"
            )
            val c = try { terminal.connect("T=1") } catch (_: CardException) { terminal.connect("*") }
            card = c
            channel = c.basicChannel
            terminalName = terminal.name
            val select = transceive(selectCommand(aidHex))
            val sw = sw(select)
            if (sw != 0x9000) {
                close()
                throw BIBOException("SELECT ${aidHex.uppercase()} failed: SW=${sw.toString(16).uppercase().padStart(4, '0')}")
            }
        } catch (e: CardException) {
            close()
            throw BIBOException("PC/SC connect failed: ${e.message}", e)
        }
        return this
    }

    @Throws(BIBOException::class)
    override fun transceive(bytes: ByteArray?): ByteArray {
        requireNotNull(bytes) { "APDU bytes must not be null" }
        refuseOversized(bytes)
        val ch = channel ?: throw BIBOException("PC/SC channel is not connected")
        val resp = try {
            ch.transmit(JCommandAPDU(bytes)).bytes
        } catch (e: CardException) {
            close()
            throw BIBOException("PC/SC transmit failed: ${e.message}", e)
        } catch (e: IllegalStateException) {
            close()
            throw BIBOException("PC/SC transmit failed: ${e.message}", e)
        }
        debugTrace?.invoke(ApduTrace.mask(bytes), resp)
        return resp
    }

    /** Disconnects without a card reset; idempotent. */
    override fun close() {
        val c = card
        card = null
        channel = null
        terminalName = null
        try {
            c?.disconnect(false)
        } catch (_: CardException) {
            // Already gone (card removed / reader unplugged): nothing to release.
        }
    }

    companion object {
        /** Applet-instance AID (`applet.aid.app` in applet/build.xml). */
        const val DEFAULT_APPLET_AID = "01020304050607080102"

        /** Short-APDU data limit; anything longer is refused, never truncated. */
        const val MAX_DATA_LENGTH = 255

        internal fun refuseOversized(bytes: ByteArray) {
            if (bytes.size < 4) throw BIBOException("APDU shorter than its 4-byte header")
            if (bytes.size > 5 && bytes[4].toInt() == 0) {
                throw BIBOException("extended-length APDUs are not supported (data must be <= $MAX_DATA_LENGTH bytes)")
            }
            if (bytes.size > 4 + 1 + MAX_DATA_LENGTH + 1) {
                throw BIBOException("APDU data exceeds $MAX_DATA_LENGTH bytes (${bytes.size} total)")
            }
        }

        internal fun selectCommand(aidHex: String): ByteArray {
            require(aidHex.length % 2 == 0 && aidHex.length in 10..32) { "AID must be 5..16 bytes of hex" }
            val aid = aidHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            return byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid
        }

        private fun sw(resp: ByteArray): Int =
            if (resp.size < 2) -1
            else ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)
    }
}

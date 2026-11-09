package com.payala.impala.card

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB

/**
 * Tag-layer facts about the card a session was opened on: the ISO 14443-3/-4
 * metadata Android reports, read once when the session opens. This class is
 * the only place in the library that reads them. All hex is upper case with no
 * separators; a fact the platform did not report is null (NFC-A fields on an
 * NFC-B card and vice versa).
 *
 * @property iso14443Part4 the tag speaks ISO 14443-4 (the only kind a session opens on)
 * @property maxTransceiveLength the largest command the platform will send (0 = unknown)
 * @property timeoutMs the per-command timeout the session set
 */
class CardTransportFacts(
    val uidHex: String,
    val techList: List<String>,
    val iso14443Part4: Boolean,
    val maxTransceiveLength: Int,
    val extendedLengthSupported: Boolean,
    val timeoutMs: Int,
    val historicalBytesHex: String?,
    val hiLayerResponseHex: String?,
    val atqaHex: String?,
    val sak: Int?,
    val nfcBApplicationDataHex: String?,
    val nfcBProtocolInfoHex: String?
) {
    override fun toString(): String =
        "CardTransportFacts(uid=$uidHex, techs=$techList, iso14443Part4=$iso14443Part4, max=$maxTransceiveLength)"

    companion object {
        /**
         * Reads the facts of [tag] and, when the session connected over ISO
         * 14443-4, of [isoDep]. Never throws: an unreadable fact is null (or
         * 0 / false for the numeric ones).
         */
        @JvmStatic
        fun of(tag: Tag, isoDep: IsoDep?): CardTransportFacts {
            val nfcA = attempt { NfcA.get(tag) }
            val nfcB = attempt { NfcB.get(tag) }
            return CardTransportFacts(
                uidHex = hex(attempt { tag.id }) ?: "",
                techList = attempt { tag.techList?.map { it.substringAfterLast('.') } } ?: emptyList(),
                iso14443Part4 = isoDep != null,
                maxTransceiveLength = attempt { isoDep?.maxTransceiveLength } ?: 0,
                extendedLengthSupported = attempt { isoDep?.isExtendedLengthApduSupported } ?: false,
                timeoutMs = attempt { isoDep?.timeout } ?: 0,
                historicalBytesHex = hex(attempt { isoDep?.historicalBytes }),
                hiLayerResponseHex = hex(attempt { isoDep?.hiLayerResponse }),
                atqaHex = hex(attempt { nfcA?.atqa }),
                sak = attempt { nfcA?.sak?.toInt()?.and(0xFF) },
                nfcBApplicationDataHex = hex(attempt { nfcB?.applicationData }),
                nfcBProtocolInfoHex = hex(attempt { nfcB?.protocolInfo })
            )
        }

        /** Upper-case hex without separators, or null for null. */
        @JvmStatic
        fun hex(bytes: ByteArray?): String? {
            if (bytes == null) return null
            val digits = "0123456789ABCDEF"
            val out = StringBuilder(bytes.size * 2)
            for (b in bytes) {
                val v = b.toInt() and 0xFF
                out.append(digits[v ushr 4]).append(digits[v and 0x0F])
            }
            return out.toString()
        }

        private inline fun <T> attempt(block: () -> T?): T? = try {
            block()
        } catch (_: Exception) {
            null
        }
    }
}

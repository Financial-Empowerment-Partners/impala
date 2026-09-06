package com.impala.sdk.models

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * Pure byte-format builders for the issuer-certified transfer protocol
 * (applet 0.2, transfer protocol v1). No crypto and no I/O: everything here
 * is reproducible host-side and pinned byte-for-byte by
 * `TransferProtocolGoldenTest` against the vectors the bridge pins too
 * (`impala-bridge/src/handlers/card_auth.rs`).
 *
 * The two messages a card signs or verifies:
 *
 * - **XFER message** (89 bytes): `"IMPALA-XFER:"(12) ‖ 0x01 ‖ programId(16) ‖ signable(60)`.
 *   ECDSA-P256/SHA-256 over this is the transfer signature; its SHA-256 is the
 *   canonical `transfer_id`.
 * - **CERT message** (114 bytes): `"IMPALA-CERT:"(12) ‖ 0x01 ‖ programId(16) ‖
 *   accountId(16) ‖ currency(4) ‖ cardPubKey(65)`. The issuer's ECDSA over this
 *   is the card certificate carried in the third 72-byte slot of every transfer
 *   envelope; its SHA-256 is the `cert_id`.
 *
 * Both tags differ from `"IMPALA-AUTH:"` in their last four bytes at equal
 * length, so the three signing domains cannot collide.
 */
object TransferProtocol {
    /** ASCII "IMPALA-XFER:" — `49 4D 50 41 4C 41 2D 58 46 45 52 3A`. */
    val XFER_DOMAIN_TAG: ByteArray = "IMPALA-XFER:".encodeToByteArray()

    /** ASCII "IMPALA-CERT:" — `49 4D 50 41 4C 41 2D 43 45 52 54 3A`. */
    val CERT_DOMAIN_TAG: ByteArray = "IMPALA-CERT:".encodeToByteArray()

    /** Transfer protocol version byte (the untagged v0 envelope is retired). */
    const val TRANSFER_VERSION: Byte = 0x01

    /** Certificate message version byte. */
    const val CERT_VERSION: Byte = 0x01

    /** Largest forward jump a receiving card accepts over its last counter (shared with the bridge). */
    const val MAX_COUNTER_JUMP: Int = 1024

    const val PROGRAM_ID_LENGTH = 16
    const val ACCOUNT_ID_LENGTH = 16
    const val CURRENCY_LENGTH = 4
    const val PUB_KEY_LENGTH = 65
    const val SIGNABLE_LENGTH = 60
    const val XFER_MESSAGE_LENGTH = 89
    const val CERT_MESSAGE_LENGTH = 114
    const val SLOT_LENGTH = 72
    const val MIN_DER_LENGTH = 8

    // Currency tags shared with the bridge's CARD_CURRENCY_TAGS. The card treats
    // the 4 bytes as opaque; these are the only tags the bridge issues.
    val CURRENCY_XLM: ByteArray get() = byteArrayOf(0x58, 0x4C, 0x4D, 0x00)   // "XLM\0"
    val CURRENCY_USDC: ByteArray get() = "USDC".encodeToByteArray()
    val CURRENCY_USDT0: ByteArray get() = "UST0".encodeToByteArray()

    /** Maps a bridge currency code ("XLM", "USDC", "USDT0") to its 4-byte card tag. */
    fun currencyTag(code: String): ByteArray = when (code) {
        "XLM" -> CURRENCY_XLM
        "USDC" -> CURRENCY_USDC
        "USDT0" -> CURRENCY_USDT0
        else -> throw IllegalArgumentException("unknown card currency code: $code")
    }

    /** `"IMPALA-XFER:" ‖ 0x01 ‖ programId ‖ signable` — the 89 bytes a card signs. */
    fun xferMessage(programId: ByteArray, signable: ByteArray): ByteArray {
        require(programId.size == PROGRAM_ID_LENGTH) { "programId must be $PROGRAM_ID_LENGTH bytes" }
        require(signable.size == SIGNABLE_LENGTH) { "signable must be $SIGNABLE_LENGTH bytes" }
        val out = ByteArray(XFER_MESSAGE_LENGTH)
        XFER_DOMAIN_TAG.copyInto(out, 0)
        out[12] = TRANSFER_VERSION
        programId.copyInto(out, 13)
        signable.copyInto(out, 29)
        return out
    }

    /** `"IMPALA-CERT:" ‖ 0x01 ‖ programId ‖ accountId ‖ currency ‖ cardPubKey` — the 114 bytes an issuer signs. */
    fun certMessage(programId: ByteArray, accountId: ByteArray, currency: ByteArray, cardPubKey: ByteArray): ByteArray {
        require(programId.size == PROGRAM_ID_LENGTH) { "programId must be $PROGRAM_ID_LENGTH bytes" }
        require(accountId.size == ACCOUNT_ID_LENGTH) { "accountId must be $ACCOUNT_ID_LENGTH bytes" }
        require(currency.size == CURRENCY_LENGTH) { "currency must be $CURRENCY_LENGTH bytes" }
        require(cardPubKey.size == PUB_KEY_LENGTH && cardPubKey[0] == 0x04.toByte()) {
            "cardPubKey must be a 65-byte uncompressed point (04 ‖ X ‖ Y)"
        }
        val out = ByteArray(CERT_MESSAGE_LENGTH)
        CERT_DOMAIN_TAG.copyInto(out, 0)
        out[12] = CERT_VERSION
        programId.copyInto(out, 13)
        accountId.copyInto(out, 29)
        currency.copyInto(out, 45)
        cardPubKey.copyInto(out, 49)
        return out
    }

    /** SHA-256 of the XFER message — THE canonical id of a card transfer. */
    fun transferId(programId: ByteArray, signable: ByteArray): ByteString =
        xferMessage(programId, signable).toByteString().sha256()

    /** SHA-256 of the CERT message — the bridge registry / revocation key of a card certificate. */
    fun certId(programId: ByteArray, accountId: ByteArray, currency: ByteArray, cardPubKey: ByteArray): ByteString =
        certMessage(programId, accountId, currency, cardPubKey).toByteString().sha256()

    /**
     * Trims a zero-padded 72-byte DER slot (or any 8..72-byte slot) to the DER
     * signature it carries: `slot[1] + 2` bytes. Throws [IllegalArgumentException]
     * on anything that is not `30 LL …` with `8 <= LL + 2 <= slot.size`.
     */
    fun trimDer(slot: ByteArray): ByteArray {
        require(slot.size in MIN_DER_LENGTH..SLOT_LENGTH) { "DER slot must be $MIN_DER_LENGTH..$SLOT_LENGTH bytes, got ${slot.size}" }
        require(slot[0] == 0x30.toByte()) { "DER signature must start with 0x30" }
        val len = (slot[1].toInt() and 0xFF) + 2
        require(len in MIN_DER_LENGTH..slot.size) { "DER length $len is outside $MIN_DER_LENGTH..${slot.size}" }
        return slot.copyOfRange(0, len)
    }

    /** Zero-pads a DER signature (8..72 bytes) into the fixed 72-byte wire slot. */
    fun padSlot72(der: ByteArray): ByteArray {
        require(der.size in MIN_DER_LENGTH..SLOT_LENGTH) { "DER signature must be $MIN_DER_LENGTH..$SLOT_LENGTH bytes, got ${der.size}" }
        return der.copyOf(SLOT_LENGTH)
    }

    /**
     * The counter a receiving card accepts next: `last + 1`. Throws
     * [IllegalStateException] at `Int.MAX_VALUE` (the stream is exhausted; the
     * card must be replaced).
     */
    fun nextReceiveCounter(last: Int): Int {
        require(last >= 0) { "receive counter must be non-negative" }
        if (last == Int.MAX_VALUE) throw IllegalStateException("receive counter stream exhausted (0x7FFFFFFF)")
        return last + 1
    }

    /**
     * Allocates the next send sequence (`dateTime` in the signable) for a
     * sending card: `max(previous + 1, nowMillis)`. It is a strictly increasing
     * 63-bit per-sender sequence, never a trusted timestamp.
     */
    fun nextSendSequence(previous: Long, nowMillis: Long): Long {
        require(previous >= 0 && nowMillis >= 0) { "sequence values must be non-negative" }
        return maxOf(previous + 1, nowMillis)
    }
}

/**
 * The 60-byte signable a card signs (inside the XFER message) — layout unchanged
 * from protocol v0: `dateTime(8)@0 ‖ sender(16)@8 ‖ recipient(16)@24 ‖
 * currency(4)@40 ‖ amount(4)@44 ‖ phoneId(8)@48 ‖ counter(4)@56`, big-endian.
 *
 * `dateTime` is the sender's send sequence (strictly increasing per sending
 * card; MSB clear), `amount` is an unsigned 32-bit minor-unit amount (never
 * zero), `counter` is the recipient's receive counter (positive, MSB clear).
 */
class Signable(
    val dateTime: Long,
    val sender: ByteArray,
    val recipient: ByteArray,
    val currency: ByteArray,
    val amount: Long,
    val phoneId: Long,
    val counter: Int
) {
    init {
        require(sender.size == 16 && recipient.size == 16 && currency.size == 4) {
            "sender/recipient must be 16 bytes and currency 4 bytes"
        }
        require(amount in 1..0xFFFF_FFFFL) { "amount must be 1..0xFFFFFFFF minor units" }
        require(counter > 0) { "counter must be positive" }
        require(dateTime >= 0) { "dateTime (send sequence) must be non-negative" }
    }

    /** Encodes the 60-byte big-endian signable. */
    fun encode(): ByteArray {
        val out = ByteArray(TransferProtocol.SIGNABLE_LENGTH)
        putLong(out, OFFSET_DATE_TIME, dateTime)
        sender.copyInto(out, OFFSET_SENDER)
        recipient.copyInto(out, OFFSET_RECIPIENT)
        currency.copyInto(out, OFFSET_CURRENCY)
        putInt(out, OFFSET_AMOUNT, amount.toInt())
        putLong(out, OFFSET_PHONE_ID, phoneId)
        putInt(out, OFFSET_COUNTER, counter)
        return out
    }

    override fun equals(other: Any?): Boolean =
        other is Signable && encode().contentEquals(other.encode())

    override fun hashCode(): Int = encode().contentHashCode()

    override fun toString(): String =
        "Signable(dateTime=$dateTime, amount=$amount, counter=$counter, currency=${currency.decodeToString()})"

    companion object {
        const val OFFSET_DATE_TIME = 0
        const val OFFSET_SENDER = 8
        const val OFFSET_RECIPIENT = 24
        const val OFFSET_CURRENCY = 40
        const val OFFSET_AMOUNT = 44
        const val OFFSET_PHONE_ID = 48
        const val OFFSET_COUNTER = 56

        /** Decodes a 60-byte signable; the same validity rules as the constructor apply. */
        fun decode(b: ByteArray): Signable {
            require(b.size == TransferProtocol.SIGNABLE_LENGTH) { "signable must be ${TransferProtocol.SIGNABLE_LENGTH} bytes" }
            return Signable(
                dateTime = getLong(b, OFFSET_DATE_TIME),
                sender = b.copyOfRange(OFFSET_SENDER, OFFSET_RECIPIENT),
                recipient = b.copyOfRange(OFFSET_RECIPIENT, OFFSET_CURRENCY),
                currency = b.copyOfRange(OFFSET_CURRENCY, OFFSET_AMOUNT),
                amount = getInt(b, OFFSET_AMOUNT).toLong() and 0xFFFF_FFFFL,
                phoneId = getLong(b, OFFSET_PHONE_ID),
                counter = getInt(b, OFFSET_COUNTER)
            )
        }

        internal fun putLong(dst: ByteArray, off: Int, v: Long) {
            for (i in 0 until 8) dst[off + i] = (v ushr (8 * (7 - i))).toByte()
        }

        internal fun putInt(dst: ByteArray, off: Int, v: Int) {
            for (i in 0 until 4) dst[off + i] = (v ushr (8 * (3 - i))).toByte()
        }

        internal fun getLong(src: ByteArray, off: Int): Long {
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (src[off + i].toLong() and 0xFF)
            return v
        }

        internal fun getInt(src: ByteArray, off: Int): Int {
            var v = 0
            for (i in 0 until 4) v = (v shl 8) or (src[off + i].toInt() and 0xFF)
            return v
        }
    }
}

/**
 * A complete offline-verifiable transfer: the 60-byte signable plus the
 * 209-byte SIGN_TRANSFER_V2 response (`sig ‖ pubkey ‖ certificate`) with both
 * DER slots trimmed. `signable ‖ tail209()` is the 269-byte envelope a terminal
 * stores and uploads.
 */
class TransferEnvelope(
    val signable: ByteArray,
    val signature: ByteArray,
    val pubKey: ByteArray,
    val certificate: ByteArray
) {
    init {
        require(signable.size == TransferProtocol.SIGNABLE_LENGTH) { "signable must be 60 bytes" }
        require(pubKey.size == TransferProtocol.PUB_KEY_LENGTH) { "pubKey must be 65 bytes" }
        require(signature.size in TransferProtocol.MIN_DER_LENGTH..TransferProtocol.SLOT_LENGTH) { "signature must be 8..72 bytes" }
        require(certificate.size in TransferProtocol.MIN_DER_LENGTH..TransferProtocol.SLOT_LENGTH) { "certificate must be 8..72 bytes" }
    }

    /** The 209-byte VERIFY_TRANSFER_V2 tail: `pad72(sig) ‖ pubKey ‖ pad72(cert)`. */
    fun tail209(): ByteArray =
        TransferProtocol.padSlot72(signature) + pubKey + TransferProtocol.padSlot72(certificate)

    /** `SHA-256(XFER message)` for this envelope under [programId]. */
    fun transferId(programId: ByteArray): ByteString = TransferProtocol.transferId(programId, signable)

    override fun equals(other: Any?): Boolean =
        other is TransferEnvelope && signable.contentEquals(other.signable) && tail209().contentEquals(other.tail209())

    override fun hashCode(): Int = signable.contentHashCode() * 31 + tail209().contentHashCode()
}

/** GET_RECEIVE_STATE: the card's last accepted receive counter and the transfer id it belongs to. */
class ReceiveState(val counter: Int, val lastDigest: ByteString) {
    override fun equals(other: Any?): Boolean =
        other is ReceiveState && counter == other.counter && lastDigest == other.lastDigest

    override fun hashCode(): Int = counter * 31 + lastDigest.hashCode()

    override fun toString(): String = "ReceiveState(counter=$counter, lastDigest=${lastDigest.hex()})"
}

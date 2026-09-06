package com.impala.sdk.models

/**
 * Pure builders/parsers for the card personalization ceremony (applet 0.2):
 * the install-parameter TLV (`gp --params`), PERSONALIZE part A, and the
 * GET_PERSONALIZATION read-back. No crypto, no I/O.
 */
object PersonalizationProtocol {
    const val TAG_INSTALL_PROVISIONING: Byte = 0x01

    /** Gate SIGN_* with 0x6985 until a user PIN is provisioned. */
    const val FLAG_ENFORCE = 0x01
    /** ENC(16) ‖ MAC(16) ‖ DEK(16) follow the flags. */
    const val FLAG_KEYS = 0x02
    /** masterPIN(8 digits) ‖ userPIN(4 digits) follow the keys. */
    const val FLAG_PINS = 0x04
    /** programId(16) ‖ issuerPubKey(65) follow the PINs (requires FLAG_KEYS). */
    const val FLAG_PROGRAM = 0x08

    const val IDENTITY_LENGTH = 40
    const val PERSONALIZATION_LENGTH = 159

    /**
     * Builds the install-parameter TLV
     * `[0x01][flags] [ENC MAC DEK] [masterPIN userPIN] [programId issuerPubKey]`.
     * A program block without custom keys is refused here exactly as the applet
     * refuses it (a program-bound card must never run on the GP default keys).
     */
    fun installParams(
        enforce: Boolean,
        keys: Triple<ByteArray, ByteArray, ByteArray>?,
        pins: Pair<ByteArray, ByteArray>?,
        program: Pair<ByteArray, ByteArray>?
    ): ByteArray {
        require(program == null || keys != null) { "a program block requires custom SCP03 keys (flag 0x08 needs 0x02)" }
        var flags = 0
        if (enforce) flags = flags or FLAG_ENFORCE
        if (keys != null) flags = flags or FLAG_KEYS
        if (pins != null) flags = flags or FLAG_PINS
        if (program != null) flags = flags or FLAG_PROGRAM
        var out = byteArrayOf(TAG_INSTALL_PROVISIONING, flags.toByte())
        keys?.let { (enc, mac, dek) ->
            require(enc.size == 16 && mac.size == 16 && dek.size == 16) { "SCP03 keys must be 16 bytes each" }
            out += enc + mac + dek
        }
        pins?.let { (master, user) ->
            require(master.size == 8 && user.size == 4) { "master PIN is 8 digits, user PIN is 4 digits" }
            out += master + user
        }
        program?.let { (programId, issuerPubKey) ->
            require(programId.size == 16 && issuerPubKey.size == 65 && issuerPubKey[0] == 0x04.toByte()) {
                "programId must be 16 bytes and issuerPubKey a 65-byte uncompressed point"
            }
            out += programId + issuerPubKey
        }
        return out
    }

    /** PERSONALIZE part A (P1=0x01): `accountId(16) ‖ currency(4) ‖ programId(16) ‖ initialReceiveCounter(4)`. */
    fun identityPart(accountId: ByteArray, currency: ByteArray, programId: ByteArray, initialReceiveCounter: Int = 0): ByteArray {
        require(accountId.size == 16 && accountId.any { it != 0.toByte() }) { "accountId must be a non-nil 16-byte UUID" }
        require(currency.size == 4 && currency.any { it != 0.toByte() }) { "currency must be 4 non-zero bytes" }
        require(programId.size == 16 && programId.any { it != 0.toByte() }) { "programId must be 16 non-zero bytes" }
        require(initialReceiveCounter >= 0) { "initialReceiveCounter must be non-negative" }
        val out = ByteArray(IDENTITY_LENGTH)
        accountId.copyInto(out, 0)
        currency.copyInto(out, 16)
        programId.copyInto(out, 20)
        Signable.putInt(out, 36, initialReceiveCounter)
        return out
    }

    /** Parses the 159-byte GET_PERSONALIZATION response. */
    fun parsePersonalization(data: ByteArray): CardPersonalization {
        require(data.size == PERSONALIZATION_LENGTH) { "GET_PERSONALIZATION must be $PERSONALIZATION_LENGTH bytes, got ${data.size}" }
        val issuerPubKey = data.copyOfRange(22, 87)
        val certSlot = data.copyOfRange(87, 159)
        return CardPersonalization(
            state = data[0],
            flags = data[1],
            programId = data.copyOfRange(2, 18),
            currency = data.copyOfRange(18, 22),
            issuerPubKey = if (issuerPubKey.all { it == 0.toByte() }) null else issuerPubKey,
            certificate = if (certSlot.all { it == 0.toByte() }) null else TransferProtocol.trimDer(certSlot)
        )
    }
}

/**
 * GET_PERSONALIZATION read-back. [state] is `0x00` blank, `0x01` initialized,
 * `0x02` personalized, `0xFF` terminated; [flags] carries the orthogonal bits.
 * [issuerPubKey] / [certificate] are `null` while the slot is all zeros.
 */
class CardPersonalization(
    val state: Byte,
    val flags: Byte,
    val programId: ByteArray,
    val currency: ByteArray,
    val issuerPubKey: ByteArray?,
    val certificate: ByteArray?
) {
    val initialized: Boolean get() = flags.toInt() and 0x01 != 0
    val programBound: Boolean get() = flags.toInt() and 0x02 != 0
    val personalized: Boolean get() = flags.toInt() and 0x04 != 0
    val scp03KeysDefault: Boolean get() = flags.toInt() and 0x08 != 0
    val pinProvisioned: Boolean get() = flags.toInt() and 0x10 != 0
    val provisioningEnforced: Boolean get() = flags.toInt() and 0x20 != 0
    val terminated: Boolean get() = flags.toInt() and 0x40 != 0

    override fun toString(): String =
        "CardPersonalization(state=0x${hex2(state)}, flags=0x${hex2(flags)}, programBound=$programBound, " +
            "personalized=$personalized, terminated=$terminated)"

    private fun hex2(b: Byte): String = (b.toInt() and 0xFF).toString(16).uppercase().padStart(2, '0')
}

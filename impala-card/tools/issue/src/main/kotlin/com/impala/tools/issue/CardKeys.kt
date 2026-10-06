package com.impala.tools.issue

import com.impala.sdk.scp03.AESCMAC

/**
 * Per-card SCP03 keys for the pilot (open decision OD-3, recommended option):
 * `K = AES-CMAC(KMK, cardId ‖ "IMPALA-SCP03-" ‖ label)` for label ENC, MAC,
 * DEK. The 16-byte KMK is an operator secret held outside the bridge and every
 * phone; the tool re-derives keys on demand and stores nothing.
 */
object CardKeys {
    /** The GlobalPlatform default test key `40 41 … 4F`: the card refuses it as a rotation target. */
    val GP_DEFAULT: ByteArray = ByteArray(16) { (0x40 + it).toByte() }

    fun gpDefaultKeys(): Triple<ByteArray, ByteArray, ByteArray> = Triple(GP_DEFAULT.copyOf(), GP_DEFAULT.copyOf(), GP_DEFAULT.copyOf())

    fun derive(kmk: ByteArray, cardId: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        require(kmk.size == 16) { "KMK must be 16 bytes" }
        require(cardId.size == 16) { "cardId must be 16 bytes" }
        fun k(label: String): ByteArray {
            val key = AESCMAC.sign(kmk, cardId + "IMPALA-SCP03-$label".encodeToByteArray()).copyOf(16)
            check(!key.contentEquals(GP_DEFAULT)) { "derived key equals the GP default" }
            return key
        }
        return Triple(k("ENC"), k("MAC"), k("DEK"))
    }
}

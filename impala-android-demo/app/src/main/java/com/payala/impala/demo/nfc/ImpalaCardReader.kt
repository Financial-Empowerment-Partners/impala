package com.payala.impala.demo.nfc

import java.nio.ByteBuffer
import java.util.UUID

/**
 * Represents card-stored user identity read via [ImpalaCardReader.getUserData].
 *
 * @param accountId Payala account UUID (first 16 bytes of user data)
 * @param cardId    card UUID (next 16 bytes of user data)
 * @param fullName  UTF-8 full name (remaining bytes)
 */
data class CardUser(
    val accountId: String,
    val cardId: String,
    val fullName: String
) {
    companion object {
        private const val UUID_LENGTH = 16

        /**
         * Parses raw card user data bytes into a [CardUser].
         *
         * Layout: `[accountId: 16B UUID] [cardId: 16B UUID] [fullName: UTF-8]`
         */
        fun fromCardData(data: ByteArray): CardUser {
            val accountUuid = bytesToUuid(data, 0)
            val cardUuid = bytesToUuid(data, UUID_LENGTH)
            val nameOffset = UUID_LENGTH * 2
            val fullName = String(data, nameOffset, data.size - nameOffset, Charsets.UTF_8)
            return CardUser(
                accountId = accountUuid.toString(),
                cardId = cardUuid.toString(),
                fullName = fullName
            )
        }

        private fun bytesToUuid(bytes: ByteArray, offset: Int): UUID {
            val buf = ByteBuffer.wrap(bytes, offset, UUID_LENGTH)
            val mostSigBits = buf.long
            val leastSigBits = buf.long
            return UUID(mostSigBits, leastSigBits)
        }
    }
}

/**
 * Focused card reader for authentication-related APDU operations.
 *
 * A subset of `ImpalaSDK` from `impala-card/sdk`, containing only the methods
 * needed to read card identity, public keys, and signed timestamps for JWT
 * authentication against the impala-bridge.
 *
 * Does NOT include SCP03 secure channel — that is only needed for card
 * provisioning, not for reading user data or signing.
 *
 * @param apduChannel a connected [BIBO] transport (e.g., [IsoDepBibo])
 */
class ImpalaCardReader(apduChannel: BIBO) {

    private val channel = APDUBIBO(apduChannel)

    companion object {
        // APDU instruction bytes (from impala-card Constants.kt)
        const val INS_GET_USER_DATA: Byte = 30
        const val INS_GET_EC_PUB_KEY: Byte = 36
        const val INS_GET_RSA_PUB_KEY: Byte = 7
        const val INS_SIGN_AUTH: Byte = 37
        const val INS_VERIFY_PIN: Byte = 24
        const val INS_GET_CARD_NONCE: Byte = 35
        const val INS_GET_VERSION: Byte = 100

        // PIN type selector
        const val P2_MASTER_PIN: Byte = 0x81.toByte()

        // Success status word
        const val SW_OK = 0x9000
    }

    /**
     * Reads card-stored user identity (account ID, card ID, full name).
     *
     * @throws BIBOException if the card communication fails
     * @throws IllegalStateException if the response status word is not 0x9000
     */
    fun getUserData(): CardUser {
        val resp = transmit(CommandAPDU(INS_GET_USER_DATA))
        return CardUser.fromCardData(resp.data)
    }

    /**
     * Reads the card's EC (secp256r1) public key (65 bytes, uncompressed).
     */
    fun getECPubKey(): ByteArray {
        val resp = transmit(CommandAPDU(INS_GET_EC_PUB_KEY))
        return resp.data
    }

    /**
     * Reads the card's RSA public key modulus.
     */
    fun getRSAPubKey(): ByteArray {
        val resp = transmit(CommandAPDU(INS_GET_RSA_PUB_KEY))
        return resp.data
    }

    /**
     * Gets the card to sign a timestamp using its EC private key (INS_SIGN_AUTH).
     *
     * @param timestamp Unix epoch seconds
     * @return DER-encoded ECDSA signature
     */
    fun getSignedTimestamp(timestamp: Long): ByteArray {
        val bytes = ByteArray(8)
        for (i in 7 downTo 0) {
            bytes[7 - i] = (timestamp shr (i * 8)).toByte()
        }
        val cmd = CommandAPDU(INS_SIGN_AUTH, bytes)
        return transmit(cmd).data
    }

    /**
     * Gets a random nonce from the card's PRNG.
     */
    fun getNonce(): Int {
        val resp = transmit(CommandAPDU(INS_GET_CARD_NONCE))
        var result = 0
        for (i in 0..3) {
            result += (resp.data[i].toInt() and 0xFF) * (1 shl (i * 8))
        }
        return result
    }

    /**
     * Verifies the master PIN against the card.
     *
     * @param pin 8-digit master PIN (default "14117298")
     * @throws BIBOException if the PIN is rejected or communication fails
     */
    fun verifyMasterPin(pin: String = "14117298") {
        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        val cmd = CommandAPDU(0x00, INS_VERIFY_PIN.toInt(), 0x00, P2_MASTER_PIN.toInt(), pinBytes)
        transmit(cmd)
    }

    /**
     * Sends an APDU command and verifies the response status word is SW_OK (0x9000).
     *
     * @throws BIBOException if the status word indicates an error
     */
    private fun transmit(cmd: CommandAPDU): ResponseAPDU {
        val resp = channel.transmit(cmd)
        if (resp.sw != SW_OK) {
            throw BIBOException("Card operation failed: SW=0x${Integer.toHexString(resp.sw)}")
        }
        return resp
    }
}

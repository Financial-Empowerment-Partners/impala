package com.impala.sdk

import com.impala.sdk.Constants.INS_VERIFY_PIN
import com.impala.sdk.apdu4j.APDUBIBO
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.CommandAPDU.Companion.decodeHexString_imp
import com.impala.sdk.apdu4j.CommandAPDU.Companion.encodeHexString_imp
import com.impala.sdk.apdu4j.ResponseAPDU
import com.impala.sdk.models.ImpalaCardUser
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaUser
import com.impala.sdk.models.ImpalaVersion
import com.impala.sdk.models.toUuid
import com.impala.sdk.scp03.SCP03Channel
import com.impala.sdk.scp03.SCP03Constants
import okio.ByteString
import okio.ByteString.Companion.toByteString
import okio.internal.commonAsUtf8ToByteArray
import kotlin.math.pow

/**
 * ImpalaSDK is API for ImpalaApplet
 *
 * @version 1.0
 * @since 02.06.2026
 */
class ImpalaSDK(
    apduChannel: BIBO,
    private val scp03Keys: Triple<ByteArray, ByteArray, ByteArray>? = null
) {
    private val apduChannel: APDUBIBO = APDUBIBO(apduChannel)
    private var scp03Channel: SCP03Channel? = null

    /**
     * Sends prepared APDU.
     *
     * @param cmd APDU to send.
     * @return ResponseAPDU with response.
     */
    fun tx(cmd: CommandAPDU): ResponseAPDU {
        val resp: ResponseAPDU
        try {
            resp = apduChannel.transmit(cmd)
            if (!this.isResponseOk(resp)) {
                throw ImpalaException.fromStatusWord(resp.sw)
            }
        } catch (e: ImpalaException) {
            throw e
        } catch (e: BIBOException) {
            throw ImpalaException("Unable to write to card", e)
        }
        return resp
    }

    /**
     * Gets installed ImpalaApplet version from the card.
     * The response is 10 bytes: [major(2)] [minor(2)] [revList(2)] [shortHash(4)].
     *
     * @return ImpalaVersion
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun getImpalaAppletVersion() : ImpalaVersion {
        val resp: ResponseAPDU = tx(CommandAPDU(Constants.INS_GET_VERSION))
        val data: ByteArray = resp.data

        if (data.size != 10) {
            throw ImpalaException(
                "Error while getting applet-version: incorrect length (" + data.size + ") expected 10."
            )
        }

        val major = ((data[0].toInt() and 0xFF shl 8) or (data[1].toInt() and 0xFF)).toShort()
        val minor = ((data[2].toInt() and 0xFF shl 8) or (data[3].toInt() and 0xFF)).toShort()
        var revList = ((data[4].toInt() and 0xFF shl 8) or (data[5].toInt() and 0xFF)).toShort()
        val shortHash = data.sliceArray(6..9).let { bytes ->
            bytes.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }
        }
        return ImpalaVersion(major, minor, revList, shortHash)
    }

    /**
     * Set users gender on the card.
     *
     * @param gender to set
     * @return true if successfull.
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun setGender(gender: String) {
        val barr = gender.encodeToByteArray();
        require(barr.size in 1..16) { "Gender must be 1-16 bytes" }
        tx(CommandAPDU(Constants.INS_SET_GENDER, barr))
    }

    /**
     * Gets the value of the gender stored on the card.
     *
     * @return gender as string
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun getGender() : String {
            return tx(CommandAPDU(Constants.INS_GET_GENDER)).data.decodeToString()
    }


    /**
     * Set the PRNG seed for the card
     *
     * @return gender as string
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun setSeed() {
        tx(getSeedPrngCmd(4.toShort()))
    }

    /**
     * Gets the EC Pub key from the card.
     *
     * @return ByteString with pubkey.
     * @throws ImpalaException
     */
    fun getECPubKey(): ByteString {
        val resp = tx(CommandAPDU(Constants.INS_GET_EC_PUB_KEY))
        return resp.data.toByteString()
    }

    /**
     * Get RSA pub key from the card.
     *
     * @return ByteString with RSA modulus
     * @throws ImpalaException
     */
    fun getRSAPubKey(): ByteString {
        val resp: ResponseAPDU = tx(CommandAPDU(Constants.INS_GET_RSA_PUB_KEY))
        return resp.data.toByteString()
    }

    /**
     * Get generated nonce from the card.
     *
     * @returns int containing nonce
     * @throws ImpalaException
     */
    fun getNonce(): Int {
        val resp: ResponseAPDU = tx(CommandAPDU(Constants.INS_GET_CARD_NONCE))
        // Int32 from 4B long bArr
        var result = 0
        for (index in 0..3) {
            result += resp.data[index].toUByte().toInt() * 256f.pow(index).toInt()
        }
        return result
    }

    /**
     * Get user data stored on the card.
     *
     * @returns ImpalaUser containing the data from the card.
     * @throws ImpalaException
     */
    fun getUserData(): ImpalaUser {
        val resp: ResponseAPDU = tx(CommandAPDU(Constants.INS_GET_USER_DATA))
        return ImpalaUser(ImpalaCardUser(resp.data))
    }

    /**
     * Set name of the user on the card.
     *
     * @param name: full name of the user to write on the card
     * @throws ImpalaException
     */
    fun setUserName(name: String) {
        val barr = name.encodeToByteArray()
        require(barr.size in 1..128) { "Name must be 1-128 bytes" }
        tx(CommandAPDU(Constants.INS_SET_FULL_NAME, barr))
    }

    /**
     * Gets the on-card balance as a Long (8-byte big-endian).
     *
     * @return the balance in the card's lowest denomination
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun getBalance(): Long {
        val resp = tx(CommandAPDU(Constants.INS_GET_BALANCE))
        val data = resp.data
        if (data.size != 8) {
            throw ImpalaException("Expected 8 bytes for balance, got ${data.size}")
        }
        var value = 0L
        for (i in 0..7) {
            value = (value shl 8) or (data[i].toLong() and 0xFF)
        }
        return value
    }

    /**
     * Gets the account ID stored on the card as a UUID string.
     *
     * @return 16-byte UUID formatted as a string
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun getAccountId(): String {
        val resp = tx(CommandAPDU(Constants.INS_GET_ACCOUNT_ID))
        val data = resp.data
        if (data.size != 16) {
            throw ImpalaException("Expected 16 bytes for account ID, got ${data.size}")
        }
        return data.toUuid().toString()
    }

    /**
     * Gets the full name stored on the card.
     *
     * @return the cardholder's full name
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun getFullName(): String {
        val resp = tx(CommandAPDU(Constants.INS_GET_FULL_NAME))
        return resp.data.decodeToString()
    }

    /**
     * Signs a transfer with the user PIN and signable data.
     * The card returns: [signature (72B)] [pubKey (65B)] [pubKeySig (72B)].
     *
     * @param userPin the 4-digit user PIN
     * @param signableData the 60-byte signable transaction data
     * @return Triple of (signature, pubKey, pubKeySig) as ByteStrings
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun signTransfer(userPin: String, signableData: ByteArray): Triple<ByteString, ByteString, ByteString> {
        require(signableData.size == Constants.SIGNABLE_LENGTH.toInt()) {
            "Signable data must be ${Constants.SIGNABLE_LENGTH} bytes"
        }
        val pinBytes = mapDigitsToByteArray(userPin)
        val payload = pinBytes + signableData
        val cmd = CommandAPDU(Constants.INS_SIGN_TRANSFER, payload)
        val resp = tx(cmd)
        val data = resp.data

        val sigLen = Constants.MAX_SIG_LENGTH.toInt()
        val pubKeyLen = Constants.PUB_KEY_LENGTH.toInt()
        val expectedLen = sigLen + pubKeyLen + sigLen
        if (data.size != expectedLen) {
            throw ImpalaException("Expected $expectedLen bytes for signTransfer response, got ${data.size}")
        }

        val signature = data.sliceArray(0 until sigLen).toByteString()
        val pubKey = data.sliceArray(sigLen until sigLen + pubKeyLen).toByteString()
        val pubKeySig = data.sliceArray(sigLen + pubKeyLen until expectedLen).toByteString()
        return Triple(signature, pubKey, pubKeySig)
    }

    /**
     * Verifies an incoming transfer in two phases.
     * Phase 1 (P1=0x00): sends signable data + signature.
     * Phase 2 (P1=0x01): sends pubKey + pubKeySig.
     *
     * @param signableData the 60-byte signable transaction data
     * @param signature DER-encoded ECDSA signature
     * @param pubKey 65-byte EC public key
     * @param pubKeySig DER-encoded ECDSA signature of the public key
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun verifyTransfer(signableData: ByteArray, signature: ByteArray, pubKey: ByteArray, pubKeySig: ByteArray) {
        // Phase 1: send signable data
        val cmd1 = CommandAPDU(0x00, Constants.INS_VERIFY_TRANSFER.toInt(), 0x00, 0x00, signableData)
        tx(cmd1)
        // Phase 2: send signature + pubKey + pubKeySig
        val tailPayload = signature + pubKey + pubKeySig
        val cmd2 = CommandAPDU(0x00, Constants.INS_VERIFY_TRANSFER.toInt(), 0x01, 0x00, tailPayload)
        tx(cmd2)
    }

    /**
     * Sets arbitrary card data on the applet.
     *
     * @param data the data to store on the card
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun setCardData(data: ByteArray) {
        tx(CommandAPDU(Constants.INS_SET_CARD_DATA, data))
    }

    /**
     * Updates the master PIN on the card.
     *
     * @param newPin the new 8-digit master PIN
     * @throws ImpalaException
     */
    @Throws(ImpalaException::class)
    fun updateMasterPin(newPin: String) {
        require(newPin.length == 8 && newPin.all { it.isDigit() }) { "Master PIN must be exactly 8 digits" }
        val pinBytes = mapDigitsToByteArray(newPin)
        val cmd = CommandAPDU(0x00, Constants.INS_UPDATE_MASTER_PIN.toInt(), 0x00, 0x00, pinBytes)
        tx(cmd)
    }

    /**
     * Checks if the card is alive (not terminated).
     *
     * @return true if the card responded with SW_OK
     */
    fun isCardAlive(): Boolean {
        return try {
            tx(CommandAPDU(Constants.INS_IS_CARD_ALIVE))
            true
        } catch (_: ImpalaException) {
            false
        }
    }

    /**
     * Verifies the user PIN on the card.
     *
     * @param pin the 4-digit user PIN
     * @throws ImpalaException if PIN verification fails
     */
    @Throws(ImpalaException::class)
    fun verifyUserPin(pin: String) {
        val pinBytes = mapDigitsToByteArray(pin)
        val cmd = CommandAPDU(0x00, Constants.INS_VERIFY_PIN, 0x00, Constants.P2_USER_PIN, pinBytes)
        tx(cmd)
    }

    /**
     * Returns true if the card responded with SW_OK.
     *
     * @param resp is the response 9000
     * @return
     */
    private fun isResponseOk(resp: ResponseAPDU): Boolean {
        return resp.sw == 36864
    }

    fun SWtoString(sw: Int): String {
        val bSW = byteArrayOf(
            (((sw and 0xff00) shr 8) and 0xff).toByte(),
            (sw and 0xff).toByte()
        )
        return encodeHexString_imp(bSW)
    }

    /**
     * Return an array containing random bytes.
     *
     * @param size of the resulting array.
     * @return
     */
    private fun createRandomByteArray(size: Short): ByteArray {
        val rand = ByteArray(size.toInt())
        kotlin.random.Random.nextBytes(rand)
        return rand
    }

    /**
     * Prepares command to initialize PRNG of the card.
     *
     * @param seedLen length of seed. (usually 4)
     * @return Prepared command.
     */
    private fun getSeedPrngCmd(seedLen: Short): CommandAPDU {
        return CommandAPDU(
            Constants.INS_INITIALIZE,
            createRandomByteArray(seedLen)
        )
    }

    /**
     * Gets the nonce signed by the card.
     *
     * @param nonce to sign
     * @return signed nonce
     * @throws ImpalaException
     */
    private fun getSignedNonce(nonce: ByteArray): ByteString {
        val cmd = CommandAPDU(Constants.INS_SIGN_AUTH, nonce)
        val bArr = tx(cmd).data
        return bArr.toByteString()
    }

    fun verifyMasterPin(mPin: String) {
        require(mPin.length == 8 && mPin.all { it.isDigit() }) { "Master PIN must be exactly 8 digits" }
        val masterPin = mapStringToByteArray(mPin)
        val cmd = CommandAPDU(0x00, Constants.INS_VERIFY_PIN, 0x00, Constants.P2_MASTER_PIN, masterPin)
        tx(cmd)
    }

    fun getSignedTimestamp(timestamp: Long): ByteString {
        val bytes = okio.Buffer().writeLong(timestamp).readByteArray()
        return getSignedNonce(bytes)
    }

    fun updateUserPin(pin: String) {
        require(pin.length == 4 && pin.all { it.isDigit() } && pin != "0000") { "User PIN must be 4 digits and not 0000" }
        val pinBarr = mapDigitsToByteArray(pin)
        val cmd = CommandAPDU(0x00, Constants.INS_UPDATE_USER_PIN, 0x00, Constants.P2_USER_PIN, pinBarr)
        tx(cmd)
    }

    // IMPORTANT: this maps a string of digits (e.g. a pin like "1234") to [1, 2, 3, 4] instead of the character codes for these digits [31, 32, 33, 34]
    fun mapDigitsToByteArray(digits: String): ByteArray {
        val regex = Regex("^[0-9]+$")
        check(regex.matches(digits))

        return digits.map { c: Char ->
            (c.toByte() - 0x30).toByte() // "1" -> 1
        }.toByteArray()
    }

    fun mapStringToByteArray(str: String): ByteArray {
        return str.commonAsUtf8ToByteArray()
    }

    // --- SCP03 Secure Channel API ---

    /**
     * Opens an SCP03 secure channel to the card.
     * Requires scp03Keys to be provided in the constructor.
     *
     * @param securityLevel desired security level (default 0x33 = C-MAC | C-DEC | R-MAC | R-ENC)
     * @return true if the channel was successfully opened
     * @throws ImpalaException if keys are not configured or authentication fails
     */
    @Throws(ImpalaException::class)
    fun openSecureChannel(securityLevel: Byte = 0x33): Boolean {
        val keys = scp03Keys ?: throw ImpalaException("SCP03 keys not configured")
        val channel = SCP03Channel(apduChannel, keys.first, keys.second, keys.third)
        val result = channel.openSecureChannel(securityLevel)
        scp03Channel = channel
        return result
    }

    /**
     * Closes the SCP03 secure channel.
     */
    fun closeSecureChannel() {
        scp03Channel?.closeSecureChannel()
        scp03Channel = null
    }

    /**
     * Transmits an APDU through the SCP03 secure channel.
     * The command is wrapped (MAC'd and optionally encrypted) before sending,
     * and the response is unwrapped (MAC verified and optionally decrypted).
     *
     * @param cmd the plaintext command APDU
     * @return the unwrapped response APDU
     * @throws ImpalaException if the secure channel is not open
     */
    @Throws(ImpalaException::class)
    fun secureTx(cmd: CommandAPDU): ResponseAPDU {
        val channel = scp03Channel ?: throw ImpalaException("Secure channel is not open")
        val resp = channel.secureTransmit(cmd)
        if (!isResponseOk(resp)) {
            throw ImpalaException.fromStatusWord(resp.sw)
        }
        return resp
    }

    /**
     * Provisions the master PIN (8 digits) over the SCP03 secure channel.
     *
     * @param pin the new master PIN as a digit string (e.g., "14117298")
     * @throws ImpalaException if the secure channel is not open or the operation fails
     */
    @Throws(ImpalaException::class)
    fun provisionMasterPIN(pin: String) {
        val pinBytes = mapDigitsToByteArray(pin)
        require(pinBytes.size == 8) { "Master PIN must be 8 digits" }
        val payload = byteArrayOf(Constants.P2_MASTER_PIN, pinBytes.size.toByte()) + pinBytes
        val cmd = CommandAPDU(
            SCP03Constants.CLA_GP.toInt(),
            SCP03Constants.INS_PROVISION_PIN.toInt(),
            0x00, 0x00, payload
        )
        secureTx(cmd)
    }

    /**
     * Provisions the user PIN (4 digits) over the SCP03 secure channel.
     *
     * @param pin the new user PIN as a digit string (e.g., "1234")
     * @throws ImpalaException if the secure channel is not open or the operation fails
     */
    @Throws(ImpalaException::class)
    fun provisionUserPIN(pin: String) {
        val pinBytes = mapDigitsToByteArray(pin)
        require(pinBytes.size == 4) { "User PIN must be 4 digits" }
        val payload = byteArrayOf(Constants.P2_USER_PIN, pinBytes.size.toByte()) + pinBytes
        val cmd = CommandAPDU(
            SCP03Constants.CLA_GP.toInt(),
            SCP03Constants.INS_PROVISION_PIN.toInt(),
            0x00, 0x00, payload
        )
        secureTx(cmd)
    }

    /**
     * Sends an applet update data chunk over the SCP03 secure channel.
     *
     * @param seq  sequence number for ordering update chunks
     * @param data the update data payload
     * @throws ImpalaException if the secure channel is not open or the operation fails
     */
    @Throws(ImpalaException::class)
    fun sendAppletUpdate(seq: Int, data: ByteArray) {
        val header = byteArrayOf(
            ((seq shr 8) and 0xFF).toByte(),
            (seq and 0xFF).toByte(),
            ((data.size shr 8) and 0xFF).toByte(),
            (data.size and 0xFF).toByte()
        )
        val payload = header + data
        val cmd = CommandAPDU(
            SCP03Constants.CLA_GP.toInt(),
            SCP03Constants.INS_APPLET_UPDATE.toInt(),
            0x00, 0x00, payload
        )
        secureTx(cmd)
    }
}

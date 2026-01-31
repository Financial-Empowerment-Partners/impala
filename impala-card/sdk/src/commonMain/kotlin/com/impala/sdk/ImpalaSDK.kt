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
class ImpalaSDK(apduChannel: BIBO) {
    private val apduChannel: APDUBIBO = APDUBIBO(apduChannel)

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
                // TODO: error based on cmd.ins parse to constant
                throw ImpalaException("Operation unsuccessful: " + resp.sw)
            }
        } catch (e: BIBOException) {
            throw ImpalaException("Unable to write to card", e)
        }
        return resp
    }

    /**
     * Gets installed ImpalaApplet version from the card
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

        val major = data[2].toShort()
        val minor = data[3].toShort()
        var revList = (data[4].toInt() shl 8).toShort()
        revList = (revList.toInt() or data[5].toInt()).toShort()
//            val shortHash: String = java.util.Arrays.copyOfRange(data, 6, 10).toString()
//            val version: ImpalaVersion = ImpalaVersion(major, minor, revList, shortHash)
        return ImpalaVersion(major, minor, revList, "0123")
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
        tx(CommandAPDU(Constants.INS_SET_FULL_NAME, name.encodeToByteArray()))
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

    fun verifyMasterPin(mPin: String = "14117298") {
//        byteArrayOf(0, INS_VERIFY_PIN, 0, Constants.P2_MASTER_PIN) + appendParameters(masterPin)
        val masterPin = mapStringToByteArray(mPin)
        val cmd = CommandAPDU(0x00, Constants.INS_VERIFY_PIN, 0x00, Constants.P2_MASTER_PIN, masterPin)
        tx(cmd)
    }

    fun getSignedTimestamp(timestamp: Long): ByteString {
        val bytes = okio.Buffer().writeLong(timestamp).readByteArray()
        return getSignedNonce(bytes)
    }

    fun updateUserPin(pin: String="1234"){
//        = byteArrayOf(0, INS_UPDATE_USER_PIN, 0, Constants.P2_USER_PIN) + appendParameters(pin)
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
}

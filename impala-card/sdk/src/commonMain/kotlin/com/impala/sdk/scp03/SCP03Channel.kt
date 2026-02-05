package com.impala.sdk.scp03

import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.APDUBIBO
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.ResponseAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.scp03.SCP03Constants.BLOCK_SIZE
import com.impala.sdk.scp03.SCP03Constants.CARD_CRYPTO
import com.impala.sdk.scp03.SCP03Constants.CHALLENGE_LENGTH
import com.impala.sdk.scp03.SCP03Constants.CLA_GP
import com.impala.sdk.scp03.SCP03Constants.CLA_GP_SECURED
import com.impala.sdk.scp03.SCP03Constants.CRYPTOGRAM_LENGTH
import com.impala.sdk.scp03.SCP03Constants.DERIVATION_DATA_LENGTH
import com.impala.sdk.scp03.SCP03Constants.HOST_CRYPTO
import com.impala.sdk.scp03.SCP03Constants.INS_EXTERNAL_AUTHENTICATE
import com.impala.sdk.scp03.SCP03Constants.INS_INITIALIZE_UPDATE
import com.impala.sdk.scp03.SCP03Constants.S_ENC
import com.impala.sdk.scp03.SCP03Constants.S_MAC
import com.impala.sdk.scp03.SCP03Constants.S_RMAC
import com.impala.sdk.scp03.SCP03Constants.C_MAC
import com.impala.sdk.scp03.SCP03Constants.C_DEC
import com.impala.sdk.scp03.SCP03Constants.R_MAC
import com.impala.sdk.scp03.SCP03Constants.R_ENC

/**
 * Host-side SCP03 secure channel manager.
 * Handles mutual authentication and transparent APDU wrapping/unwrapping.
 *
 * @param apduChannel underlying card communication channel
 * @param staticENC   16-byte static ENC key
 * @param staticMAC   16-byte static MAC key
 * @param staticDEK   16-byte static DEK key
 */
class SCP03Channel(
    private val apduChannel: APDUBIBO,
    private val staticENC: ByteArray,
    private val staticMAC: ByteArray,
    private val staticDEK: ByteArray
) {
    private var sessionENC: ByteArray = ByteArray(0)
    private var sessionMAC: ByteArray = ByteArray(0)
    private var sessionRMAC: ByteArray = ByteArray(0)
    private var macChainValue: ByteArray = ByteArray(BLOCK_SIZE)
    private var securityLevel: Byte = 0
    private var isOpen: Boolean = false

    /**
     * Opens a secure channel by performing INITIALIZE UPDATE and EXTERNAL AUTHENTICATE.
     *
     * @param secLevel desired security level (default 0x33 = C-MAC | C-DEC | R-MAC | R-ENC)
     * @return true if the channel was successfully opened
     * @throws ImpalaException on authentication failure
     */
    fun openSecureChannel(secLevel: Byte = 0x33): Boolean {
        // Generate host challenge
        val hostChallenge = kotlin.random.Random.nextBytes(CHALLENGE_LENGTH)

        // --- INITIALIZE UPDATE ---
        val initCmd = CommandAPDU(
            CLA_GP.toInt(), INS_INITIALIZE_UPDATE.toInt(), 0x00, 0x00, hostChallenge
        )
        val initResp = apduChannel.transmit(initCmd)
        if (initResp.sw != 0x9000) {
            throw ImpalaException("INITIALIZE UPDATE failed: SW=${initResp.sw}")
        }

        val respData = initResp.data
        if (respData.size != 29) {
            throw ImpalaException("INITIALIZE UPDATE: unexpected response length ${respData.size}")
        }

        // Parse response: keyDiversification(10) + keyInfo(3) + cardChallenge(8) + cardCryptogram(8)
        val cardChallenge = respData.copyOfRange(13, 21)
        val cardCryptogram = respData.copyOfRange(21, 29)

        // Derive session keys
        sessionENC = deriveSessionKey(staticENC, S_ENC, hostChallenge, cardChallenge)
        sessionMAC = deriveSessionKey(staticMAC, S_MAC, hostChallenge, cardChallenge)
        sessionRMAC = deriveSessionKey(staticMAC, S_RMAC, hostChallenge, cardChallenge)

        // Verify card cryptogram
        val expectedCardCrypto = computeCryptogram(sessionMAC, CARD_CRYPTO, 0x0040, hostChallenge, cardChallenge)
        if (!cardCryptogram.contentEquals(expectedCardCrypto)) {
            throw ImpalaException("Card cryptogram verification failed")
        }

        // Compute host cryptogram
        val hostCryptogram = computeCryptogram(sessionMAC, HOST_CRYPTO, 0x0040, hostChallenge, cardChallenge)

        // Reset MAC chaining value
        macChainValue = ByteArray(BLOCK_SIZE)

        // --- EXTERNAL AUTHENTICATE ---
        // Build data: hostCryptogram(8) + C-MAC(8)
        // First compute C-MAC over: macChainValue || CLA INS P1 P2 Lc || hostCryptogram
        val macInput = ByteArray(BLOCK_SIZE + 5 + CRYPTOGRAM_LENGTH) // 29 bytes
        macChainValue.copyInto(macInput, 0)
        macInput[BLOCK_SIZE] = CLA_GP_SECURED
        macInput[BLOCK_SIZE + 1] = INS_EXTERNAL_AUTHENTICATE
        macInput[BLOCK_SIZE + 2] = secLevel
        macInput[BLOCK_SIZE + 3] = 0x00
        macInput[BLOCK_SIZE + 4] = 0x10 // Lc = 16 (8 cryptogram + 8 MAC)
        hostCryptogram.copyInto(macInput, BLOCK_SIZE + 5)

        val fullMac = AESCMAC.sign(sessionMAC, macInput)
        val cMac = fullMac.copyOf(CRYPTOGRAM_LENGTH)

        // Update MAC chaining value
        macChainValue = fullMac.copyOf()

        // Build EXTERNAL AUTHENTICATE APDU
        val extAuthData = hostCryptogram + cMac
        val extAuthCmd = CommandAPDU(
            CLA_GP_SECURED.toInt(), INS_EXTERNAL_AUTHENTICATE.toInt(),
            secLevel.toInt(), 0x00, extAuthData
        )
        val extAuthResp = apduChannel.transmit(extAuthCmd)
        if (extAuthResp.sw != 0x9000) {
            throw ImpalaException("EXTERNAL AUTHENTICATE failed: SW=${extAuthResp.sw}")
        }

        securityLevel = secLevel
        isOpen = true
        return true
    }

    /**
     * Wraps and transmits a command APDU through the secure channel, then unwraps the response.
     *
     * @param cmd the plaintext command APDU to send
     * @return the unwrapped response APDU
     */
    fun secureTransmit(cmd: CommandAPDU): ResponseAPDU {
        if (!isOpen) {
            throw ImpalaException("Secure channel is not open")
        }

        val wrappedCmd = wrapCommand(cmd)
        val resp = apduChannel.transmit(wrappedCmd)
        return unwrapResponse(resp)
    }

    /**
     * Closes the secure channel.
     */
    fun closeSecureChannel() {
        isOpen = false
        sessionENC = ByteArray(0)
        sessionMAC = ByteArray(0)
        sessionRMAC = ByteArray(0)
        macChainValue = ByteArray(BLOCK_SIZE)
        securityLevel = 0
    }

    /**
     * Returns true if the secure channel is currently open and authenticated.
     */
    fun isChannelOpen(): Boolean = isOpen

    // ---- Internal wrapping/unwrapping ----

    private fun wrapCommand(cmd: CommandAPDU): CommandAPDU {
        var payload = cmd.data

        // C-DECRYPTION (encrypt the payload)
        if (securityLevel.toInt() and C_DEC.toInt() != 0 && payload.isNotEmpty()) {
            payload = padISO9797(payload)
            val iv = ByteArray(BLOCK_SIZE) // zero IV
            payload = AES128.encryptCBC(sessionENC, iv, payload)
        }

        // C-MAC
        val adjustedLc = payload.size + CRYPTOGRAM_LENGTH
        // Build MAC input: macChainValue || CLA INS P1 P2 Lc || payload
        val macInput = ByteArray(BLOCK_SIZE + 5 + payload.size)
        macChainValue.copyInto(macInput, 0)
        macInput[BLOCK_SIZE] = CLA_GP_SECURED
        macInput[BLOCK_SIZE + 1] = cmd.iNS.toByte()
        macInput[BLOCK_SIZE + 2] = cmd.p1.toByte()
        macInput[BLOCK_SIZE + 3] = cmd.p2.toByte()
        macInput[BLOCK_SIZE + 4] = adjustedLc.toByte()
        payload.copyInto(macInput, BLOCK_SIZE + 5)

        val fullMac = AESCMAC.sign(sessionMAC, macInput)
        val cMac = fullMac.copyOf(CRYPTOGRAM_LENGTH)
        macChainValue = fullMac.copyOf()

        // Build wrapped APDU
        val wrappedData = payload + cMac
        return CommandAPDU(
            CLA_GP_SECURED.toInt(), cmd.iNS, cmd.p1, cmd.p2, wrappedData
        )
    }

    private fun unwrapResponse(resp: ResponseAPDU): ResponseAPDU {
        var data = resp.data
        val sw = resp.sw

        // R-MAC verification
        if (securityLevel.toInt() and R_MAC.toInt() != 0 && data.size >= CRYPTOGRAM_LENGTH) {
            val respPayload = data.copyOfRange(0, data.size - CRYPTOGRAM_LENGTH)
            val receivedMac = data.copyOfRange(data.size - CRYPTOGRAM_LENGTH, data.size)

            // MAC input: macChainValue || responseData || SW
            val macInput = ByteArray(BLOCK_SIZE + respPayload.size + 2)
            macChainValue.copyInto(macInput, 0)
            respPayload.copyInto(macInput, BLOCK_SIZE)
            macInput[BLOCK_SIZE + respPayload.size] = ((sw shr 8) and 0xFF).toByte()
            macInput[BLOCK_SIZE + respPayload.size + 1] = (sw and 0xFF).toByte()

            val expectedMac = AESCMAC.sign(sessionRMAC, macInput)
            if (!receivedMac.contentEquals(expectedMac.copyOf(CRYPTOGRAM_LENGTH))) {
                throw ImpalaException("Response MAC verification failed")
            }

            macChainValue = expectedMac.copyOf()
            data = respPayload
        }

        // R-DECRYPTION
        if (securityLevel.toInt() and R_ENC.toInt() != 0 && data.isNotEmpty()) {
            val iv = ByteArray(BLOCK_SIZE) // zero IV
            data = AES128.decryptCBC(sessionENC, iv, data)
            data = removePaddingISO9797(data)
        }

        // Reconstruct ResponseAPDU with unwrapped data + original SW
        val result = ByteArray(data.size + 2)
        data.copyInto(result, 0)
        result[data.size] = ((sw shr 8) and 0xFF).toByte()
        result[data.size + 1] = (sw and 0xFF).toByte()
        return ResponseAPDU(result)
    }

    // ---- Key derivation ----

    private fun deriveSessionKey(
        staticKey: ByteArray,
        derivConst: Byte,
        hostChallenge: ByteArray,
        cardChallenge: ByteArray
    ): ByteArray {
        val dd = buildDerivationData(derivConst, 0x0080, hostChallenge, cardChallenge)
        return AESCMAC.sign(staticKey, dd)
    }

    private fun computeCryptogram(
        sessionMACKey: ByteArray,
        derivConst: Byte,
        keyLenBits: Int,
        hostChallenge: ByteArray,
        cardChallenge: ByteArray
    ): ByteArray {
        val dd = buildDerivationData(derivConst, keyLenBits, hostChallenge, cardChallenge)
        val fullMac = AESCMAC.sign(sessionMACKey, dd)
        return fullMac.copyOf(CRYPTOGRAM_LENGTH) // first 8 bytes
    }

    private fun buildDerivationData(
        derivConst: Byte,
        keyLenBits: Int,
        hostChallenge: ByteArray,
        cardChallenge: ByteArray
    ): ByteArray {
        val dd = ByteArray(DERIVATION_DATA_LENGTH)
        // Bytes 0-10: zeros (11-byte label)
        // Byte 11: derivation constant
        dd[11] = derivConst
        // Byte 12: 0x00 (separator)
        // Bytes 13-14: key length in bits
        dd[13] = ((keyLenBits shr 8) and 0xFF).toByte()
        dd[14] = (keyLenBits and 0xFF).toByte()
        // Byte 15: counter (always 1 for 128-bit keys)
        dd[15] = 0x01
        // Bytes 16-23: host challenge
        hostChallenge.copyInto(dd, 16)
        // Bytes 24-31: card challenge
        cardChallenge.copyInto(dd, 24)
        return dd
    }

    // ---- Padding ----

    private fun padISO9797(data: ByteArray): ByteArray {
        val paddedLen = ((data.size + BLOCK_SIZE) / BLOCK_SIZE) * BLOCK_SIZE
        val padded = ByteArray(paddedLen)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        return padded
    }

    private fun removePaddingISO9797(data: ByteArray): ByteArray {
        for (i in data.size - 1 downTo 0) {
            if (data[i] == 0x80.toByte()) {
                return data.copyOfRange(0, i)
            }
            if (data[i] != 0x00.toByte()) {
                throw ImpalaException("Invalid ISO 9797-1 padding")
            }
        }
        throw ImpalaException("No padding marker found")
    }
}

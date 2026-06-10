package com.impala.sdk

import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaCardDataException
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaSecurityException
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * SCP03 counter-ICV hardening tests (GP 2.3 Amd D §6.2.6):
 * - command/response ICVs recomputed from the raw wire transcript with an
 *   independent implementation (javax.crypto AES + BouncyCastle CMAC),
 * - tampered C-MAC rejected with SW 0x6688 and a hard channel reset,
 * - old-firmware key version rejected with a clear host-side error.
 */
class Scp03CounterIcvTest {

    private val staticKey = ByteArray(16) { (0x40 + it).toByte() }

    private fun defaultKeys() = Triple(staticKey.copyOf(), staticKey.copyOf(), staticKey.copyOf())

    /** Records every (command, response) pair crossing the BIBO. */
    private class RecordingBibo(private val inner: BIBO) : BIBO {
        val exchanges = mutableListOf<Pair<ByteArray, ByteArray>>()

        override fun transceive(bytes: ByteArray?): ByteArray? {
            val resp = inner.transceive(bytes)
            exchanges.add(bytes!!.copyOf() to resp!!.copyOf())
            return resp
        }

        override fun close() = inner.close()
    }

    /** Flips one bit of the C-MAC of the next non-handshake secured command. */
    private class TamperingBibo(private val inner: BIBO) : BIBO {
        var tamperNext = false

        override fun transceive(bytes: ByteArray?): ByteArray? {
            val toSend = bytes!!.copyOf()
            if (tamperNext && toSend[0] == 0x84.toByte() && toSend[1] != 0x82.toByte()) {
                toSend[toSend.size - 1] = (toSend[toSend.size - 1].toInt() xor 0x01).toByte()
                tamperNext = false
            }
            return inner.transceive(toSend)
        }

        override fun close() = inner.close()
    }

    // --- Independent reference crypto (NOT the SDK implementation) ---

    private fun bcCmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = CMac(AESEngine.newInstance())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        return ByteArray(16).also { mac.doFinal(it, 0) }
    }

    private fun derivationData(constant: Byte, lengthBits: Int, hostCh: ByteArray, cardCh: ByteArray): ByteArray {
        val dd = ByteArray(32)
        dd[11] = constant
        dd[13] = ((lengthBits shr 8) and 0xFF).toByte()
        dd[14] = (lengthBits and 0xFF).toByte()
        dd[15] = 0x01
        hostCh.copyInto(dd, 16)
        cardCh.copyInto(dd, 24)
        return dd
    }

    private fun jcaEcbEncrypt(key: ByteArray, block: ByteArray): ByteArray =
        Cipher.getInstance("AES/ECB/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            doFinal(block)
        }

    private fun jcaCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }

    private fun counterBlock(value: Int, firstByte: Byte = 0x00): ByteArray =
        ByteArray(16).also {
            it[0] = firstByte
            it[15] = value.toByte()
        }

    // --- Tests ---

    @Test
    fun `command and response ICVs recomputed from the wire transcript via javax crypto`() {
        val recorder = RecordingBibo(SimulatorBibo())
        val sdk = ImpalaSDK(recorder, defaultKeys())

        sdk.openSecureChannel()
        sdk.provisionUserPIN("9753") // 1st secured command, encrypted payload
        val balance = sdk.secureTx(CommandAPDU(Constants.INS_GET_BALANCE)) // 2nd, encrypted response
        assertEquals(8, balance.data.size)

        // exchanges: [0] INITIALIZE UPDATE, [1] EXTERNAL AUTHENTICATE,
        //            [2] wrapped PROVISION_PIN, [3] wrapped GET_BALANCE
        val initCmd = recorder.exchanges[0].first
        val initResp = recorder.exchanges[0].second
        val hostChallenge = initCmd.copyOfRange(5, 13)
        val cardChallenge = initResp.copyOfRange(13, 21)

        // Independent session ENC key: AES-CMAC(staticENC, KDF context)
        val sEnc = bcCmac(staticKey, derivationData(0x04, 0x0080, hostChallenge, cardChallenge))

        // Command ICV, counter = 1: decrypt the recorded PROVISION_PIN payload
        val provisionCmd = recorder.exchanges[2].first
        assertEquals(0x84.toByte(), provisionCmd[0])
        assertEquals(0x70.toByte(), provisionCmd[1])
        val encryptedPin = provisionCmd.copyOfRange(5, 21)
        val commandIcv = jcaEcbEncrypt(sEnc, counterBlock(1))
        val pinPlaintext = jcaCbcDecrypt(sEnc, commandIcv, encryptedPin)
        // [pinType=0x82][len=4][4,3,2,1... -> 9,7,5,3] + ISO 9797-1 padding
        assertContentEquals(
            byteArrayOf(0x82.toByte(), 0x04, 9, 7, 5, 3, 0x80.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0),
            pinPlaintext
        )

        // Response ICV, counter = 2 with first byte 0x80: decrypt the recorded
        // GET_BALANCE response payload
        val balanceResp = recorder.exchanges[3].second
        val encryptedBalance = balanceResp.copyOfRange(0, 16)
        val responseIcv = jcaEcbEncrypt(sEnc, counterBlock(2, firstByte = 0x80.toByte()))
        val balancePlaintext = jcaCbcDecrypt(sEnc, responseIcv, encryptedBalance)
        assertContentEquals(
            ByteArray(8) + byteArrayOf(0x80.toByte(), 0, 0, 0, 0, 0, 0, 0),
            balancePlaintext
        )
    }

    @Test
    fun `tampered command MAC returns 0x6688 and resets the channel`() {
        val tamper = TamperingBibo(SimulatorBibo())
        val sdk = ImpalaSDK(tamper, defaultKeys())
        sdk.openSecureChannel()

        tamper.tamperNext = true
        // Applet signals C-MAC verification failure with SW 0x6688
        assertFailsWith<ImpalaCardDataException> { sdk.secureTx(CommandAPDU(Constants.INS_GET_BALANCE)) }

        // Card-side session was torn down: an untampered secured command is now
        // refused with 0x6985 until a fresh handshake
        assertFailsWith<ImpalaSecurityException> { sdk.secureTx(CommandAPDU(Constants.INS_GET_BALANCE)) }

        // A fresh handshake restores service
        sdk.openSecureChannel()
        assertEquals(8, sdk.secureTx(CommandAPDU(Constants.INS_GET_BALANCE)).data.size)
    }

    @Test
    fun `old firmware key version is rejected with a clear error`() {
        val mock = MockBIBO()
        // INITIALIZE UPDATE response: keyDiv(10) + keyInfo(0x01 = zero-IV firmware) +
        // cardChallenge(8) + cardCryptogram(8)
        mock.respondWith(ByteArray(10) + byteArrayOf(0x01, 0x03, 0x70) + ByteArray(16))
        val sdk = ImpalaSDK(mock, defaultKeys())

        val ex = assertFailsWith<ImpalaException> { sdk.openSecureChannel() }
        assertTrue(ex.message!!.contains("key version 0x01"), "unexpected message: ${ex.message}")
        assertTrue(ex.message!!.contains("0x02"), "unexpected message: ${ex.message}")
        // Failed before EXTERNAL AUTHENTICATE was attempted
        assertEquals(1, mock.sentCommands.size)
    }

    @Test
    fun `current key version passes the version gate`() {
        val mock = MockBIBO()
        mock.respondWith(ByteArray(10) + byteArrayOf(0x02, 0x03, 0x70) + ByteArray(16))
        val sdk = ImpalaSDK(mock, defaultKeys())

        // Version gate passes; the canned all-zero cryptogram then fails, which
        // pins the check ordering (version first, then cryptogram)
        val ex = assertFailsWith<ImpalaException> { sdk.openSecureChannel() }
        assertTrue(ex.message!!.contains("cryptogram"), "unexpected message: ${ex.message}")
    }
}

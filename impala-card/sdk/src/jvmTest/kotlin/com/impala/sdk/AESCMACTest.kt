package com.impala.sdk

import com.impala.sdk.scp03.AESCMAC
import com.impala.sdk.scp03.AES128
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Unit tests for the pure-Kotlin AES-128 and AES-CMAC implementations.
 *
 * Test vectors are from NIST SP 800-38B (AES-CMAC) and FIPS 197 (AES-128).
 * These tests verify the cryptographic primitives used by SCP03 without
 * requiring a JavaCard simulator.
 */
class AESCMACTest {

    /**
     * NIST SP 800-38B Example 1: AES-CMAC with empty message.
     * Key:  2b7e1516 28aed2a6 abf71588 09cf4f3c
     * Msg:  <empty>
     * CMAC: bb1d6929 e9593728 7fa37d12 9b756746
     */
    @Test
    fun `AES-CMAC with empty message matches NIST vector`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val msg = byteArrayOf()
        val expected = hexToBytes("bb1d6929e95937287fa37d129b756746")

        val result = AESCMAC.sign(key, msg)
        assertEquals(expected.toList(), result.toList())
    }

    /**
     * NIST SP 800-38B Example 2: AES-CMAC with 16-byte message.
     * Key:  2b7e1516 28aed2a6 abf71588 09cf4f3c
     * Msg:  6bc1bee2 2e409f96 e93d7e11 7393172a
     * CMAC: 070a16b4 6b4d4144 f79bdd9d d04a287c
     */
    @Test
    fun `AES-CMAC with 16-byte message matches NIST vector`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val msg = hexToBytes("6bc1bee22e409f96e93d7e117393172a")
        val expected = hexToBytes("070a16b46b4d4144f79bdd9dd04a287c")

        val result = AESCMAC.sign(key, msg)
        assertEquals(expected.toList(), result.toList())
    }

    /**
     * NIST SP 800-38B Example 3: AES-CMAC with 40-byte message.
     * Key:  2b7e1516 28aed2a6 abf71588 09cf4f3c
     * Msg:  6bc1bee2 2e409f96 e93d7e11 7393172a
     *       ae2d8a57 1e03ac9c 9eb76fac 45af8e51
     *       30c81c46 a35ce411
     * CMAC: dfa66747 de9ae630 30ca3261 1497c827
     */
    @Test
    fun `AES-CMAC with 40-byte message matches NIST vector`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val msg = hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411"
        )
        val expected = hexToBytes("dfa66747de9ae63030ca32611497c827")

        val result = AESCMAC.sign(key, msg)
        assertEquals(expected.toList(), result.toList())
    }

    /**
     * NIST SP 800-38B Example 4: AES-CMAC with 64-byte message.
     * Key:  2b7e1516 28aed2a6 abf71588 09cf4f3c
     * Msg:  6bc1bee2 2e409f96 e93d7e11 7393172a
     *       ae2d8a57 1e03ac9c 9eb76fac 45af8e51
     *       30c81c46 a35ce411 e5fbc119 1a0a52ef
     *       f69f2445 df4f9b17 ad2b417b e66c3710
     * CMAC: 51f0bebf 7e3b9d92 fc497417 79363cfe
     */
    @Test
    fun `AES-CMAC with 64-byte message matches NIST vector`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val msg = hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        val expected = hexToBytes("51f0bebf7e3b9d92fc49741779363cfe")

        val result = AESCMAC.sign(key, msg)
        assertEquals(expected.toList(), result.toList())
    }

    @Test
    fun `AES-128 ECB encrypt-decrypt round-trip`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val plaintext = hexToBytes("6bc1bee22e409f96e93d7e117393172a")

        val ciphertext = AES128.encryptBlock(key, plaintext)
        val decrypted = AES128.decryptBlock(key, ciphertext)

        assertEquals(plaintext.toList(), decrypted.toList())
        assertNotEquals(plaintext.toList(), ciphertext.toList())
    }

    @Test
    fun `AES-128 CBC encrypt-decrypt round-trip`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val iv = ByteArray(16) // zero IV
        val plaintext = hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        )

        val ciphertext = AES128.encryptCBC(key, iv, plaintext)
        val decrypted = AES128.decryptCBC(key, iv, ciphertext)

        assertEquals(plaintext.toList(), decrypted.toList())
        assertEquals(32, ciphertext.size)
    }

    @Test
    fun `AES-128 ECB matches FIPS 197 test vector`() {
        // FIPS 197 Appendix B
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val plaintext = hexToBytes("3243f6a8885a308d313198a2e0370734")
        val expected = hexToBytes("3925841d02dc09fbdc118597196a0b32")

        val result = AES128.encryptBlock(key, plaintext)
        assertEquals(expected.toList(), result.toList())
    }

    @Test
    fun `different keys produce different CMAC`() {
        val key1 = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        val key2 = hexToBytes("3b7e151628aed2a6abf7158809cf4f3c")
        val msg = hexToBytes("6bc1bee22e409f96e93d7e117393172a")

        val mac1 = AESCMAC.sign(key1, msg)
        val mac2 = AESCMAC.sign(key2, msg)

        assertNotEquals(mac1.toList(), mac2.toList())
    }

    @Test
    fun `CMAC output is always 16 bytes`() {
        val key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")

        assertEquals(16, AESCMAC.sign(key, byteArrayOf()).size)
        assertEquals(16, AESCMAC.sign(key, ByteArray(1)).size)
        assertEquals(16, AESCMAC.sign(key, ByteArray(15)).size)
        assertEquals(16, AESCMAC.sign(key, ByteArray(16)).size)
        assertEquals(16, AESCMAC.sign(key, ByteArray(17)).size)
        assertEquals(16, AESCMAC.sign(key, ByteArray(100)).size)
    }

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in result.indices) {
            result[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }
}

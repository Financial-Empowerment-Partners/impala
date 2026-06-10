package com.impala.sdk

import com.impala.sdk.scp03.AES128
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Cross-checks the pure-Kotlin AES-128 implementation against javax.crypto on
 * random vectors, so commonMain crypto changes cannot silently diverge from
 * the JCA reference.
 */
class AesJavaxCryptoCrossCheckTest {

    private fun jcaEcb(mode: Int, key: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/ECB/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"))
            doFinal(data)
        }

    private fun jcaCbc(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(data)
        }

    @Test
    fun `encryptBlock matches javax crypto AES-ECB`() {
        repeat(32) {
            val key = Random.nextBytes(16)
            val block = Random.nextBytes(16)
            assertContentEquals(jcaEcb(Cipher.ENCRYPT_MODE, key, block), AES128.encryptBlock(key, block))
        }
    }

    @Test
    fun `decryptBlock matches javax crypto AES-ECB`() {
        repeat(32) {
            val key = Random.nextBytes(16)
            val block = Random.nextBytes(16)
            assertContentEquals(jcaEcb(Cipher.DECRYPT_MODE, key, block), AES128.decryptBlock(key, block))
        }
    }

    @Test
    fun `CBC encrypt and decrypt match javax crypto with random IVs`() {
        repeat(16) {
            val key = Random.nextBytes(16)
            val iv = Random.nextBytes(16)
            val data = Random.nextBytes(16 * (1 + Random.nextInt(4)))

            val ciphertext = jcaCbc(Cipher.ENCRYPT_MODE, key, iv, data)
            assertContentEquals(ciphertext, AES128.encryptCBC(key, iv, data))
            assertContentEquals(data, AES128.decryptCBC(key, iv, ciphertext))
            assertContentEquals(jcaCbc(Cipher.DECRYPT_MODE, key, iv, ciphertext), data)
        }
    }
}

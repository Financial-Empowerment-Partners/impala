package com.impala.sdk

import com.impala.sdk.models.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Tests for ImpalaException.fromStatusWord() — verifies that each
 * status word maps to the correct exception subclass.
 */
class ExceptionMappingTest {

    @Test
    fun `PIN failure 0x69C0 maps to ImpalaPinException with 0 tries`() {
        val ex = ImpalaException.fromStatusWord(0x69C0)
        assertIs<ImpalaPinException>(ex)
        assertEquals(0, (ex as ImpalaPinException).triesRemaining)
    }

    @Test
    fun `PIN failure 0x69C1 maps to ImpalaPinException with 1 try`() {
        val ex = ImpalaException.fromStatusWord(0x69C1)
        assertIs<ImpalaPinException>(ex)
        assertEquals(1, (ex as ImpalaPinException).triesRemaining)
    }

    @Test
    fun `PIN failure 0x69C5 maps to ImpalaPinException with 5 tries`() {
        val ex = ImpalaException.fromStatusWord(0x69C5)
        assertIs<ImpalaPinException>(ex)
        assertEquals(5, (ex as ImpalaPinException).triesRemaining)
    }

    @Test
    fun `PIN failure 0x69C9 maps to ImpalaPinException with 9 tries`() {
        val ex = ImpalaException.fromStatusWord(0x69C9)
        assertIs<ImpalaPinException>(ex)
        assertEquals(9, (ex as ImpalaPinException).triesRemaining)
    }

    @Test
    fun `all PIN failure SWs produce correct tries count`() {
        for (tries in 0..9) {
            val sw = 0x69C0 + tries
            val ex = ImpalaException.fromStatusWord(sw)
            assertIs<ImpalaPinException>(ex)
            assertEquals(tries, (ex as ImpalaPinException).triesRemaining,
                "SW 0x${sw.toString(16)} should have $tries tries remaining")
        }
    }

    @Test
    fun `card terminated maps to ImpalaCardTerminatedException`() {
        val ex = ImpalaException.fromStatusWord(0x6687)
        assertIs<ImpalaCardTerminatedException>(ex)
    }

    @Test
    fun `insufficient funds maps to ImpalaInsufficientFundsException`() {
        val ex = ImpalaException.fromStatusWord(0x6224)
        assertIs<ImpalaInsufficientFundsException>(ex)
    }

    @Test
    fun `INS not supported maps to ImpalaInstructionNotSupportedException`() {
        val ex = ImpalaException.fromStatusWord(0x6D00)
        assertIs<ImpalaInstructionNotSupportedException>(ex)
    }

    @Test
    fun `wrong length maps to ImpalaWrongLengthException`() {
        val ex = ImpalaException.fromStatusWord(0x6700)
        assertIs<ImpalaWrongLengthException>(ex)
    }

    @Test
    fun `security status not satisfied maps to ImpalaSecurityException`() {
        val ex = ImpalaException.fromStatusWord(0x6982)
        assertIs<ImpalaSecurityException>(ex)
    }

    @Test
    fun `conditions not satisfied maps to ImpalaSecurityException`() {
        val ex = ImpalaException.fromStatusWord(0x6985)
        assertIs<ImpalaSecurityException>(ex)
    }

    @Test
    fun `PIN required maps to ImpalaSecurityException`() {
        val ex = ImpalaException.fromStatusWord(0x6690)
        assertIs<ImpalaSecurityException>(ex)
    }

    @Test
    fun `PIN rejected maps to ImpalaSecurityException`() {
        val ex = ImpalaException.fromStatusWord(0x6691)
        assertIs<ImpalaSecurityException>(ex)
    }

    @Test
    fun `crypto exception maps to ImpalaCryptoException`() {
        val ex = ImpalaException.fromStatusWord(0x6683)
        assertIs<ImpalaCryptoException>(ex)
    }

    @Test
    fun `invalid AES key maps to ImpalaCryptoException`() {
        val ex = ImpalaException.fromStatusWord(0x6684)
        assertIs<ImpalaCryptoException>(ex)
    }

    @Test
    fun `key verification failed maps to ImpalaCryptoException`() {
        val ex = ImpalaException.fromStatusWord(0x0022)
        assertIs<ImpalaCryptoException>(ex)
    }

    @Test
    fun `signature verification failed maps to ImpalaCryptoException`() {
        val ex = ImpalaException.fromStatusWord(0x0023)
        assertIs<ImpalaCryptoException>(ex)
    }

    @Test
    fun `EC card key missing maps to ImpalaCryptoException`() {
        val ex = ImpalaException.fromStatusWord(0x6230)
        assertIs<ImpalaCryptoException>(ex)
    }

    @Test
    fun `error init signer maps to ImpalaCryptoException`() {
        val ex = ImpalaException.fromStatusWord(0x6227)
        assertIs<ImpalaCryptoException>(ex)
    }

    @Test
    fun `wrong sender maps to ImpalaTransferException`() {
        val ex = ImpalaException.fromStatusWord(0x6231)
        assertIs<ImpalaTransferException>(ex)
    }

    @Test
    fun `wrong recipient maps to ImpalaTransferException`() {
        val ex = ImpalaException.fromStatusWord(0x6232)
        assertIs<ImpalaTransferException>(ex)
    }

    @Test
    fun `error parsing recipient maps to ImpalaTransferException`() {
        val ex = ImpalaException.fromStatusWord(0x6226)
        assertIs<ImpalaTransferException>(ex)
    }

    @Test
    fun `wrong currency maps to ImpalaTransferException`() {
        val ex = ImpalaException.fromStatusWord(0x6229)
        assertIs<ImpalaTransferException>(ex)
    }

    @Test
    fun `card data signature invalid maps to ImpalaCardDataException`() {
        val ex = ImpalaException.fromStatusWord(0x6677)
        assertIs<ImpalaCardDataException>(ex)
    }

    @Test
    fun `card data nonce invalid maps to ImpalaCardDataException`() {
        val ex = ImpalaException.fromStatusWord(0x6678)
        assertIs<ImpalaCardDataException>(ex)
    }

    @Test
    fun `wrong card ID maps to ImpalaCardDataException`() {
        val ex = ImpalaException.fromStatusWord(0x6679)
        assertIs<ImpalaCardDataException>(ex)
    }

    @Test
    fun `tag lost maps to ImpalaTagLostException`() {
        val ex = ImpalaException.fromStatusWord(0x0000)
        assertIs<ImpalaTagLostException>(ex)
    }

    @Test
    fun `SCP03 auth failed maps to ImpalaSecurityException`() {
        val ex = ImpalaException.fromStatusWord(0x6300)
        assertIs<ImpalaSecurityException>(ex)
    }

    @Test
    fun `unknown SW produces base ImpalaException with hex message`() {
        val ex = ImpalaException.fromStatusWord(0xABCD)
        assertIs<ImpalaException>(ex)
        // Should not be a subclass
        assertEquals(ImpalaException::class, ex::class)
        assertTrue(ex.message!!.contains("ABCD"), "Message should contain hex status word")
    }

    @Test
    fun `unknown SW 0x6F00 produces base ImpalaException`() {
        val ex = ImpalaException.fromStatusWord(0x6F00)
        assertIs<ImpalaException>(ex)
        assertEquals(ImpalaException::class, ex::class)
    }

    // --- applet 0.2 / transfer protocol v1 status words (docs/apdu.md §1.2 registry) ---

    private fun assertMapping(sw: Int, expected: kotlin.reflect.KClass<out ImpalaException>) {
        val ex = ImpalaException.fromStatusWord(sw)
        assertEquals(expected, ex::class, "0x${sw.toString(16).uppercase()} should map to ${expected.simpleName}")
        val hex = sw.toString(16).uppercase().padStart(4, '0')
        assertTrue(ex.message!!.uppercase().contains(hex), "message '${ex.message}' must carry 0x$hex")
    }

    @Test
    fun `transfer counter invalid 0x6233 maps to ImpalaTransferException`() = assertMapping(0x6233, ImpalaTransferException::class)

    @Test
    fun `not personalized 0x6234 maps to ImpalaPersonalizationException`() = assertMapping(0x6234, ImpalaPersonalizationException::class)

    @Test
    fun `already personalized 0x6235 maps to ImpalaPersonalizationException`() = assertMapping(0x6235, ImpalaPersonalizationException::class)

    @Test
    fun `default SCP03 keys 0x6236 maps to ImpalaSecurityException`() = assertMapping(0x6236, ImpalaSecurityException::class)

    @Test
    fun `personalize sequence 0x6237 maps to ImpalaPersonalizationException`() = assertMapping(0x6237, ImpalaPersonalizationException::class)

    @Test
    fun `send sequence invalid 0x6238 maps to ImpalaTransferException`() = assertMapping(0x6238, ImpalaTransferException::class)

    @Test
    fun `zero amount 0x6239 maps to ImpalaTransferException`() = assertMapping(0x6239, ImpalaTransferException::class)

    @Test
    fun `transfer counter jump 0x623A maps to ImpalaTransferException`() = assertMapping(0x623A, ImpalaTransferException::class)

    @Test
    fun `program already bound 0x623B maps to ImpalaPersonalizationException`() = assertMapping(0x623B, ImpalaPersonalizationException::class)

    @Test
    fun `wrong data 0x6A80 maps to ImpalaCardDataException`() = assertMapping(0x6A80, ImpalaCardDataException::class)

    @Test
    fun `data invalid 0x6984 maps to ImpalaCardDataException`() = assertMapping(0x6984, ImpalaCardDataException::class)

    @Test
    fun `record not found 0x6A83 maps to ImpalaCardDataException`() = assertMapping(0x6A83, ImpalaCardDataException::class)

    @Test
    fun `CLA not supported 0x6E00 maps to ImpalaInstructionNotSupportedException`() = assertMapping(0x6E00, ImpalaInstructionNotSupportedException::class)

    @Test
    fun `card data signature invalid 0x6677 carries its hex`() = assertMapping(0x6677, ImpalaCardDataException::class)

    @Test
    fun `invalid AES key 0x6684 carries its hex`() = assertMapping(0x6684, ImpalaCryptoException::class)

    @Test
    fun `incorrect P1P2 0x6A86 is a base ImpalaException carrying its hex`() = assertMapping(0x6A86, ImpalaException::class)
}

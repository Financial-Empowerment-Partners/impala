package com.impala.sdk.flows

import com.impala.sdk.Constants
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.apdu4j.BIBOTagLostException
import com.impala.sdk.models.ImpalaException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class CardErrorTest {
    /** Every `SW_*` the registry (Constants.kt, mirrored from the applet) declares. */
    private fun registryStatusWords(): Map<String, Int> =
        Constants::class.java.declaredFields
            .filter { it.name.startsWith("SW_") && (it.type == Short::class.javaPrimitiveType || it.type == Int::class.javaPrimitiveType) }
            .associate { f -> f.isAccessible = true; f.name to ((f.get(null) as Number).toInt() and 0xFFFF) }
            .filterValues { it != 0x9000 }

    @Test
    fun `every registry status word the applet throws maps to a CardError case`() {
        val sws = registryStatusWords()
        assertTrue(sws.size > 20, "expected the SW registry, found ${sws.size}")
        for ((name, sw) in sws) {
            val viaException = CardError.from(ImpalaException.fromStatusWord(sw))
            val direct = CardError.fromStatusWord(sw)
            assertEquals(direct::class, viaException::class, name)
            assertTrue(viaException.userMessageKey in CardError.ALL_MESSAGE_KEYS, name)
            if (viaException is CardError.Other) assertEquals(sw, viaException.sw, name)
        }
    }

    @Test
    fun `named status words map to their typed cases`() {
        assertIs<CardError.NotPersonalized>(CardError.fromStatusWord(0x6234))
        assertIs<CardError.ProvisioningRequired>(CardError.fromStatusWord(0x6985))
        assertIs<CardError.Terminated>(CardError.fromStatusWord(0x6687))
        assertIs<CardError.PinBlocked>(CardError.fromStatusWord(0x69C0))
        assertEquals(3, assertIs<CardError.WrongPin>(CardError.fromStatusWord(0x69C3)).triesLeft)
        assertIs<CardError.InsufficientFunds>(CardError.fromStatusWord(0x6224))
        assertIs<CardError.CounterInvalid>(CardError.fromStatusWord(0x6233))
        assertIs<CardError.CounterJump>(CardError.fromStatusWord(0x623A))
        assertIs<CardError.SendSequenceInvalid>(CardError.fromStatusWord(0x6238))
        assertEquals("6233", CardError.fromStatusWord(0x6233).statusWordHex)
    }

    @Test
    fun `tag loss is found through the SDK's wrapping`() {
        val wrapped = ImpalaException("Unable to write to card", BIBOTagLostException("lost"))
        assertIs<CardError.TagLost>(CardError.from(wrapped))
        assertIs<CardError.Other>(CardError.from(ImpalaException("Unable to write to card", BIBOException("io"))))
    }
}

package com.impala.sdk

import com.impala.sdk.apdu4j.ApduNames
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.flows.CardError
import com.impala.sdk.models.ImpalaChallengeException
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.StellarCardKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The SDK side of the Stellar key commands against a scripted transport: the
 * exact command bytes it sends, how it splits a challenge into parts, and how
 * it reads the answers. The applet's side is in [StellarKeyInteropTest].
 */
class StellarKeySdkTest {
    /** Answers each command from a script and records the raw bytes it was sent. */
    private class Script(private val answers: MutableList<ByteArray>) : BIBO {
        val sent = mutableListOf<ByteArray>()
        override fun transceive(bytes: ByteArray?): ByteArray {
            sent += bytes!!
            return if (answers.size > 1) answers.removeAt(0) else answers[0]
        }
        override fun close() {}
    }

    private val ok = byteArrayOf(0x90.toByte(), 0x00)
    private fun sw(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private val networkId = ByteArray(32) { (0x10 + it).toByte() }
    private val signature = ByteArray(64) { (0x80 + it).toByte() }

    private fun sign(txSize: Int): Pair<Script, ByteArray> {
        // every part but the last answers 9000 with no data; the last answer carries the signature
        val tx = ByteArray(txSize) { (it % 251).toByte() }
        val parts = 1 + (if (txSize > 223) (txSize - 223 + 254) / 255 else 1)
        val answers = MutableList(parts - 1) { ok } + listOf(signature + ok)
        val scripted = Script(answers.toMutableList())
        val out = ImpalaSDK(scripted).signSep10(networkId, tx)
        assertContentEquals(signature, out)
        // the parts, put back together, are exactly the network id and the transaction
        val data = scripted.sent.map { it.copyOfRange(if (it.size > 4) 5 else 4, it.size) }
        assertContentEquals(networkId + tx, data.fold(ByteArray(0)) { a, b -> a + b }, "$txSize bytes reassembled")
        return scripted to tx
    }

    @Test
    fun `a challenge that fits one part still leaves its last byte for FINISH`() {
        val (script, tx) = sign(100)
        assertEquals(2, script.sent.size)
        assertEquals("0038000083" + hex(networkId) + hex(tx.copyOfRange(0, 99)), hex(script.sent[0]), "BEGIN: 32 + 99 bytes")
        // Never the four-byte form: a command with no data field that expects a
        // signature back is where readers and card runtimes disagree.
        assertEquals("0038020001" + hex(tx.copyOfRange(99, 100)), hex(script.sent[1]), "FINISH carries the last byte")
    }

    @Test
    fun `every part of every size carries a data field`() {
        for (size in 2..640) {
            val sent = sign(size).first.sent
            assertTrue(sent.all { it.size >= 6 && (it[4].toInt() and 0xFF) == it.size - 5 }, "$size bytes")
            assertEquals(0x02, sent.last()[2].toInt(), "$size bytes: the last part is FINISH")
        }
    }

    @Test
    fun `parts are 223 bytes with the network id, then up to 255`() {
        fun header(apdu: ByteArray) = hex(apdu.copyOfRange(0, minOf(5, apdu.size)))
        sign(223).first.let { s ->
            assertEquals(listOf("00380000fe", "0038020001"), s.sent.map(::header), "222 + 1")
        }
        sign(224).first.let { s ->
            assertEquals(listOf("00380000ff", "0038020001"), s.sent.map(::header))
        }
        sign(478).first.let { s ->
            assertEquals(listOf("00380000ff", "00380200ff"), s.sent.map(::header), "223 + 255")
        }
        sign(479).first.let { s ->
            assertEquals(listOf("00380000ff", "00380100ff", "0038020001"), s.sent.map(::header), "223 + 255 + 1")
        }
        sign(640).first.let { s ->
            assertEquals(listOf("00380000ff", "00380100ff", "00380200a2"), s.sent.map(::header), "the largest: 223 + 255 + 162")
        }
        sign(2).first.let { s ->
            assertEquals(listOf("0038000021", "0038020001"), s.sent.map(::header), "the smallest: 1 + 1")
        }
        for (size in 2..640) sign(size)
    }

    @Test
    fun `nothing is sent for a transaction the card could not take`() {
        for (bad in listOf(0, 1, 641, 1000)) {
            val script = Script(mutableListOf(ok))
            assertFailsWith<IllegalArgumentException> { ImpalaSDK(script).signSep10(networkId, ByteArray(bad)) }
            assertTrue(script.sent.isEmpty(), "$bad bytes")
        }
        for (bad in listOf(0, 31, 33)) {
            val script = Script(mutableListOf(ok))
            assertFailsWith<IllegalArgumentException> { ImpalaSDK(script).signSep10(ByteArray(bad), ByteArray(100)) }
            assertTrue(script.sent.isEmpty())
        }
    }

    @Test
    fun `a refusal stops the exchange and carries the status word`() {
        // refused at FINISH: the card's parser said no
        val atFinish = Script(mutableListOf(ok, sw(0x6241)))
        val e = assertFailsWith<ImpalaException> { ImpalaSDK(atFinish).signSep10(networkId, ByteArray(100)) }
        assertIs<ImpalaChallengeException>(e)
        assertEquals(0x6241, e.statusWord)
        assertIs<CardError.ChallengeRefused>(CardError.from(e))
        assertEquals("6241", CardError.from(e).statusWordHex)
        // refused at BEGIN: nothing else is sent
        val atBegin = Script(mutableListOf(sw(0x6234)))
        assertEquals(0x6234, assertFailsWith<ImpalaException> { ImpalaSDK(atBegin).signSep10(networkId, ByteArray(600)) }.statusWord)
        assertEquals(1, atBegin.sent.size)
        // a signature of the wrong length is not a signature
        val short = Script(mutableListOf(ok, ByteArray(63) + ok))
        assertFailsWith<ImpalaException> { ImpalaSDK(short).signSep10(networkId, ByteArray(100)) }
    }

    @Test
    fun `GET_STELLAR_KEY is parsed, and a card without a key is null`() {
        val pub = ByteArray(32) { (it + 1).toByte() }
        val der = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07)
        val proof = ByteArray(64) { (0xA0 + it).toByte() }
        val bound = Script(mutableListOf(byteArrayOf(0x01) + pub + der + ByteArray(72 - der.size) + proof + ok))
        val key = ImpalaSDK(bound).getStellarKey()!!
        assertEquals("00370000", hex(bound.sent.single()))
        assertEquals(StellarCardKey.ENGINE_SOFT, key.engine)
        assertEquals("soft", key.engineName)
        assertContentEquals(pub, key.publicKey)
        assertContentEquals(der, key.bindingSignature, "the DER signature without its slot padding")
        assertContentEquals(proof, key.proofSignature)
        assertTrue(key.isBound)

        val unbound = Script(mutableListOf(byteArrayOf(0x02) + pub + ByteArray(72 + 64) + ok))
        ImpalaSDK(unbound).getStellarKey()!!.let {
            assertEquals("native", it.engineName)
            assertNull(it.bindingSignature)
            assertNull(it.proofSignature)
            assertFalse(it.isBound)
        }
        assertEquals("unknown(0x7F)", StellarCardKey.parse(byteArrayOf(0x7F) + ByteArray(168)).engineName)

        // no Stellar key on this card (623C), or an applet from before 0.3 (6D00)
        assertNull(ImpalaSDK(Script(mutableListOf(sw(0x623C)))).getStellarKey())
        assertNull(ImpalaSDK(Script(mutableListOf(sw(0x6D00)))).getStellarKey())
        // anything else is an error, as is a response of the wrong length
        assertEquals(0x6E00, assertFailsWith<ImpalaException> { ImpalaSDK(Script(mutableListOf(sw(0x6E00)))).getStellarKey() }.statusWord)
        assertFailsWith<ImpalaException> { ImpalaSDK(Script(mutableListOf(ByteArray(168) + ok))).getStellarKey() }
        assertFailsWith<IllegalArgumentException> { StellarCardKey.parse(ByteArray(170)) }
    }

    @Test
    fun `the cross-signature messages are the documented bytes`() {
        val account = ByteArray(16) { (0x11 * (it % 15 + 1)).toByte() }
        val cardId = ByteArray(16) { (0xF0 + it).toByte() }
        val ed = ByteArray(32) { (0x40 + it).toByte() }
        val ec = byteArrayOf(0x04) + ByteArray(64) { (0x60 + it).toByte() }
        val tag = "494d50414c412d534b45593a" // "IMPALA-SKEY:"
        assertEquals(tag + "01" + hex(account) + hex(cardId) + hex(ed), hex(StellarCardKey.bindingMessage(account, cardId, ed)))
        assertEquals(tag + "02" + hex(account) + hex(cardId) + hex(ec), hex(StellarCardKey.proofMessage(account, cardId, ec)))
        assertEquals(Constants.SKEY_BINDING_MESSAGE_LENGTH.toInt(), StellarCardKey.bindingMessage(account, cardId, ed).size)
        assertEquals(Constants.SKEY_PROOF_MESSAGE_LENGTH.toInt(), StellarCardKey.proofMessage(account, cardId, ec).size)
        assertFailsWith<IllegalArgumentException> { StellarCardKey.bindingMessage(account, cardId, ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { StellarCardKey.proofMessage(account, cardId, ByteArray(65)) }
        assertFailsWith<IllegalArgumentException> { StellarCardKey.proofMessage(account.copyOf(15), cardId, ec) }
    }

    @Test
    fun `flag 0x80 of GET_PERSONALIZATION says whether the card has a Stellar key`() {
        fun flags(f: Int) = PersonalizationProtocol.parsePersonalization(ByteArray(159).also { it[0] = 2; it[1] = f.toByte() })
        assertTrue(flags(0x85).stellarKey)
        assertFalse(flags(0x05).stellarKey)
        assertTrue(flags(0x85).personalized && flags(0x85).initialized && !flags(0x85).terminated)
        assertTrue(flags(0xC5).terminated && flags(0xC5).stellarKey)
    }

    @Test
    fun `names, read-only classification and expected answers`() {
        assertEquals("GET_STELLAR_KEY", ApduNames.ins(0x00, 0x37))
        assertEquals("SIGN_SEP10", ApduNames.ins(0x00, 0x38))
        assertTrue(ApduNames.isReadOnly(0x00, 0x37))
        assertFalse(ApduNames.isReadOnly(0x00, 0x38), "signing is never read-only")
        assertEquals("STELLAR_KEY_MISSING", ApduNames.sw(0x623C))
        assertEquals(
            listOf("SEP10_MALFORMED", "SEP10_SEQUENCE_NOT_ZERO", "SEP10_NOT_MANAGE_DATA", "SEP10_WRONG_ACCOUNT", "SEP10_NOT_AUTH_CHALLENGE", "SEP10_NO_TIME_BOUNDS"),
            (0x6240..0x6245).map(ApduNames::sw)
        )
        // a legacy card answering 623C to the key read is not an error in a trace
        assertTrue(ApduNames.isExpectedStatus(0x00, 0x37, 0x623C))
        assertFalse(ApduNames.isExpectedStatus(0x00, 0x38, 0x623C), "but it is one when asked to sign")
        assertFalse(ApduNames.isExpectedStatus(0x00, 0x37, 0x6E00))
        assertTrue(ApduNames.isExpectedStatus(0x00, 0x36, 0x6A83), "the earlier case still holds")
        for (code in 0x6240..0x6245) {
            assertIs<CardError.ChallengeRefused>(CardError.fromStatusWord(code))
            assertEquals("card_error_challenge_refused", CardError.fromStatusWord(code).userMessageKey)
        }
        assertIs<CardError.Other>(CardError.fromStatusWord(0x623C))
        assertTrue("card_error_challenge_refused" in CardError.ALL_MESSAGE_KEYS)
    }
}

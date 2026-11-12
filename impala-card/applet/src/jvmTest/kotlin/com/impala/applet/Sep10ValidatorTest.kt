package com.impala.applet

import com.impala.applet.Sep10Reference.MALFORMED
import com.impala.applet.Sep10Reference.NOT_AUTH_CHALLENGE
import com.impala.applet.Sep10Reference.NOT_MANAGE_DATA
import com.impala.applet.Sep10Reference.NO_TIME_BOUNDS
import com.impala.applet.Sep10Reference.SEQUENCE_NOT_ZERO
import com.impala.applet.Sep10Reference.WRONG_ACCOUNT
import com.impala.applet.Sep10Xdr.op
import com.impala.applet.Sep10Xdr.tx
import com.impala.applet.Sep10Xdr.u32
import java.util.Random
import javacard.framework.ISOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The card's own check of a SEP-10 challenge ([Sep10.validate]): what it
 * accepts, the status word for each rule it enforces, and agreement with an
 * independent parser ([Sep10Reference]) over mutated and truncated input.
 */
class Sep10ValidatorTest {
    private val rnd = Random(0x5E910L)
    private val card = ByteArray(32) { (0x10 + it).toByte() }
    private val server = ByteArray(32) { (0xA0 + it).toByte() }
    private val other = ByteArray(32) { (0x55 xor it).toByte() }
    private val nonce = ByteArray(64) { ('a'.code + it % 26).toByte() }

    /** The card's verdict: null when it would sign, else the status word. */
    private fun verdict(tx: ByteArray, key: ByteArray = card, lead: Int = 0, trail: ByteArray = ByteArray(0)): Int? {
        // The transaction sits inside a larger array, as it does in the applet's stage.
        val staged = ByteArray(lead) { 0x77 } + tx + trail
        val keyArea = ByteArray(5) { 0x33 } + key
        return try {
            Sep10.validate(staged, lead.toShort(), tx.size.toShort(), keyArea, 5)
            null
        } catch (e: ISOException) {
            e.reason.toInt() and 0xFFFF
        }
    }

    private fun assertAccepted(tx: ByteArray, what: String) {
        assertNull(Sep10Reference.verdict(tx, card), "$what: the reference accepts")
        assertNull(verdict(tx)?.let { "%04X".format(it) }, "$what: the card accepts")
        assertNull(verdict(tx, lead = 32)?.let { "%04X".format(it) }, "$what: at the stage offset")
    }

    private fun assertRefused(sw: Int, tx: ByteArray, what: String) {
        assertEquals("%04X".format(sw), Sep10Reference.verdict(tx, card)?.let { "%04X".format(it) }, "$what: reference")
        assertEquals("%04X".format(sw), verdict(tx)?.let { "%04X".format(it) }, what)
        assertEquals("%04X".format(sw), verdict(tx, lead = 32)?.let { "%04X".format(it) }, "$what: at the stage offset")
    }

    private fun auth(name: String = "bridge.example.org auth", value: ByteArray? = nonce, source: ByteArray = card) =
        op(source, name, value)

    private fun webAuth(source: ByteArray = server) = op(source, "web_auth_domain", "bridge.example.org".toByteArray())

    private fun standard() = tx(server, listOf(auth(), webAuth()))

    @Test
    fun `a SEP-10 challenge for this card is accepted`() {
        assertAccepted(standard(), "auth + web_auth_domain")
        assertAccepted(Sep10Xdr.challenge(card, server), "the fixture")
        assertAccepted(tx(server, listOf(auth())), "the auth entry alone")
        assertAccepted(tx(server, listOf(auth("a auth", byteArrayOf(1)))), "the shortest name and value")
        assertAccepted(tx(server, listOf(auth("x".repeat(59) + " auth"))), "a 64-byte name")
        assertAccepted(
            tx(server, listOf(auth(), webAuth(), op(other, "client_domain", "wallet.example".toByteArray()))),
            "a client_domain entry from a third account"
        )
        assertAccepted(tx(server, listOf(auth(), op(server, "note", null))), "a later entry without a value")
        assertAccepted(tx(server, listOf(auth(), op(server, "note", ByteArray(0)))), "a later entry with an empty value")
        assertAccepted(tx(server, listOf(auth()) + List(4) { webAuth() }), "five operations")
        assertAccepted(tx(server, listOf(auth(), webAuth()), fee = 0), "fee 0")
        assertAccepted(tx(server, listOf(auth(), webAuth()), fee = 0xFFFFFFFFL), "the largest fee")
        assertAccepted(tx(server, listOf(auth(), webAuth()), minTime = 0, maxTime = 1), "minTime 0")
        assertAccepted(tx(server, listOf(auth(), webAuth()), minTime = -1, maxTime = -1), "the largest time bounds")
        for (len in 1..64) {
            assertAccepted(tx(server, listOf(auth(value = ByteArray(len) { 9 }))), "a $len-byte value")
        }
        for (len in 6..64) {
            assertAccepted(tx(server, listOf(auth("d".repeat(len - 5) + " auth"))), "a $len-byte name")
        }
    }

    @Test
    fun `the sequence number must be zero`() {
        for (seq in listOf(1L, 2L, 0x100L, 0x0100000000000000L, Long.MAX_VALUE, Long.MIN_VALUE, -1L, 123_456_789_012L)) {
            assertRefused(SEQUENCE_NOT_ZERO, tx(server, listOf(auth(), webAuth()), sequence = seq), "sequence $seq")
        }
    }

    @Test
    fun `every operation must be manage data`() {
        // The transaction a thief would want signed: a payment out of the card's account.
        for (type in listOf(0, 1, 2, 3, 5, 6, 8, 9, 11, 13, 24, 26, 0x0A00, 0x0A000000, 0x0100000A, -1)) {
            assertRefused(NOT_MANAGE_DATA, tx(server, listOf(op(card, "bridge.example.org auth".toByteArray(), nonce, type = type))), "first operation of type $type")
            assertRefused(NOT_MANAGE_DATA, tx(server, listOf(auth(), op(server, "web_auth_domain".toByteArray(), nonce, type = type))), "second operation of type $type")
            assertRefused(NOT_MANAGE_DATA, tx(server, listOf(auth(), webAuth(), webAuth(), webAuth(), op(other, "x".toByteArray(), null, type = type))), "fifth operation of type $type")
        }
        assertRefused(NOT_MANAGE_DATA, tx(server, emptyList()), "no operations")
        assertRefused(NOT_MANAGE_DATA, tx(server, listOf(auth()) + List(5) { webAuth() }), "six operations")
        for (count in listOf(0L, 6L, 0x80L, 0xFFL, 0x100L, 0x0101L, 0x010001L, 0x01000001L, 0x80000001L, 0xFFFFFFFFL)) {
            assertRefused(NOT_MANAGE_DATA, tx(server, listOf(auth()), opCount = count), "operation count $count")
        }
    }

    @Test
    fun `the first entry is this card's and no other is`() {
        assertRefused(WRONG_ACCOUNT, tx(server, listOf(auth(source = other), webAuth())), "auth entry of another account")
        assertRefused(WRONG_ACCOUNT, tx(server, listOf(auth(source = server), webAuth())), "auth entry of the server")
        assertRefused(WRONG_ACCOUNT, tx(server, listOf(auth(), webAuth(source = card))), "a second entry sourced by the card")
        assertRefused(WRONG_ACCOUNT, tx(server, listOf(auth(), webAuth(), webAuth(), webAuth(), webAuth(source = card))), "a fifth entry sourced by the card")
        assertRefused(WRONG_ACCOUNT, tx(card, listOf(auth(), webAuth())), "a transaction whose source is the card")
        // One bit away from the card's key is another account.
        for (bit in listOf(0, 7, 100, 255)) {
            val near = card.clone().also { it[bit / 8] = (it[bit / 8].toInt() xor (1 shl (bit % 8))).toByte() }
            assertRefused(WRONG_ACCOUNT, tx(server, listOf(auth(source = near), webAuth())), "auth entry of a key differing in bit $bit")
            assertAccepted(tx(near, listOf(auth(), webAuth(source = near))), "a server key differing in bit $bit")
        }
    }

    @Test
    fun `the first entry is an auth entry with a value`() {
        for (name in listOf("bridge.example.org", "bridge.example.org auth ", "bridge.example.org AUTH", "bridge.example.org_auth",
            " auth", "auth", "x", "authx", "bridge.example.org auth\u0000", "web_auth_domain", "a  aut", "a auth".reversed())) {
            assertRefused(NOT_AUTH_CHALLENGE, tx(server, listOf(auth(name), webAuth())), "name '$name'")
        }
        assertRefused(NOT_AUTH_CHALLENGE, tx(server, listOf(auth(value = null), webAuth())), "no value")
        assertRefused(NOT_AUTH_CHALLENGE, tx(server, listOf(auth(value = ByteArray(0)), webAuth())), "an empty value")
    }

    @Test
    fun `time bounds are required`() {
        assertRefused(NO_TIME_BOUNDS, tx(server, listOf(auth(), webAuth()), condType = 0, timeBounds = ByteArray(0)), "PRECOND_NONE")
        assertRefused(NO_TIME_BOUNDS, tx(server, listOf(auth(), webAuth()), condType = 0), "PRECOND_NONE with stray bounds")
        assertRefused(NO_TIME_BOUNDS, tx(server, listOf(auth(), webAuth()), condType = 2), "PRECOND_V2")
        assertRefused(NO_TIME_BOUNDS, tx(server, listOf(auth(), webAuth()), condType = 0x01000000), "an unknown precondition type")
        assertRefused(NO_TIME_BOUNDS, tx(server, listOf(auth(), webAuth()), maxTime = 0), "no upper bound")
        assertRefused(NO_TIME_BOUNDS, tx(server, listOf(auth(), webAuth()), minTime = 0, maxTime = 0), "no bounds at all")
    }

    @Test
    fun `anything else in the envelope is malformed`() {
        assertRefused(MALFORMED, ByteArray(0), "nothing")
        assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), sourceKeyType = 0x100), "a muxed source account")
        assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), sourceKeyType = 1), "an unknown source key type")
        for (memo in listOf(u32(1) + u32(4) + "memo".toByteArray(), u32(2) + ByteArray(8), u32(3) + ByteArray(32), u32(4) + ByteArray(32), u32(5))) {
            assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), memo = memo), "memo type ${memo[3]}")
        }
        assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), ext = u32(1)), "a Soroban extension")
        assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), ext = u32(0) + byteArrayOf(0)), "one trailing byte")
        assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), ext = u32(0) + u32(0)), "four trailing bytes")
        assertRefused(MALFORMED, tx(server, listOf(auth(), webAuth()), ext = ByteArray(0)), "no extension")
        // operation source accounts
        assertRefused(MALFORMED, tx(server, listOf(op(null, "bridge.example.org auth", nonce))), "an auth entry without a source account")
        assertRefused(MALFORMED, tx(server, listOf(auth(), op(null, "web_auth_domain", nonce))), "a later entry without a source account")
        assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, sourceKeyType = 0x100))), "a muxed operation source")
        // names
        assertRefused(MALFORMED, tx(server, listOf(auth(), op(server, ByteArray(0), nonce))), "an empty name")
        assertRefused(MALFORMED, tx(server, listOf(op(card, ("y".repeat(60) + " auth").toByteArray(), nonce))), "a 65-byte name")
        assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, namePadding = byteArrayOf(0, 1)))), "non-zero name padding")
        assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, namePadding = ByteArray(0)))), "missing name padding")
        // values
        assertRefused(MALFORMED, tx(server, listOf(auth(value = ByteArray(65)))), "a 65-byte value")
        assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), ByteArray(3) { 1 }, valuePadding = byteArrayOf(1)))), "non-zero value padding")
        assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, valueFlag = 2))), "a value flag of 2")
        assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, valueFlag = 0x01000000))), "a value flag with a high byte")
        // lengths that do not fit a short, or run past the end
        for (len in listOf(0x41L, 0x7FFFL, 0x8000L, 0xFFFFL, 0x10000L, 0x10006L, 0x01000006L, 0x80000006L, 0xFFFFFFFFL)) {
            assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, nameLength = len))), "a name length of $len")
            assertRefused(MALFORMED, tx(server, listOf(op(card, "a auth".toByteArray(), nonce, valueLength = len))), "a value length of $len")
        }
    }

    @Test
    fun `every truncation is refused without reading past the end`() {
        for (full in listOf(standard(), tx(server, listOf(auth())), tx(server, listOf(auth()) + List(4) { webAuth() }))) {
            for (n in 0 until full.size) {
                val cut = full.copyOfRange(0, n)
                val want = Sep10Reference.verdict(cut, card)
                assertNotNull(want, "the reference refuses $n of ${full.size} bytes")
                // Exactly sized array: a read past the end would be an ArrayIndexOutOfBoundsException.
                assertEquals(want, verdict(cut), "$n of ${full.size} bytes")
                // The missing bytes present just outside the declared length must not be read either.
                assertEquals(want, verdict(cut, trail = full.copyOfRange(n, full.size)), "$n of ${full.size} bytes, rest out of bounds")
                assertEquals(want, verdict(cut, lead = 32, trail = full.copyOfRange(n, full.size)), "$n of ${full.size} bytes, staged")
            }
        }
    }

    @Test
    fun `every single-bit change gets the reference's verdict`() {
        var accepted = 0
        var refused = 0
        for (full in listOf(standard(), tx(server, listOf(auth("a auth", byteArrayOf(7)), op(other, "k", null))))) {
            for (bit in 0 until full.size * 8) {
                val mutant = full.clone().also { it[bit / 8] = (it[bit / 8].toInt() xor (0x80 ushr (bit % 8))).toByte() }
                val want = Sep10Reference.verdict(mutant, card)
                assertEquals(want, verdict(mutant), "bit $bit of ${full.size * 8}")
                if (want == null) accepted++ else refused++
            }
        }
        // Flips in the fee, the bounds, the server key, the nonce and the domain stay
        // acceptable; flips in any structural field do not.
        assertTrue(accepted > 1000, "accepted $accepted")
        assertTrue(refused > 300, "refused $refused")
    }

    @Test
    fun `random damage gets the reference's verdict`() {
        val seeds = listOf(standard(), tx(server, listOf(auth()) + List(4) { webAuth() }), tx(server, listOf(auth("a auth", byteArrayOf(7)))))
        val structural = byteArrayOf(0, 1, 2, 10, 64, 65, 0x7F, 0x80.toByte(), 0xFF.toByte())
        var refused = 0
        repeat(20_000) {
            val m = seeds[rnd.nextInt(seeds.size)].clone()
            var out = m
            when (rnd.nextInt(6)) {
                0 -> repeat(1 + rnd.nextInt(3)) { m[rnd.nextInt(m.size)] = structural[rnd.nextInt(structural.size)] }
                1 -> repeat(1 + rnd.nextInt(4)) { m[rnd.nextInt(m.size)] = rnd.nextInt(256).toByte() }
                2 -> out = m.copyOfRange(0, rnd.nextInt(m.size + 1))
                3 -> out = m + ByteArray(1 + rnd.nextInt(8)).also { b -> rnd.nextBytes(b) }
                4 -> { // overwrite one aligned word, where the type tags and lengths live
                    val at = 4 * rnd.nextInt(m.size / 4)
                    System.arraycopy(u32(listOf(0L, 1L, 2L, 5L, 6L, 10L, 64L, 65L, 0x100L, 0xFFFFFFFFL)[rnd.nextInt(10)]), 0, m, at, 4)
                }
                else -> { // splice two transactions together
                    val o = seeds[rnd.nextInt(seeds.size)]
                    val at = 4 * rnd.nextInt(minOf(m.size, o.size) / 4)
                    out = m.copyOfRange(0, at) + o.copyOfRange(at, o.size)
                }
            }
            val want = Sep10Reference.verdict(out, card)
            val got = try {
                verdict(out)
            } catch (e: RuntimeException) {
                fail("the card's parser threw ${e::class.simpleName} on ${out.joinToString("") { b -> "%02x".format(b) }}")
            }
            assertEquals(want, got, out.joinToString("") { b -> "%02x".format(b) })
            if (want != null) refused++
        }
        assertTrue(refused > 5_000, "refused $refused")
    }

    @Test
    fun `the verdict depends on this card's key`() {
        val forOther = tx(server, listOf(auth(source = other), webAuth()))
        assertEquals(WRONG_ACCOUNT, verdict(forOther))
        assertNull(verdict(forOther, key = other), "the same bytes are a challenge for the other card")
        assertEquals(WRONG_ACCOUNT, verdict(standard(), key = other))
        assertEquals(WRONG_ACCOUNT, verdict(standard(), key = server), "the server cannot be the card")
    }
}

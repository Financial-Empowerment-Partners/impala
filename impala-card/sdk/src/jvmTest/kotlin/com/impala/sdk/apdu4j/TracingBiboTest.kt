package com.impala.sdk.apdu4j

import com.impala.sdk.ImpalaSDK
import com.impala.simulator.SimulatorBibo
import java.io.IOException
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TestTimeSource

class TracingBiboTest {
    /** Answers [answer] after advancing [clock] by [delayMs]; records every command it receives. */
    private class FakeBibo(
        private val clock: TestTimeSource? = null,
        private val delayMs: Long = 0,
        var answer: () -> ByteArray? = { byteArrayOf(0x90.toByte(), 0x00) }
    ) : BIBO {
        val received = mutableListOf<ByteArray?>()
        var closes = 0
        override fun transceive(bytes: ByteArray?): ByteArray? {
            received += bytes
            clock?.plusAssign(delayMs.milliseconds)
            return answer()
        }
        override fun close() { closes++ }
    }

    private fun recorder(): Pair<MutableList<ApduExchange>, ApduExchangeHook> {
        val list = mutableListOf<ApduExchange>()
        return list to ApduExchangeHook { list += it }
    }

    @Test
    fun `ApduExchange carries no byte field and no text field`() {
        val fields = generateSequence<Class<*>>(ApduExchange::class.java) { it.superclass }
            .flatMap { it.declaredFields.asSequence() }
            .filter { !Modifier.isStatic(it.modifiers) }
            .toList()
        assertTrue(fields.isNotEmpty(), "reflection found no fields")
        // An allow-list, not a deny-list: List<Byte>, okio.ByteString, IntArray or any wrapper would carry bytes too.
        val allowed = setOf(Int::class.javaPrimitiveType, Long::class.javaPrimitiveType, Int::class.javaObjectType, ApduExchange.Outcome::class.java)
        val leaky = fields.filter { it.type !in allowed }
        assertTrue(leaky.isEmpty(), "ApduExchange must stay header-only; found ${leaky.map { it.name + ": " + it.type.name }}")
    }

    @Test
    fun `header, Lc, status word, response length and elapsed time are reported`() {
        val clock = TestTimeSource()
        val inner = FakeBibo(clock, delayMs = 12) { ByteArray(10) + byteArrayOf(0x90.toByte(), 0x00) }
        val (seen, hook) = recorder()
        val bibo = TracingBibo(inner, hook, clock)
        val cmd = byteArrayOf(0x00, 0x64, 0x01, 0x02, 0x03, 0x0A, 0x0B, 0x0C)
        val resp = bibo.transceive(cmd)
        assertEquals(12, resp!!.size)
        assertContentEquals(cmd, inner.received.single())
        val e = seen.single()
        assertEquals(0x00, e.cla); assertEquals(0x64, e.ins); assertEquals(1, e.p1); assertEquals(2, e.p2)
        assertEquals(3, e.lc)
        assertEquals(0x9000, e.sw)
        assertEquals("9000", e.swHex)
        assertEquals("OK", e.swName)
        assertEquals("GET_VERSION", e.insName)
        assertEquals(10, e.responseLength)
        assertEquals(12_000_000L, e.elapsedNanos)
        assertEquals(12L, e.elapsedMillis)
        assertEquals(ApduExchange.Outcome.OK, e.outcome)
        assertEquals(1, e.sequence)
        assertEquals("GET_VERSION 9000 12ms", e.toString())
    }

    @Test
    fun `sequence numbers increase per exchange and close is forwarded`() {
        val inner = FakeBibo()
        val (seen, hook) = recorder()
        val bibo = TracingBibo(inner, hook)
        repeat(3) { bibo.transceive(byteArrayOf(0x00, 0x02, 0x00, 0x00)) }
        assertEquals(listOf(1, 2, 3), seen.map { it.sequence })
        bibo.close()
        assertEquals(1, inner.closes)
    }

    @Test
    fun `a non-9000 answer is CARD_ERROR with its status word`() {
        val (seen, hook) = recorder()
        TracingBibo(FakeBibo { byteArrayOf(0x6A, 0x83.toByte()) }, hook).transceive(byteArrayOf(0x00, 0x36, 0x00, 0x00))
        val e = seen.single()
        assertEquals(ApduExchange.Outcome.CARD_ERROR, e.outcome)
        assertEquals("6A83", e.swHex)
        assertEquals("RECORD_NOT_FOUND", e.swName)
        assertEquals(0, e.responseLength)
    }

    @Test
    fun `a null or one-byte response is TRANSPORT_FAILURE and is returned unchanged`() {
        val (seen, hook) = recorder()
        assertNull(TracingBibo(FakeBibo { null }, hook).transceive(byteArrayOf(0x00, 0x04, 0x00, 0x00)))
        val one = byteArrayOf(0x6F)
        assertSame(one, TracingBibo(FakeBibo { one }, hook).transceive(byteArrayOf(0x00, 0x04, 0x00, 0x00)))
        assertEquals(listOf(ApduExchange.Outcome.TRANSPORT_FAILURE, ApduExchange.Outcome.TRANSPORT_FAILURE), seen.map { it.outcome })
        assertTrue(seen.all { it.sw == null && it.swHex == null && it.swName == null })
    }

    @Test
    fun `tag loss, refusal and transport failure are recorded and the same exception is rethrown`() {
        val (seen, hook) = recorder()
        val lost = BIBOTagLostException("gone", IOException())
        val io = BIBOException("io")
        val crash = IllegalStateException("bug")
        for (t in listOf<Throwable>(lost, io, crash)) {
            val thrown = assertFailsWith<Throwable> {
                TracingBibo(FakeBibo { throw t }, hook).transceive(byteArrayOf(0x00, 0x30, 0x00, 0x00, 0x01, 0x00))
            }
            assertSame(t, thrown)
        }
        val refused = assertFailsWith<ReadOnlyViolationException> {
            TracingBibo(ReadOnlyBibo(FakeBibo()), hook).transceive(byteArrayOf(0x00, 0x25, 0x00, 0x00, 0x01, 0x00))
        }
        assertEquals(0x25, refused.ins)
        assertEquals(
            listOf(ApduExchange.Outcome.TAG_LOST, ApduExchange.Outcome.TRANSPORT_FAILURE, ApduExchange.Outcome.TRANSPORT_FAILURE, ApduExchange.Outcome.REFUSED),
            seen.map { it.outcome }
        )
        assertTrue(seen.all { it.sw == null && it.responseLength == 0 })
        assertEquals("SIGN_AUTH", seen.last().insName)
    }

    @Test
    fun `a throwing hook cannot replace the transport's exception`() {
        val lost = BIBOTagLostException("gone", IOException())
        val bibo = TracingBibo(FakeBibo { throw lost }, { throw IllegalStateException("hook bug") })
        val thrown = assertFailsWith<BIBOTagLostException> { bibo.transceive(byteArrayOf(0x00, 0x04, 0x00, 0x00)) }
        assertSame(lost, thrown)
    }

    @Test
    fun `a throwing hook cannot fail a successful exchange`() {
        val ok = byteArrayOf(1, 2, 0x90.toByte(), 0x00)
        val bibo = TracingBibo(FakeBibo { ok }, { throw OutOfMemoryError("hook bug") })
        assertSame(ok, bibo.transceive(byteArrayOf(0x00, 0x04, 0x00, 0x00)))
    }

    @Test
    fun `commands shorter than the 4-byte header, and null, are forwarded untouched and not reported`() {
        val inner = FakeBibo()
        val (seen, hook) = recorder()
        val bibo = TracingBibo(inner, hook)
        val three = byteArrayOf(0x00, 0xA4.toByte(), 0x04)
        bibo.transceive(three)
        bibo.transceive(null)
        assertSame(three, inner.received[0])
        assertContentEquals(byteArrayOf(0x00, 0xA4.toByte(), 0x04), inner.received[0])
        assertNull(inner.received[1])
        assertTrue(seen.isEmpty())
    }

    @Test
    fun `Lc is decoded for short, Le-only and extended-length commands`() {
        val c = TracingBibo.Companion
        assertEquals(0, c.commandDataLength(byteArrayOf(0, 0x04, 0, 0)))
        assertEquals(0, c.commandDataLength(byteArrayOf(0, 0x04, 0, 0, 0x08)))          // case 2s (Le)
        assertEquals(2, c.commandDataLength(byteArrayOf(0, 0x25, 0, 0, 0x02, 1, 2)))    // case 3s
        assertEquals(0, c.commandDataLength(byteArrayOf(0, 0x04, 0, 0, 0, 0x01, 0x00))) // case 2e (Le)
        val ext = byteArrayOf(0, 0x31, 1, 0, 0, 0x01, 0x00) + ByteArray(256)
        assertEquals(256, c.commandDataLength(ext))                                     // case 3e
        val (seen, hook) = recorder()
        TracingBibo(FakeBibo(), hook).transceive(ext)
        assertEquals(256, seen.single().lc)
    }

    @Test
    fun `the SDK's reads over jcardsim are traced with real status words`() {
        val (seen, hook) = recorder()
        val sdk = ImpalaSDK(TracingBibo(SimulatorBibo(), hook))
        sdk.getImpalaAppletVersion()
        runCatching { sdk.getLastTransfer() } // a blank card never signed: not 9000
        assertEquals("GET_VERSION", seen[0].insName)
        assertEquals(ApduExchange.Outcome.OK, seen[0].outcome)
        assertEquals(10, seen[0].responseLength)
        assertEquals("GET_LAST_TRANSFER", seen[1].insName)
        assertFalse(seen[1].outcome == ApduExchange.Outcome.OK)
        assertTrue(seen[1].swHex != null)
    }
}

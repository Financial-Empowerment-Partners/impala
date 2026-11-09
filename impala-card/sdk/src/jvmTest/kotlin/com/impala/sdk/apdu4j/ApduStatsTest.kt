package com.impala.sdk.apdu4j

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ApduStatsTest {
    private var seq = 0
    private fun ex(ins: Int, ms: Long, outcome: ApduExchange.Outcome = ApduExchange.Outcome.OK, sw: Int? = 0x9000) =
        ApduExchange(0x00, ins, 0, 0, 0, sw, 0, ms * 1_000_000L, outcome, ++seq)

    @Test
    fun `min, avg, max per INS and the outcome counts`() {
        val stats = ApduStats.of(listOf(
            ex(0x64, 10), ex(0x34, 30), ex(0x64, 20), ex(0x64, 31),
            ex(0x04, 5, ApduExchange.Outcome.TAG_LOST, null),
            ex(0x25, 0, ApduExchange.Outcome.REFUSED, null),
            ex(0x36, 7, ApduExchange.Outcome.CARD_ERROR, 0x6A83),
            ex(0x02, 1, ApduExchange.Outcome.TRANSPORT_FAILURE, null),
            ex(0x34, 0, ApduExchange.Outcome.CARD_ERROR, 0x6234)
        ))
        assertEquals(9, stats.count)
        assertEquals(104_000_000L, stats.totalNanos)
        assertEquals(1, stats.tagLosses)
        assertEquals(1, stats.refusals)
        // GET_LAST_TRANSFER's 6A83 (never signed) is an expected answer; NOT_PERSONALIZED is a card error.
        assertEquals(1, stats.cardErrors)
        assertEquals(1, stats.expectedStatuses)
        assertEquals(1, stats.transportFailures)
        assertEquals(listOf("GET_VERSION", "GET_PERSONALIZATION", "GET_BALANCE", "SIGN_AUTH", "GET_LAST_TRANSFER", "NOP"), stats.perIns.keys.toList())
        val v = stats.perIns.getValue("GET_VERSION")
        assertEquals(3, v.count)
        assertEquals(10_000_000L, v.minNanos)
        assertEquals(31_000_000L, v.maxNanos)
        assertEquals(61_000_000L, v.totalNanos)
        assertEquals(20_333_333L, v.avgNanos) // integer mean
        assertEquals(31_000_000L, stats.maxNanos)
    }

    @Test
    fun `a healthy never-signed card reports no card error`() {
        val stats = ApduStats.of(listOf(
            ex(0x64, 3), ex(0x34, 4), ex(0x36, 2, ApduExchange.Outcome.CARD_ERROR, 0x6A83), ex(0x04, 2)
        ))
        assertEquals(0, stats.cardErrors)
        assertEquals(1, stats.expectedStatuses)
    }

    @Test
    fun `only GET_LAST_TRANSFER at CLA 00 answering 6A83 is an expected status`() {
        assertTrue(ApduNames.isExpectedStatus(0x00, 0x36, 0x6A83))
        assertFalse(ApduNames.isExpectedStatus(0x00, 0x36, 0x9000))
        assertFalse(ApduNames.isExpectedStatus(0x00, 0x36, null))
        assertFalse(ApduNames.isExpectedStatus(0x00, 0x04, 0x6A83)) // GET_BALANCE: 6A83 is not documented there
        assertFalse(ApduNames.isExpectedStatus(0x80, 0x36, 0x6A83))
        assertFalse(ApduNames.isExpectedStatus(0x00, 0x36, 0x6A82))
        // Another command's 6A83 still counts as a card error.
        val stats = ApduStats.of(listOf(ex(0x35, 1, ApduExchange.Outcome.CARD_ERROR, 0x6A83)))
        assertEquals(1, stats.cardErrors)
        assertEquals(0, stats.expectedStatuses)
    }

    @Test
    fun `no exchanges gives zeros`() {
        val stats = ApduStats.of(emptyList())
        assertEquals(0, stats.count)
        assertEquals(0, stats.expectedStatuses)
        assertEquals(0L, stats.totalNanos)
        assertEquals(0L, stats.maxNanos)
        assertTrue(stats.perIns.isEmpty())
        assertEquals(0L, ApduStats.InsStats(0, 0, 0, 0).avgNanos)
    }
}

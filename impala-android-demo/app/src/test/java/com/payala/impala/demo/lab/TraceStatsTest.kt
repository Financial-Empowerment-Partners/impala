package com.payala.impala.demo.lab

import com.impala.sdk.apdu4j.ApduExchange
import com.payala.impala.demo.ui.lab.CheckStatus
import com.payala.impala.demo.ui.lab.adapters.StatsGrid
import com.payala.impala.demo.ui.lab.adapters.toneOf
import org.junit.Assert.assertEquals
import org.junit.Test

/** The Trace tab: a never-signed card's GET_LAST_TRANSFER 6A83 is not an error, and the stats grid reflows at large font. */
class TraceStatsTest {
    private fun ex(ins: Int, sw: Int?, outcome: ApduExchange.Outcome) = ApduExchange(0x00, ins, 0, 0, 0, sw, 0, 1_000_000L, outcome, 1)

    @Test
    fun `GET_LAST_TRANSFER answering 6A83 is informational, other card errors warn`() {
        assertEquals(CheckStatus.INFO, toneOf(ex(0x36, 0x6A83, ApduExchange.Outcome.CARD_ERROR)))
        assertEquals(CheckStatus.WARN, toneOf(ex(0x34, 0x6234, ApduExchange.Outcome.CARD_ERROR)))
        assertEquals(CheckStatus.WARN, toneOf(ex(0x35, 0x6A83, ApduExchange.Outcome.CARD_ERROR)))
        assertEquals(CheckStatus.PASS, toneOf(ex(0x36, 0x9000, ApduExchange.Outcome.OK)))
        assertEquals(CheckStatus.FAIL, toneOf(ex(0x04, null, ApduExchange.Outcome.TAG_LOST)))
        assertEquals(CheckStatus.FAIL, toneOf(ex(0x25, null, ApduExchange.Outcome.REFUSED)))
    }

    @Test
    fun `the stats grid uses two columns at large font or on a narrow screen`() {
        assertEquals(4, StatsGrid.columns(1.0f, 411))
        assertEquals(4, StatsGrid.columns(1.1f, 411))
        assertEquals(2, StatsGrid.columns(1.3f, 411))
        assertEquals(2, StatsGrid.columns(2.0f, 411))
        assertEquals(2, StatsGrid.columns(1.0f, 320))
        assertEquals(4, StatsGrid.columns(1.0f, 0)) // unknown width: by font scale only
    }
}

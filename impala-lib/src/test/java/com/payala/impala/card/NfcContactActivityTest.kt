package com.payala.impala.card

import android.content.Intent
import android.nfc.NfcAdapter
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.NfcContactActivity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class NfcContactActivityTest {
    @After
    fun tearDown() = ImpalaCardTapHandler.setCardTapListener(null)

    @Test
    fun `system dispatch forwards identity to the registered listener and sends no state-changing INS`() {
        val account = uuidBytes()
        val card = personalizedCard(TestIssuer(), account)
        val ins = mutableListOf<Int>()
        card.bibo.debugTrace = { cmd, _ -> ins += cmd[1].toInt() and 0xFF }
        var delivered: CardTapEvent? = null
        ImpalaCardTapHandler.setCardTapListener { delivered = it }

        val event = offMain { ImpalaCardSession.fromBibo(card.bibo).use { ImpalaCardTapHandler.readTap(it) } }
        assertNotNull(event)
        ImpalaCardTapHandler.deliver(event!!)
        assertEquals(com.impala.sdk.flows.UuidBytes.format(account), delivered!!.identity.accountUuid)
        assertTrue("unexpected INS in $ins", ins.all { it in setOf(0x64, 0x1E, 0x24, 0x34) })
        assertEquals(setOf(0x64, 0x1E, 0x24, 0x34), ins.toSet())
    }

    @Test
    fun `no listener means the card is not read`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        var sent = 0
        card.bibo.debugTrace = { _, _ -> sent++ }
        assertNull(offMain { ImpalaCardSession.fromBibo(card.bibo).use { ImpalaCardTapHandler.readTap(it) } })
        assertEquals(0, sent)
    }

    @Test
    fun `an intent without a tag finishes without touching anything`() {
        val intent = Intent(NfcAdapter.ACTION_TECH_DISCOVERED)
        val activity = Robolectric.buildActivity(NfcContactActivity::class.java, intent).create().get()
        assertTrue(activity.isFinishing)
    }
}

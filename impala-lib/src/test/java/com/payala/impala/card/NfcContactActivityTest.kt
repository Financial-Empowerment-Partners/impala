package com.payala.impala.card

import android.app.Application
import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import com.impala.sdk.apdu4j.BIBO
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
import org.robolectric.Shadows.shadowOf
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
class NfcContactActivityTest {
    private val app: Application = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        ImpalaCardTapHandler.setCardTapListener(null)
        NfcContactActivity.resetSessionOpener()
    }

    /** The non-mutating set system dispatch may send (SELECT is not an applet INS and is checked separately). */
    private val identityIns = setOf(0x64, 0x1E, 0x24, 0x34)

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
        assertTrue("unexpected INS in $ins", ins.all { it in identityIns })
        assertEquals(identityIns, ins.toSet())
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

    // --- the dispatched tap SELECTs the consuming app's AID (CardAppletAid) ---

    private class Dispatch(val aid: String?, val commands: List<ByteArray>, val event: CardTapEvent?)

    /** Dispatches a tag with [meta] as the app's meta-data and returns what the activity did. */
    private fun dispatch(meta: Bundle?, expectEvent: Boolean = true): Dispatch {
        shadowOf(app.packageManager).getInternalMutablePackageInfo(app.packageName).applicationInfo!!.metaData = meta
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val recorder = object : BIBO {
            val sent = java.util.Collections.synchronizedList(mutableListOf<ByteArray>())
            override fun transceive(bytes: ByteArray?): ByteArray? { sent += bytes!!.copyOf(); return card.bibo.transceive(bytes) }
            override fun close() {}
        }
        val aid = AtomicReference<String?>("unset")
        val opened = CountDownLatch(1)
        val read = CountDownLatch(1)
        NfcContactActivity.sessionOpener = NfcContactActivity.SessionOpener { _, aidHex ->
            aid.set(aidHex)
            opened.countDown()
            try {
                ImpalaCardSession.fromBibo(recorder, aidHex)
            } finally {
                read.countDown()
            }
        }
        var event: CardTapEvent? = null
        ImpalaCardTapHandler.setCardTapListener { event = it }
        val intent = Intent(NfcAdapter.ACTION_TECH_DISCOVERED).putExtra(NfcAdapter.EXTRA_TAG, TestTags.isoDepA())
        val activity = Robolectric.buildActivity(NfcContactActivity::class.java, intent).create().get()
        assertTrue(activity.isFinishing)
        assertTrue("the activity never opened a session", opened.await(10, TimeUnit.SECONDS))
        assertTrue(read.await(10, TimeUnit.SECONDS))
        if (expectEvent) {
            idleMainUntil { event != null }
        } else {
            // A refused SELECT throws out of the opener: nothing is read or posted.
            Thread.sleep(200)
            shadowOf(android.os.Looper.getMainLooper()).idle()
        }
        return Dispatch(aid.get(), recorder.sent.toList(), event)
    }

    private fun ByteArray.ins() = this[1].toInt() and 0xFF

    @Test
    fun `absent meta-data SELECTs the testnet AID, then reads only the identity`() {
        val d = dispatch(null)
        assertEquals(ImpalaCardSession.TESTNET_APPLET_AID, d.aid)
        assertEquals(0xA4, d.commands.first().ins())
        assertEquals("00a404000a" + ImpalaCardSession.TESTNET_APPLET_AID, d.commands.first().joinToString("") { "%02x".format(it) })
        val applet = d.commands.drop(1).map { it.ins() }
        assertTrue("unexpected INS in $applet", applet.all { it in identityIns })
        assertEquals(identityIns, applet.toSet())
        assertNotNull(d.event)
    }

    @Test
    fun `an empty AID means no SELECT (the default-selected applet answers)`() {
        val d = dispatch(Bundle().apply { putString(CardAppletAid.META_DATA_KEY, "") })
        assertNull(d.aid)
        assertTrue(d.commands.none { it.ins() == 0xA4 })
        assertEquals(identityIns, d.commands.map { it.ins() }.toSet())
        assertNotNull(d.event)
    }

    @Test
    fun `a custom AID is the one SELECTed`() {
        val custom = "A0000006472F0001"
        val d = dispatch(Bundle().apply { putString(CardAppletAid.META_DATA_KEY, custom) }, expectEvent = false)
        assertEquals(custom, d.aid)
        assertEquals("00A4040008$custom", d.commands.first().joinToString("") { "%02X".format(it) })
        // jcardsim has no applet under that AID: 6A82, nothing read, nothing delivered.
        assertEquals(1, d.commands.size)
        assertNull(d.event)
    }
}

package com.payala.impala.card

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.os.Looper
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOTagLostException
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.sdk.flows.CardIdentity
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.argThat
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class CardReaderControllerTest {
    private val activity: Activity = Robolectric.buildActivity(Activity::class.java).get()
    private val tag: Tag = mock(Tag::class.java)

    @Test
    fun `enableReaderMode passes the NFC-A, NFC-B and SKIP_NDEF flags and the 250 ms presence delay`() {
        val adapter = mock(NfcAdapter::class.java)
        val controller = CardReaderController(activity, adapter)
        assertTrue(controller.enableReaderMode({ 1 }, { }))
        val expected = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        verify(adapter).enableReaderMode(
            eq(activity), any(),
            eq(expected),
            argThat { b: Bundle? -> b?.getInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY) == 250 }
        )
        controller.disableReaderMode()
        verify(adapter).disableReaderMode(activity)
    }

    @Test
    fun `no adapter means reader mode is unavailable`() {
        val controller = CardReaderController(activity, null)
        assertEquals(false, controller.isNfcAvailable)
        assertEquals(false, controller.enableReaderMode({ 1 }, { }))
    }

    @Test
    fun `onTap runs off the main thread and onResult is delivered on the main thread`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val controller = CardReaderController(activity, mock(NfcAdapter::class.java), sessionFactory = { ImpalaCardSession.fromBibo(card.bibo) })
        var tapThread: Thread? = null
        var resultThread: Thread? = null
        var result: Result<CardIdentity>? = null
        offMain {
            controller.handleTag(tag, { s -> tapThread = Thread.currentThread(); s.identity }, { r ->
                resultThread = Thread.currentThread(); result = r
            })
        }
        shadowOf(Looper.getMainLooper()).idle()
        assertNotSame(Looper.getMainLooper().thread, tapThread)
        assertSame(Looper.getMainLooper().thread, resultThread)
        assertTrue(result!!.isSuccess)
    }

    @Test
    fun `tag lost during onTap yields CardError TagLost and disables nothing`() {
        val adapter = mock(NfcAdapter::class.java)
        val lost = object : BIBO {
            override fun transceive(bytes: ByteArray?): ByteArray = throw BIBOTagLostException("gone", IOException())
            override fun close() {}
        }
        val controller = CardReaderController(activity, adapter, sessionFactory = { ImpalaCardSession.fromBibo(lost) })
        var result: Result<CardIdentity>? = null
        offMain { controller.handleTag(tag, { it.identity }, { result = it }) }
        shadowOf(Looper.getMainLooper()).idle()
        val e = result!!.exceptionOrNull() as CardFlowException
        assertSame(CardError.TagLost, e.error)
        verify(adapter, never()).disableReaderMode(any())
    }

    @Test
    fun `non-card failures in onTap pass through unchanged`() {
        val card = personalizedCard(TestIssuer(), uuidBytes())
        val controller = CardReaderController(activity, mock(NfcAdapter::class.java), sessionFactory = { ImpalaCardSession.fromBibo(card.bibo) })
        var result: Result<Unit>? = null
        offMain { controller.handleTag(tag, { throw IOException("HTTP 503") }, { result = it }) }
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(result!!.exceptionOrNull() is IOException)
    }
}

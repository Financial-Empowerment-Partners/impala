package com.payala.impala.card

import android.os.Bundle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CardTransportFactsTest {
    @Test
    fun `hex is upper case without separators, null for null`() {
        assertEquals("00ABFF10", CardTransportFacts.hex(byteArrayOf(0x00, 0xAB.toByte(), 0xFF.toByte(), 0x10)))
        assertEquals("", CardTransportFacts.hex(ByteArray(0)))
        assertNull(CardTransportFacts.hex(null))
    }

    @Test
    fun `an NFC-A tag reports UID, techs, ATQA and SAK, and nulls for NFC-B`() {
        val tag = TestTags.isoDepA(id = byteArrayOf(0x04, 0xA1.toByte(), 0x5C, 0x7E), atqa = byteArrayOf(0x44, 0x03), sak = 0x20)
        val facts = CardTransportFacts.of(tag, null)
        assertEquals("04A15C7E", facts.uidHex)
        assertEquals(listOf("NfcA", "IsoDep"), facts.techList)
        assertEquals("4403", facts.atqaHex)
        assertEquals(0x20, facts.sak)
        assertNull(facts.nfcBApplicationDataHex)
        assertNull(facts.nfcBProtocolInfoHex)
        assertFalse(facts.iso14443Part4) // no IsoDep handle was passed
        assertEquals(0, facts.maxTransceiveLength)
        assertNull(facts.historicalBytesHex)
    }

    @Test
    fun `an NFC-B tag reports its application data and protocol info, and nulls for NFC-A`() {
        val extras = arrayOf(
            Bundle().apply { putByteArray("appdata", byteArrayOf(0x01, 0x02, 0x03, 0x04)); putByteArray("protinfo", byteArrayOf(0x00, 0x71)) },
            Bundle()
        )
        val tag = TestTags.tag(byteArrayOf(0x11, 0x22), intArrayOf(TestTags.NFC_B, TestTags.ISO_DEP), extras)
        val facts = CardTransportFacts.of(tag, android.nfc.tech.IsoDep.get(tag))
        assertEquals("1122", facts.uidHex)
        assertEquals("01020304", facts.nfcBApplicationDataHex)
        assertEquals("0071", facts.nfcBProtocolInfoHex)
        assertNull(facts.atqaHex)
        assertNull(facts.sak)
        assertTrue(facts.iso14443Part4)
    }

    @Test
    fun `toString carries no historical bytes or ATQA`() {
        val facts = CardTransportFacts("04A1", listOf("IsoDep"), true, 261, false, 15_000, "8073", null, "4400", 0x20, null, null)
        assertFalse(facts.toString().contains("8073"))
    }
}

package com.payala.impala.demo

import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.card.CardAuthenticator
import com.payala.impala.card.ImpalaCardSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Golden wire forms the bridge pins (`validate_card_id`, `validate_ec_pubkey`, `validate_hex_signature`). */
@RunWith(RobolectricTestRunner::class)
class WireFormatsTest {
    @Test
    fun `card id is the dash-stripped lowercase 32-hex UUID`() {
        val identity = fakeIdentity(cardUuid = "00112233-4455-6677-8899-AABBCCDDEEFF")
        assertEquals("00112233445566778899aabbccddeeff", identity.wireCardId)
        assertEquals("00112233-4455-6677-8899-aabbccddeeff", identity.cardUuid)
    }

    @Test
    fun `ec pubkey is the 130-hex uncompressed point passed through unchanged`() {
        val point = byteArrayOf(0x04) + ByteArray(64) { (0xF0 + it % 16).toByte() }
        val identity = fakeIdentity(pubKey = point)
        assertEquals(130, identity.pubKeyHex.length)
        assertEquals(Hex.encode(point), identity.pubKeyHex)
        assertTrue(identity.pubKeyHex.startsWith("04"))
    }

    @Test
    fun `signature hex is lowercase DER without separators`() {
        val card = personalizedCard(TestIssuer(), UuidBytes.parse("0f0e0d0c-0b0a-0908-0706-050403020100"))
        val sig = offMain { CardAuthenticator.signChallenge(ImpalaCardSession.fromBibo(card.bibo), "ab".repeat(32)) }
        assertTrue(sig.matches(Regex("30[0-9a-f]+")))
        assertTrue(sig.length in 16..144)
        assertEquals(sig.length, ((sig.substring(2, 4).toInt(16)) + 2) * 2)
    }

    /** The shared golden transfer_id (scripts/check-shared-vectors.sh pins this literal here too). */
    @Test
    fun `transfer id of the golden XFER message matches the shared vector`() {
        val program = ByteArray(16) { (0xA0 + it).toByte() }
        val signable = com.impala.sdk.models.Signable(
            1, UuidBytes.parse("00112233-4455-6677-8899-aabbccddeeff"), Hex.decode("ffeeddccbbaa99887766554433221100"),
            com.impala.sdk.models.TransferProtocol.CURRENCY_USDC, 1000, 0, 1
        ).encode()
        assertEquals(
            "6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9",
            com.impala.sdk.models.TransferProtocol.transferId(program, signable).hex()
        )
    }
}

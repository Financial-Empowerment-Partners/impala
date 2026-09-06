package com.impala.sdk

import com.impala.applet.SecP256r1
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferEnvelope
import com.impala.sdk.models.TransferProtocol
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Golden vectors for the issuer-certified transfer protocol (applet 0.2,
 * protocol v1). The four hex literals below are THE shared fixture: the bridge
 * pins the same bytes in `impala-bridge/src/handlers/card_auth.rs`
 * (`golden_xfer_message_layout` / `golden_cert_message_layout`), and
 * `scripts/check-shared-vectors.sh` greps each literal in both files.
 * Change them only by changing both sides together.
 */
class TransferProtocolGoldenTest {

    private companion object {
        val PROGRAM_ID = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf".decodeHex().toByteArray()
        val ACCOUNT_ID = "00112233445566778899aabbccddeeff".decodeHex().toByteArray() // card_auth.rs test_uuid()
        val RECIPIENT = "ffeeddccbbaa99887766554433221100".decodeHex().toByteArray()
        val USDC = "USDC".encodeToByteArray()

        /** The P-256 generator, exactly as GET_EC_PUB_KEY would return it. */
        val CARD_PUBKEY: ByteArray = SecP256r1.P_secp256r1.copyOf()

        // --- shared golden literals (verbatim from the protocol spec §3.3) ---
        const val CERT_MESSAGE_HEX =
            "494d50414c412d434552543a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff55534443046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        const val XFER_MESSAGE_HEX =
            "494d50414c412d584645523a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000100112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110055534443000003e8000000000000000000000001"
        const val TRANSFER_ID_HEX = "6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9"
        const val CERT_ID_HEX = "82cb580b058873f2554b100cfee07bc7ef7fa5def3ddc477e333f2f60258b77b"
    }

    private fun goldenSignable(): Signable = Signable(
        dateTime = 1L,
        sender = ACCOUNT_ID,
        recipient = RECIPIENT,
        currency = USDC,
        amount = 1000L,
        phoneId = 0L,
        counter = 1
    )

    @Test
    fun `domain tags are the pinned ASCII bytes and differ from the auth tag`() {
        assertContentEquals(
            byteArrayOf(0x49, 0x4D, 0x50, 0x41, 0x4C, 0x41, 0x2D, 0x58, 0x46, 0x45, 0x52, 0x3A),
            TransferProtocol.XFER_DOMAIN_TAG
        )
        assertContentEquals(
            byteArrayOf(0x49, 0x4D, 0x50, 0x41, 0x4C, 0x41, 0x2D, 0x43, 0x45, 0x52, 0x54, 0x3A),
            TransferProtocol.CERT_DOMAIN_TAG
        )
        val auth = "IMPALA-AUTH:".encodeToByteArray()
        assertEquals(12, auth.size)
        assertEquals(12, TransferProtocol.XFER_DOMAIN_TAG.size)
        assertEquals(12, TransferProtocol.CERT_DOMAIN_TAG.size)
        assert(!auth.contentEquals(TransferProtocol.XFER_DOMAIN_TAG))
        assert(!auth.contentEquals(TransferProtocol.CERT_DOMAIN_TAG))
        assert(!TransferProtocol.XFER_DOMAIN_TAG.contentEquals(TransferProtocol.CERT_DOMAIN_TAG))
        assertEquals(0x01, TransferProtocol.TRANSFER_VERSION.toInt())
        assertEquals(0x01, TransferProtocol.CERT_VERSION.toInt())
        assertEquals(1024, TransferProtocol.MAX_COUNTER_JUMP)
    }

    @Test
    fun `CERT message matches the shared golden vector`() {
        val cert = TransferProtocol.certMessage(PROGRAM_ID, ACCOUNT_ID, USDC, CARD_PUBKEY)
        assertEquals(114, cert.size)
        assertEquals(CERT_MESSAGE_HEX, cert.toByteString().hex())
        assertEquals(CERT_ID_HEX, TransferProtocol.certId(PROGRAM_ID, ACCOUNT_ID, USDC, CARD_PUBKEY).hex())
    }

    @Test
    fun `XFER message and transfer id match the shared golden vector`() {
        val signable = goldenSignable().encode()
        val xfer = TransferProtocol.xferMessage(PROGRAM_ID, signable)
        assertEquals(89, xfer.size)
        assertEquals(XFER_MESSAGE_HEX, xfer.toByteString().hex())
        assertEquals(TRANSFER_ID_HEX, TransferProtocol.transferId(PROGRAM_ID, signable).hex())
        assertEquals(TRANSFER_ID_HEX, TransferEnvelope(signable, ByteArray(8) { 0x30 }, CARD_PUBKEY, ByteArray(8) { 0x30 }).transferId(PROGRAM_ID).hex())
    }

    @Test
    fun `signable encodes at the pinned offsets and round-trips`() {
        val s = goldenSignable()
        val b = s.encode()
        assertEquals(60, b.size)
        assertEquals(0, Signable.OFFSET_DATE_TIME)
        assertEquals(8, Signable.OFFSET_SENDER)
        assertEquals(24, Signable.OFFSET_RECIPIENT)
        assertEquals(40, Signable.OFFSET_CURRENCY)
        assertEquals(44, Signable.OFFSET_AMOUNT)
        assertEquals(48, Signable.OFFSET_PHONE_ID)
        assertEquals(56, Signable.OFFSET_COUNTER)
        assertContentEquals("0000000000000001".decodeHex().toByteArray(), b.copyOfRange(0, 8))
        assertContentEquals(ACCOUNT_ID, b.copyOfRange(8, 24))
        assertContentEquals(RECIPIENT, b.copyOfRange(24, 40))
        assertContentEquals(USDC, b.copyOfRange(40, 44))
        assertContentEquals("000003e8".decodeHex().toByteArray(), b.copyOfRange(44, 48))
        assertContentEquals(ByteArray(8), b.copyOfRange(48, 56))
        assertContentEquals("00000001".decodeHex().toByteArray(), b.copyOfRange(56, 60))

        val decoded = Signable.decode(b)
        assertEquals(s, decoded)
        assertContentEquals(b, decoded.encode())
        assertEquals(1000L, decoded.amount)
        assertEquals(1, decoded.counter)
    }

    @Test
    fun `signable amount bounds are 1 to 0xFFFFFFFF`() {
        assertFailsWith<IllegalArgumentException> { goldenSignable().let { Signable(it.dateTime, it.sender, it.recipient, it.currency, 0L, 0L, 1) } }
        assertFailsWith<IllegalArgumentException> { goldenSignable().let { Signable(it.dateTime, it.sender, it.recipient, it.currency, 0x1_0000_0000L, 0L, 1) } }
        val max = goldenSignable().let { Signable(it.dateTime, it.sender, it.recipient, it.currency, 0xFFFF_FFFFL, 0L, 1) }
        assertEquals(0xFFFF_FFFFL, Signable.decode(max.encode()).amount)
        assertFailsWith<IllegalArgumentException> { goldenSignable().let { Signable(it.dateTime, it.sender, it.recipient, it.currency, 1L, 0L, 0) } }
        assertFailsWith<IllegalArgumentException> { goldenSignable().let { Signable(-1L, it.sender, it.recipient, it.currency, 1L, 0L, 1) } }
        assertFailsWith<IllegalArgumentException> { Signable.decode(ByteArray(59)) }
    }

    @Test
    fun `trimDer and padSlot72 enforce the slot bounds`() {
        val der = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
        val slot = TransferProtocol.padSlot72(der)
        assertEquals(72, slot.size)
        assertContentEquals(der, TransferProtocol.trimDer(slot))
        assertContentEquals(der, TransferProtocol.trimDer(der))
        assertFailsWith<IllegalArgumentException> { TransferProtocol.padSlot72(ByteArray(7)) }
        assertFailsWith<IllegalArgumentException> { TransferProtocol.padSlot72(ByteArray(73)) }
        assertFailsWith<IllegalArgumentException> { TransferProtocol.trimDer(ByteArray(72)) }               // not 0x30
        assertFailsWith<IllegalArgumentException> { TransferProtocol.trimDer(byteArrayOf(0x30, 0x47) + ByteArray(70)) } // 73 > 72
        assertFailsWith<IllegalArgumentException> { TransferProtocol.trimDer(byteArrayOf(0x30, 0x04) + ByteArray(70)) } // 6 < 8
        assertFailsWith<IllegalArgumentException> { TransferProtocol.trimDer(ByteArray(73)) }
        assertFailsWith<IllegalArgumentException> { TransferProtocol.trimDer(ByteArray(7)) }
    }

    @Test
    fun `counter and sequence allocators`() {
        assertEquals(1, TransferProtocol.nextReceiveCounter(0))
        assertEquals(Int.MAX_VALUE, TransferProtocol.nextReceiveCounter(Int.MAX_VALUE - 1))
        assertFailsWith<IllegalStateException> { TransferProtocol.nextReceiveCounter(Int.MAX_VALUE) }
        assertFailsWith<IllegalArgumentException> { TransferProtocol.nextReceiveCounter(-1) }
        assertEquals(6L, TransferProtocol.nextSendSequence(5, 3))
        assertEquals(9L, TransferProtocol.nextSendSequence(5, 9))
        assertFailsWith<IllegalArgumentException> { TransferProtocol.nextSendSequence(-1, 0) }
    }

    @Test
    fun `currency tags match the bridge table`() {
        assertContentEquals(byteArrayOf(0x58, 0x4C, 0x4D, 0x00), TransferProtocol.currencyTag("XLM"))
        assertContentEquals("USDC".encodeToByteArray(), TransferProtocol.currencyTag("USDC"))
        assertContentEquals("UST0".encodeToByteArray(), TransferProtocol.currencyTag("USDT0"))
        assertFailsWith<IllegalArgumentException> { TransferProtocol.currencyTag("EUR") }
    }

    @Test
    fun `install parameter layouts`() {
        val keys = Triple(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 })
        val program = Pair(PROGRAM_ID, CARD_PUBKEY)
        val full = PersonalizationProtocol.installParams(enforce = true, keys = keys, pins = null, program = program)
        assertEquals(2 + 48 + 81, full.size)
        assertContentEquals(byteArrayOf(0x01, 0x0B), full.copyOfRange(0, 2))
        assertContentEquals(keys.first + keys.second + keys.third, full.copyOfRange(2, 50))
        assertContentEquals(PROGRAM_ID + CARD_PUBKEY, full.copyOfRange(50, 131))

        val withPins = PersonalizationProtocol.installParams(
            enforce = true, keys = keys, pins = Pair(ByteArray(8) { 9 }, byteArrayOf(4, 3, 2, 1)), program = null
        )
        assertEquals(2 + 48 + 12, withPins.size)
        assertContentEquals(byteArrayOf(0x01, 0x07), withPins.copyOfRange(0, 2))

        assertContentEquals(byteArrayOf(0x01, 0x00), PersonalizationProtocol.installParams(false, null, null, null))
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.installParams(true, null, null, program) }
    }

    @Test
    fun `identity part is 40 bytes and refuses nil ids`() {
        val part = PersonalizationProtocol.identityPart(ACCOUNT_ID, USDC, PROGRAM_ID, 4711)
        assertEquals(40, part.size)
        assertContentEquals(ACCOUNT_ID, part.copyOfRange(0, 16))
        assertContentEquals(USDC, part.copyOfRange(16, 20))
        assertContentEquals(PROGRAM_ID, part.copyOfRange(20, 36))
        assertContentEquals("00001267".decodeHex().toByteArray(), part.copyOfRange(36, 40))
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.identityPart(ByteArray(16), USDC, PROGRAM_ID) }
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.identityPart(ACCOUNT_ID, ByteArray(4), PROGRAM_ID) }
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.identityPart(ACCOUNT_ID, USDC, ByteArray(16)) }
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.identityPart(ACCOUNT_ID, USDC, PROGRAM_ID, -1) }
    }

    @Test
    fun `parsePersonalization pins the 159-byte layout and nulls empty slots`() {
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.parsePersonalization(ByteArray(158)) }
        assertFailsWith<IllegalArgumentException> { PersonalizationProtocol.parsePersonalization(ByteArray(160)) }

        val blank = PersonalizationProtocol.parsePersonalization(ByteArray(159))
        assertEquals(0x00, blank.state.toInt())
        assertNull(blank.issuerPubKey)
        assertNull(blank.certificate)

        val der = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
        val data = byteArrayOf(0x02, 0x3F) + PROGRAM_ID + USDC + CARD_PUBKEY + TransferProtocol.padSlot72(der)
        val p = PersonalizationProtocol.parsePersonalization(data)
        assertEquals(0x02, p.state.toInt())
        assertContentEquals(PROGRAM_ID, p.programId)
        assertContentEquals(USDC, p.currency)
        assertContentEquals(CARD_PUBKEY, p.issuerPubKey)
        assertContentEquals(der, p.certificate)
        assert(p.initialized && p.programBound && p.personalized && p.scp03KeysDefault && p.pinProvisioned && p.provisioningEnforced)
        assert(!p.terminated)
    }
}

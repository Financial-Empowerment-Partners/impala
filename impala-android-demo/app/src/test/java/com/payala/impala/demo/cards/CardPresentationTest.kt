package com.payala.impala.demo.cards

import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.ui.cards.CardPresentation
import com.payala.impala.demo.ui.cards.CardPresentation.Chip
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** The card face: full grouped id, chip rule, the line's parts, and nothing personal. */
class CardPresentationTest {

    private val cardId = "8d7d1a2b3c4d5e6f00112233aabbccdd"
    private val program = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

    private fun card(programIdHex: String = program, registeredAt: String = "2026-11-09T10:42:00.123Z") = StoredCard(
        cardId = cardId,
        accountUuid = "10000000-0000-4000-8000-000000000006",
        pubkeyFingerprint = "01:02:03:04:05:06:07:08:09:0a",
        programIdHex = programIdHex,
        currency = "XLM",
        appletVersion = "0.2",
        registeredAt = registeredAt
    )

    @Test
    fun `the full 32-hex id is shown as eight groups of four on two lines`() {
        val grouped = CardPresentation.groupedId(cardId)
        assertEquals("8d7d 1a2b 3c4d 5e6f\n0011 2233 aabb ccdd", grouped)
        assertEquals("nothing dropped", cardId, grouped.replace(" ", "").replace("\n", ""))
        assertEquals(2, grouped.lines().size)
        grouped.lines().forEach { line -> assertEquals(4, line.split(' ').size) }
    }

    @Test
    fun `grouping never truncates an unexpected length`() {
        assertEquals("0011 2233 4455 6677\n8899 aabb ccdd eeff\n0102", CardPresentation.groupedId("00112233445566778899aabbccddeeff0102"))
        assertEquals("abc", CardPresentation.groupedId("abc"))
        assertEquals("", CardPresentation.groupedId(""))
    }

    @Test
    fun `chip is Registered unless the bridge's known program differs`() {
        assertEquals(Chip.REGISTERED, CardPresentation.chip(program, program))
        assertEquals("hex compares ignoring case", Chip.REGISTERED, CardPresentation.chip(program, program.uppercase()))
        assertEquals("issuer unknown or unconfigured", Chip.REGISTERED, CardPresentation.chip(program, null))
        assertEquals(Chip.REGISTERED, CardPresentation.chip(program, ""))
        assertEquals("a record without a program id", Chip.REGISTERED, CardPresentation.chip("", program))
        assertEquals(Chip.PROGRAM_MISMATCH, CardPresentation.chip(program, "ffffffffffffffffffffffffffffffff"))
    }

    @Test
    fun `face carries the line parts and the last four for the overflow label`() {
        val face = CardPresentation.face(card(), bridgeProgramIdHex = "ffffffffffffffffffffffffffffffff")
        assertEquals(Chip.PROGRAM_MISMATCH, face.chip)
        assertEquals("ccdd", face.last4)
        assertEquals("0.2", face.appletVersion)
        assertEquals("XLM", face.currency)
        assertEquals("2026-11-09", face.registeredDate)
        assertEquals(Chip.REGISTERED, CardPresentation.face(card(), program).chip)
    }

    @Test
    fun `registered date is the date part of the instant, or empty`() {
        assertEquals("2026-11-09", CardPresentation.registeredDate("2026-11-09T10:42:00Z"))
        assertEquals("2026-11-09", CardPresentation.registeredDate("2026-11-09"))
        assertEquals("", CardPresentation.registeredDate(""))
    }

    @Test
    fun `the face has no holder name or balance to show`() {
        // Structural: the face type exposes identifiers only.
        val names = CardPresentation.Face::class.java.declaredFields.map { it.name.lowercase() }
        for (forbidden in listOf("holder", "name", "balance", "amount", "fullname")) {
            assertFalse("$forbidden on the card face: $names", names.any { forbidden in it })
        }
    }
}

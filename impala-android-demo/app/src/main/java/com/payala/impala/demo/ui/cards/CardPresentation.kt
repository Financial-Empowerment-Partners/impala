package com.payala.impala.demo.ui.cards

import com.payala.impala.demo.card.StoredCard

/**
 * What a card face on the Cards list shows (pure; CardPresentationTest).
 *
 * The face shows identifiers only: the **full** 32-hex card id (never
 * truncated) in eight groups of four over two lines, the applet version, the
 * currency, the registration date and a status chip. The holder name and the
 * balance are never on the face.
 */
object CardPresentation {

    enum class Chip { REGISTERED, PROGRAM_MISMATCH }

    class Face(
        /** The id in two lines of four groups of four ("8d7d 1a2b 3c4d 5e6f\n…"). */
        val groupedId: String,
        val last4: String,
        val appletVersion: String,
        val currency: String,
        /** `YYYY-MM-DD` of the bridge's successful registration, or "" when unknown. */
        val registeredDate: String,
        val chip: Chip
    )

    /**
     * [bridgeProgramIdHex]: the bridge's card program when known (null when
     * unknown or unconfigured: nothing to compare, so the card shows as
     * Registered).
     */
    fun face(card: StoredCard, bridgeProgramIdHex: String?): Face = Face(
        groupedId = groupedId(card.cardId),
        last4 = card.cardId.takeLast(4),
        appletVersion = card.appletVersion,
        currency = card.currency,
        registeredDate = registeredDate(card.registeredAt),
        chip = chip(card.programIdHex, bridgeProgramIdHex)
    )

    fun chip(cardProgramIdHex: String, bridgeProgramIdHex: String?): Chip = when {
        bridgeProgramIdHex.isNullOrBlank() || cardProgramIdHex.isBlank() -> Chip.REGISTERED
        cardProgramIdHex.equals(bridgeProgramIdHex, ignoreCase = true) -> Chip.REGISTERED
        else -> Chip.PROGRAM_MISMATCH
    }

    /**
     * Groups of four separated by spaces, four groups per line. Any length
     * is grouped (nothing dropped); a 32-hex id gives exactly two lines.
     */
    fun groupedId(cardId: String): String =
        cardId.chunked(GROUP).chunked(GROUPS_PER_LINE).joinToString("\n") { it.joinToString(" ") }

    /** The date part of an ISO-8601 instant (`2026-11-09T10:00:00Z` → `2026-11-09`). */
    fun registeredDate(iso: String): String = iso.substringBefore('T').take(DATE_LENGTH)

    private const val GROUP = 4
    private const val GROUPS_PER_LINE = 4
    private const val DATE_LENGTH = 10
}

package com.payala.impala.demo.transfer

/**
 * Card amounts are unsigned 32-bit integers in the card's minor units
 * (`Signable.amount`). They are parsed from digits only and formatted with
 * integer arithmetic; floating point never touches money here (pinned by
 * NoFloatingPointMoneyTest).
 */
object Money {
    const val MAX_CARD_AMOUNT: Long = 0xFFFF_FFFFL

    /** Digits only, 1..[MAX_CARD_AMOUNT]; null for anything else (signs, separators, decimals, zero, overflow). */
    fun parseCardAmount(text: String): Long? {
        val t = text.trim()
        if (t.isEmpty() || t.length > 10 || !t.all { it in '0'..'9' }) return null
        val v = t.toLong()
        return if (v in 1..MAX_CARD_AMOUNT) v else null
    }

    /** `minor` at `scale` decimal places as a decimal string, display only ("1234567" @7 -> "0.1234567"). */
    fun format(minor: Long, scale: Int): String {
        require(scale in 0..18) { "scale must be 0..18" }
        if (scale == 0) return minor.toString()
        val negative = minor < 0
        val digits = (if (negative) -minor else minor).toString().padStart(scale + 1, '0')
        val whole = digits.substring(0, digits.length - scale)
        val frac = digits.substring(digits.length - scale)
        return (if (negative) "-" else "") + whole + "." + frac
    }
}

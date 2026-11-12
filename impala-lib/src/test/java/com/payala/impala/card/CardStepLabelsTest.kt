package com.payala.impala.card

import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduNames
import com.payala.impala.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CardStepLabelsTest {
    private fun ex(ins: Int, cla: Int = 0x00) = ApduExchange(cla, ins, 0, 0, 0, 0x9000, 0, 1_000_000, ApduExchange.Outcome.OK, 1)

    @Test
    fun `reads, login signing, transfer signing and credit each have their label`() {
        assertEquals(R.string.card_step_reading, CardStepLabels.labelFor(ex(ApduNames.SELECT_INS)))
        for (ins in ApduNames.READ_ONLY_INS) assertEquals("INS $ins", R.string.card_step_reading, CardStepLabels.labelFor(ex(ins)))
        assertEquals(R.string.card_step_signing_login, CardStepLabels.labelFor(ex(0x25)))
        // SIGN_SEP10 signs a login too; GET_STELLAR_KEY is a read like the others
        assertEquals(R.string.card_step_signing_login, CardStepLabels.labelFor(ex(0x38)))
        assertEquals(R.string.card_step_reading, CardStepLabels.labelFor(ex(0x37)))
        assertEquals(R.string.card_step_signing_transfer, CardStepLabels.labelFor(ex(0x30)))
        assertEquals(R.string.card_step_applying_credit, CardStepLabels.labelFor(ex(0x31)))
    }

    @Test
    fun `VERIFY_PIN and every other command have no label`() {
        assertNull(CardStepLabels.labelFor(ex(0x18)))  // no app flow sends VERIFY_PIN
        for (ins in listOf(0x19, 0x1F, 0x22, 0x2C, 0x50, 0x70, 0x72, 0x99)) assertNull(CardStepLabels.labelFor(ex(ins)))
        assertNull(CardStepLabels.labelFor(ex(0x04, cla = 0x84)))
    }
}

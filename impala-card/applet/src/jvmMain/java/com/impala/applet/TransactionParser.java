package com.impala.applet;

import javacard.framework.Util;

import static com.impala.applet.Constants.ZERO;
import static com.impala.applet.Constants.INT32_LENGTH;
import static com.impala.applet.Constants.INT64_LENGTH;
import static com.impala.applet.Constants.UUID_LENGTH;

/**
 * Parses fields from the 60-byte signable transaction buffer.
 *
 * Signable layout:
 *   [dateTime (8B) | sender (16B) | recipient (16B) | currency (4B) | amount (4B) | phoneId (8B) | counter (4B)]
 */
public class TransactionParser {
    // Field offsets within the signable buffer
    public static final short OFFSET_MY_DATE_TIME = 0;
    public static final short OFFSET_SENDER = OFFSET_MY_DATE_TIME + INT64_LENGTH;
    public static final short OFFSET_RECIPIENT = OFFSET_SENDER + UUID_LENGTH;
    public static final short OFFSET_CURRENCY = OFFSET_RECIPIENT + UUID_LENGTH;
    public static final short OFFSET_AMOUNT = OFFSET_CURRENCY + 4;
    public static final short OFFSET_PHONE_ID = OFFSET_AMOUNT + INT32_LENGTH;
    public static final short OFFSET_COUNTER = OFFSET_PHONE_ID + INT64_LENGTH;

    private TransactionParser() {
        // do not instantiate this
    }

    /**
     * Extracts the 4-byte amount from the signable buffer into an 8-byte (int64) output buffer.
     * The amount is placed in the lower 4 bytes; the upper 4 bytes are zeroed.
     */
    public static void getAmount(byte[] inBuff, short inOffset, byte[] outBuff) {
        // ! getAmount()
        // this is very important, because there may be garbage in the destination
        // buffer
        Util.arrayFillNonAtomic(outBuff, ZERO, INT32_LENGTH, (byte) 0);
        // integers are big endian, so copy to the second half of the buffer
        Util.arrayCopyNonAtomic(inBuff, (short) (inOffset + OFFSET_AMOUNT),
                outBuff, (short) (INT64_LENGTH - INT32_LENGTH), INT32_LENGTH);
        // ! getAmount() | outBuff: {outBuff}
    }

    /** Extracts the 4-byte transaction counter from the signable buffer. */
    public static void getCounter(byte[] inBuff, short inOffset, byte[] outBuff) {
        Util.arrayCopyNonAtomic(inBuff, (short) (inOffset + OFFSET_COUNTER),
                outBuff, ZERO, INT32_LENGTH);
        // ! getCounter() | outBuff: {outBuff}
    }
}

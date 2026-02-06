/*
 * Copyright (c) 2019 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.impala.sdk.apdu4j

/**
 * Represents an ISO 7816-4 Response APDU received from a smartcard.
 *
 * The raw bytes are structured as: `[data...] [SW1] [SW2]`, where `SW1` and
 * `SW2` form the 2-byte status word. A response must contain at least the
 * status word (2 bytes); the data portion may be empty.
 *
 * @param apdu raw response bytes (must be at least 2 bytes)
 * @throws IllegalArgumentException if [apdu] is shorter than 2 bytes
 */
class ResponseAPDU (private val apdu: ByteArray){

    init {
       if (apdu.size < 2) {
           throw IllegalArgumentException("APDU must be at least 2 bytes!")
       }
   }

    /** Status byte 1 (the second-to-last byte), as an unsigned int (0x00-0xFF). */
    val sW1: Int
        get() = apdu[apdu.size - 2].toInt() and 0xff

    /** Status byte 2 (the last byte), as an unsigned int (0x00-0xFF). */
    val sW2: Int
        get() = apdu[apdu.size - 1].toInt() and 0xff

    /** Combined 2-byte status word: `(SW1 shl 8) or SW2`. 0x9000 = success. */
    val sw: Int
        get() = (sW1 shl 8) or this.sW2

    /** Response data payload (everything except the trailing 2-byte status word). */
    val data: ByteArray
        get() = apdu.copyOf(apdu.size - 2)

    /** Complete raw response bytes including the status word. */
    val bytes: ByteArray
        get() = apdu.copyOf()

    /** The 2-byte status word as a ByteArray: `[SW1, SW2]`. */
    val sWBytes: ByteArray
        get() =  apdu.copyOfRange(apdu.size -2, apdu.size)
}

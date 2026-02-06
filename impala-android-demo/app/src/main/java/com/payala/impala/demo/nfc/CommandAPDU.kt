package com.payala.impala.demo.nfc

import kotlin.jvm.Transient

/*
* Copyright (c) 2005, 2006, Oracle and/or its affiliates. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* This code is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 only, as
* published by the Free Software Foundation.  Oracle designates this
* particular file as subject to the "Classpath" exception as provided
* by Oracle in the LICENSE file that accompanied this code.
*
* This code is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* version 2 for more details (a copy is included in the LICENSE file that
* accompanied this code).
*
* You should have received a copy of the GNU General Public License version
* 2 along with this work; if not, write to the Free Software Foundation,
* Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
* or visit www.oracle.com if you need additional information or have any
* questions.
*/

/**
 * A command APDU following the structure defined in ISO/IEC 7816-4.
 *
 * Ported from `com.impala.sdk.apdu4j.CommandAPDU`.
 */
class CommandAPDU {
    private var apdu: ByteArray

    @Transient
    var nc: Int = 0
        private set

    @Transient
    var ne: Int = 0
        private set

    @Transient
    private var dataOffset = 0

    constructor(apdu: ByteArray) {
        this.apdu = apdu.copyOf()
        parse()
    }

    constructor(ins: Byte) : this(0, ins.toInt(), 0, 0)

    constructor(ins: Byte, data: ByteArray) : this(0, ins.toInt(), 0, 0, data)

    constructor(cla: Byte, ins: Byte, p1: Byte, p2: Byte, data: ByteArray) : this(
        cla.toInt(), ins.toInt(), p1.toInt(), p2.toInt(), data, 0, data.size, 0
    )

    constructor(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray) : this(
        cla, ins, p1, p2, data, 0, data.size, 0
    )

    private fun checkArrayBounds(b: ByteArray?, ofs: Int, len: Int) {
        if ((ofs < 0) || (len < 0)) {
            throw IllegalArgumentException("Offset and length must not be negative")
        }
        if (b == null) {
            if ((ofs != 0) && (len != 0)) {
                throw IllegalArgumentException("offset and length must be 0 if array is null")
            }
        } else {
            if (ofs > b.size - len) {
                throw IllegalArgumentException("Offset plus length exceed array size")
            }
        }
    }

    constructor(
        cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray? = null,
        dataOffset: Int = 0, dataLength: Int = 0, ne: Int = 0
    ) {
        checkArrayBounds(data, dataOffset, dataLength)
        if (dataLength > 65535) {
            throw IllegalArgumentException("dataLength is too large")
        }
        if (ne < 0) {
            throw IllegalArgumentException("ne must not be negative")
        }
        if (ne > 65536) {
            throw IllegalArgumentException("ne is too large")
        }
        this.ne = ne
        this.nc = dataLength
        if (dataLength == 0) {
            if (ne == 0) {
                this.apdu = ByteArray(4)
                setHeader(cla, ins, p1, p2)
            } else {
                if (ne <= 256) {
                    val len = if ((ne != 256)) ne.toByte() else 0
                    this.apdu = ByteArray(5)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = len
                } else {
                    val l1: Byte
                    val l2: Byte
                    if (ne == 65536) {
                        l1 = 0
                        l2 = 0
                    } else {
                        l1 = (ne shr 8).toByte()
                        l2 = ne.toByte()
                    }
                    this.apdu = ByteArray(7)
                    setHeader(cla, ins, p1, p2)
                    apdu[5] = l1
                    apdu[6] = l2
                }
            }
        } else {
            if (ne == 0) {
                if (dataLength <= 255) {
                    apdu = ByteArray(4 + 1 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = dataLength.toByte()
                    this.dataOffset = 5
                    data?.copyInto(apdu, this.dataOffset, dataOffset, dataOffset + dataLength)
                } else {
                    apdu = ByteArray(4 + 3 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = 0
                    apdu[5] = (dataLength shr 8).toByte()
                    apdu[6] = dataLength.toByte()
                    this.dataOffset = 7
                    data?.copyInto(apdu, this.dataOffset, dataOffset, dataOffset + dataLength)
                }
            } else {
                if ((dataLength <= 255) && (ne <= 256)) {
                    apdu = ByteArray(4 + 2 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = dataLength.toByte()
                    this.dataOffset = 5
                    data?.copyInto(apdu, this.dataOffset, dataOffset, dataOffset + dataLength)
                    apdu[apdu.size - 1] = if ((ne != 256)) ne.toByte() else 0
                } else {
                    apdu = ByteArray(4 + 5 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = 0
                    apdu[5] = (dataLength shr 8).toByte()
                    apdu[6] = dataLength.toByte()
                    this.dataOffset = 7
                    data?.copyInto(apdu, this.dataOffset, dataOffset, dataOffset + dataLength)
                    if (ne != 65536) {
                        val leOfs = apdu.size - 2
                        apdu[leOfs] = (ne shr 8).toByte()
                        apdu[leOfs + 1] = ne.toByte()
                    }
                }
            }
        }
    }

    private fun setHeader(cla: Int, ins: Int, p1: Int, p2: Int) {
        apdu[0] = cla.toByte()
        apdu[1] = ins.toByte()
        apdu[2] = p1.toByte()
        apdu[3] = p2.toByte()
    }

    private fun parse() {
        if (apdu.size < 4) {
            throw IllegalArgumentException("apdu must be at least 4 bytes long")
        }
        if (apdu.size == 4) {
            return
        }
        val l1 = apdu[4].toInt() and 0xff
        if (apdu.size == 5) {
            this.ne = if ((l1 == 0)) 256 else l1
            return
        }
        if (l1 != 0) {
            if (apdu.size == 4 + 1 + l1) {
                this.nc = l1
                this.dataOffset = 5
                return
            } else if (apdu.size == 4 + 2 + l1) {
                this.nc = l1
                this.dataOffset = 5
                val l2 = apdu[apdu.size - 1].toInt() and 0xff
                this.ne = if ((l2 == 0)) 256 else l2
                return
            } else {
                throw IllegalArgumentException("Invalid APDU: length=" + apdu.size + ", b1=" + l1)
            }
        }
        if (apdu.size < 7) {
            throw IllegalArgumentException("Invalid APDU: length=" + apdu.size + ", b1=" + l1)
        }
        val l2 = ((apdu[5].toInt() and 0xff) shl 8) or (apdu[6].toInt() and 0xff)
        if (apdu.size == 7) {
            this.ne = if ((l2 == 0)) 65536 else l2
            return
        }
        if (l2 == 0) {
            throw IllegalArgumentException(
                "Invalid APDU: length=" + apdu.size + ", b1=" + l1 + ", b2||b3=" + l2
            )
        }
        if (apdu.size == 4 + 3 + l2) {
            this.nc = l2
            this.dataOffset = 7
            return
        } else if (apdu.size == 4 + 5 + l2) {
            this.nc = l2
            this.dataOffset = 7
            val leOfs = apdu.size - 2
            val l3 = ((apdu[leOfs].toInt() and 0xff) shl 8) or (apdu[leOfs + 1].toInt() and 0xff)
            this.ne = if ((l3 == 0)) 65536 else l3
        } else {
            throw IllegalArgumentException(
                "Invalid APDU: length=" + apdu.size + ", b1=" + l1 + ", b2||b3=" + l2
            )
        }
    }

    val cLA: Int
        get() = apdu[0].toInt() and 0xff

    val iNS: Int
        get() = apdu[1].toInt() and 0xff

    val p1: Int
        get() = apdu[2].toInt() and 0xff

    val p2: Int
        get() = apdu[3].toInt() and 0xff

    val data: ByteArray
        get() {
            val data = ByteArray(nc)
            apdu.copyInto(data, 0, dataOffset, dataOffset + nc)
            return data
        }

    val bytes: ByteArray
        get() = apdu.copyOf()

    override fun toString(): String {
        return "CommandAPDU: " + apdu.size + " bytes, nc=" + nc + ", ne=" + ne
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CommandAPDU) return false
        return apdu.contentEquals(other.apdu)
    }

    override fun hashCode(): Int {
        return apdu.contentHashCode()
    }
}

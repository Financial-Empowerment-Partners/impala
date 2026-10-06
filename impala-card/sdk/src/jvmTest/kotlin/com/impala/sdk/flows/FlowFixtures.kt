package com.impala.sdk.flows

import java.nio.ByteBuffer
import java.util.UUID

internal fun uuidBytes(u: UUID = UUID.randomUUID()): ByteArray =
    ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()

internal val GOLDEN_PROGRAM = ByteArray(16) { (0xA0 + it).toByte() }
internal val GOLDEN_SENDER = Hex.decode("00112233445566778899aabbccddeeff")
internal val GOLDEN_RECIPIENT = Hex.decode("ffeeddccbbaa99887766554433221100")

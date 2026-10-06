package com.payala.impala.card

import com.impala.sdk.apdu4j.BIBO
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/** Runs [block] on a non-main thread and returns its value (rethrowing its exception). */
internal fun <T> offMain(block: () -> T): T {
    val ex = Executors.newSingleThreadExecutor()
    try {
        return ex.submit<T> { block() }.get(30, TimeUnit.SECONDS)
    } catch (e: ExecutionException) {
        throw e.cause ?: e
    } finally {
        ex.shutdown()
    }
}

internal fun uuidBytes(u: UUID = UUID.randomUUID()): ByteArray =
    ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()

/** A BIBO that answers from a script keyed by INS and records every command. */
internal class ScriptedBibo(private val answers: Map<Int, ByteArray>) : BIBO {
    val sent = mutableListOf<ByteArray>()
    var closes = 0
    override fun transceive(bytes: ByteArray?): ByteArray {
        val cmd = bytes!!
        sent += cmd
        return answers[cmd[1].toInt() and 0xFF] ?: byteArrayOf(0x6D, 0x00)
    }
    override fun close() { closes++ }
}

internal val SW_OK = byteArrayOf(0x90.toByte(), 0x00)

/** GET_VERSION answer for applet major.minor. */
internal fun versionAnswer(major: Int, minor: Int): ByteArray =
    byteArrayOf(0, major.toByte(), 0, minor.toByte(), 0, 1, 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()) + SW_OK

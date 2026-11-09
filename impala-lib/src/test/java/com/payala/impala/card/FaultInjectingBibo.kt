package com.payala.impala.card

import android.nfc.Tag
import android.os.Bundle
import android.os.Looper
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.apdu4j.BIBOTagLostException
import org.robolectric.Shadows.shadowOf
import java.io.IOException

/**
 * Test transport decorator: records every command, and on request loses the
 * tag, fails the transport, or rewrites the response for a given INS. Tag loss
 * cannot happen on the TCP lane, so this is how lib tests cover it.
 */
internal class FaultInjectingBibo(private val inner: BIBO) : BIBO {
    val sent = mutableListOf<ByteArray>()
    var closes = 0
    /** Throw [BIBOTagLostException] when this INS is sent (and for every command after it). */
    var loseTagOnIns: Int? = null
    /** Throw a plain [BIBOException] when this INS is sent. */
    var failOnIns: Int? = null
    /** Rewrites the inner response for an INS. */
    val responseRewrites = mutableMapOf<Int, (ByteArray) -> ByteArray>()
    private var lost = false

    val insSent: List<Int> get() = sent.map { it[1].toInt() and 0xFF }

    override fun transceive(bytes: ByteArray?): ByteArray? {
        val cmd = requireNotNull(bytes)
        sent += cmd.copyOf()
        val ins = cmd[1].toInt() and 0xFF
        if (lost || ins == loseTagOnIns) {
            lost = true
            throw BIBOTagLostException("injected tag loss", IOException("Tag was lost."))
        }
        if (ins == failOnIns) throw BIBOException("injected transport failure", IOException("Transceive failed"))
        val resp = inner.transceive(cmd) ?: return null
        return responseRewrites[ins]?.invoke(resp.copyOf()) ?: resp
    }

    override fun close() {
        closes++
        inner.close()
    }
}

/** Real (Robolectric) NFC tags built with the platform's hidden `Tag.createMockTag`. */
internal object TestTags {
    const val NFC_A = 1
    const val NFC_B = 2
    const val ISO_DEP = 3

    fun tag(id: ByteArray, techs: IntArray, extras: Array<Bundle>): Tag {
        val m = Tag::class.java.methods.first { it.name == "createMockTag" }
        return when (m.parameterCount) {
            4 -> m.invoke(null, id, techs, extras, 0L)
            else -> m.invoke(null, id, techs, extras)
        } as Tag
    }

    /** An NFC-A + ISO-DEP tag with the given ATQA/SAK. */
    fun isoDepA(id: ByteArray = byteArrayOf(0x04, 0x11, 0x22, 0x33), atqa: ByteArray = byteArrayOf(0x44, 0x00), sak: Short = 0x20): Tag =
        tag(id, intArrayOf(NFC_A, ISO_DEP), arrayOf(Bundle().apply { putByteArray("atqa", atqa); putShort("sak", sak) }, Bundle()))
}

/** Idles the main looper until [done] or ~5 s pass (results posted from worker threads). */
internal fun idleMainUntil(done: () -> Boolean) {
    repeat(250) {
        shadowOf(Looper.getMainLooper()).idle()
        if (done()) return
        Thread.sleep(20)
    }
}

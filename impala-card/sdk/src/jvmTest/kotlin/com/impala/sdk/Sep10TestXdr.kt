package com.impala.sdk

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Hand-built Stellar `Transaction` XDR for the card tests: deliberately not the
 * SDK's own codec, so the card is checked against bytes assembled independently
 * (the grammar is docs/sep10-card-keys.md, section 3.3).
 */
internal object Sep10TestXdr {
    const val TESTNET = "Test SDF Network ; September 2015"
    const val PUBNET = "Public Global Stellar Network ; September 2015"

    fun u32(v: Long): ByteArray = ByteBuffer.allocate(4).putInt(v.toInt()).array()
    fun u64(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()
    private fun padded(b: ByteArray): ByteArray = b + ByteArray((4 - b.size % 4) % 4)

    fun networkId(passphrase: String = TESTNET): ByteArray = MessageDigest.getInstance("SHA-256").digest(passphrase.toByteArray())

    /** A MANAGE_DATA operation (type 10), or another operation type with the same body for the refusal tests. */
    fun op(source: ByteArray, name: String, value: ByteArray?, type: Long = 10): ByteArray =
        u32(1) + u32(0) + source + u32(type) + u32(name.length.toLong()) + padded(name.toByteArray()) +
            (if (value == null) u32(0) else u32(1) + u32(value.size.toLong()) + padded(value))

    fun tx(
        source: ByteArray,
        ops: List<ByteArray>,
        sequence: Long = 0,
        condType: Long = 1,
        minTime: Long = 1_700_000_000,
        maxTime: Long = 1_700_000_900,
        memo: ByteArray = u32(0),
        ext: ByteArray = u32(0)
    ): ByteArray =
        u32(0) + source + u32(100) + u64(sequence) + u32(condType) + u64(minTime) + u64(maxTime) + memo +
            u32(ops.size.toLong()) + ops.fold(ByteArray(0)) { a, b -> a + b } + ext

    /** What a SEP-10 server issues: the auth entry for the client key, then `web_auth_domain`. */
    fun challenge(
        cardKey: ByteArray,
        serverKey: ByteArray,
        homeDomain: String = "bridge.example.org",
        nonce: ByteArray = ByteArray(64) { ('A'.code + it % 26).toByte() },
        extraOps: List<ByteArray> = emptyList()
    ): ByteArray = tx(
        serverKey,
        listOf(op(cardKey, "$homeDomain auth", nonce), op(serverKey, "web_auth_domain", homeDomain.toByteArray())) + extraOps
    )

    /**
     * A challenge of exactly [size] bytes (a multiple of four, 148..1000): the
     * auth entry plus as many further entries as the size needs, their names
     * and values stretched to fit.
     */
    fun challengeOfSize(cardKey: ByteArray, serverKey: ByteArray, size: Int): ByteArray {
        require(size % 4 == 0 && size in 148..1000) { "cannot build a challenge of $size bytes" }
        // 76 bytes of header and 4 of extension; an entry is 56 bytes plus its padded name and value
        val body = size - 80
        val count = (body + 183) / 184
        val ops = mutableListOf<ByteArray>()
        var left = body
        for (i in 0 until count) {
            val entry = minOf(184, left - 60 * (count - 1 - i))
            left -= entry
            val content = entry - 56
            if (i == 0) {
                val nameLength = minOf(64, content - 4)
                ops += op(cardKey, "d".repeat(nameLength - 5) + " auth", ByteArray(content - nameLength) { 0x42 })
            } else {
                val nameLength = minOf(64, content)
                ops += op(serverKey, "n".repeat(nameLength), ByteArray(content - nameLength) { 0x43 })
            }
        }
        return tx(serverKey, ops).also { check(it.size == size) { "built ${it.size} bytes, wanted $size" } }
    }

    /** The hash a Stellar signature covers: SHA-256(networkId ‖ ENVELOPE_TYPE_TX ‖ transaction). */
    fun signatureBase(networkId: ByteArray, tx: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(networkId + u32(2) + tx)

    /** Ed25519 verification by the JDK, from the raw 32-byte public key. */
    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(prefix + publicKey))
        return Signature.getInstance("Ed25519").run { initVerify(key); update(message); verify(signature) }
    }
}

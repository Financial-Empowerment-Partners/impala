package com.impala.sdk.stellar

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Test-only, independent SEP-10 challenge encoder (java.io.DataOutputStream,
 * written from the XDR definitions, sharing no code with the SDK's reader or
 * writer) and JDK Ed25519 helpers used as the oracle.
 */
object Jdk25519 {
    private val SPKI_PREFIX = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    fun keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    fun raw(pub: PublicKey): ByteArray = pub.encoded.also { check(it.size == 44) }.copyOfRange(12, 44)

    fun publicKey(raw: ByteArray): PublicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(SPKI_PREFIX + raw))

    fun sign(priv: PrivateKey, message: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").run { initSign(priv); update(message); sign() }

    fun verify(pub: ByteArray, message: ByteArray, sig: ByteArray): Boolean = try {
        Signature.getInstance("Ed25519").run { initVerify(publicKey(pub)); update(message); verify(sig) }
    } catch (_: Exception) {
        false
    }

    val verifier = Ed25519Verifier { pub, msg, sig -> verify(pub, msg, sig) }
}

fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }

fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

data class TestOp(
    /** null: no source account; otherwise the 32-byte key. */
    val source: ByteArray?,
    val name: ByteArray,
    val value: ByteArray?,
    val type: Int = 10,
    val muxedSource: Boolean = false,
)

data class TestTx(
    val source: ByteArray,
    val ops: List<TestOp>,
    val minTime: Long,
    val maxTime: Long,
    val envelopeType: Int = 2,
    val muxedSource: Boolean = false,
    val sourceKeyType: Int? = null,
    val fee: Long = 200,
    val seq: Long = 0,
    val cond: Int = 1,
    val memoText: String? = null,
    val ext: Int = 0,
) {
    fun txBytes(): ByteArray = encode { out ->
        account(out, source, muxedSource, sourceKeyType)
        out.writeInt(fee.toInt())
        out.writeLong(seq)
        out.writeInt(cond)
        if (cond == 1) { out.writeLong(minTime); out.writeLong(maxTime) }
        if (cond == 2) error("PRECOND_V2 encoding not needed: the tag alone is rejected")
        if (memoText == null) out.writeInt(0) else { out.writeInt(1); opaque(out, memoText.toByteArray()) }
        out.writeInt(ops.size)
        for (op in ops) {
            if (op.source == null) out.writeInt(0) else { out.writeInt(1); account(out, op.source, op.muxedSource, null) }
            out.writeInt(op.type)
            opaque(out, op.name)
            if (op.value == null) out.writeInt(0) else { out.writeInt(1); opaque(out, op.value) }
        }
        out.writeInt(ext)
    }

    fun hash(passphrase: String): ByteArray = sha256(sha256(passphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), txBytes())

    /** The envelope with [signatures] as (hint, signature) pairs. */
    fun envelope(signatures: List<Pair<ByteArray, ByteArray>>): ByteArray = encode { out ->
        out.writeInt(envelopeType)
        out.write(txBytes())
        out.writeInt(signatures.size)
        for ((hint, sig) in signatures) { out.write(hint); opaque(out, sig) }
    }

    companion object {
        fun encode(body: (DataOutputStream) -> Unit): ByteArray {
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use(body)
            return bytes.toByteArray()
        }

        fun account(out: DataOutputStream, key: ByteArray, muxed: Boolean, keyType: Int?) {
            if (muxed) { out.writeInt(0x100); out.writeLong(42); out.write(key) } else { out.writeInt(keyType ?: 0); out.write(key) }
        }

        fun opaque(out: DataOutputStream, bytes: ByteArray) {
            out.writeInt(bytes.size)
            out.write(bytes)
            repeat((4 - bytes.size % 4) % 4) { out.write(0) }
        }
    }
}

/** A server, a client and a well-formed challenge between them, with knobs for every mutation. */
class ChallengeFixture {
    val passphrase = "Test SDF Network ; September 2015"
    val homeDomain = "bridge.example.com"
    val webAuthDomain = "auth.example.com"
    val server: KeyPair = Jdk25519.keyPair()
    val client: KeyPair = Jdk25519.keyPair()
    val serverPub = Jdk25519.raw(server.public)
    val clientPub = Jdk25519.raw(client.public)
    val now = 1_800_000_000L
    val nonce = ByteArray(64) { ('A'.code + it % 26).toByte() }

    fun expectation(
        passphrase: String = this.passphrase,
        homeDomain: String = this.homeDomain,
        webAuthDomain: String = this.webAuthDomain,
        serverKey: ByteArray = serverPub,
        clientKey: ByteArray = clientPub,
    ) = Sep10Expectation(serverKey, passphrase, homeDomain, webAuthDomain, clientKey)

    fun authOp(name: String = "$homeDomain auth", value: ByteArray? = nonce, source: ByteArray? = clientPub) =
        TestOp(source, name.toByteArray(), value)

    fun webAuthOp(value: ByteArray? = webAuthDomain.toByteArray(), source: ByteArray? = serverPub) =
        TestOp(source, "web_auth_domain".toByteArray(), value)

    fun tx(ops: List<TestOp> = listOf(authOp(), webAuthOp()), minTime: Long = now, maxTime: Long = now + 900) =
        TestTx(source = serverPub, ops = ops, minTime = minTime, maxTime = maxTime)

    /** [tx] signed by the server over [passphrase]'s network, as base64. */
    fun signed(tx: TestTx = tx(), passphrase: String = this.passphrase, by: KeyPair = server, hint: ByteArray? = null): String {
        val sig = Jdk25519.sign(by.private, tx.hash(passphrase))
        return b64(tx.envelope(listOf((hint ?: Jdk25519.raw(by.public).copyOfRange(28, 32)) to sig)))
    }

    fun verify(envelope: String, now: Long = this.now, expect: Sep10Expectation = expectation()): Sep10Challenge =
        Sep10Challenge.verify(envelope, expect, now, Jdk25519.verifier)
}

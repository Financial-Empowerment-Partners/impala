package com.payala.impala.stellar

import com.impala.sdk.stellar.StrKey
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

/** JDK (17+) Ed25519 as the independent oracle. */
internal object Jdk {
    private val SPKI_PREFIX = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    fun keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    fun raw(pub: PublicKey): ByteArray = pub.encoded.copyOfRange(12, 44)
    fun publicKey(raw: ByteArray): PublicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(SPKI_PREFIX + raw))
    fun sign(priv: PrivateKey, message: ByteArray): ByteArray = Signature.getInstance("Ed25519").run { initSign(priv); update(message); sign() }
    fun verify(pub: ByteArray, message: ByteArray, sig: ByteArray): Boolean = try {
        Signature.getInstance("Ed25519").run { initVerify(publicKey(pub)); update(message); verify(sig) }
    } catch (_: Exception) {
        false
    }
}

internal fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }

/**
 * A test SEP-10 server: a JDK signing key and an independent challenge
 * encoder (DataOutputStream from the XDR definitions; no SDK code).
 */
internal class TestAnchor(
    val homeDomain: String = "bridge.example.com",
    val webAuthEndpoint: String = "https://auth.example.com/auth/sep10",
    val passphrase: String = "Test SDF Network ; September 2015",
) {
    var signer: KeyPair = Jdk.keyPair()
    val signingKey: String get() = StrKey.encodeAccountId(Jdk.raw(signer.public))

    fun toml(
        signingKey: String = this.signingKey,
        endpoint: String? = webAuthEndpoint,
        passphrase: String? = this.passphrase,
    ): String = buildString {
        append("# test anchor\nVERSION = \"2.0.0\"\n")
        if (passphrase != null) append("NETWORK_PASSPHRASE = \"$passphrase\"\n")
        append("SIGNING_KEY = \"$signingKey\"\n")
        if (endpoint != null) append("WEB_AUTH_ENDPOINT = \"$endpoint\"\n")
        append("\n[DOCUMENTATION]\nORG_NAME = \"Example\"\n")
    }

    fun challenge(
        client: ByteArray,
        now: Long,
        webAuthDomain: String = java.net.URI(webAuthEndpoint).host,
        signWith: KeyPair = signer,
        sourceKey: ByteArray = Jdk.raw(signer.public),
        signPassphrase: String = passphrase,
    ): String {
        val nonce = ByteArray(64) { ('a'.code + it % 26).toByte() }
        val tx = encode { o ->
            o.writeInt(0); o.write(sourceKey)
            o.writeInt(200)
            o.writeLong(0)
            o.writeInt(1); o.writeLong(now); o.writeLong(now + 900)
            o.writeInt(0)
            o.writeInt(2)
            o.writeInt(1); o.writeInt(0); o.write(client); o.writeInt(10); opaque(o, "$homeDomain auth".toByteArray()); o.writeInt(1); opaque(o, nonce)
            o.writeInt(1); o.writeInt(0); o.write(sourceKey); o.writeInt(10); opaque(o, "web_auth_domain".toByteArray()); o.writeInt(1); opaque(o, webAuthDomain.toByteArray())
            o.writeInt(0)
        }
        val hash = sha256(sha256(signPassphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), tx)
        val signerPub = Jdk.raw(signWith.public)
        val env = encode { o ->
            o.writeInt(2); o.write(tx)
            o.writeInt(1); o.write(signerPub.copyOfRange(28, 32)); opaque(o, Jdk.sign(signWith.private, hash))
        }
        return Base64.getEncoder().encodeToString(env)
    }

    fun challengeJson(envelope: String, passphrase: String? = this.passphrase): String =
        if (passphrase == null) "{\"transaction\":\"$envelope\"}" else "{\"transaction\":\"$envelope\",\"network_passphrase\":\"$passphrase\"}"

    private fun encode(body: (DataOutputStream) -> Unit): ByteArray =
        ByteArrayOutputStream().also { DataOutputStream(it).use(body) }.toByteArray()

    private fun opaque(o: DataOutputStream, b: ByteArray) {
        o.writeInt(b.size); o.write(b); repeat((4 - b.size % 4) % 4) { o.write(0) }
    }
}

/** Scripted [Sep10Transport]: records every call, answers from the lambdas. */
internal class FakeTransport(
    var toml: () -> String,
    var challenge: (endpoint: String, account: String, homeDomain: String) -> String,
    var post: (endpoint: String, transaction: String) -> String = { _, _ -> "{\"token\":\"t\",\"success\":true}" },
) : Sep10Transport {
    val calls = mutableListOf<String>()
    /** The extras the last postChallenge carried (for MFA-threading assertions). */
    var lastPostExtras: Sep10PostExtras = Sep10PostExtras.NONE
    override fun fetchToml(homeDomain: String): String { calls += "toml $homeDomain"; return toml() }
    override fun getChallenge(webAuthEndpoint: String, account: String, homeDomain: String): String {
        calls += "challenge $webAuthEndpoint $account $homeDomain"; return challenge(webAuthEndpoint, account, homeDomain)
    }
    override fun postChallenge(webAuthEndpoint: String, transaction: String, extras: Sep10PostExtras): String {
        calls += "post $webAuthEndpoint"; lastPostExtras = extras; return post(webAuthEndpoint, transaction)
    }
}

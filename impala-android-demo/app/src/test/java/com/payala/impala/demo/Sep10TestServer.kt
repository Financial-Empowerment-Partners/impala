package com.payala.impala.demo

import com.impala.sdk.stellar.StrKey
import com.payala.impala.stellar.Sep10HttpException
import com.payala.impala.stellar.Sep10Transport
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * A SEP-10 server for app tests, as a [Sep10Transport]: a JDK Ed25519 signing
 * key, challenges encoded here from the XDR definitions (no SDK code), and a
 * token only for an envelope that carries the server's signature and a valid
 * signature of the account the challenge was issued for. Everything else is
 * the generic 401 a real server answers.
 */
internal class Sep10TestServer(
    val homeDomain: String = "bridge.test.example",
    val passphrase: String = "Test SDF Network ; September 2015",
    val refreshToken: String = "refresh-token"
) : Sep10Transport {
    private val spki = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
    val signer: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val serverPub: ByteArray = signer.public.encoded.copyOfRange(12, 44)
    val endpoint = "https://$homeDomain/auth/sep10"
    val now: Long = System.currentTimeMillis() / 1000

    val calls = mutableListOf<String>()
    /** Override to simulate a server without SEP-10 or one that refuses. */
    var tomlAnswer: (() -> String)? = null
    var challengeAnswer: ((account: String) -> String)? = null
    var postAnswer: ((transaction: String) -> String)? = null
    /** The MFA extras the last postChallenge carried (for assertions). */
    var lastPostExtras: com.payala.impala.stellar.Sep10PostExtras = com.payala.impala.stellar.Sep10PostExtras.NONE
    private var issuedFor: String? = null

    private fun sha256(vararg parts: ByteArray) = MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }

    private fun verify(pub: ByteArray, message: ByteArray, sig: ByteArray): Boolean = try {
        val key = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki + pub))
        Signature.getInstance("Ed25519").run { initVerify(key); update(message); verify(sig) }
    } catch (_: Exception) {
        false
    }

    private fun encode(body: (DataOutputStream) -> Unit) = ByteArrayOutputStream().also { DataOutputStream(it).use(body) }.toByteArray()
    private fun opaque(o: DataOutputStream, b: ByteArray) { o.writeInt(b.size); o.write(b); repeat((4 - b.size % 4) % 4) { o.write(0) } }

    /** The challenge envelope for [client], signed by [by] (the server key unless a test says otherwise). */
    fun challenge(client: ByteArray, by: KeyPair = signer): String {
        val nonce = ByteArray(64) { ('a'.code + it % 26).toByte() }
        val tx = encode { o ->
            o.writeInt(0); o.write(serverPub); o.writeInt(200); o.writeLong(0)
            o.writeInt(1); o.writeLong(now); o.writeLong(now + 300); o.writeInt(0); o.writeInt(2)
            o.writeInt(1); o.writeInt(0); o.write(client); o.writeInt(10); opaque(o, "$homeDomain auth".toByteArray()); o.writeInt(1); opaque(o, nonce)
            o.writeInt(1); o.writeInt(0); o.write(serverPub); o.writeInt(10); opaque(o, "web_auth_domain".toByteArray()); o.writeInt(1); opaque(o, homeDomain.toByteArray())
            o.writeInt(0)
        }
        val hash = sha256(sha256(passphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), tx)
        val sig = Signature.getInstance("Ed25519").run { initSign(by.private); update(hash); sign() }
        return Base64.getEncoder().encodeToString(encode { o -> o.writeInt(2); o.write(tx); o.writeInt(1); o.write(by.public.encoded.copyOfRange(40, 44)); opaque(o, sig) })
    }

    override fun fetchToml(homeDomain: String): String {
        calls += "toml"
        tomlAnswer?.let { return it() }
        return "NETWORK_PASSPHRASE = \"$passphrase\"\nSIGNING_KEY = \"${StrKey.encodeAccountId(serverPub)}\"\nWEB_AUTH_ENDPOINT = \"$endpoint\"\n"
    }

    override fun getChallenge(webAuthEndpoint: String, account: String, homeDomain: String): String {
        calls += "challenge"
        issuedFor = account
        challengeAnswer?.let { return it(account) }
        return "{\"transaction\":\"${challenge(StrKey.decodeAccountId(account))}\",\"network_passphrase\":\"$passphrase\"}"
    }

    override fun postChallenge(
        webAuthEndpoint: String,
        transaction: String,
        extras: com.payala.impala.stellar.Sep10PostExtras,
    ): String {
        calls += "post"
        lastPostExtras = extras
        postAnswer?.let { return it(transaction) }
        val env = Base64.getDecoder().decode(transaction)
        val client = StrKey.decodeAccountId(issuedFor ?: throw Sep10HttpException(401, ""))
        if (env.size < 4 + 4 + 2 * 72) throw Sep10HttpException(401, "")
        val tx = env.copyOfRange(4, env.size - 4 - 2 * 72)
        val hash = sha256(sha256(passphrase.toByteArray()), byteArrayOf(0, 0, 0, 2), tx)
        val sigs = env.copyOfRange(env.size - 2 * 72, env.size)
        val ok = verify(serverPub, hash, sigs.copyOfRange(8, 72)) &&
            sigs.copyOfRange(72, 76).contentEquals(client.copyOfRange(28, 32)) && verify(client, hash, sigs.copyOfRange(80, 144))
        if (!ok) throw Sep10HttpException(401, "")
        return "{\"token\":\"temporal\",\"success\":true,\"message\":\"SEP-10 authentication successful\"," +
            "\"refresh_token\":\"$refreshToken\",\"temporal_token\":\"temporal\"}"
    }
}

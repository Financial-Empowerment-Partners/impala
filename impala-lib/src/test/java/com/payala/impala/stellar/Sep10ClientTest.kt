package com.payala.impala.stellar

import com.impala.sdk.stellar.Sep10Exception
import com.impala.sdk.stellar.StrKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class Sep10ClientTest {
    private val anchor = TestAnchor()
    private val client = Jdk.keyPair()
    private val clientPub = Jdk.raw(client.public)
    private var now = 1_800_000_000L

    private fun transport(
        toml: () -> String = { anchor.toml() },
        challenge: (String, String, String) -> String = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now)) },
    ) = FakeTransport(toml, challenge)

    private fun sep10(t: Sep10Transport, passphrase: String = anchor.passphrase) =
        Sep10Client(anchor.homeDomain, passphrase, t, Ed25519) { now }

    @Test
    fun `happy path - toml, challenge for the client's G address, verify, sign, submit`() {
        var posted: String? = null
        val t = transport()
        t.post = { _, tx -> posted = tx; "{\"token\":\"jwt\",\"success\":true,\"refresh_token\":\"r\"}" }
        val c = sep10(t)
        val prepared = c.prepare(clientPub)
        assertEquals(anchor.webAuthEndpoint, prepared.webAuthEndpoint)
        val account = StrKey.encodeAccountId(clientPub)
        assertEquals(listOf("toml ${anchor.homeDomain}", "challenge ${anchor.webAuthEndpoint} $account ${anchor.homeDomain}"), t.calls)

        val sig = Jdk.sign(client.private, prepared.challenge.hash)
        val token = c.submit(prepared.webAuthEndpoint, prepared.challenge.signedEnvelope(sig))
        assertEquals("{\"token\":\"jwt\",\"success\":true,\"refresh_token\":\"r\"}", token)
        val env = Base64.getDecoder().decode(posted)
        assertArrayEquals(sig, env.copyOfRange(env.size - 64, env.size))
    }

    @Test
    fun `stellar toml is cached for under 60 s, then refetched`() {
        val t = transport()
        val c = sep10(t)
        c.prepare(clientPub)
        now += 59
        c.prepare(clientPub)
        assertEquals(1, t.calls.count { it.startsWith("toml") })
        now += 1
        c.prepare(clientPub)
        assertEquals(2, t.calls.count { it.startsWith("toml") })
        // a clock that went backwards does not trust the cache
        now -= 10
        c.prepare(clientPub)
        assertEquals(3, t.calls.count { it.startsWith("toml") })
        c.clearCache()
        c.prepare(clientPub)
        assertEquals(4, t.calls.count { it.startsWith("toml") })
    }

    @Test
    fun `a rotated signing key is followed by exactly one toml refetch that bypasses the cache`() {
        val t = transport()
        val c = sep10(t)
        c.prepare(clientPub) // caches the toml with key 1
        anchor.signer = Jdk.keyPair() // the server rotates: new toml, new challenges
        now += 5
        c.prepare(clientPub)
        assertEquals(
            listOf("toml", "challenge", "challenge", "toml", "challenge"),
            t.calls.map { it.substringBefore(' ') }
        )
    }

    @Test
    fun `a bad server signature after the refetch is a SERVER_SIGNATURE failure, after one refetch only`() {
        val impostor = Jdk.keyPair()
        val t = transport(challenge = { _, _, _ ->
            // source and hint claim the toml key, the signature is someone else's
            anchor.challengeJson(anchor.challenge(clientPub, now, signWith = impostor).let { swapHint(it) })
        })
        val e = assertThrows(Sep10Exception::class.java) { sep10(t).prepare(clientPub) }
        assertEquals(Sep10Exception.Reason.SERVER_SIGNATURE, e.reason)
        assertEquals(listOf("toml", "challenge", "toml", "challenge"), t.calls.map { it.substringBefore(' ') })
    }

    /** Rewrites the signature hint to the anchor's real key so only the signature check fails. */
    private fun swapHint(envelope: String): String {
        val b = Base64.getDecoder().decode(envelope)
        Jdk.raw(anchor.signer.public).copyOfRange(28, 32).copyInto(b, b.size - 72)
        return Base64.getEncoder().encodeToString(b)
    }

    @Test
    fun `a challenge from another source key is SERVER_KEY after one refetch`() {
        val stranger = Jdk.keyPair()
        val t = transport(challenge = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now, signWith = stranger, sourceKey = Jdk.raw(stranger.public))) })
        val e = assertThrows(Sep10Exception::class.java) { sep10(t).prepare(clientPub) }
        assertEquals(Sep10Exception.Reason.SERVER_KEY, e.reason)
        assertEquals(2, t.calls.count { it.startsWith("toml") })
    }

    @Test
    fun `other challenge rule failures do not refetch`() {
        val t = transport(challenge = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now - 2000)) })
        val e = assertThrows(Sep10Exception::class.java) { sep10(t).prepare(clientPub) }
        assertEquals(Sep10Exception.Reason.TIME_BOUNDS_EXPIRED, e.reason)
        assertEquals(1, t.calls.count { it.startsWith("toml") })
    }

    @Test
    fun `network passphrase must agree in all three places`() {
        // expected vs toml
        assertEquals(
            Sep10Exception.Reason.NETWORK,
            assertThrows(Sep10Exception::class.java) { sep10(transport(), passphrase = "Public Global Stellar Network ; September 2015").prepare(clientPub) }.reason
        )
        // toml differs
        val t1 = transport(toml = { anchor.toml(passphrase = "Other") })
        assertEquals(Sep10Exception.Reason.NETWORK, assertThrows(Sep10Exception::class.java) { sep10(t1).prepare(clientPub) }.reason)
        assertTrue("no challenge fetched on a toml mismatch", t1.calls.none { it.startsWith("challenge") })
        // toml lacks it
        val t2 = transport(toml = { anchor.toml(passphrase = null) })
        assertEquals(Sep10Exception.Reason.NETWORK, assertThrows(Sep10Exception::class.java) { sep10(t2).prepare(clientPub) }.reason)
        // challenge response differs, or lacks it
        val t3 = transport(challenge = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now), passphrase = "Other") })
        assertEquals(Sep10Exception.Reason.NETWORK, assertThrows(Sep10Exception::class.java) { sep10(t3).prepare(clientPub) }.reason)
        val t4 = transport(challenge = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now), passphrase = null) })
        assertEquals(Sep10Exception.Reason.NETWORK, assertThrows(Sep10Exception::class.java) { sep10(t4).prepare(clientPub) }.reason)
    }

    @Test
    fun `the web auth endpoint scheme rule - https, or http only for local hosts`() {
        for (endpoint in listOf("http://auth.example.com/auth", "ftp://auth.example.com/auth", "https://auth.example.com/auth?x=1", "https://u:p@auth.example.com/auth", "/auth", "https:///auth", "https://${"a".repeat(61)}.com/auth")) {
            val t = transport(toml = { anchor.toml(endpoint = endpoint) })
            val e = assertThrows(endpoint, Sep10ClientException::class.java) { sep10(t).prepare(clientPub) }
            assertEquals(endpoint, Sep10ClientException.Kind.INSECURE_ENDPOINT, e.kind)
            assertTrue(t.calls.none { it.startsWith("challenge") })
        }
        for ((endpoint, domain) in listOf(
            "http://localhost:8080/auth/sep10" to "localhost:8080",
            "http://127.0.0.1/auth/sep10" to "127.0.0.1",
            "http://10.0.2.2:8080/auth/sep10" to "10.0.2.2:8080",
            "https://Auth.Example.com:8443/auth" to "auth.example.com:8443",
        )) {
            val t = transport(toml = { anchor.toml(endpoint = endpoint) }, challenge = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now, webAuthDomain = domain)) })
            assertEquals(endpoint, sep10(t).prepare(clientPub).webAuthEndpoint)
        }
        assertThrows(Sep10ClientException::class.java) { sep10(transport()).submit("http://auth.example.com/auth", "AAAA") }
    }

    @Test
    fun `web_auth_domain must be the endpoint's host`() {
        val t = transport(challenge = { _, _, _ -> anchor.challengeJson(anchor.challenge(clientPub, now, webAuthDomain = anchor.homeDomain)) })
        assertEquals(Sep10Exception.Reason.WEB_AUTH_DOMAIN, assertThrows(Sep10Exception::class.java) { sep10(t).prepare(clientPub) }.reason)
    }

    @Test
    fun `a toml without SEP-10 is NOT_OFFERED, a broken one TOML_INVALID, and neither is cached`() {
        val none = transport(toml = { anchor.toml(endpoint = null) })
        val c = sep10(none)
        assertEquals(Sep10ClientException.Kind.NOT_OFFERED, assertThrows(Sep10ClientException::class.java) { c.prepare(clientPub) }.kind)
        assertEquals(Sep10ClientException.Kind.NOT_OFFERED, assertThrows(Sep10ClientException::class.java) { c.prepare(clientPub) }.kind)
        assertEquals(2, none.calls.size)
        val badKey = transport(toml = { anchor.toml(signingKey = anchor.signingKey.dropLast(1) + "A") })
        assertEquals(Sep10ClientException.Kind.TOML_INVALID, assertThrows(Sep10ClientException::class.java) { sep10(badKey).prepare(clientPub) }.kind)
        val dup = transport(toml = { "SIGNING_KEY = \"${anchor.signingKey}\"\n" + anchor.toml() })
        assertEquals(Sep10ClientException.Kind.TOML_INVALID, assertThrows(Sep10ClientException::class.java) { sep10(dup).prepare(clientPub) }.kind)
    }

    @Test
    fun `oversized bodies are refused`() {
        val bigToml = transport(toml = { anchor.toml() + "# " + "x".repeat(StellarToml.MAX_LENGTH) })
        assertEquals(Sep10ClientException.Kind.TOML_INVALID, assertThrows(Sep10ClientException::class.java) { sep10(bigToml).prepare(clientPub) }.kind)
        val bigChallenge = transport(challenge = { _, _, _ -> "{\"pad\":\"" + "x".repeat(Sep10Client.MAX_JSON_LENGTH) + "\"}" })
        assertEquals(Sep10ClientException.Kind.RESPONSE_INVALID, assertThrows(Sep10ClientException::class.java) { sep10(bigChallenge).prepare(clientPub) }.kind)
        val bigEnvelope = transport(challenge = { _, _, _ -> anchor.challengeJson("A".repeat(8000)) })
        assertEquals(Sep10Exception.Reason.MALFORMED, assertThrows(Sep10Exception::class.java) { sep10(bigEnvelope).prepare(clientPub) }.reason)
    }

    @Test
    fun `malformed challenge and token responses are RESPONSE_INVALID`() {
        for (body in listOf("", "[]", "{", "{\"transaction\":1}", "{\"network_passphrase\":\"x\"}", "{\"transaction\":\"a\",\"transaction\":\"b\"}", "<html>")) {
            val t = transport(challenge = { _, _, _ -> body })
            assertEquals(body, Sep10ClientException.Kind.RESPONSE_INVALID, assertThrows(body, Sep10ClientException::class.java) { sep10(t).prepare(clientPub) }.kind)
        }
        for (body in listOf("{}", "{\"token\":\"\"}", "{\"token\":null}", "not json")) {
            val t = transport()
            t.post = { _, _ -> body }
            assertEquals(body, Sep10ClientException.Kind.RESPONSE_INVALID, assertThrows(body, Sep10ClientException::class.java) { sep10(t).submit(anchor.webAuthEndpoint, "AAAA") }.kind)
        }
    }

    @Test
    fun `HTTP failures surface as Sep10HttpException with the status`() {
        val t = transport(toml = { throw Sep10HttpException(404, "not found") })
        assertEquals(404, assertThrows(Sep10HttpException::class.java) { sep10(t).prepare(clientPub) }.status)
        val t2 = transport(challenge = { _, _, _ -> throw Sep10HttpException(503, "") })
        assertEquals(503, assertThrows(Sep10HttpException::class.java) { sep10(t2).prepare(clientPub) }.status)
        val t3 = transport()
        t3.post = { _, _ -> throw Sep10HttpException(401, "{\"error\":\"unauthorized\"}") }
        assertEquals(401, assertThrows(Sep10HttpException::class.java) { sep10(t3).submit(anchor.webAuthEndpoint, "AAAA") }.status)
    }

    @Test
    fun `constructor and argument checks`() {
        assertThrows(IllegalArgumentException::class.java) { Sep10Client("https://x.example.com", "p", transport()) }
        assertThrows(IllegalArgumentException::class.java) { Sep10Client("X.example.com", "p", transport()) }
        assertThrows(IllegalArgumentException::class.java) { Sep10Client("x.example.com", "", transport()) }
        Sep10Client("10.0.2.2:8080", "p", transport())
        assertThrows(IllegalArgumentException::class.java) { sep10(transport()).prepare(ByteArray(31)) }
    }
}

package com.payala.impala.stellar

import com.impala.sdk.stellar.StrKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Opt-in conformance run against the SDF reference anchor
 * (https://testanchor.stellar.org, testnet): our toml reader, transport,
 * challenge codec, verifier and envelope framing against a real SEP-10
 * server. Skipped unless IMPALA_SEP10_LIVE=1; run with `--rerun` so a cached
 * skipped result is not reused.
 */
class Sep10LiveConformanceTest {
    @Test
    fun `testanchor issues a challenge our codec accepts and accepts our signed envelope`() {
        assumeTrue("set IMPALA_SEP10_LIVE=1 to run", System.getenv("IMPALA_SEP10_LIVE") == "1")
        val home = "testanchor.stellar.org"
        val passphrase = "Test SDF Network ; September 2015"
        val transport = HttpSep10Transport()
        val toml = StellarToml.parse(transport.fetchToml(home))
        assertEquals(passphrase, toml.networkPassphrase)
        assertTrue(StrKey.isValidAccountId(toml.signingKey!!))

        val key = Jdk.keyPair()
        val pub = Jdk.raw(key.public)
        val client = Sep10Client(home, passphrase, transport, Ed25519)
        val prepared = client.prepare(pub)
        assertEquals(toml.webAuthEndpoint, prepared.webAuthEndpoint)
        val challenge = prepared.challenge
        assertTrue(challenge.maxTime > challenge.minTime)

        val sig = Jdk.sign(key.private, challenge.hash)
        assertTrue(Ed25519.verify(pub, challenge.hash, sig))
        val body = client.submit(prepared.webAuthEndpoint, challenge.signedEnvelope(sig))
        val token = MiniJson.stringFields(body)["token"]
        assertTrue("a token in $body", !token.isNullOrEmpty() && token.count { it == '.' } == 2)
        println("SEP-10 live: ${StrKey.encodeAccountId(pub)} lifetime=${challenge.maxTime - challenge.minTime}s tx=${challenge.transactionBytes.size}B token-length=${token!!.length}")
    }
}

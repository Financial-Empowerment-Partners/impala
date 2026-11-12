package com.payala.impala.stellar

import com.impala.sdk.stellar.Ed25519Verifier
import com.impala.sdk.stellar.Sep10Challenge
import com.impala.sdk.stellar.Sep10Exception
import com.impala.sdk.stellar.Sep10Expectation
import com.impala.sdk.stellar.StrKey
import java.io.IOException

/**
 * The server does not offer usable SEP-10 or answered something unreadable.
 * [kind] separates "no SEP-10 here" ([Kind.NOT_OFFERED], a reason to fall
 * back to another sign-in) from a broken or hostile server.
 */
class Sep10ClientException(val kind: Kind, message: String, cause: Throwable? = null) : Exception(message, cause) {
    enum class Kind {
        /** stellar.toml has no `WEB_AUTH_ENDPOINT` or no `SIGNING_KEY`. */
        NOT_OFFERED,
        /** stellar.toml is malformed (bad line, duplicate key, too large) or its `SIGNING_KEY` is not an account id. */
        TOML_INVALID,
        /** `WEB_AUTH_ENDPOINT` breaks the scheme rule (https, or http only for a local host) or is not a plain URL. */
        INSECURE_ENDPOINT,
        /** The challenge or token response is not the JSON object it must be. */
        RESPONSE_INVALID,
    }
}

/** A verified challenge and the endpoint it came from (where the signed envelope goes). */
class Sep10Prepared(val challenge: Sep10Challenge, val webAuthEndpoint: String)

/**
 * SEP-10 client steps around the card: [prepare] (stellar.toml, challenge,
 * [Sep10Challenge.verify]) and [submit]. Signing happens in between, on the
 * card, over `prepare(...).challenge.hash`.
 *
 * stellar.toml is cached for at most [TOML_CACHE_SECONDS]. When a challenge
 * fails the server-identity rules (its source is not the cached
 * `SIGNING_KEY`, or the server signature does not verify), the client
 * refetches stellar.toml once, bypassing the cache, and retries with a fresh
 * challenge before giving up with that [Sep10Exception]; this follows a
 * signing-key rotation and is TLS trust in [homeDomain], not an independent
 * pin. The three network passphrases (expected, stellar.toml, challenge
 * response) must be equal, else [Sep10Exception.Reason.NETWORK].
 *
 * Blocking (the transport is): call off the main thread. Nothing here logs.
 */
class Sep10Client @JvmOverloads constructor(
    private val homeDomain: String,
    private val expectedNetworkPassphrase: String,
    private val transport: Sep10Transport,
    private val verifier: Ed25519Verifier = Ed25519,
    /** Epoch seconds. */
    private val clock: () -> Long = { System.currentTimeMillis() / 1000L },
) {
    private class CachedToml(val toml: StellarToml, val fetchedAt: Long)

    private val lock = Any()
    private var cached: CachedToml? = null

    init {
        require(Sep10Urls.isValidHomeDomain(homeDomain)) { "invalid home domain" }
        require(expectedNetworkPassphrase.isNotEmpty()) { "network passphrase must not be empty" }
    }

    /**
     * Fetches and verifies a challenge for the 32-byte [clientKey]. Throws
     * [Sep10Exception] (a challenge rule, or NETWORK), [Sep10ClientException],
     * [Sep10HttpException] (a non-2xx answer) or [IOException].
     */
    @Throws(IOException::class, Sep10Exception::class, Sep10ClientException::class)
    fun prepare(clientKey: ByteArray): Sep10Prepared {
        require(clientKey.size == 32) { "client key must be 32 bytes" }
        val first = toml(bypassCache = false)
        try {
            return attempt(first, clientKey)
        } catch (e: Sep10Exception) {
            if (e.reason != Sep10Exception.Reason.SERVER_KEY && e.reason != Sep10Exception.Reason.SERVER_SIGNATURE) throw e
        }
        return attempt(toml(bypassCache = true), clientKey)
    }

    /**
     * Posts [signedEnvelope] to [webAuthEndpoint] and returns the raw token
     * JSON, after checking it is a JSON object with a string `token`.
     */
    @JvmOverloads
    @Throws(IOException::class, Sep10ClientException::class)
    fun submit(
        webAuthEndpoint: String,
        signedEnvelope: String,
        extras: Sep10PostExtras = Sep10PostExtras.NONE,
    ): String {
        checkedEndpoint(webAuthEndpoint)
        val body = transport.postChallenge(webAuthEndpoint, signedEnvelope, extras)
        val fields = jsonFields(body, "token response")
        if (fields["token"].isNullOrEmpty()) throw Sep10ClientException(Sep10ClientException.Kind.RESPONSE_INVALID, "token response has no token")
        return body
    }

    /** Drops the cached stellar.toml. */
    fun clearCache() {
        synchronized(lock) { cached = null }
    }

    private fun attempt(toml: StellarToml, clientKey: ByteArray): Sep10Prepared {
        val endpoint = toml.webAuthEndpoint!!
        val serverKey = StrKey.decodeAccountId(toml.signingKey!!)
        if (toml.networkPassphrase != expectedNetworkPassphrase) {
            throw Sep10Exception(Sep10Exception.Reason.NETWORK, "stellar.toml NETWORK_PASSPHRASE is not the expected network")
        }
        val webAuthDomain = checkedEndpoint(endpoint)
        val response = jsonFields(
            transport.getChallenge(endpoint, StrKey.encodeAccountId(clientKey), homeDomain),
            "challenge response"
        )
        val transaction = response["transaction"]
            ?: throw Sep10ClientException(Sep10ClientException.Kind.RESPONSE_INVALID, "challenge response has no transaction")
        if (response["network_passphrase"] != expectedNetworkPassphrase) {
            throw Sep10Exception(Sep10Exception.Reason.NETWORK, "challenge network_passphrase is absent or not the expected network")
        }
        if (serverKey.contentEquals(clientKey)) {
            throw Sep10Exception(Sep10Exception.Reason.SERVER_KEY, "the client key is the server signing key")
        }
        val expect = Sep10Expectation(serverKey, expectedNetworkPassphrase, homeDomain, webAuthDomain, clientKey)
        return Sep10Prepared(Sep10Challenge.verify(transaction, expect, clock(), verifier), endpoint)
    }

    private fun checkedEndpoint(endpoint: String): String = try {
        // a manage-data value holds at most 64 bytes, so no challenge could name a longer domain
        Sep10Urls.webAuthDomain(endpoint).also { require(it.length <= 64) { "web auth endpoint host longer than 64 characters" } }
    } catch (e: IllegalArgumentException) {
        throw Sep10ClientException(Sep10ClientException.Kind.INSECURE_ENDPOINT, e.message ?: "bad web auth endpoint", e)
    }

    private fun toml(bypassCache: Boolean): StellarToml {
        val now = clock()
        if (!bypassCache) {
            synchronized(lock) {
                val c = cached
                if (c != null && now >= c.fetchedAt && now - c.fetchedAt < TOML_CACHE_SECONDS) return c.toml
            }
        }
        val text = transport.fetchToml(homeDomain)
        val toml = try {
            StellarToml.parse(text)
        } catch (e: StellarTomlException) {
            throw Sep10ClientException(Sep10ClientException.Kind.TOML_INVALID, e.message ?: "invalid stellar.toml", e)
        }
        if (toml.webAuthEndpoint.isNullOrEmpty() || toml.signingKey.isNullOrEmpty()) {
            throw Sep10ClientException(Sep10ClientException.Kind.NOT_OFFERED, "stellar.toml offers no SEP-10 (WEB_AUTH_ENDPOINT or SIGNING_KEY missing)")
        }
        if (!StrKey.isValidAccountId(toml.signingKey)) {
            throw Sep10ClientException(Sep10ClientException.Kind.TOML_INVALID, "stellar.toml SIGNING_KEY is not a valid account id")
        }
        synchronized(lock) { cached = CachedToml(toml, now) }
        return toml
    }

    private fun jsonFields(body: String, what: String): Map<String, String> {
        if (body.length > MAX_JSON_LENGTH) throw Sep10ClientException(Sep10ClientException.Kind.RESPONSE_INVALID, "$what too large")
        return try {
            MiniJson.stringFields(body)
        } catch (e: MiniJson.JsonException) {
            throw Sep10ClientException(Sep10ClientException.Kind.RESPONSE_INVALID, "$what is not a JSON object", e)
        }
    }

    companion object {
        const val TOML_CACHE_SECONDS = 60L
        const val MAX_JSON_LENGTH = 16 * 1024
    }
}

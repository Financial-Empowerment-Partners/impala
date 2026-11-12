package com.payala.impala.demo.auth

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.model.TokenResponse
import com.payala.impala.stellar.HttpSep10Transport
import com.payala.impala.stellar.Sep10Client
import com.payala.impala.stellar.Sep10Transport
import com.payala.impala.stellar.Sep10Urls

/**
 * SEP-10 card sign-in for this build: the client for
 * [BuildConfig.SEP10_HOME_DOMAIN] on [BuildConfig.STELLAR_NETWORK_PASSPHRASE]'s
 * network, or none when the build has no home domain (SEP-10 off: every card
 * then signs in with the legacy challenge).
 *
 * The transport is impala-lib's `HttpURLConnection` one, so the app's network
 * security config applies to it as to every other request; it sends no
 * session token (the exchange happens before there is one) and logs nothing.
 */
object CardSep10 {
    /** Each of the three SEP-10 requests gets this long; they run while the card is held to the phone. */
    private const val TIMEOUT_MS = 6_000

    /** The process-wide client (it caches stellar.toml for a minute), or null when SEP-10 is off. */
    val client: Sep10Client? by lazy {
        clientFor(BuildConfig.SEP10_HOME_DOMAIN, BuildConfig.STELLAR_NETWORK_PASSPHRASE)
    }

    /**
     * A client for [homeDomain], or null when it is blank or not a valid
     * home domain (a misconfigured build signs in the legacy way rather than
     * failing every card login).
     */
    fun clientFor(
        homeDomain: String,
        networkPassphrase: String,
        transport: Sep10Transport = HttpSep10Transport(TIMEOUT_MS, TIMEOUT_MS)
    ): Sep10Client? {
        val domain = homeDomain.trim()
        if (domain.isEmpty()) return null
        if (!Sep10Urls.isValidHomeDomain(domain) || networkPassphrase.isEmpty()) {
            AppLogger.w("Auth", "SEP-10 is off: the configured home domain is not usable")
            return null
        }
        return Sep10Client(domain, networkPassphrase, transport)
    }

    /**
     * The bridge's `POST /auth/sep10` answer: the tokens `POST /auth/card`
     * returns, plus SEP-10's own `token`. Null when [json] is not that object.
     */
    fun parseTokens(json: String): TokenResponse? = try {
        Gson().fromJson(json, TokenResponse::class.java)
    } catch (_: JsonSyntaxException) {
        null
    }
}

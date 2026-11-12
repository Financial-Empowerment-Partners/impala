package com.payala.impala.demo.e2e

import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TestIssuer
import com.impala.simulator.personalizedCard
import com.payala.impala.card.CardAuthMechanism
import com.payala.impala.card.CardAuthenticator
import com.payala.impala.card.CardSignIn
import com.payala.impala.card.CardSignInResult
import com.payala.impala.card.ImpalaCardSession
import com.payala.impala.card.TcpBibo
import com.payala.impala.demo.BuildConfig
import com.payala.impala.stellar.HttpSep10Transport
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.util.UUID

/**
 * E2E-4, the card at SEP-10 servers nobody here wrote (T1): for each home
 * domain in IMPALA_E2E_SEP10_THIRD_PARTY (testnet; the demo's default is the
 * SDF reference anchor, `testanchor.stellar.org`) and each Ed25519 engine, a
 * card reads the server's challenge with its own on-card rules, signs it, and
 * the server issues its token. The token is then shown to do its job: a
 * SEP-24 route of that server refuses a request without it and answers the
 * same request with it.
 *
 * The cards: the one served at IMPALA_E2E_CARD_TCP when that is set (in the
 * demo kit, the holder's card that the bridge issued and that signs in to the
 * bridge on the emulator), and one jcardsim card per hardware class, each
 * personalized with a local test issuer: the default CAP (the software
 * Ed25519 engine) on a simulated JavaCard 3.0.5 card and the native CAP (the
 * platform's EdDSA) on a simulated JavaCard 3.2 card. A third-party server
 * authenticates the Stellar key, not the card's certificate, so no bridge is
 * needed here.
 *
 * A server that cannot be reached is reported, not failed; when none can, the
 * test is skipped with that reason. A server that is not on testnet fails the
 * test before anything is signed.
 */
@RunWith(RobolectricTestRunner::class)
class CardSep10ThirdPartyE2ETest {
    /** A card to sign in with: what it is, its engine and simulated hardware when known, and how to open a session on it. */
    private class Card(val label: String, val engine: String?, val platform: String?, val open: () -> ImpalaCardSession)

    private fun cards(): List<Card> {
        val list = mutableListOf<Card>()
        System.getenv("IMPALA_E2E_CARD_TCP")?.trim()?.takeIf { it.isNotEmpty() }?.let { endpoint ->
            val host = endpoint.substringBeforeLast(':')
            val port = endpoint.substringAfterLast(':').toInt()
            // Its hardware is the simulator server's business (the demo kit records it); the card says only its engine.
            list += Card("the issued card at $endpoint", null, null) {
                ImpalaCardSession.fromBibo(TcpBibo(host, port), BuildConfig.CARD_APPLET_AID)
            }
        }
        // One card per hardware class: the default CAP on a JavaCard 3.0.5 card, the native CAP on a JavaCard 3.2 card.
        for (engine in listOf(SimulatorBibo.ED25519_SOFT, SimulatorBibo.ED25519_NATIVE)) {
            val hardware = E2e.hardwareFor(engine)
            val bibo = personalizedCard(TestIssuer(), E2e.uuidBytes(UUID.randomUUID().toString()), ed25519 = engine, platform = hardware).bibo
            list += Card("a jcardsim card on ${hardware.name()} hardware (test issuer)", engine, hardware.name()) { ImpalaCardSession.fromBibo(bibo) }
        }
        return list
    }

    @Test
    fun `a card signs in at third-party SEP-10 servers and the token opens a protected route`() {
        val domains = Sep10E2e.thirdParties
        assumeTrue("IMPALA_E2E_SEP10_THIRD_PARTY is not set — name the testnet SEP-10 servers to sign in to (see app/src/e2e/README.md)", domains.isNotEmpty())

        val cards = cards()
        val servers = JSONArray()
        var reached = 0
        for (domain in domains) {
            val server = JSONObject().put("domain", domain)
            servers.put(server)
            val toml = try {
                HttpSep10Transport(20_000, 20_000).fetchToml(domain)
            } catch (e: IOException) {
                server.put("reachable", false).put("reason", e.javaClass.simpleName)
                println("e2e: $domain is not reachable (${e.javaClass.simpleName}); skipped")
                continue
            }
            reached++
            server.put("reachable", true)
                .put("web_auth_endpoint", Sep10E2e.tomlValue(toml, "WEB_AUTH_ENDPOINT"))
                .put("signing_key", Sep10E2e.tomlValue(toml, "SIGNING_KEY"))
            assertEquals(
                "$domain is not a testnet server; this lane never signs in on another network",
                Sep10E2e.TESTNET_PASSPHRASE, Sep10E2e.tomlValue(toml, "NETWORK_PASSPHRASE")
            )

            val signIns = JSONArray()
            server.put("sign_ins", signIns)
            var firstToken: String? = null
            for (card in cards) {
                val what = "$domain, ${card.label}${card.engine?.let { " [$it]" } ?: ""}"
                val signIn = CardSignIn(Sep10E2e.thirdPartyClient(domain)) {
                    error("$domain offers SEP-10: the legacy challenge must not be asked for")
                }
                var engineName = card.engine
                val result = E2e.offMain {
                    card.open().use { session ->
                        // The engine the card itself reports (the issued card's is not known in advance).
                        if (engineName == null) engineName = CardAuthenticator.stellarKey(session)?.engineName
                        signIn.signIn(session)
                    }
                }
                assertEquals(what, CardAuthMechanism.SEP10, result.mechanism)
                val sep10 = result as CardSignInResult.Sep10
                val token = Sep10E2e.tokenOf(sep10.tokenJson)
                val claims = Sep10E2e.jwtClaims(token) ?: throw AssertionError("$what: the token is not a JWT")
                assertTrue(
                    "$what: the token is for the card's Stellar account (sub=${claims.optString("sub")})",
                    claims.optString("sub").startsWith(sep10.stellarAddress)
                )
                assertTrue("$what: the token has not expired", claims.optLong("exp") > System.currentTimeMillis() / 1000)
                if (firstToken == null) firstToken = token
                signIns.put(
                    JSONObject().put("card", card.label).put("engine", engineName).put("platform", card.platform ?: JSONObject.NULL)
                        .put("stellar_address", sep10.stellarAddress)
                        .put("token_length", token.length)
                        .put("claims", JSONObject().put("iss", claims.opt("iss")).put("sub", claims.opt("sub"))
                            .put("iat", claims.opt("iat")).put("exp", claims.opt("exp")))
                )
                println("e2e: SEP-10 at $domain: ${card.label} (${engineName ?: "?"} engine) ${sep10.stellarAddress} signed in (iss=${claims.opt("iss")})")
            }

            // The token at work: a SEP-24 route answers 401/403 without it and 200 with it.
            val sep24 = Sep10E2e.tomlValue(toml, "TRANSFER_SERVER_SEP0024")?.trimEnd('/')
            if (sep24 == null) {
                server.put("protected", JSONObject().put("checked", false).put("reason", "no TRANSFER_SERVER_SEP0024 in stellar.toml"))
            } else {
                val (infoStatus, info) = Sep10E2e.httpGet("$sep24/info")
                assertEquals("$domain: SEP-24 /info is public", 200, infoStatus)
                val asset = JSONObject(info).getJSONObject("deposit").keys().asSequence().sorted().first()
                val url = "$sep24/transactions?asset_code=$asset"
                val (anonymous, _) = Sep10E2e.httpGet(url)
                val (authenticated, _) = Sep10E2e.httpGet(url, firstToken)
                server.put("protected", JSONObject().put("checked", true).put("url", url)
                    .put("anonymous_status", anonymous).put("authenticated_status", authenticated))
                assertTrue("$domain: $url must refuse a request without a token (got $anonymous)", anonymous == 401 || anonymous == 403)
                assertEquals("$domain: $url must answer the card's token", 200, authenticated)
                println("e2e: $domain: $url answers $anonymous without the token and $authenticated with it")
            }
        }
        Sep10E2e.writeReport("sep10-third-party.json", JSONObject().put("servers", servers))
        assumeTrue("none of ${domains.joinToString()} was reachable from this host", reached > 0)
    }
}

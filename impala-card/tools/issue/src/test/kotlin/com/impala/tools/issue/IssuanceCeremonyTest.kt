package com.impala.tools.issue

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.flows.CardAuthFlow
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.ImpalaUser
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.Jca
import com.impala.simulator.SimulatorBibo
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IssuanceCeremonyTest {
    private val account = UUID.randomUUID().toString()
    private val kmk = ByteArray(16) { (0x70 + it).toByte() }

    private fun freshCard(): SimulatorBibo = SimulatorBibo(
        installParams = PersonalizationProtocol.installParams(enforce = true, keys = null, pins = null, program = null)
    )

    private fun config() = IssuanceConfig(
        accountId = account, currency = "XLM", kmk = kmk,
        userPin = "2580".toCharArray(), masterPin = "14117298".toCharArray()
    )

    private fun ceremony(bibo: BIBO, bridge: FakeBridge, notices: MutableList<String> = mutableListOf()) = IssuanceCeremony(
        bibo, config(),
        CertificateSource.Bridge(HttpBridgeClient(bridge.url), bridge.holderToken, bridge.operatorToken, 7),
        notice = { notices += it }
    )

    @Test
    fun `full ceremony on jcardsim against a fake bridge yields a personalized card whose certificate verifies under the fake issuer key`() {
        FakeBridge().use { bridge ->
            val bibo = freshCard()
            val record = ceremony(bibo, bridge).run()
            val sdk = ImpalaSDK(bibo)
            val p = sdk.getPersonalization()
            assertTrue(p.personalized && p.pinProvisioned && !p.scp03KeysDefault)
            assertContentEquals(bridge.issuer.programId, p.programId)
            assertContentEquals(TransferProtocol.CURRENCY_XLM, p.currency)

            val pub = sdk.getECPubKey().toByteArray()
            val certMsg = TransferProtocol.certMessage(bridge.issuer.programId, UuidBytes.parse(account), TransferProtocol.CURRENCY_XLM, pub)
            assertTrue(Jca.verifyP256(bridge.issuer.keys.public, certMsg, p.certificate!!))
            assertEquals(Hex.encode(TransferProtocol.certId(bridge.issuer.programId, UuidBytes.parse(account), TransferProtocol.CURRENCY_XLM, pub).toByteArray()), record.certIdHex)

            // SIGN_AUTH no longer answers 6234.
            val sig = CardAuthFlow.sign(sdk, "11".repeat(32))
            val msg = "IMPALA-AUTH:".encodeToByteArray() + UuidBytes.parse(account) + Hex.decode("11".repeat(32))
            assertTrue(Jca.verifyP256(Jca.jcaPublicKey(pub), msg, Hex.decode(sig)))

            // The card row was registered with no rsa_pubkey, under the holder's token.
            assertEquals(account, bridge.cards[record.cardId]!!.first)
            assertEquals(Hex.encode(pub), bridge.cards[record.cardId]!!.second)
            assertEquals(1, record.issuerVersion)
            assertFalse(record.testIssuer)
        }
    }

    @Test
    fun `re-running on a personalized card is a no-op exit 0`() {
        FakeBridge().use { bridge ->
            val bibo = freshCard()
            val first = ceremony(bibo, bridge).run()
            val before = bridge.requests.size
            val notices = mutableListOf<String>()
            val second = ceremony(bibo, bridge, notices).run()
            assertTrue(second.alreadyIssued)
            assertEquals(first.certIdHex, second.certIdHex)
            assertEquals(before, bridge.requests.size, "no bridge calls on a no-op re-run")
            assertTrue(notices.any { it.contains("already personalized") })

            // And through the CLI: exit 0, record on stdout.
            val out = ByteArrayOutputStream()
            val code = runCli(
                arrayOf("--transport", "simulator", "--account", account, "--bridge", bridge.url),
                cliEnv(bridge, out, ByteArrayOutputStream(), transport = bibo)
            )
            assertEquals(EXIT_OK, code)
            assertTrue(out.toString().contains("status=already-issued"))
        }
    }

    /** Fails the first PERSONALIZE part C exchange (CLA 84 INS 72 P1 03) as if the card were pulled. */
    private class TearPartC(private val inner: BIBO) : BIBO {
        var tore = false
        override fun transceive(bytes: ByteArray?): ByteArray? {
            val b = bytes!!
            if (!tore && b.size > 3 && b[1] == 0x72.toByte() && b[2] == 0x03.toByte()) {
                tore = true
                throw BIBOException("card removed")
            }
            return inner.transceive(b)
        }
        override fun close() {}
    }

    @Test
    fun `a torn personalize (fail after part A) re-runs from part A on the next invocation`() {
        FakeBridge().use { bridge ->
            val card = freshCard()
            val torn = TearPartC(card)
            assertFailsWith<BIBOException> { ceremony(torn, bridge).run() }
            assertTrue(torn.tore)
            val p = ImpalaSDK(card).getPersonalization()
            assertFalse(p.personalized, "nothing committed before part C")

            val notices = mutableListOf<String>()
            val record = ceremony(card, bridge, notices).run()
            assertFalse(record.alreadyIssued)
            assertTrue(ImpalaSDK(card).getPersonalization().personalized)
            assertTrue(notices.any { it.contains("per-card keys") })
            assertTrue(notices.any { it.contains("recertifying") })
        }
    }

    @Test
    fun `bearer tokens never appear in argv, stdout or the trace hook`() {
        FakeBridge().use { bridge ->
            val trace = ByteArrayOutputStream()
            val card = freshCard().apply { debugTrace = { c, r -> trace.write(c); trace.write(r) } }
            val out = ByteArrayOutputStream()
            val err = ByteArrayOutputStream()
            val args = arrayOf("--transport", "simulator", "--account", account, "--bridge", bridge.url)
            val code = runCli(args, cliEnv(bridge, out, err, transport = card))
            assertEquals(EXIT_OK, code, err.toString())
            for (secret in listOf(bridge.holderToken, bridge.operatorToken, Hex.encode(kmk), "2580", "14117298")) {
                assertFalse(args.any { it.contains(secret) })
                assertFalse(out.toString().contains(secret), "stdout leaks $secret")
                assertFalse(err.toString().contains(secret), "stderr leaks $secret")
                assertFalse(trace.toString(Charsets.ISO_8859_1).contains(secret), "trace leaks $secret")
            }
            // A token-looking argument is refused as usage, not parsed.
            assertEquals(EXIT_USAGE, runCli(arrayOf("--holder-token", "x"), cliEnv(bridge, out, err, transport = card)))
        }
    }

    @Test
    fun `account id on card equals the bridge account UUID bytes`() {
        FakeBridge().use { bridge ->
            val bibo = freshCard()
            ceremony(bibo, bridge).run()
            val user: ImpalaUser = ImpalaSDK(bibo).getUserData()
            assertEquals(account, user.accountId)
        }
    }

    @Test
    fun `test issuer mode is refused against a pubnet bridge and prints the banner otherwise`() {
        FakeBridge(network = "pubnet").use { bridge ->
            val err = ByteArrayOutputStream()
            val code = runCli(
                arrayOf("--transport", "simulator", "--account", account, "--bridge", bridge.url, "--test-issuer"),
                cliEnv(bridge, ByteArrayOutputStream(), err, transport = freshCard())
            )
            assertEquals(EXIT_REFUSED, code)
            assertTrue(err.toString().contains("pubnet"))
        }
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(
            arrayOf("--transport", "simulator", "--account", account, "--test-issuer"),
            cliEnv(null, out, err, transport = freshCard())
        )
        assertEquals(EXIT_OK, code, err.toString())
        assertTrue(err.toString().contains("TEST ISSUER"))
        assertTrue(out.toString().contains("issuer=TEST (not redeemable)"))
    }

    @Test
    fun `usage errors exit 2`() {
        val err = ByteArrayOutputStream()
        val env = CliEnv(env = emptyMap(), out = PrintStream(ByteArrayOutputStream()), err = PrintStream(err), readSecret = { null })
        assertEquals(EXIT_USAGE, runCli(arrayOf("--bogus"), env))
        assertEquals(EXIT_USAGE, runCli(arrayOf("--account", account, "--test-issuer", "--transport", "simulator"), env)) // no KMK
        assertEquals(EXIT_USAGE, runCli(arrayOf("--account", "not-a-uuid"), env))
        assertEquals(EXIT_USAGE, runCli(arrayOf("--terminate"), env))
    }

    @Test
    fun `terminate prints the card's holdings and requires the matching card id`() {
        FakeBridge().use { bridge ->
            val bibo = freshCard()
            val record = ceremony(bibo, bridge).run()
            val out = ByteArrayOutputStream()
            val err = ByteArrayOutputStream()
            assertEquals(EXIT_USAGE, runCli(arrayOf("--transport", "simulator", "--terminate", "--yes-terminate", "00".repeat(16)), cliEnv(bridge, out, err, transport = bibo)))
            assertFalse(ImpalaSDK(bibo).getPersonalization().terminated)
            assertEquals(EXIT_OK, runCli(arrayOf("--transport", "simulator", "--terminate", "--yes-terminate", record.cardId), cliEnv(bridge, out, err, transport = bibo)), err.toString())
            assertTrue(out.toString().contains("balance=0"))
            assertTrue(out.toString().contains("status=terminated"))
            assertTrue(ImpalaSDK(bibo).getPersonalization().terminated)
        }
    }

    private fun cliEnv(bridge: FakeBridge?, out: ByteArrayOutputStream, err: ByteArrayOutputStream, transport: BIBO): CliEnv = CliEnv(
        env = buildMap {
            put("IMPALA_ISSUE_KMK", Hex.encode(kmk))
            put("IMPALA_USER_PIN", "2580")
            put("IMPALA_MASTER_PIN", "14117298")
            if (bridge != null) {
                put("IMPALA_HOLDER_TOKEN", bridge.holderToken)
                put("IMPALA_OPERATOR_TOKEN", bridge.operatorToken)
            }
        },
        out = PrintStream(out, true),
        err = PrintStream(err, true),
        readSecret = { null },
        openTransport = { _, _, _ -> object : BIBO by transport { override fun close() {} } }
    )
}

class CardKeysTest {
    @Test
    fun `per-card keys are deterministic, distinct per card and per label, never the GP default`() {
        val kmk = ByteArray(16) { it.toByte() }
        val a = CardKeys.derive(kmk, ByteArray(16) { 1 })
        val b = CardKeys.derive(kmk, ByteArray(16) { 2 })
        assertContentEquals(a.first, CardKeys.derive(kmk, ByteArray(16) { 1 }).first)
        assertFalse(a.first.contentEquals(b.first))
        assertFalse(a.first.contentEquals(a.second) || a.second.contentEquals(a.third))
        for (k in listOf(a.first, a.second, a.third)) assertFalse(k.contentEquals(CardKeys.GP_DEFAULT))
    }
}

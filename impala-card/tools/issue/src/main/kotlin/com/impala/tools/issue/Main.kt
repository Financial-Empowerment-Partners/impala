package com.impala.tools.issue

import com.impala.sdk.Constants
import com.impala.sdk.ImpalaSDK
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.BIBOException
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.apdu4j.PcscBibo
import com.impala.sdk.flows.Hex
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.simulator.SimulatorBibo
import com.impala.simulator.TcpApduClient
import com.impala.simulator.TestIssuer
import java.io.File
import java.io.PrintStream
import java.security.MessageDigest
import kotlin.system.exitProcess

const val EXIT_OK = 0
const val EXIT_REFUSED = 1
const val EXIT_USAGE = 2

internal const val USAGE = """usage: impala-issue --account UUID [options]            issue (personalize) a card
       impala-issue --terminate --yes-terminate CARD_ID [options]   terminate a recovered card

Transport:
  --transport pcsc|simulator|tcp:HOST:PORT   default pcsc (simulator = in-process jcardsim, test only)
  --reader NAME          PC/SC reader name filter (case-insensitive substring)
  --aid HEX              applet instance AID (default 01020304050607080102)

Issuance:
  --account UUID         bridge account (payala_account_id) the card is issued to
  --currency CODE        XLM (default), USDC or USDT0
  --card-minor-scale N   card minor-unit scale for the bridge certificate (default 7)
  --initial-counter N    receive-counter floor (replacement cards; default 0)
  --bridge URL           bridge base URL (required unless --test-issuer)
  --test-issuer          use a throwaway local issuer: login-only cards, NOT redeemable;
                         refused when the bridge reports pubnet
  --cap FILE             CAP file whose sha256 goes into the record

Secrets come from the environment or no-echo prompts, never from arguments:
  IMPALA_ISSUE_KMK            32 hex: master key for per-card SCP03 keys (required)
  IMPALA_SCP03_TRANSPORT_KEYS 96 hex ENC‖MAC‖DEK the card was installed with (default: GP test keys)
  IMPALA_HOLDER_TOKEN         bearer token of the card holder (POST /card)
  IMPALA_OPERATOR_TOKEN       bearer token with ManageKeys (certificate)
  IMPALA_USER_PIN / IMPALA_MASTER_PIN   else prompted without echo

Exit: 0 done, 1 refused by the card or the bridge, 2 usage."""

/** Everything the CLI reads from outside, injectable for tests. */
class CliEnv(
    val env: Map<String, String> = System.getenv(),
    val out: PrintStream = System.out,
    val err: PrintStream = System.err,
    /** No-echo prompt; null when there is no console. */
    val readSecret: (prompt: String) -> CharArray? = { prompt -> System.console()?.readPassword(prompt) },
    val openTransport: (spec: String, reader: String?, aid: String) -> BIBO = ::openTransport,
    val bridgeFactory: (url: String) -> BridgeClient = { HttpBridgeClient(it) }
)

class UsageException(message: String) : RuntimeException(message)

internal class Options(args: Array<String>) {
    var transport = "pcsc"
    var reader: String? = null
    var aid = PcscBibo.DEFAULT_APPLET_AID
    var account: String? = null
    var currency = "XLM"
    var cardMinorScale = 7
    var initialCounter = 0
    var bridge: String? = null
    var testIssuer = false
    var cap: String? = null
    var terminate = false
    var yesTerminate: String? = null
    var help = false

    init {
        var i = 0
        fun value(name: String): String = args.getOrNull(++i) ?: throw UsageException("$name needs a value")
        while (i < args.size) {
            when (val a = args[i]) {
                "--transport" -> transport = value(a)
                "--reader" -> reader = value(a)
                "--aid" -> aid = value(a)
                "--account" -> account = value(a)
                "--currency" -> currency = value(a)
                "--card-minor-scale" -> cardMinorScale = value(a).toIntOrNull()?.takeIf { it in 0..7 } ?: throw UsageException("--card-minor-scale must be 0..7")
                "--initial-counter" -> initialCounter = value(a).toIntOrNull()?.takeIf { it >= 0 } ?: throw UsageException("--initial-counter must be a non-negative integer")
                "--bridge" -> bridge = value(a)
                "--test-issuer" -> testIssuer = true
                "--cap" -> cap = value(a)
                "--terminate" -> terminate = true
                "--yes-terminate" -> yesTerminate = value(a)
                "-h", "--help" -> help = true
                else -> throw UsageException(
                    if (a.contains("token", ignoreCase = true) || a.contains("pin", ignoreCase = true) || a.contains("kmk", ignoreCase = true))
                        "secrets are never accepted as arguments; use the environment (see --help)"
                    else "unknown argument: $a"
                )
            }
            i++
        }
    }
}

fun openTransport(spec: String, reader: String?, aid: String): BIBO = when {
    spec == "pcsc" -> PcscBibo(reader, aid).connect()
    spec == "simulator" -> SimulatorBibo(
        aidHex = aid,
        installParams = PersonalizationProtocol.installParams(enforce = true, keys = null, pins = null, program = null)
    )
    spec.startsWith("tcp:") -> {
        val hp = spec.removePrefix("tcp:")
        val idx = hp.lastIndexOf(':')
        val port = hp.substring(idx + 1).toIntOrNull()
        if (idx <= 0 || port == null) throw UsageException("--transport tcp:HOST:PORT")
        TcpApduClient(hp.substring(0, idx), port)
    }
    else -> throw UsageException("unknown transport: $spec")
}

/** Runs the CLI; returns the exit code (never calls exitProcess). */
fun runCli(args: Array<String>, cli: CliEnv = CliEnv()): Int {
    val opts = try {
        Options(args)
    } catch (e: UsageException) {
        cli.err.println("impala-issue: ${e.message}")
        cli.err.println(USAGE)
        return EXIT_USAGE
    }
    if (opts.help) {
        cli.err.println(USAGE)
        return EXIT_OK
    }
    return try {
        if (opts.terminate) terminate(opts, cli) else issue(opts, cli)
    } catch (e: UsageException) {
        cli.err.println("impala-issue: ${e.message}")
        EXIT_USAGE
    } catch (e: CeremonyRefused) {
        cli.err.println("impala-issue: ${e.message}")
        EXIT_REFUSED
    } catch (e: BIBOException) {
        cli.err.println("impala-issue: card transport failed: ${e.message}")
        EXIT_REFUSED
    } catch (e: IllegalArgumentException) {
        cli.err.println("impala-issue: ${e.message}")
        EXIT_USAGE
    }
}

private fun secretHex(cli: CliEnv, name: String, bytes: Int, required: Boolean): ByteArray? {
    val v = cli.env[name]?.trim()
    if (v.isNullOrEmpty()) {
        if (required) throw UsageException("$name is not set")
        return null
    }
    return try {
        Hex.decode(v, bytes)
    } catch (_: IllegalArgumentException) {
        throw UsageException("$name must be ${bytes * 2} hex characters")
    }
}

private fun pin(cli: CliEnv, envName: String, prompt: String, digits: Int): CharArray {
    val v = cli.env[envName]?.toCharArray() ?: cli.readSecret(prompt)
        ?: throw UsageException("$envName is not set and there is no console to prompt on")
    if (v.size != digits || v.any { it !in '0'..'9' }) throw UsageException("$envName must be $digits digits")
    return v
}

private fun issue(opts: Options, cli: CliEnv): Int {
    val account = opts.account ?: throw UsageException("--account is required")
    if (!opts.testIssuer && opts.bridge == null) throw UsageException("--bridge is required (or --test-issuer for login-only test cards)")
    val kmk = secretHex(cli, "IMPALA_ISSUE_KMK", 16, required = true)!!
    val transportKeys = secretHex(cli, "IMPALA_SCP03_TRANSPORT_KEYS", 48, required = false)
        ?.let { Triple(it.copyOfRange(0, 16), it.copyOfRange(16, 32), it.copyOfRange(32, 48)) }
    val capSha = opts.cap?.let { path ->
        val f = File(path)
        if (!f.isFile) throw UsageException("--cap: no such file: $path")
        Hex.encode(MessageDigest.getInstance("SHA-256").digest(f.readBytes()))
    }

    val bridge = opts.bridge?.let(cli.bridgeFactory)
    val source: CertificateSource = if (opts.testIssuer) {
        if (bridge != null && bridge.stellarNetwork() == "pubnet") {
            throw CeremonyRefused("--test-issuer is refused against a pubnet bridge")
        }
        cli.err.println("*** TEST ISSUER — the card will NOT be redeemable on any bridge; reflash before transfer use ***")
        CertificateSource.Test(TestIssuer(), bridge?.let { b -> cli.env["IMPALA_HOLDER_TOKEN"]?.let { b to it } })
    } else {
        val holder = cli.env["IMPALA_HOLDER_TOKEN"]?.takeIf { it.isNotBlank() } ?: throw UsageException("IMPALA_HOLDER_TOKEN is not set")
        val operator = cli.env["IMPALA_OPERATOR_TOKEN"]?.takeIf { it.isNotBlank() } ?: throw UsageException("IMPALA_OPERATOR_TOKEN is not set")
        CertificateSource.Bridge(bridge!!, holder, operator, opts.cardMinorScale)
    }

    val userPin = pin(cli, "IMPALA_USER_PIN", "User PIN (4 digits): ", 4)
    if (userPin.contentEquals(charArrayOf('0', '0', '0', '0'))) throw UsageException("user PIN 0000 is refused (it is the PIN-less request marker)")
    val masterPin = pin(cli, "IMPALA_MASTER_PIN", "Master PIN (8 digits): ", 8)

    val bibo = cli.openTransport(opts.transport, opts.reader, opts.aid)
    try {
        val record = IssuanceCeremony(
            bibo,
            IssuanceConfig(account, opts.currency, opts.initialCounter, kmk, transportKeys, userPin, masterPin, capSha),
            source,
            notice = { cli.err.println(it) }
        ).run()
        record.lines().forEach(cli.out::println)
        return EXIT_OK
    } finally {
        userPin.fill('\u0000')
        masterPin.fill('\u0000')
        kmk.fill(0)
        bibo.close()
    }
}

/** docs/transfer-protocol.md §6.6 "recovered card": print what the card still holds, then TERMINATE over the per-card channel. */
private fun terminate(opts: Options, cli: CliEnv): Int {
    val confirm = opts.yesTerminate ?: throw UsageException("--terminate requires --yes-terminate CARD_ID")
    val kmk = secretHex(cli, "IMPALA_ISSUE_KMK", 16, required = true)!!
    val bibo = cli.openTransport(opts.transport, opts.reader, opts.aid)
    try {
        val plain = ImpalaSDK(bibo)
        val userData = refusing { plain.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data }
        val account = userData.copyOfRange(0, 16)
        val cardId = userData.copyOfRange(16, 32)
        val wire = Hex.encode(cardId)
        if (!confirm.equals(wire, ignoreCase = true)) throw UsageException("--yes-terminate $confirm does not match the tapped card $wire")
        val receive = refusing { plain.getReceiveState() }
        cli.out.println("card_id=$wire")
        cli.out.println("balance=${refusing { plain.getBalance() }}")
        cli.out.println("receive_counter=${receive.counter}")
        cli.out.println("receive_digest=${receive.lastDigest.hex()}")
        val last = refusing { plain.getLastTransfer() }
        cli.out.println("last_signed_transfer=${last?.let { Hex.encode(it.first) } ?: "none"}")
        val sdk = ImpalaSDK(bibo, CardKeys.derive(kmk, cardId))
        refusing { sdk.openSecureChannel(0x33) }
        try {
            refusing { sdk.terminate(account) }
        } finally {
            sdk.closeSecureChannel()
        }
        cli.out.println("status=terminated")
        return EXIT_OK
    } finally {
        kmk.fill(0)
        bibo.close()
    }
}

private inline fun <T> refusing(block: () -> T): T = try {
    block()
} catch (e: ImpalaException) {
    throw CeremonyRefused("card refused: ${e.message}", e)
}

fun main(args: Array<String>) {
    exitProcess(runCli(args))
}

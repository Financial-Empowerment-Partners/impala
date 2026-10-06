package com.impala.tools.issue

import com.impala.sdk.Constants
import com.impala.sdk.ImpalaSDK
import com.impala.sdk.apdu4j.BIBO
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.CardPersonalization
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.Jca
import com.impala.simulator.TestIssuer

/** Where the card certificate comes from. */
sealed class CertificateSource {
    /**
     * The bridge certifies the card (`POST /admin/cards/{id}/certificate`,
     * operator token) after the holder registers it (`POST /card`, holder token).
     */
    class Bridge(
        val client: BridgeClient,
        val holderToken: String,
        val operatorToken: String,
        val cardMinorScale: Int
    ) : CertificateSource()

    /**
     * A locally generated issuer (`--test-issuer`): login-only pilot cards. A
     * bridge that does not know this key can never redeem them; re-issue
     * (reflash) before any transfer use.
     */
    class Test(val issuer: TestIssuer = TestIssuer(), val registerWith: Pair<BridgeClient, String>? = null) : CertificateSource()
}

data class IssuanceConfig(
    /** The bridge account (payala_account_id) the card is issued to; must be a UUID. */
    val accountId: String,
    /** "XLM", "USDC" or "USDT0". */
    val currency: String = "XLM",
    val initialCounter: Int = 0,
    /** 16-byte KMK for per-card SCP03 keys (OD-3). */
    val kmk: ByteArray,
    /** SCP03 keys the card was installed with; null = GP defaults (installed without the KEYS flag). */
    val transportKeys: Triple<ByteArray, ByteArray, ByteArray>? = null,
    val userPin: CharArray,
    val masterPin: CharArray,
    val capSha256: String? = null
)

/** The signed-off issuance record printed at the end (and on a no-op re-run). */
data class IssuanceRecord(
    val cardId: String,
    val accountUuid: String,
    val programIdHex: String,
    val currency: String,
    val certIdHex: String,
    val appletVersion: String,
    val capSha256: String?,
    val issuerVersion: Int?,
    val testIssuer: Boolean,
    val alreadyIssued: Boolean
) {
    fun lines(): List<String> = listOfNotNull(
        "card_id=$cardId",
        "account_uuid=$accountUuid",
        "program_id=$programIdHex",
        "currency=$currency",
        "cert_id=$certIdHex",
        "applet_version=$appletVersion",
        capSha256?.let { "cap_sha256=$it" },
        issuerVersion?.let { "issuer_version=$it" },
        "issuer=${if (testIssuer) "TEST (not redeemable)" else "bridge"}",
        "status=${if (alreadyIssued) "already-issued" else "issued"}"
    )
}

/** A card or bridge refusal the CLI maps to exit 1. */
class CeremonyRefused(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * docs/transfer-protocol.md §5, in order, idempotent per step:
 * (1) version + state; (2) INITIALIZE unless done; (3) read cardId + pubkey;
 * (4) SCP03 on per-card keys, rotating from the transport keys first if needed;
 * (5) register + certify (or test issuer); (6) PERSONALIZE A[,B],C;
 * (7) PROVISION_PIN master + user; (8) read-back and record.
 * A personalized card prints its record and changes nothing. A torn
 * PERSONALIZE re-runs from part A (the applet commits all-or-nothing).
 */
class IssuanceCeremony(
    private val bibo: BIBO,
    private val config: IssuanceConfig,
    private val certificates: CertificateSource,
    private val notice: (String) -> Unit = { System.err.println(it) }
) {
    private val accountBytes: ByteArray = try {
        UuidBytes.parse(config.accountId)
    } catch (e: IllegalArgumentException) {
        throw IllegalArgumentException("--account must be a UUID (card auth binds the account UUID the card signs with)", e)
    }
    private val currencyTag: ByteArray = TransferProtocol.currencyTag(config.currency)

    fun run(): IssuanceRecord {
        require(config.userPin.size == 4 && config.userPin.all { it in '0'..'9' }) { "user PIN must be 4 digits" }
        require(!config.userPin.contentEquals(charArrayOf('0', '0', '0', '0'))) { "user PIN 0000 is the PIN-less request marker" }
        require(config.masterPin.size == 8 && config.masterPin.all { it in '0'..'9' }) { "master PIN must be 8 digits" }

        val plain = ImpalaSDK(bibo)
        val version = card { plain.requireCertifiedProtocol() }
        val versionText = "${version.major}.${version.minor}+${version.shortHash}"
        var p = card { plain.getPersonalization() }
        if (p.terminated) throw CeremonyRefused("card is terminated")
        if (p.personalized) {
            notice("card is already personalized; nothing to do")
            return recordFor(plain, p, versionText, alreadyIssued = true, issuerVersion = null)
        }

        // (2) INITIALIZE with host entropy, once.
        if (!p.initialized) {
            card { plain.setSeed() }
            notice("initialized (card key generated)")
        }
        // (3) identity
        val userData = card { plain.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data }
        val cardId = userData.copyOfRange(16, 32)
        val pub = card { plain.getECPubKey().toByteArray() }
        val wireCardId = Hex.encode(cardId)
        notice("card $wireCardId")

        // (4) per-card SCP03 keys
        val perCard = CardKeys.derive(config.kmk, cardId)
        val sdk = openPerCardChannel(perCard)

        try {
            // (5) certificate
            val cert = obtainCertificate(wireCardId, pub)
            if (p.programBound && !p.programId.contentEquals(cert.programId)) {
                throw CeremonyRefused("card is bound at install to program ${Hex.encode(p.programId)}, issuer is ${Hex.encode(cert.programId)}")
            }
            // Self-check before touching the card: the certificate verifies under the issuer key.
            val certMsg = TransferProtocol.certMessage(cert.programId, accountBytes, currencyTag, pub)
            if (!Jca.verifyP256(Jca.jcaPublicKey(cert.issuerPub), certMsg, cert.der)) {
                throw CeremonyRefused("certificate does not verify under the issuer key over the CERT message")
            }

            // (6) PERSONALIZE A[,B],C
            card {
                sdk.personalize(
                    accountBytes, currencyTag, cert.programId, cert.der,
                    issuerPubKey = if (p.programBound) null else cert.issuerPub,
                    initialReceiveCounter = config.initialCounter
                )
            }
            notice("personalized")

            // (7) PINs (lifts ENFORCE)
            card {
                sdk.provisionMasterPIN(String(config.masterPin))
                sdk.provisionUserPIN(String(config.userPin))
            }
            notice("PINs provisioned")
        } finally {
            sdk.closeSecureChannel()
        }

        // (8) read-back
        p = card { plain.getPersonalization() }
        if (!(p.personalized && p.pinProvisioned && !p.scp03KeysDefault)) {
            throw CeremonyRefused("read-back does not show PERSONALIZED|PIN_PROVISIONED|!SCP03_KEYS_DEFAULT: $p")
        }
        return recordFor(plain, p, versionText, alreadyIssued = false, issuerVersion = lastIssuerVersion)
    }

    private var lastIssuerVersion: Int? = null

    private class Cert(val der: ByteArray, val programId: ByteArray, val issuerPub: ByteArray)

    private fun obtainCertificate(wireCardId: String, pub: ByteArray): Cert = when (val src = certificates) {
        is CertificateSource.Test -> {
            src.registerWith?.let { (client, holderToken) -> register(client, holderToken, wireCardId, pub) }
            notice("TEST ISSUER — this card is not redeemable on any bridge; re-issue before transfer use")
            Cert(src.issuer.certify(accountBytes, currencyTag, pub), src.issuer.programId, src.issuer.pub65)
        }
        is CertificateSource.Bridge -> {
            val issuer = bridge { src.client.cardIssuer() }
                ?: throw CeremonyRefused("the bridge has no card issuer key (GET /card-issuer: configured=false)")
            register(src.client, src.holderToken, wireCardId, pub)
            val resp = try {
                bridge { src.client.certify(src.operatorToken, wireCardId, config.currency, src.cardMinorScale, recertify = false) }
            } catch (e: CeremonyRefused) {
                // A previous run certified this card but tore before PERSONALIZE
                // committed: the card is unpersonalized, so a fresh certificate
                // over the same CERT message is safe.
                val status = (e.cause as? BridgeException)?.status
                if (status != 409) throw e
                notice("card already certified by an earlier run; recertifying")
                bridge { src.client.certify(src.operatorToken, wireCardId, config.currency, src.cardMinorScale, recertify = true) }
            }
            if (!resp.issuerPublicKeyHex.equals(issuer.publicKeyHex, ignoreCase = true)) {
                throw CeremonyRefused("certificate issuer key differs from GET /card-issuer (key rotated mid-ceremony?)")
            }
            val programHex = resp.programIdHex ?: issuer.programIdHex
            if (!programHex.equals(issuer.programIdHex, ignoreCase = true)) {
                throw CeremonyRefused("certificate program id differs from GET /card-issuer")
            }
            lastIssuerVersion = resp.issuerVersion
            Cert(Hex.decode(resp.issuerCertHex), Hex.decode(programHex, 16), Hex.decode(resp.issuerPublicKeyHex, 65))
        }
    }

    private fun register(client: BridgeClient, holderToken: String, wireCardId: String, pub: ByteArray) {
        try {
            client.registerCard(holderToken, config.accountId, wireCardId, Hex.encode(pub))
            notice("registered with the bridge (POST /card)")
        } catch (e: BridgeException) {
            // The bridge answers a generic error for an already-registered
            // card; certification (which requires the active row) decides.
            notice("POST /card refused (HTTP ${e.status}); continuing — certification requires the card row")
        }
    }

    /** Opens SCP03 (security level 0x33) on the per-card keys, rotating to them first when the card is still on its transport keys. */
    private fun openPerCardChannel(perCard: Triple<ByteArray, ByteArray, ByteArray>): ImpalaSDK {
        val perCardSdk = ImpalaSDK(bibo, perCard)
        if (runCatching { perCardSdk.openSecureChannel(0x33) }.isSuccess) {
            notice("SCP03 open on per-card keys")
            return perCardSdk
        }
        val transport = ImpalaSDK(bibo, config.transportKeys ?: CardKeys.gpDefaultKeys())
        card { transport.openSecureChannel(0x33) }
        try {
            card { transport.rotateScp03Keys(perCard.first, perCard.second, perCard.third) }
        } finally {
            transport.closeSecureChannel()
        }
        notice("SCP03 keys rotated to per-card keys (APPLET_UPDATE seq 0x0001)")
        card { perCardSdk.openSecureChannel(0x33) }
        return perCardSdk
    }

    private fun recordFor(sdk: ImpalaSDK, p: CardPersonalization, version: String, alreadyIssued: Boolean, issuerVersion: Int?): IssuanceRecord {
        val userData = card { sdk.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data }
        val account = userData.copyOfRange(0, 16)
        val pub = card { sdk.getECPubKey().toByteArray() }
        val certId = TransferProtocol.certId(p.programId, account, p.currency, pub).hex()
        return IssuanceRecord(
            cardId = Hex.encode(userData.copyOfRange(16, 32)),
            accountUuid = UuidBytes.format(account),
            programIdHex = Hex.encode(p.programId),
            currency = p.currency.decodeToString().trimEnd('\u0000'),
            certIdHex = certId,
            appletVersion = version,
            capSha256 = config.capSha256,
            issuerVersion = issuerVersion,
            testIssuer = certificates is CertificateSource.Test,
            alreadyIssued = alreadyIssued
        )
    }

    private inline fun <T> card(block: () -> T): T = try {
        block()
    } catch (e: ImpalaException) {
        val sw = e.statusWord?.let { " (SW=${it.toString(16).uppercase().padStart(4, '0')})" } ?: ""
        throw CeremonyRefused("card refused: ${e.message}$sw", e)
    }

    private inline fun <T> bridge(block: () -> T): T = try {
        block()
    } catch (e: BridgeException) {
        throw CeremonyRefused(e.message ?: "bridge refused", e)
    }
}

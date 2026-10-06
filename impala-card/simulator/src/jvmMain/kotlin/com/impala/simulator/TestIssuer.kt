package com.impala.simulator

import com.impala.sdk.ImpalaSDK
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.TransferEnvelope
import com.impala.sdk.models.TransferProtocol
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Host-side P-256 crypto (JCA): the independent oracle jcardsim's JavaCard
 * engines and the bridge's verifier are checked against.
 */
object Jca {
    fun genP256(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /** DER ECDSA-SHA256 over [data]. */
    fun signP256(privateKey: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    fun verifyP256(publicKey: PublicKey, data: ByteArray, der: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(data)
            verify(der)
        }

    /** Encodes a JCA EC public key as a 65-byte uncompressed SEC1 point. */
    fun uncompressedPoint(publicKey: ECPublicKey): ByteArray {
        fun pad32(value: BigInteger): ByteArray {
            val raw = value.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - raw.size) + raw
        }
        return byteArrayOf(0x04) + pad32(publicKey.w.affineX) + pad32(publicKey.w.affineY)
    }

    /** Reconstructs a JCA public key from a 65-byte uncompressed SEC1 point on secp256r1. */
    fun jcaPublicKey(uncompressed: ByteArray): PublicKey {
        require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte()) { "expected a 65-byte uncompressed point" }
        val x = BigInteger(1, uncompressed.copyOfRange(1, 33))
        val y = BigInteger(1, uncompressed.copyOfRange(33, 65))
        val params = AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
    }
}

/**
 * A program issuer for tests and the issuance tool's `--test-issuer` mode: a
 * locally generated P-256 key that certifies card keys and mints certified
 * external senders. A card certified by a TestIssuer is never redeemable on a
 * bridge (the bridge does not know this key).
 */
class TestIssuer @JvmOverloads constructor(
    val programId: ByteArray = randomProgramId(),
    val keys: KeyPair = Jca.genP256()
) {
    init {
        require(programId.size == 16 && programId.any { it != 0.toByte() }) { "programId must be 16 non-zero bytes" }
    }

    val pub65: ByteArray = Jca.uncompressedPoint(keys.public as ECPublicKey)

    /** The issuer's DER signature over CERT(programId, accountId, currency, cardPub65). */
    fun certify(accountId: ByteArray, currency: ByteArray, cardPub65: ByteArray): ByteArray =
        Jca.signP256(keys.private, TransferProtocol.certMessage(programId, accountId, currency, cardPub65))

    /** A fresh issuer-certified sending key under this program (models the bridge treasury or another card). */
    @JvmOverloads
    fun externalSender(accountId: ByteArray, currency: ByteArray = TransferProtocol.CURRENCY_USDC): CertifiedKey {
        val kp = Jca.genP256()
        val pub = Jca.uncompressedPoint(kp.public as ECPublicKey)
        return CertifiedKey(accountId, currency, kp, pub, certify(accountId, currency, pub), programId)
    }

    companion object {
        fun randomProgramId(): ByteArray {
            val out = ByteArray(16)
            do SecureRandom().nextBytes(out) while (out.all { it == 0.toByte() })
            return out
        }
    }
}

/** An issuer-certified key that can sign transfers (a treasury key or a peer card modelled host-side). */
class CertifiedKey(
    val accountId: ByteArray,
    val currency: ByteArray,
    val keys: KeyPair,
    val pub65: ByteArray,
    val cert: ByteArray,
    val programId: ByteArray
) {
    fun sign(signable: ByteArray): ByteArray = Jca.signP256(keys.private, TransferProtocol.xferMessage(programId, signable))
    fun envelope(signable: ByteArray): TransferEnvelope = TransferEnvelope(signable, sign(signable), pub65, cert)
}

/** A personalized simulated card: the SDK, its transport, identity, key material and installed certificate. */
class PersonalizedCard(
    val sdk: ImpalaSDK,
    val bibo: SimulatorBibo,
    val accountId: ByteArray,
    val currency: ByteArray,
    val pub65: ByteArray,
    val cert: ByteArray,
    val keys: Triple<ByteArray, ByteArray, ByteArray>
)

/** Deterministic non-default SCP03 keys for simulated cards (never use on a real card). */
fun simulatorScp03Keys(): Triple<ByteArray, ByteArray, ByteArray> =
    Triple(ByteArray(16) { (0x10 + it).toByte() }, ByteArray(16) { (0x20 + it).toByte() }, ByteArray(16) { (0x30 + it).toByte() })

/**
 * Installs a fresh simulated card (ENFORCE + custom SCP03 keys, plus the program
 * block when [bindAtInstall]), initializes it, and runs the full PERSONALIZE
 * ceremony + user-PIN provisioning, returning a ready-to-transact card.
 *
 * [certify] defaults to [issuer]'s local key; pass a function that asks a real
 * bridge for the certificate to personalize a simulated card the bridge can
 * redeem (the T1 lane).
 */
@JvmOverloads
fun personalizedCard(
    issuer: TestIssuer,
    accountId: ByteArray,
    currency: ByteArray = TransferProtocol.CURRENCY_USDC,
    userPin: String = "1111",
    initialCounter: Int = 0,
    bindAtInstall: Boolean = false,
    certify: (accountId: ByteArray, currency: ByteArray, cardPub65: ByteArray) -> ByteArray = issuer::certify
): PersonalizedCard {
    val keys = simulatorScp03Keys()
    val params = PersonalizationProtocol.installParams(
        enforce = true,
        keys = keys,
        pins = null,
        program = if (bindAtInstall) Pair(issuer.programId, issuer.pub65) else null
    )
    val bibo = SimulatorBibo(installParams = params)
    val sdk = ImpalaSDK(bibo, keys)
    sdk.setSeed()
    val pub = sdk.getECPubKey().toByteArray()
    val cert = certify(accountId, currency, pub)
    sdk.openSecureChannel()
    sdk.personalize(
        accountId, currency, issuer.programId, cert,
        issuerPubKey = if (bindAtInstall) null else issuer.pub65,
        initialReceiveCounter = initialCounter
    )
    sdk.provisionUserPIN(userPin)
    sdk.closeSecureChannel()
    return PersonalizedCard(sdk, bibo, accountId, currency, pub, cert, keys)
}

/**
 * Credits [card] with [amount] minor units from an issuer-certified sender,
 * reading the card's live receive counter. [sendSequence] is the sender's
 * strictly increasing `dateTime`.
 */
fun fund(card: PersonalizedCard, from: CertifiedKey, amount: Long, sendSequence: Long) {
    val counter = TransferProtocol.nextReceiveCounter(card.sdk.getReceiveState().counter)
    val signable = com.impala.sdk.models.Signable(sendSequence, from.accountId, card.accountId, card.currency, amount, 0L, counter)
    card.sdk.verifyTransferV2(from.envelope(signable.encode()))
}

package com.impala.sdk

import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.Signable
import com.impala.sdk.models.TransferEnvelope
import com.impala.sdk.models.TransferProtocol
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Shared fixtures for the applet-interop tests (applet 0.2, transfer protocol
 * v1). [Jca] is the independent host-side oracle: pure JCA P-256 crypto that
 * jcardsim's JavaCard engines are checked against. [TestIssuer] / [CertifiedKey]
 * mint the issuer certificates and transfer signatures the applet verifies;
 * [personalizedCard] runs the full personalization ceremony end-to-end so the
 * transfer tests start from a certified card.
 */

internal val PROGRAM_A = ByteArray(16) { (0xA0 + it).toByte() }
internal val PROGRAM_B = ByteArray(16) { (0xB0 + it).toByte() }
internal val USDC = "USDC".encodeToByteArray()
internal val EUR_ = "EUR ".encodeToByteArray()

internal fun customKeys(): Triple<ByteArray, ByteArray, ByteArray> =
    Triple(ByteArray(16) { (0x10 + it).toByte() }, ByteArray(16) { (0x20 + it).toByte() }, ByteArray(16) { (0x30 + it).toByte() })

internal fun defaultKeys(): Triple<ByteArray, ByteArray, ByteArray> {
    val key = ByteArray(16) { (0x40 + it).toByte() }
    return Triple(key, key.copyOf(), key.copyOf())
}

/** Status word from a raw response APDU. */
internal fun swOf(resp: ByteArray): Int =
    ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)

/** The message of an ImpalaException (assertions match on the embedded hex SW). */
internal fun swOf(e: ImpalaException): String? = e.message

internal object Jca {
    fun genP256(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

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
        require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte())
        val x = BigInteger(1, uncompressed.copyOfRange(1, 33))
        val y = BigInteger(1, uncompressed.copyOfRange(33, 65))
        val params = AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
    }

    /** Pads a DER signature with trailing zeros to a fixed 72-byte wire slot (lenient: any size <= 72). */
    fun pad72(der: ByteArray): ByteArray {
        require(der.size <= 72) { "DER signature too long: ${der.size}" }
        return der + ByteArray(72 - der.size)
    }

    /** Trims the trailing zero padding off a 72-byte signature slot using the DER length byte. */
    fun trimDer(padded: ByteArray): ByteArray =
        padded.copyOfRange(0, (padded[1].toInt() and 0xFF) + 2)

    fun verifyMasterPinCmd(pinDigits: ByteArray): CommandAPDU =
        CommandAPDU(0x00, Constants.INS_VERIFY_PIN.toInt(), 0x00, Constants.P2_MASTER_PIN.toInt(), pinDigits)
}

/** A program issuer: a P-256 key pair that certifies card keys and mints external senders. */
internal class TestIssuer(val programId: ByteArray = PROGRAM_A) {
    val keys: KeyPair = Jca.genP256()
    val pub65: ByteArray = Jca.uncompressedPoint(keys.public as ECPublicKey)

    /** The issuer's DER signature over CERT(programId, accountId, currency, cardPub65). */
    fun certify(accountId: ByteArray, currency: ByteArray, cardPub65: ByteArray): ByteArray =
        Jca.signP256(keys.private, TransferProtocol.certMessage(programId, accountId, currency, cardPub65))

    /** A fresh issuer-certified sending key under this program (models the bridge treasury or another card). */
    fun externalSender(accountId: ByteArray, currency: ByteArray = USDC): CertifiedKey {
        val kp = Jca.genP256()
        val pub = Jca.uncompressedPoint(kp.public as ECPublicKey)
        return CertifiedKey(accountId, currency, kp, pub, certify(accountId, currency, pub), programId)
    }
}

/** An issuer-certified key that can sign transfers (a treasury key or a peer card modelled host-side). */
internal class CertifiedKey(
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

/** Per-test monotone send-sequence source (dateTime allocator). */
internal class SeqAllocator {
    private var last = 0L
    fun next(): Long = ++last
}

/** Builds a 60-byte signable with a freshly allocated send sequence. */
internal fun signable(
    sender: ByteArray,
    recipient: ByteArray,
    amount: Long,
    counter: Int,
    seq: SeqAllocator,
    currency: ByteArray = USDC,
    phoneId: Long = 0L
): ByteArray = Signable(seq.next(), sender, recipient, currency, amount, phoneId, counter).encode()

/** A personalized card under test: the SDK, its transport, identity, key material and installed certificate. */
internal class PersonalizedCard(
    val sdk: ImpalaSDK,
    val bibo: SimulatorBibo,
    val accountId: ByteArray,
    val pub65: ByteArray,
    val cert: ByteArray,
    val keys: Triple<ByteArray, ByteArray, ByteArray>
)

/**
 * Installs a fresh simulated card (ENFORCE + custom SCP03 keys, plus the program
 * block when [bindAtInstall]), initializes it, and runs the full PERSONALIZE
 * ceremony + user-PIN provisioning, returning a ready-to-transact card.
 */
internal fun personalizedCard(
    issuer: TestIssuer,
    accountId: ByteArray,
    currency: ByteArray = USDC,
    userPin: String = "1111",
    initialCounter: Int = 0,
    bindAtInstall: Boolean = false
): PersonalizedCard {
    val keys = customKeys()
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
    val cert = issuer.certify(accountId, currency, pub)
    sdk.openSecureChannel()
    sdk.personalize(
        accountId, currency, issuer.programId, cert,
        issuerPubKey = if (bindAtInstall) null else issuer.pub65,
        initialReceiveCounter = initialCounter
    )
    sdk.provisionUserPIN(userPin)
    sdk.closeSecureChannel()
    return PersonalizedCard(sdk, bibo, accountId, pub, cert, keys)
}

/** Credits [card] with [amount] from an issuer-certified sender, reading the live receive counter. */
internal fun fund(card: PersonalizedCard, from: CertifiedKey, amount: Long, seq: SeqAllocator) {
    val counter = TransferProtocol.nextReceiveCounter(card.sdk.getReceiveState().counter)
    card.sdk.verifyTransferV2(from.envelope(signable(from.accountId, card.accountId, amount, counter, seq)))
}

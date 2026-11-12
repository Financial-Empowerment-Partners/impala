package com.impala.sdk.stellar

import okio.Buffer
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString

/**
 * Pure Ed25519 verification (RFC 8032) of [signature] over [message] under the
 * 32-byte [publicKey]. The SDK carries no crypto; the platform supplies this
 * (impala-lib: `com.payala.impala.stellar.Ed25519`). It must return false, not
 * throw, for malformed keys and signatures.
 */
fun interface Ed25519Verifier {
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

/** A SEP-10 challenge rejected by [Sep10Challenge.verify] (or by a client check); [reason] says which rule. */
class Sep10Exception(val reason: Reason, message: String) : Exception(message) {
    enum class Reason {
        /** Not base64, not XDR of a transaction envelope, a muxed or unknown key type, a non-zero ext, trailing bytes, too large. */
        MALFORMED,
        /** The envelope is not `ENVELOPE_TYPE_TX` (2): a v0 or fee-bump envelope, or an unknown type. */
        ENVELOPE_TYPE,
        /** The transaction source is not the server's signing key (or is a muxed account). */
        SERVER_KEY,
        /** `seqNum != 0`. */
        SEQUENCE,
        /** Preconditions are not `PRECOND_TIME`, or `maxTime == 0` (no upper bound). */
        TIME_BOUNDS_MISSING,
        /** A time bound above 2^63 - 1, or `minTime > maxTime`. */
        TIME_BOUNDS_INVALID,
        /** `now < minTime - grace`. */
        TIME_BOUNDS_TOO_EARLY,
        /** `now > maxTime`. */
        TIME_BOUNDS_EXPIRED,
        /** `maxTime - minTime` above the allowed lifetime. */
        TIME_BOUNDS_LIFETIME,
        /** A memo other than `MEMO_NONE`. */
        MEMO,
        /** Zero operations, or more than [Sep10Challenge.MAX_OPERATIONS]. */
        OPERATION_COUNT,
        /** An operation that is not `MANAGE_DATA`. */
        OPERATION_TYPE,
        /** An operation without a source account, a muxed source, op[0] not sourced by the client key, or a later op not sourced by the server key. */
        OPERATION_SOURCE,
        /** op[0]'s data name is not exactly `"<homeDomain> auth"`. */
        HOME_DOMAIN_KEY,
        /** op[0]'s value is absent or not 64 bytes. */
        NONCE_LENGTH,
        /** A `web_auth_domain` operation whose value is absent or not the expected web-auth domain. */
        WEB_AUTH_DOMAIN,
        /** Not exactly one signature on the envelope. */
        SIGNATURE_COUNT,
        /** The one signature's hint is not the server key's, or it does not verify under the server key. */
        SERVER_SIGNATURE,
        /** The network passphrases (expected, stellar.toml, challenge response) disagree. Raised by clients, not by [Sep10Challenge.verify]. */
        NETWORK,
    }

    override fun toString(): String = "Sep10Exception($reason: $message)"
}

/**
 * What the client expects of a challenge. Keys are raw 32-byte Ed25519 public
 * keys; [serverSigningKey] comes from stellar.toml `SIGNING_KEY` and
 * [clientKey] is the key that will sign (the card's Stellar key).
 */
class Sep10Expectation(
    serverSigningKey: ByteArray,
    val networkPassphrase: String,
    val homeDomain: String,
    val webAuthDomain: String,
    clientKey: ByteArray,
    val minTimeGraceSeconds: Long = 300,
    val maxLifetimeSeconds: Long = 900,
) {
    private val server = serverSigningKey.copyOf()
    private val client = clientKey.copyOf()

    val serverSigningKey: ByteArray get() = server.copyOf()
    val clientKey: ByteArray get() = client.copyOf()

    internal val serverKeyBytes: ByteArray get() = server
    internal val clientKeyBytes: ByteArray get() = client
    internal val homeDomainKey: ByteArray = "$homeDomain auth".encodeUtf8().toByteArray()
    internal val webAuthDomainBytes: ByteArray = webAuthDomain.encodeUtf8().toByteArray()

    init {
        require(server.size == 32) { "server signing key must be 32 bytes" }
        require(client.size == 32) { "client key must be 32 bytes" }
        require(!server.contentEquals(client)) { "client key must differ from the server signing key" }
        require(networkPassphrase.isNotEmpty()) { "network passphrase must not be empty" }
        require(homeDomain.isNotEmpty() && homeDomainKey.size <= 64) { "home domain must be 1..59 bytes" }
        require(webAuthDomainBytes.size in 1..64) { "web auth domain must be 1..64 bytes" }
        require(minTimeGraceSeconds in 0..86_400) { "minTime grace must be 0..86400 seconds" }
        require(maxLifetimeSeconds in 1..86_400) { "max lifetime must be 1..86400 seconds" }
    }
}

/**
 * A SEP-10 challenge transaction that passed every client rule. Only
 * [verify] creates one, so holding a `Sep10Challenge` means the bytes were
 * checked; [transactionBytes] is the exact `Transaction` slice of the server's
 * envelope (never re-encoded) and [hash] is what the client key signs.
 */
class Sep10Challenge private constructor(
    private val envelope: ByteArray,
    private val txStart: Int,
    private val txEnd: Int,
    private val signatureCountOffset: Int,
    private val signatureCount: Int,
    private val netId: ByteArray,
    private val txHash: ByteArray,
    private val client: ByteArray,
    val minTime: Long,
    val maxTime: Long,
) {
    /** The `Transaction` XDR (the `tx` member of the v1 envelope, without envelope tag and signatures). */
    val transactionBytes: ByteArray get() = envelope.copyOfRange(txStart, txEnd)

    /** SHA-256 of the network passphrase. */
    val networkId: ByteArray get() = netId.copyOf()

    /** SHA-256(networkId ‖ 00000002 ‖ transactionBytes): the Stellar transaction hash the client signs. */
    val hash: ByteArray get() = txHash.copyOf()

    /**
     * The server's envelope, byte for byte, with one more `DecoratedSignature`
     * (hint = the client key's last 4 bytes, the 64-byte [clientSignature])
     * appended, as standard base64. The caller verifies [clientSignature]
     * first; this only frames it.
     */
    fun signedEnvelope(clientSignature: ByteArray): String {
        require(clientSignature.size == 64) { "an Ed25519 signature is 64 bytes, got ${clientSignature.size}" }
        val out = XdrWriter()
            .raw(envelope.copyOfRange(0, signatureCountOffset))
            .uint32(signatureCount + 1L)
            .raw(envelope.copyOfRange(signatureCountOffset + 4, envelope.size))
            .fixedOpaque(client.copyOfRange(28, 32))
            .varOpaque(clientSignature)
            .toByteArray()
        return out.toByteString().base64()
    }

    companion object {
        const val ENVELOPE_TYPE_TX = 2
        const val MAX_OPERATIONS = 5
        /** Far above any challenge these rules accept (about 1.5 KB of base64 at five full operations). */
        const val MAX_ENVELOPE_BASE64_LENGTH = 4096

        private const val KEY_TYPE_ED25519 = 0
        private const val KEY_TYPE_MUXED_ED25519 = 0x100
        private const val PRECOND_TIME = 1
        private const val MEMO_NONE = 0
        private const val MANAGE_DATA = 10
        private const val MAX_SIGNATURES = 20
        private val WEB_AUTH_DOMAIN_KEY = "web_auth_domain".encodeUtf8().toByteArray()

        /**
         * Applies every SEP-10 client rule to [envelopeBase64] at
         * [nowEpochSeconds] and returns the verified challenge, or throws
         * [Sep10Exception] naming the first rule it breaks.
         */
        fun verify(
            envelopeBase64: String,
            expect: Sep10Expectation,
            nowEpochSeconds: Long,
            verifier: Ed25519Verifier,
        ): Sep10Challenge {
            if (envelopeBase64.length > MAX_ENVELOPE_BASE64_LENGTH) {
                fail(Sep10Exception.Reason.MALFORMED, "envelope longer than $MAX_ENVELOPE_BASE64_LENGTH base64 characters")
            }
            val decoded = envelopeBase64.decodeBase64()
            if (decoded == null || decoded.size == 0 || decoded.base64() != envelopeBase64) {
                fail(Sep10Exception.Reason.MALFORMED, "envelope is not canonical standard base64")
            }
            return try {
                parse(decoded.toByteArray(), expect, nowEpochSeconds, verifier)
            } catch (e: XdrException) {
                fail(Sep10Exception.Reason.MALFORMED, e.message ?: "malformed XDR")
            }
        }

        private fun parse(env: ByteArray, expect: Sep10Expectation, now: Long, verifier: Ed25519Verifier): Sep10Challenge {
            val r = XdrReader(env)
            val envelopeType = r.int32()
            if (envelopeType != ENVELOPE_TYPE_TX) fail(Sep10Exception.Reason.ENVELOPE_TYPE, "envelope type $envelopeType is not ENVELOPE_TYPE_TX")
            val txStart = r.position

            // sourceAccount
            when (val t = r.int32()) {
                KEY_TYPE_ED25519 -> if (!r.fixedOpaque(32).contentEquals(expect.serverKeyBytes)) {
                    fail(Sep10Exception.Reason.SERVER_KEY, "transaction source is not the server signing key")
                }
                KEY_TYPE_MUXED_ED25519 -> fail(Sep10Exception.Reason.SERVER_KEY, "transaction source is a muxed account")
                else -> throw XdrException("unknown transaction source key type $t")
            }
            r.uint32() // fee: any
            val seq = r.int64()
            if (seq != 0L) fail(Sep10Exception.Reason.SEQUENCE, "sequence number is not 0")

            // cond
            val cond = r.int32()
            if (cond != PRECOND_TIME) fail(Sep10Exception.Reason.TIME_BOUNDS_MISSING, "preconditions are not PRECOND_TIME (type $cond)")
            val minTime = r.int64()
            val maxTime = r.int64()
            checkTimeBounds(minTime, maxTime, expect, now)

            val memo = r.int32()
            if (memo != MEMO_NONE) fail(Sep10Exception.Reason.MEMO, "memo type $memo is not MEMO_NONE")

            val opCount = r.uint32()
            if (opCount < 1 || opCount > MAX_OPERATIONS) {
                fail(Sep10Exception.Reason.OPERATION_COUNT, "$opCount operations (allowed 1..$MAX_OPERATIONS)")
            }
            for (i in 0 until opCount.toInt()) {
                if (!r.optional()) fail(Sep10Exception.Reason.OPERATION_SOURCE, "operation $i has no source account")
                val source = when (val t = r.int32()) {
                    KEY_TYPE_ED25519 -> r.fixedOpaque(32)
                    KEY_TYPE_MUXED_ED25519 -> fail(Sep10Exception.Reason.OPERATION_SOURCE, "operation $i source is a muxed account")
                    else -> throw XdrException("unknown operation $i source key type $t")
                }
                val type = r.int32()
                if (type != MANAGE_DATA) fail(Sep10Exception.Reason.OPERATION_TYPE, "operation $i is type $type, not MANAGE_DATA")
                val name = r.string(64)
                val value = if (r.optional()) r.varOpaque(64) else null
                if (i == 0) {
                    if (!source.contentEquals(expect.clientKeyBytes)) fail(Sep10Exception.Reason.OPERATION_SOURCE, "operation 0 is not sourced by the client key")
                    if (!name.contentEquals(expect.homeDomainKey)) fail(Sep10Exception.Reason.HOME_DOMAIN_KEY, "operation 0 key is not \"${expect.homeDomain} auth\"")
                    if (value == null || value.size != 64) fail(Sep10Exception.Reason.NONCE_LENGTH, "operation 0 value is ${value?.size ?: "absent"}, not 64 bytes")
                } else {
                    if (!source.contentEquals(expect.serverKeyBytes)) fail(Sep10Exception.Reason.OPERATION_SOURCE, "operation $i is not sourced by the server key")
                    if (name.contentEquals(WEB_AUTH_DOMAIN_KEY) && (value == null || !value.contentEquals(expect.webAuthDomainBytes))) {
                        fail(Sep10Exception.Reason.WEB_AUTH_DOMAIN, "web_auth_domain is not \"${expect.webAuthDomain}\"")
                    }
                }
            }
            val ext = r.int32()
            if (ext != 0) throw XdrException("transaction ext $ext is not 0")
            val txEnd = r.position

            val signatureCountOffset = r.position
            val signatureCount = r.count(MAX_SIGNATURES)
            val hints = ArrayList<ByteArray>(signatureCount)
            val signatures = ArrayList<ByteArray>(signatureCount)
            repeat(signatureCount) {
                hints += r.fixedOpaque(4)
                signatures += r.varOpaque(64)
            }
            r.requireEnd()
            if (signatureCount != 1) fail(Sep10Exception.Reason.SIGNATURE_COUNT, "$signatureCount signatures, expected exactly 1")

            val networkId = expect.networkPassphrase.encodeUtf8().sha256().toByteArray()
            val hash = Buffer()
                .write(networkId)
                .writeInt(ENVELOPE_TYPE_TX)
                .write(env, txStart, txEnd - txStart)
                .sha256()
                .toByteArray()

            val server = expect.serverKeyBytes
            if (!hints[0].contentEquals(server.copyOfRange(28, 32))) fail(Sep10Exception.Reason.SERVER_SIGNATURE, "signature hint is not the server key's")
            if (signatures[0].size != 64 || !verifier.verify(server.copyOf(), hash.copyOf(), signatures[0].copyOf())) {
                fail(Sep10Exception.Reason.SERVER_SIGNATURE, "the server signature does not verify")
            }
            return Sep10Challenge(
                env, txStart, txEnd, signatureCountOffset, signatureCount, networkId, hash,
                expect.clientKeyBytes.copyOf(), minTime, maxTime
            )
        }

        private fun checkTimeBounds(minTime: Long, maxTime: Long, expect: Sep10Expectation, now: Long) {
            // TimePoint is uint64; a value with the top bit set reads as negative here.
            if (maxTime == 0L) fail(Sep10Exception.Reason.TIME_BOUNDS_MISSING, "maxTime is 0 (no upper bound)")
            if (minTime < 0 || maxTime < 0) fail(Sep10Exception.Reason.TIME_BOUNDS_INVALID, "time bound above 2^63 - 1")
            if (minTime > maxTime) fail(Sep10Exception.Reason.TIME_BOUNDS_INVALID, "minTime is after maxTime")
            if (maxTime - minTime > expect.maxLifetimeSeconds) {
                fail(Sep10Exception.Reason.TIME_BOUNDS_LIFETIME, "lifetime ${maxTime - minTime} s exceeds ${expect.maxLifetimeSeconds} s")
            }
            if (now < minTime - expect.minTimeGraceSeconds) fail(Sep10Exception.Reason.TIME_BOUNDS_TOO_EARLY, "challenge is not valid yet")
            if (now > maxTime) fail(Sep10Exception.Reason.TIME_BOUNDS_EXPIRED, "challenge has expired")
        }

        private fun fail(reason: Sep10Exception.Reason, message: String): Nothing = throw Sep10Exception(reason, message)
    }
}

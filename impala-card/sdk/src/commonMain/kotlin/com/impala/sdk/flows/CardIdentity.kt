package com.impala.sdk.flows

import com.impala.sdk.Constants
import com.impala.sdk.ImpalaSDK
import com.impala.sdk.apdu4j.CommandAPDU
import com.impala.sdk.models.CardPersonalization
import com.impala.sdk.models.ImpalaException
import com.impala.sdk.models.ImpalaVersion

/**
 * Everything a client needs to know about a tapped card before driving a flow,
 * read with four non-mutating commands (GET_VERSION, GET_PERSONALIZATION,
 * GET_USER_DATA, GET_EC_PUB_KEY).
 */
class CardIdentity(
    val version: ImpalaVersion,
    /** The on-card account UUID (16 bytes, RFC-4122 big-endian). */
    val accountId: ByteArray,
    /** The card UUID (16 bytes). */
    val cardId: ByteArray,
    /** The card's 65-byte uncompressed P-256 public key (`04 ‖ X ‖ Y`). */
    val pubKey: ByteArray,
    val personalization: CardPersonalization,
    /** The cardholder name stored on the card (UTF-8 after the two UUIDs of GET_USER_DATA); display only. */
    val fullName: String = ""
) {
    /** Lowercase dashed account UUID. */
    val accountUuid: String get() = UuidBytes.format(accountId)

    /** Lowercase dashed card UUID. */
    val cardUuid: String get() = UuidBytes.format(cardId)

    /** The bridge's `card_id` wire form: 32 lowercase hex chars, no dashes. */
    val wireCardId: String get() = Hex.encode(cardId)

    /** The bridge's `ec_pubkey` wire form: 130 lowercase hex chars, exactly as the card returned it. */
    val pubKeyHex: String get() = Hex.encode(pubKey)

    val versionString: String get() = "${version.major}.${version.minor}"

    /** GET_PERSONALIZATION state: 0x00 blank, 0x01 initialized, 0x02 personalized, 0xFF terminated. */
    val state: Int get() = personalization.state.toInt() and 0xFF
    val flags: Int get() = personalization.flags.toInt() and 0xFF
    val isPersonalized: Boolean get() = state == STATE_PERSONALIZED
    val programId: ByteArray get() = personalization.programId
    val programIdHex: String get() = Hex.encode(personalization.programId)
    val currency: ByteArray get() = personalization.currency

    /** The issuer certificate (trimmed DER), or null before PERSONALIZE part C. */
    val certificate: ByteArray? get() = personalization.certificate

    /** Fails with the typed error unless the card can sign (personalized, not terminated). */
    fun requirePersonalized(): CardIdentity {
        if (state == STATE_TERMINATED || personalization.terminated) throw CardFlowException(CardError.Terminated)
        if (!isPersonalized) throw CardFlowException(CardError.NotPersonalized)
        return this
    }

    companion object {
        const val STATE_BLANK = 0x00
        const val STATE_INITIALIZED = 0x01
        const val STATE_PERSONALIZED = 0x02
        const val STATE_TERMINATED = 0xFF

        /**
         * Reads the identity. The version gate runs first, so a 0.1 card fails
         * with [CardError.WrongProtocolVersion] before any V2 command; a card
         * that was never INITIALIZEd (no EC key, 0x6230) is
         * [CardError.NotPersonalized].
         */
        fun read(sdk: ImpalaSDK): CardIdentity = cardFlow {
            val version = sdk.getImpalaAppletVersion()
            if (version.major.toInt() == 0 && version.minor < 2) {
                throw CardFlowException(CardError.WrongProtocolVersion("${version.major}.${version.minor}"))
            }
            val personalization = sdk.getPersonalization()
            val userData = sdk.tx(CommandAPDU(Constants.INS_GET_USER_DATA)).data
            if (userData.size < 32) throw ImpalaException("GET_USER_DATA returned ${userData.size} bytes, expected >= 32")
            val pubKey = try {
                sdk.getECPubKey().toByteArray()
            } catch (e: ImpalaException) {
                if (e.statusWord == 0x6230) throw CardFlowException(CardError.NotPersonalized, e)
                throw e
            }
            if (pubKey.size != 65 || pubKey[0] != 0x04.toByte()) {
                throw ImpalaException("GET_EC_PUB_KEY returned ${pubKey.size} bytes, expected a 65-byte uncompressed point")
            }
            CardIdentity(
                version, userData.copyOfRange(0, 16), userData.copyOfRange(16, 32), pubKey, personalization,
                userData.copyOfRange(32, userData.size).decodeToString()
            )
        }
    }
}

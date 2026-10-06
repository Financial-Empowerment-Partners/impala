package com.payala.impala.demo

import com.impala.sdk.flows.CardIdentity
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.CardPersonalization
import com.impala.sdk.models.ImpalaVersion
import com.impala.sdk.models.TransferProtocol
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Runs [block] on a non-main thread (card sessions refuse the main thread) and returns its value. */
internal fun <T> offMain(block: () -> T): T {
    val ex = Executors.newSingleThreadExecutor()
    try {
        return ex.submit<T> { block() }.get(60, TimeUnit.SECONDS)
    } catch (e: ExecutionException) {
        throw e.cause ?: e
    } finally {
        ex.shutdown()
    }
}

/** A [CardIdentity] without a card, for view-model tests that never touch NFC. */
internal fun fakeIdentity(
    accountUuid: String = "0f0e0d0c-0b0a-0908-0706-050403020100",
    cardUuid: String = "00112233-4455-6677-8899-aabbccddeeff",
    state: Int = CardIdentity.STATE_PERSONALIZED,
    major: Int = 0,
    minor: Int = 2,
    pubKey: ByteArray = byteArrayOf(0x04) + ByteArray(64) { (it + 1).toByte() }
): CardIdentity = CardIdentity(
    version = ImpalaVersion(major.toShort(), minor.toShort(), 1, "deadbeef"),
    accountId = UuidBytes.parse(accountUuid),
    cardId = UuidBytes.parse(cardUuid),
    pubKey = pubKey,
    personalization = CardPersonalization(
        state.toByte(), (if (state == CardIdentity.STATE_PERSONALIZED) 0x35 else 0x01).toByte(),
        ByteArray(16) { (0xA0 + it).toByte() }, TransferProtocol.CURRENCY_XLM, null,
        if (state == CardIdentity.STATE_PERSONALIZED) byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01) else null
    ),
    fullName = "Card Holder"
)

package com.payala.impala.demo

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.impala.sdk.flows.Hex
import com.impala.sdk.flows.UuidBytes
import com.impala.sdk.models.TransferProtocol
import com.impala.simulator.PersonalizedCard
import com.impala.simulator.TestIssuer
import com.impala.simulator.fund
import com.impala.simulator.personalizedCard
import com.payala.impala.demo.card.StoredCard
import com.payala.impala.demo.model.CardIssuerResponse
import com.payala.impala.demo.model.OfflineCardResponse
import com.payala.impala.demo.transfer.PendingTransferStore
import java.util.UUID

/** A bridge-like world for transfer tests: one issuer/program, a redemption identity, a funded XLM card. */
internal class TransferWorld(balance: Long = 100_000, userPin: String = "2468") {
    val issuer = TestIssuer()
    val redemptionUuid: String = UUID.randomUUID().toString()
    val account: String = UUID.randomUUID().toString()
    val card: PersonalizedCard = personalizedCard(issuer, UuidBytes.parse(account), TransferProtocol.CURRENCY_XLM, userPin = userPin)
    val treasury = issuer.externalSender(UuidBytes.parse(redemptionUuid), TransferProtocol.CURRENCY_XLM)
    var sendSequence = 1L
    val sins = mutableListOf<Int>()

    init {
        if (balance > 0) fund(card, treasury, balance, sendSequence++)
        card.bibo.debugTrace = { cmd, _ -> sins += cmd[1].toInt() and 0xFF }
    }

    val cardId: String get() = Hex.encode(card.sdk.getUserData().cardId.let { UuidBytes.parse(it) })

    fun issuerResponse(configured: Boolean = true) = if (!configured) CardIssuerResponse(configured = false) else CardIssuerResponse(
        version = 1, public_key_hex = Hex.encode(issuer.pub65), fingerprint = "fp",
        redemption_uuid = redemptionUuid, program_id_hex = Hex.encode(issuer.programId)
    )

    fun offlineCard(certified: Boolean = true, lastRedeemed: Int = 0) =
        OfflineCardResponse(card_id = cardId, currency = "XLM", card_minor_scale = 7, certified = certified, last_redeemed_counter = lastRedeemed)

    fun storedCard() = StoredCard(cardId, account, "fp", Hex.encode(issuer.programId), "XLM", "0.2", "2026-10-05T00:00:00Z")

    fun signTransferCount() = sins.count { it == 0x30 }
    fun verifyTransferCount() = sins.count { it == 0x31 }
}

internal fun freshStore(): PendingTransferStore {
    val ctx = ApplicationProvider.getApplicationContext<Context>()
    return PendingTransferStore(ctx.getSharedPreferences("pending-${System.nanoTime()}", Context.MODE_PRIVATE))
}

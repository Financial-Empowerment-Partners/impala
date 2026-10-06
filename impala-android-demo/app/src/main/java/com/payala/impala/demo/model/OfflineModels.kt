package com.payala.impala.demo.model

// DTOs for the bridge's offline issuance/redemption lane (spec-bridge §8.2-8.6
// as amended by the contract addendum §A). Every amount is an integer in minor
// units (Long); floating point never touches money in this app.

/** Public `GET /card-issuer`: the program key and redemption identity, or `configured: false`. */
data class CardIssuerResponse(
    val configured: Boolean? = null,
    val version: Int? = null,
    val public_key_hex: String? = null,
    val fingerprint: String? = null,
    val redemption_uuid: String? = null,
    val program_id_hex: String? = null
) {
    val isConfigured: Boolean get() = configured != false && redemption_uuid != null && public_key_hex != null
}

/** Owner `GET /offline/cards/{card_id}`: the bridge-side position and counters of one card. */
data class OfflineCardResponse(
    val card_id: String,
    val currency: String? = null,
    val card_minor_scale: Int? = null,
    val certified: Boolean = false,
    val last_issued_counter: Int = 0,
    val last_redeemed_counter: Int = 0,
    val issued_minor: Long = 0,
    val redeemed_minor: Long = 0,
    val written_off_minor: Long = 0,
    val outstanding_minor: Long = 0
)

/** `POST /offline/redemptions`: the card-signed tuple, byte-identical on every retry. */
data class RedemptionRequest(
    val payala_account_id: String,
    val card_id: String,
    val signable_hex: String,
    val signature_der_hex: String,
    val card_pubkey_hex: String,
    val card_cert_hex: String,
    val format_version: Int = 1
)

/** `POST /offline/redemptions` 202 (new or replayed). */
data class RedemptionResponse(
    val redemption_id: String,
    val redemption_ref: String? = null,
    val state: String,
    val card_amount: Long? = null,
    val amount_minor: Long? = null,
    val currency: String? = null
)

/** Owner `GET /offline/redemptions/{id}`. */
data class RedemptionStatusResponse(
    val redemption_id: String? = null,
    val state: String,
    val intent_id: String? = null,
    val stellar_hash: String? = null,
    val btxid: String? = null,
    val attempts: Int? = null,
    val reason: String? = null
)

/** `POST /offline/issuances`. */
data class IssuanceRequest(
    val payala_account_id: String,
    val card_id: String,
    val card_amount: Long,
    val observed_receive_counter: Int? = null
)

/** How to fund an issuance: passed verbatim to `POST /managed-account/sign`. */
data class FundingInstructions(
    val destination: String,
    val asset: String,
    /** Decimal string exactly as the bridge formatted it (7 dp for XLM); never parsed to a float. */
    val amount: String,
    val memo: String,
    val idempotency_key: String
)

/** `POST /offline/issuances` / `GET /offline/issuances/{id}`. */
data class IssuanceResponse(
    val issuance_id: String,
    val issuance_ref: String? = null,
    val state: String,
    val funding: FundingInstructions? = null,
    val expires_at: String? = null,
    val counter: Int? = null,
    val reason: String? = null
)

/** `GET /offline/issuances/{id}/credit`: the signed credit, identical on every replay. */
data class IssuanceCreditResponse(
    val issuance_id: String,
    val state: String,
    val counter: Int,
    val format_version: Int = 1,
    val signable_hex: String,
    val signature_der_hex: String,
    val issuer_public_key_hex: String,
    val issuer_self_cert_hex: String,
    /** 209 bytes: pad72(sig) ‖ issuer_pubkey(65) ‖ pad72(self_cert). */
    val tail_hex: String
)

/** `POST /offline/issuances/{id}/ack`: client-asserted, informational to the bridge. */
data class IssuanceAckRequest(
    val applied: Boolean,
    val status_word: String
)

/** `POST /managed-account/sign` (custodial payment, idempotency-keyed). */
data class SignSubmitRequest(
    val payala_account_id: String,
    val destination: String,
    val amount: String,
    val memo: String? = null,
    val idempotency_key: String? = null
)

data class SignSubmitResponse(
    val success: Boolean = false,
    val message: String = "",
    val stellar_hash: String? = null,
    val btxid: String? = null,
    val intent_id: String? = null,
    val idempotency_key: String? = null,
    /** prepared | submitted | settled | rejected | ambiguous */
    val status: String? = null,
    val resolution: String? = null,
    val replayed: Boolean? = null,
    val amount_minor: Long? = null
)

/** `GET /managed-account/intents/{intent_id}`. */
data class CustodialIntentResponse(
    val intent_id: String? = null,
    val status: String,
    val stellar_hash: String? = null,
    val last_error: String? = null
)

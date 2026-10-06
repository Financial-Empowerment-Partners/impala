package com.payala.impala.demo.model

/**
 * Request body for `POST /card`. Registers a smartcard's public key against an
 * account. `ec_pubkey` is the 130-hex uncompressed point exactly as the card
 * returned it. `rsa_pubkey` is legacy: applet 0.2 has no RSA key, so it stays
 * null (Gson omits nulls, and the bridge stores NULL since migration 038).
 */
data class CreateCardRequest(
    val account_id: String,
    val card_id: String,
    val ec_pubkey: String,
    val rsa_pubkey: String? = null
)

data class DeleteCardRequest(
    val card_id: String
)

data class CardResponse(
    val success: Boolean,
    val message: String
)

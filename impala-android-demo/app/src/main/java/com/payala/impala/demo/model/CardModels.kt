package com.payala.impala.demo.model

/** Request body for `POST /card`. Registers a smartcard's public keys against an account. */
data class CreateCardRequest(
    val account_id: String,
    val card_id: String,
    val ec_pubkey: String,
    val rsa_pubkey: String
)

data class DeleteCardRequest(
    val card_id: String
)

data class CardResponse(
    val success: Boolean,
    val message: String
)

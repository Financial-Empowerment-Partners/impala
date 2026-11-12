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
    val rsa_pubkey: String? = null,
    /**
     * The card's Stellar key for SEP-10 sign-in, all three or none
     * (docs/sep10-card-keys.md §6): the `G…` address, the card key's DER
     * signature binding it (lowercase hex) and the Stellar key's proof of
     * possession (128 lowercase hex characters). Omitted from the JSON when
     * null, so a card without a Stellar key registers exactly as before.
     */
    val stellar_address: String? = null,
    val stellar_binding_sig: String? = null,
    val stellar_proof_sig: String? = null
)

/**
 * `PUT /card/stellar-key`: the Stellar key of a card that is already
 * registered. The bridge verifies both signatures against the caller's
 * account and the card's stored key; a repeat for the same key succeeds.
 */
data class SetCardStellarKeyRequest(
    val card_id: String,
    val stellar_address: String,
    val stellar_binding_sig: String,
    val stellar_proof_sig: String
)

data class DeleteCardRequest(
    val card_id: String
)

data class CardResponse(
    val success: Boolean,
    val message: String
)

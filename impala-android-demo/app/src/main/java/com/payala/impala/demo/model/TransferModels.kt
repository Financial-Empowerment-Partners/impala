package com.payala.impala.demo.model

/** Request body for `POST /transaction`. Records a Stellar/Payala transaction. */
data class CreateTransactionRequest(
    val stellar_tx_id: String? = null,
    val payala_tx_id: String? = null,
    val stellar_hash: String? = null,
    val source_account: String? = null,
    val stellar_fee: Long? = null,
    val stellar_max_fee: Long? = null,
    val memo: String? = null,
    val signatures: String? = null,
    val preconditions: String? = null,
    val payala_currency: String? = null,
    val payala_digest: String? = null
)

data class CreateTransactionResponse(
    val success: Boolean,
    val message: String,
    val btxid: String? = null
)

/** Response from `GET /version`. Contains bridge build info and DB schema version. */
data class VersionResponse(
    val name: String,
    val version: String,
    val build_date: String,
    val rustc_version: String,
    val schema_version: String?
)

data class SyncRequest(
    val account_id: String
)

data class SyncResponse(
    val success: Boolean,
    val message: String,
    val timestamp: String
)

/** A single MFA enrollment returned by `GET /mfa`. */
data class MfaEnrollment(
    val account_id: String,
    val mfa_type: String,
    val secret: String?,
    val phone_number: String?,
    val enabled: Boolean
)

data class MfaResponse(
    val success: Boolean,
    val message: String
)

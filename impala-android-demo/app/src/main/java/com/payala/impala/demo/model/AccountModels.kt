package com.payala.impala.demo.model

/** Request body for `POST /account`. Creates a linked Stellar/Payala account. */
data class CreateAccountRequest(
    val stellar_account_id: String,
    val payala_account_id: String,
    val first_name: String,
    val middle_name: String? = null,
    val last_name: String,
    val nickname: String? = null,
    val affiliation: String? = null,
    val gender: String? = null
)

data class CreateAccountResponse(
    val success: Boolean,
    val message: String
)

/** Response from `GET /account`. */
data class AccountResponse(
    val payala_account_id: String,
    val first_name: String,
    val middle_name: String?,
    val last_name: String,
    val nickname: String?,
    val affiliation: String?,
    val gender: String?
)

/** Request body for `PUT /account`. All fields are optional (partial update). */
data class UpdateAccountRequest(
    val stellar_account_id: String? = null,
    val payala_account_id: String? = null,
    val first_name: String? = null,
    val middle_name: String? = null,
    val last_name: String? = null,
    val nickname: String? = null,
    val affiliation: String? = null,
    val gender: String? = null
)

data class UpdateAccountResponse(
    val success: Boolean,
    val message: String,
    val rows_affected: Long
)

package com.payala.impala.demo.model

/** Request body for `POST /notify`. Creates a notification preference record. */
data class CreateNotifyRequest(
    val account_id: String,
    val medium: String,
    val mobile: String? = null,
    val wa: String? = null,
    val signal: String? = null,
    val tel: String? = null,
    val email: String? = null,
    val url: String? = null,
    val app: String? = null
)

/** Request body for `PUT /notify`. Updates an existing notification preference record. */
data class UpdateNotifyRequest(
    val id: Int,
    val medium: String? = null,
    val mobile: String? = null,
    val wa: String? = null,
    val signal: String? = null,
    val tel: String? = null,
    val email: String? = null,
    val url: String? = null,
    val app: String? = null
)

/** Response from `POST /notify` and `PUT /notify`. */
data class NotifyResponse(
    val success: Boolean,
    val message: String,
    val id: Int? = null
)

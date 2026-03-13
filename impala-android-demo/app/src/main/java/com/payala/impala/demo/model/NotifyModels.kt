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

/** Response item from `GET /notify`. */
data class NotifyListItem(
    val id: Int,
    val account_id: String,
    val medium: String,
    val active: Boolean,
    val mobile: String? = null,
    val wa: String? = null,
    val signal: String? = null,
    val tel: String? = null,
    val email: String? = null,
    val url: String? = null,
    val app: String? = null
)

// ── Notification Subscriptions ─────────────────────────────────────────

/** Request body for `POST /notification/subscriptions`. */
data class CreateSubscriptionRequest(
    val event_type: String,
    val medium: String
)

/** Request body for `PUT /notification/subscriptions/:id`. */
data class UpdateSubscriptionRequest(
    val enabled: Boolean
)

/** Response from subscription CRUD endpoints. */
data class SubscriptionResponse(
    val success: Boolean,
    val message: String,
    val id: Int? = null
)

/** Item returned by `GET /notification/subscriptions`. */
data class SubscriptionListItem(
    val id: Int,
    val event_type: String,
    val medium: String,
    val enabled: Boolean
)

// ── Device Token ───────────────────────────────────────────────────────

/** Request body for `POST /device-token`. */
data class RegisterDeviceTokenRequest(
    val token: String,
    val platform: String = "android"
)

/** Request body for `DELETE /device-token`. */
data class DeleteDeviceTokenRequest(
    val token: String
)

/** Response from device token endpoints. */
data class DeviceTokenResponse(
    val success: Boolean,
    val message: String
)

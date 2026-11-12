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

/** Request body for `POST /mfa`. Enrolls a TOTP or SMS multi-factor method. */
data class EnrollMfaRequest(
    val account_id: String,
    val mfa_type: String,
    val secret: String? = null,
    val phone_number: String? = null
)

// ── Multi-factor sign-in (docs/mfa-card-pin-biometrics.md) ─────────────────

/** `GET /mfa/status`: the current session's assurance and the account's requirement. */
data class MfaStatusResponse(
    val amr: List<String> = emptyList(),
    val auth_time: Long = 0,
    val mfa: Boolean = false,
    val required: Boolean = false,
    val required_by_role: Boolean = false,
    val satisfied: Boolean = true,
    val max_age_secs: Long = 0,
)

/** `POST /mfa/challenge`: a single-use step-up / enrollment challenge. */
data class MfaChallengeResponse(val challenge: String, val expires_in: Long)

/** `POST /mfa/step-up`: add a factor (`totp`, `card` or `device`) to this session. */
data class StepUpRequest(
    val mfa_type: String,
    val code: String? = null,
    val challenge: String? = null,
    val card_id: String? = null,
    val signature: String? = null,
    val pin_proof: String? = null,
    val key_id: String? = null,
    val device_signature: String? = null,
)

data class StepUpResponse(
    val success: Boolean = false,
    val amr: List<String> = emptyList(),
    val refresh_token: String? = null,
    val temporal_token: String? = null,
)

/** `POST /mfa/device-keys`: enroll a phone device key proven by signing a challenge. */
data class EnrollDeviceKeyRequest(
    val public_key: String,
    val label: String? = null,
    val platform: String? = "android",
    val user_verification: String? = "none",
    val challenge: String,
    val signature: String,
)

data class EnrollDeviceKeyResponse(val success: Boolean = false, val key_id: String? = null)

/** One active device key from `GET /mfa/device-keys`. */
data class DeviceKeyView(
    val key_id: String,
    val label: String? = null,
    val platform: String? = null,
    val user_verification: String = "none",
    val created_at_unix: Long = 0,
)

/** `PUT /mfa/policy`: turn the account's own MFA requirement on or off. */
data class MfaPolicyRequest(val required: Boolean)

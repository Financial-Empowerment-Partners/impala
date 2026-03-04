package com.payala.impala.demo.model

/** Request body for `POST /authenticate`. Registers or verifies credentials. */
data class AuthenticateRequest(
    val account_id: String,
    val password: String
)

/** Response from `POST /authenticate`. [action] is `"registered"` or `"verified"`. */
data class AuthenticateResponse(
    val success: Boolean,
    val message: String,
    val action: String
)

/**
 * Request body for `POST /token`.
 * - Send [username]+[password] to get a `refresh_token`.
 * - Send [refresh_token] to get a `temporal_token`.
 */
data class TokenRequest(
    val username: String? = null,
    val password: String? = null,
    val refresh_token: String? = null
)

/** Response from `POST /token`. Contains either a refresh or temporal token. */
data class TokenResponse(
    val success: Boolean,
    val message: String,
    val refresh_token: String? = null,
    val temporal_token: String? = null
)

/** Request body for `POST /auth/okta`. Exchanges an Okta access token for local JWT tokens. */
data class OktaTokenExchangeRequest(
    val okta_token: String
)

/** Response from `GET /auth/okta/config`. Contains Okta client configuration. */
data class OktaConfigResponse(
    val enabled: Boolean,
    val issuer: String? = null,
    val client_id: String? = null,
    val authorization_endpoint: String? = null,
    val token_endpoint: String? = null,
    val scopes: List<String>? = null
)

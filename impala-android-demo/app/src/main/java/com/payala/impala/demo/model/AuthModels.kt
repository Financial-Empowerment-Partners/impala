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

/**
 * Response from `POST /token` and the `auth` token-exchange endpoints.
 * Contains either a refresh or temporal token (or both — under strict
 * refresh-token rotation a temporal exchange may also return a rotated
 * refresh token).
 *
 * [login] and [display_name] are only populated by `POST /auth/github` (the
 * bridge fetches the GitHub profile during its server-side code exchange).
 */
data class TokenResponse(
    val success: Boolean,
    val message: String,
    val refresh_token: String? = null,
    val temporal_token: String? = null,
    val login: String? = null,
    val display_name: String? = null
)

/** Request body for `POST /auth/okta`. Exchanges an Okta access token for local JWT tokens. */
data class OktaTokenExchangeRequest(
    val okta_token: String
)

/** Request body for `POST /auth/google`. Exchanges a Google ID token for local JWT tokens. */
data class GoogleTokenExchangeRequest(
    val id_token: String
)

/**
 * Request body for `POST /auth/github`. Mirrors the bridge's dual-shape
 * contract — send either:
 * - [code] + [redirect_uri]: the OAuth authorization code; the bridge performs
 *   the code→token exchange server-side (the client secret never ships in the
 *   APK). This is the shape the app uses.
 * - [access_token]: a pre-obtained GitHub access token (legacy shape, kept by
 *   the bridge for rollout compatibility).
 */
data class GitHubTokenExchangeRequest(
    val access_token: String? = null,
    val code: String? = null,
    val redirect_uri: String? = null
)

/** Request body for `POST /auth/card/challenge`. Requests a single-use card-auth challenge. */
data class CardChallengeRequest(
    val card_id: String
)

/**
 * Response from `POST /auth/card/challenge`.
 *
 * [challenge] is 64 hex characters (32 raw bytes), single-use, and expires
 * [expires_in] seconds (60) after issuance.
 */
data class CardChallengeResponse(
    val success: Boolean,
    val challenge: String? = null,
    val expires_in: Long? = null
)

/**
 * Request body for `POST /auth/card`.
 *
 * [signature] is the hex-encoded DER ECDSA-SHA256 signature produced on-card
 * over the pinned card-auth message `"IMPALA-AUTH:" || accountId (16B) ||
 * challenge`. The applet adds the domain prefix and account ID itself — only
 * the raw challenge bytes are sent to the card.
 */
data class CardAuthRequest(
    val card_id: String,
    val signature: String
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

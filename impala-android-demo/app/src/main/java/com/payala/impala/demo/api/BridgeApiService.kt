package com.payala.impala.demo.api

import com.payala.impala.demo.model.*
import retrofit2.http.*

/**
 * Retrofit service interface mapping to the impala-bridge REST API.
 *
 * Every method is a `suspend` function so callers can use coroutines. Request
 * and response types are defined in the `model` package and serialised via Gson.
 *
 * @see ApiClient for the singleton that creates this service
 */
interface BridgeApiService {

    // ── Authentication ──────────────────────────────────────────────────

    /** Register or verify credentials. Returns `action = "registered"` on first use. */
    @POST("authenticate")
    suspend fun authenticate(@Body request: AuthenticateRequest): AuthenticateResponse

    /**
     * Obtain tokens. Two modes:
     * - **Login**: send `username` + `password` to receive a 14-day `refresh_token`.
     * - **Refresh**: send `refresh_token` to receive a 1-hour `temporal_token`.
     */
    @POST("token")
    suspend fun token(@Body request: TokenRequest): TokenResponse

    /** Exchange an Okta access token for local JWT tokens. */
    @POST("auth/okta")
    suspend fun oktaTokenExchange(@Body request: OktaTokenExchangeRequest): TokenResponse

    /** Get Okta client configuration (no auth required). */
    @GET("auth/okta/config")
    suspend fun getOktaConfig(): OktaConfigResponse

    // ── Account ─────────────────────────────────────────────────────────

    /** Look up an account by its Stellar public key. */
    @GET("account")
    suspend fun getAccount(@Query("stellar_account_id") stellarAccountId: String): AccountResponse

    /** Create a new linked Stellar/Payala account. */
    @POST("account")
    suspend fun createAccount(@Body request: CreateAccountRequest): CreateAccountResponse

    /** Update mutable fields on an existing account. */
    @PUT("account")
    suspend fun updateAccount(@Body request: UpdateAccountRequest): UpdateAccountResponse

    // ── Card ────────────────────────────────────────────────────────────

    /** Register a smartcard's public keys against an account. */
    @POST("card")
    suspend fun createCard(@Body request: CreateCardRequest): CardResponse

    /** Remove a registered card by its ID. Uses `@HTTP` because DELETE with a body is non-standard. */
    @HTTP(method = "DELETE", path = "card", hasBody = true)
    suspend fun deleteCard(@Body request: DeleteCardRequest): CardResponse

    // ── Transaction ─────────────────────────────────────────────────────

    /** Record a Stellar/Payala transaction in the bridge ledger. */
    @POST("transaction")
    suspend fun createTransaction(@Body request: CreateTransactionRequest): CreateTransactionResponse

    // ── MFA ─────────────────────────────────────────────────────────────

    /** List MFA enrollments (TOTP/SMS) for the given account. */
    @GET("mfa")
    suspend fun getMfa(@Query("account_id") accountId: String): List<MfaEnrollment>

    /** Verify a TOTP or SMS code during an MFA challenge. */
    @POST("mfa/verify")
    suspend fun verifyMfa(@Body request: Map<String, String>): MfaResponse

    // ── MFA Enrollment ─────────────────────────────────────────────────

    /** Enroll in MFA (TOTP or SMS). Uses UPSERT on (account_id, mfa_type). */
    @POST("mfa")
    suspend fun enrollMfa(@Body request: EnrollMfaRequest): MfaResponse

    // ── Notify ────────────────────────────────────────────────────────

    /** List notification preferences for the authenticated user. */
    @GET("notify")
    suspend fun listNotify(): List<NotifyListItem>

    /** Create a notification preference record. */
    @POST("notify")
    suspend fun createNotify(@Body request: CreateNotifyRequest): NotifyResponse

    /** Update an existing notification preference record. */
    @PUT("notify")
    suspend fun updateNotify(@Body request: UpdateNotifyRequest): NotifyResponse

    // ── Notification Subscriptions ────────────────────────────────────

    /** List all event→medium subscriptions for the authenticated user. */
    @GET("notification/subscriptions")
    suspend fun listSubscriptions(): List<SubscriptionListItem>

    /** Subscribe to an event on a delivery medium. */
    @POST("notification/subscriptions")
    suspend fun createSubscription(@Body request: CreateSubscriptionRequest): SubscriptionResponse

    /** Enable or disable a subscription. */
    @PUT("notification/subscriptions/{id}")
    suspend fun updateSubscription(
        @Path("id") id: Int,
        @Body request: UpdateSubscriptionRequest
    ): SubscriptionResponse

    /** Remove a subscription. */
    @DELETE("notification/subscriptions/{id}")
    suspend fun deleteSubscription(@Path("id") id: Int): SubscriptionResponse

    // ── Device Token ──────────────────────────────────────────────────

    /** Register an FCM device token for push notifications. */
    @POST("device-token")
    suspend fun registerDeviceToken(@Body request: RegisterDeviceTokenRequest): DeviceTokenResponse

    /** Remove a device token (on logout or uninstall). */
    @HTTP(method = "DELETE", path = "device-token", hasBody = true)
    suspend fun deleteDeviceToken(@Body request: DeleteDeviceTokenRequest): DeviceTokenResponse

    // ── Sync ────────────────────────────────────────────────────────────

    /** Record a sync timestamp in Redis for the given account. */
    @POST("sync")
    suspend fun sync(@Body request: SyncRequest): SyncResponse

    // ── Version ─────────────────────────────────────────────────────────

    /** Retrieve bridge build info and database schema version. */
    @GET("version")
    suspend fun getVersion(): VersionResponse
}

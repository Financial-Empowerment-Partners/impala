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
     * - **Login**: send `username` + `password` to receive a 30-day `refresh_token`.
     * - **Refresh**: send `refresh_token` to receive a 1-hour `temporal_token`.
     */
    @POST("token")
    suspend fun token(@Body request: TokenRequest): TokenResponse

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

    /** Create a notification preference record. */
    @POST("notify")
    suspend fun createNotify(@Body request: CreateNotifyRequest): NotifyResponse

    /** Update an existing notification preference record. */
    @PUT("notify")
    suspend fun updateNotify(@Body request: UpdateNotifyRequest): NotifyResponse

    // ── Sync ────────────────────────────────────────────────────────────

    /** Record a sync timestamp in Redis for the given account. */
    @POST("sync")
    suspend fun sync(@Body request: SyncRequest): SyncResponse

    // ── Version ─────────────────────────────────────────────────────────

    /** Retrieve bridge build info and database schema version. */
    @GET("version")
    suspend fun getVersion(): VersionResponse
}

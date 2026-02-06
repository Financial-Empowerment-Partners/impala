package com.payala.impala.demo.auth

import android.app.Activity
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.payala.impala.demo.BuildConfig

/** Result of a Google Sign-In attempt via Credential Manager. */
sealed class GoogleSignInResult {
    /** Authentication succeeded. [idToken] is the OpenID Connect token from Google. */
    data class Success(val idToken: String, val email: String, val displayName: String?) : GoogleSignInResult()
    /** An error occurred during sign-in. */
    data class Error(val message: String) : GoogleSignInResult()
    /** The user dismissed the account picker. */
    data object Cancelled : GoogleSignInResult()
}

/**
 * Wraps the Android Credential Manager API for Google Sign-In.
 *
 * Uses [GetGoogleIdOption] to request an ID token credential. The returned
 * [GoogleSignInResult.Success.idToken] is used by [LoginViewModel] to derive a
 * stable password for the bridge's `/authenticate` endpoint.
 *
 * @param activity the host Activity (needed by Credential Manager for the UI)
 */
class GoogleAuthHelper(private val activity: Activity) {

    private val credentialManager = CredentialManager.create(activity)

    /** Launches the Google account picker and returns the result. */
    suspend fun signIn(): GoogleSignInResult {
        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(false)
            .setServerClientId(BuildConfig.GOOGLE_WEB_CLIENT_ID)
            .build()

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .build()

        return try {
            val result = credentialManager.getCredential(activity, request)
            val credential = result.credential

            if (credential is CustomCredential &&
                credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
            ) {
                val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                GoogleSignInResult.Success(
                    idToken = googleIdTokenCredential.idToken,
                    email = googleIdTokenCredential.id,
                    displayName = googleIdTokenCredential.displayName
                )
            } else {
                GoogleSignInResult.Error("Unexpected credential type")
            }
        } catch (e: GetCredentialCancellationException) {
            GoogleSignInResult.Cancelled
        } catch (e: Exception) {
            GoogleSignInResult.Error(e.message ?: "Google Sign-In failed")
        }
    }
}

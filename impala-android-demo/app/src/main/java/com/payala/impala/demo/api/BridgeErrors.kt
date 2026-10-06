package com.payala.impala.demo.api

import org.json.JSONObject
import retrofit2.HttpException

/**
 * The bridge's error envelope: `{"error": {"code": "...", "message": "..."}}`
 * (impala-bridge `error.rs`). Returns null when the body is absent or not that
 * shape; never throws.
 */
object BridgeErrors {
    data class Body(val code: String?, val message: String?)

    fun parse(e: HttpException): Body? = try {
        val raw = e.response()?.errorBody()?.string()
        if (raw.isNullOrBlank()) null else parse(raw)
    } catch (_: Exception) {
        null
    }

    fun parse(json: String): Body? = try {
        val err = JSONObject(json).optJSONObject("error")
        if (err == null) null else Body(err.optString("code").ifEmpty { null }, err.optString("message").ifEmpty { null })
    } catch (_: Exception) {
        null
    }
}

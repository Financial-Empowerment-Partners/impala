package com.impala.sdk.models

import com.impala.sdk.apdu4j.BIBOException

/**
 * Exception thrown when the response APDU from the card contains unexpected SW
 * or data.
 *
 * @copyright Financial Empowerment Partners
 * @version 1.0
 * @since 01.01.2026
 */
class ImpalaException : BIBOException {
    val code: Int

    /**
     * Creates an exception with SW and message.
     *
     * @param code    the error code
     * @param message a descriptive message of the error
     */
    constructor(code: Int, message: String) : super("$message, $code") {
        this.code = code
    }

    /**
     * Creates an exception with a message.
     *
     * @param message a descriptive message of the error
     */
    constructor(message: String?) : super(message) {
        this.code = 0
    }
    /**
     * Creates an exception based on parent.
     *
     * @param BIBOException
     */
    constructor(message: String = "", e: BIBOException) : super(message, e) {
        this.code = 0
    }
}

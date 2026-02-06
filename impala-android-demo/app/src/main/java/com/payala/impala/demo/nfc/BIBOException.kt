package com.payala.impala.demo.nfc

/**
 * Exception thrown when communication between the host and a secure element fails.
 *
 * Ported from `com.impala.sdk.apdu4j.BIBOException`.
 */
open class BIBOException : RuntimeException {
    constructor(message: String?) : super(message)
    constructor(message: String?, e: Throwable?) : super(message, e)
}

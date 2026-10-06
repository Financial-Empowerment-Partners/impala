package com.impala.sdk.apdu4j


// Not unlike CardException - happens between "here" and "secure element", for whatever reasons
open class BIBOException : RuntimeException {
    constructor(message: String?) : super(message)

    constructor(message: String?, e: Throwable?) : super(message, e)

    companion object {
        const val serialVersionUID: Long = 6710240956038548175L
    }
}

/**
 * The card left the field mid-exchange (Android `TagLostException`, a removed
 * PC/SC card). Transports throw this instead of a plain [BIBOException] so
 * callers can ask for a re-tap rather than report a failure.
 */
class BIBOTagLostException : BIBOException {
    constructor(message: String?) : super(message)

    constructor(message: String?, e: Throwable?) : super(message, e)
}

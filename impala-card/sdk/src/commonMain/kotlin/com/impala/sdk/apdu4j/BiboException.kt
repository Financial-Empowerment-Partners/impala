package com.impala.sdk.apdu4j


// Not unlike CardException - happens between "here" and "secure element", for whatever reasons
open class BIBOException : RuntimeException {
    constructor(message: String?) : super(message)

    constructor(message: String?, e: Throwable?) : super(message, e)

    companion object {
        const val serialVersionUID: Long = 6710240956038548175L
    }
}


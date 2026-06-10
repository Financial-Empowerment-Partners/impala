package com.impala.sdk

import java.security.SecureRandom

private val secureRandom = SecureRandom()

internal actual fun secureRandomBytes(n: Int): ByteArray =
    ByteArray(n).also(secureRandom::nextBytes)

package com.impala.sdk

/**
 * Returns [n] bytes from the platform CSPRNG (java.security.SecureRandom on
 * JVM/Android, SecRandomCopyBytes on iOS).
 *
 * Use this for all protocol nonces, challenges, and seeds —
 * kotlin.random.Random is not cryptographically secure.
 */
internal expect fun secureRandomBytes(n: Int): ByteArray

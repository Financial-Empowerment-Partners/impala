package com.payala.impala.stellar

import com.impala.sdk.stellar.Ed25519Verifier
import java.math.BigInteger
import java.security.MessageDigest

/**
 * RFC 8032 Ed25519 signature *verification* in `java.math.BigInteger`, for
 * API 24+ where the platform has no Ed25519. Inputs are public (keys,
 * challenge hashes, signatures), so variable time is fine.
 *
 * Strict: a signature that is not 64 bytes, `S >= L`, an `R` or `A` encoding
 * that is non-canonical (`y >= p`, or `x = 0` with the sign bit set) or off
 * the curve, and a small-order `A` are all rejected; otherwise the check is
 * the cofactorless `[S]B == R + [k]A` with `k = SHA-512(R ‖ A ‖ M) mod L`.
 * [verify] never throws on any input; it returns false.
 */
object Ed25519 : Ed25519Verifier {
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    internal val L: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
    private val D: BigInteger = BigInteger.valueOf(-121665).mod(P).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val D2: BigInteger = D.shiftLeft(1).mod(P)
    private val SQRT_M1: BigInteger = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)
    private val TWO = BigInteger.valueOf(2)

    /** Extended homogeneous coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z. */
    internal class Point(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    internal val IDENTITY = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    /** The base point: y = 4/5, x even. */
    internal val BASE: Point = run {
        val y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
        val x = recoverX(y, 0)!!
        Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        verifyStrict(publicKey, message, signature)
    } catch (_: RuntimeException) {
        false
    }

    private fun verifyStrict(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        val a = decode(publicKey) ?: return false
        if (isSmallOrder(a)) return false
        val rBytes = signature.copyOfRange(0, 32)
        val r = decode(rBytes) ?: return false
        val s = littleEndian(signature, 32, 64)
        if (s >= L) return false
        val k = MessageDigest.getInstance("SHA-512").run {
            update(rBytes); update(publicKey); update(message)
            littleEndian(digest(), 0, 64).mod(L)
        }
        return equal(multiply(BASE, s), add(r, multiply(a, k)))
    }

    internal fun littleEndian(bytes: ByteArray, from: Int, to: Int): BigInteger {
        val be = ByteArray(to - from)
        for (i in be.indices) be[i] = bytes[to - 1 - i]
        return BigInteger(1, be)
    }

    /** x for [y] with the given sign (low bit), or null when y >= p, x² has no root, or x = 0 with sign 1. */
    private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
        if (y >= P) return null
        val y2 = y.multiply(y).mod(P)
        val x2 = y2.subtract(BigInteger.ONE).multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(P)).mod(P)
        if (x2.signum() == 0) return if (sign == 1) null else BigInteger.ZERO
        var x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null
        if (x.testBit(0) != (sign == 1)) x = P.subtract(x)
        return x
    }

    /** The point of a 32-byte encoding, or null when it is non-canonical or not on the curve. */
    internal fun decode(encoded: ByteArray): Point? {
        if (encoded.size != 32) return null
        val sign = (encoded[31].toInt() ushr 7) and 1
        val yBytes = encoded.copyOf().also { it[31] = (it[31].toInt() and 0x7F).toByte() }
        val y = littleEndian(yBytes, 0, 32)
        val x = recoverX(y, sign) ?: return null
        return Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    internal fun add(p: Point, q: Point): Point {
        val a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P)
        val b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P)
        val c = D2.multiply(p.t).multiply(q.t).mod(P)
        val d = TWO.multiply(p.z).multiply(q.z).mod(P)
        val e = b.subtract(a)
        val f = d.subtract(c)
        val g = d.add(c)
        val h = b.add(a)
        return Point(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
    }

    internal fun multiply(p: Point, scalar: BigInteger): Point {
        var q = IDENTITY
        for (i in scalar.bitLength() - 1 downTo 0) {
            q = add(q, q)
            if (scalar.testBit(i)) q = add(q, p)
        }
        return q
    }

    internal fun equal(p: Point, q: Point): Boolean =
        p.x.multiply(q.z).subtract(q.x.multiply(p.z)).mod(P).signum() == 0 &&
            p.y.multiply(q.z).subtract(q.y.multiply(p.z)).mod(P).signum() == 0

    /** True when [8]P is the identity (P is one of the eight torsion points). */
    internal fun isSmallOrder(p: Point): Boolean = equal(multiply(p, BigInteger.valueOf(8)), IDENTITY)
}

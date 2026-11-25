package com.impala.probe

import java.math.BigInteger
import java.security.MessageDigest

/** One line of the report. [ok] is null for a line that only informs. */
data class Finding(val group: String, val what: String, val ok: Boolean?, val detail: String, val millis: Long)

/** What the card can do for Ed25519, from the findings. */
data class Verdict(
    val sha512: Boolean,
    val aes256: Boolean,
    /** ECDH on Wei25519 answering both coordinates, right (the engine's scalar multiplication). */
    val ecdhXy: Boolean,
    /** ECDH on Wei25519 answering the X coordinate only, right. */
    val ecdhX: Boolean,
    /** Key generation on Wei25519 that agrees with the card's own ECDH. */
    val keygen: Boolean,
    /** Raw RSA with an exponent of 2 or 3 (a modular multiplier for a software curve). */
    val rsaRaw: Boolean,
    /** Milliseconds for one 256-bit multiplication in bytecode, or null. */
    val mulMillis: Double?,
    /** The two-coordinate ECDH on Wei25519 is right only when the cofactor is not declared as 8. */
    val ecdhXyCofactorOne: Boolean = false,
    val keygenCofactorOne: Boolean = false
) {
    val softEngineRuns: Boolean get() = sha512 && aes256 && ecdhXy && keygen

    fun lines(): List<String> = buildList {
        if (softEngineRuns) {
            add("Every primitive of the soft Ed25519 engine is present and right.")
            add("If this card still gets no Stellar key, the cause is in the applet, not in the card.")
            return@buildList
        }
        val missing = buildList {
            if (!sha512) add("SHA-512")
            if (!aes256) add("a 256-bit AES key object")
            if (!ecdhXy) add("ECDH with both coordinates on Wei25519")
            if (!keygen) add("key generation on Wei25519")
        }
        add("Missing for the soft Ed25519 engine: ${missing.joinToString(", ")}.")
        when {
            ecdhXyCofactorOne -> add(
                "The two-coordinate ECDH on Wei25519 is right once the cofactor is not declared as 8" +
                    (if (keygenCofactorOne) ", and key generation agrees with it" else "") +
                    ": the engine needs a different setK, not new arithmetic."
            )
            ecdhXy -> add("The scalar multiplication is there: what is missing can be written in applet code.")
            ecdhX -> add(
                "ECDH on Wei25519 works with the X coordinate only: an engine variant can recover the " +
                    "other coordinate in applet code."
            )
            else -> add(
                "No usable ECDH on Wei25519: the scalar multiplication would have to be software" +
                    (if (rsaRaw) " (raw RSA is available as a modular multiplier)." else ", and raw RSA does not help either.")
            )
        }
        if (!sha512) add("SHA-512 would be applet code as well.")
        mulMillis?.let { add("One 256-bit multiplication in bytecode takes %.1f ms on this card.".format(it)) }
    }
}

/**
 * The host side of [ProbeApplet]: sends the probe commands through [transmit]
 * (a selected probe applet behind it), compares each answer with a value
 * computed here, and reports. Nothing here trusts the card: a primitive counts
 * as present only when its answer is right.
 */
class Probe(private val transmit: (ByteArray) -> ByteArray) {
    private val findings = mutableListOf<Finding>()

    private class Answer(val kind: Int, val code: Int, val stage: Int, val data: ByteArray, val millis: Long, val sw: Int) {
        val ok get() = sw == 0x9000 && kind == 0
        fun failure(stages: List<String> = emptyList()): String {
            if (sw != 0x9000) return "status word %04X".format(sw)
            val where = stages.getOrNull(stage - 1)?.let { " at $it" } ?: if (stage > 0) " at step $stage" else ""
            val what = when (kind) {
                1 -> "CryptoException " + (CRYPTO_REASONS[code] ?: code.toString())
                2 -> "SystemException " + (SYSTEM_REASONS[code] ?: code.toString())
                3 -> "ISOException %04X".format(code)
                4 -> "CardRuntimeException $code"
                else -> "runtime exception " + (RUNTIME[code] ?: "(other)")
            }
            return what + where
        }
    }

    private fun send(ins: Int, p1: Int = 0, p2: Int = 0, data: ByteArray = ByteArray(0)): Answer {
        val cmd = byteArrayOf(0x80.toByte(), ins.toByte(), p1.toByte(), p2.toByte()) +
            (if (data.isEmpty()) byteArrayOf() else byteArrayOf(data.size.toByte()) + data)
        val t0 = System.nanoTime()
        val resp = transmit(cmd)
        val ms = (System.nanoTime() - t0) / 1_000_000
        require(resp.size >= 2) { "short response" }
        val sw = ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)
        if (sw != 0x9000 || resp.size < 6) return Answer(-1, 0, 0, ByteArray(0), ms, if (sw == 0x9000) 0x6F00 else sw)
        return Answer(
            resp[0].toInt(), ((resp[1].toInt() and 0xFF) shl 8) or (resp[2].toInt() and 0xFF), resp[3].toInt(),
            resp.copyOfRange(4, resp.size - 2), ms, sw
        )
    }

    private fun note(group: String, what: String, ok: Boolean?, detail: String, ms: Long): Boolean {
        findings += Finding(group, what, ok, detail, ms)
        return ok == true
    }

    /** Runs every probe and returns the findings in order. */
    fun run(): Pair<List<Finding>, Verdict> {
        findings.clear()
        info()
        val digests = listOf("SHA-1" to 1, "SHA-256" to 4, "SHA-384" to 5, "SHA-512" to 6).associate { (name, alg) ->
            name to digest(name, alg)
        }
        for ((name, alg) in KEY_AGREEMENTS) {
            val a = send(0x52, 1, alg)
            note("key agreement", "$name ($alg)", a.ok, if (a.ok) "present" else a.failure(listOf("getInstance")), a.millis)
        }
        for ((name, type, bits) in KEYS) {
            val a = send(0x53, type, 0, short(bits))
            note("key objects", "$name, $bits bits", a.ok, if (a.ok) "built" else a.failure(listOf("buildKey")), a.millis)
        }
        ecdh("P-256", P256, 3, CURVE_P256, wantXy = false)
        ecdh("P-256", P256, 6, CURVE_P256, wantXy = true)
        ecdhHashed("Wei25519", WEI, CURVE_WEI)
        val x = ecdh("Wei25519", WEI, 3, CURVE_WEI, wantXy = false)
        val xNoK = ecdh("Wei25519, cofactor unset", WEI, 3, CURVE_WEI or NO_COFACTOR, wantXy = false)
        val xy = ecdh("Wei25519", WEI, 6, CURVE_WEI, wantXy = true)
        val xyNoK = ecdh("Wei25519, cofactor unset", WEI, 6, CURVE_WEI or NO_COFACTOR, wantXy = true)
        ecdh("Wei25519, transient key", WEI, 6, CURVE_WEI, wantXy = true, keyType = TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT)
        // The cofactor declared as 1: plain ECDH never multiplies by it, and some cards take nothing else.
        val xyK1 = ecdh("Wei25519, cofactor declared 1", WEI, 6, CURVE_WEI or COFACTOR_ONE, wantXy = true)
        ecdh(
            "Wei25519, cofactor declared 1, transient key", WEI, 6, CURVE_WEI or COFACTOR_ONE, wantXy = true,
            keyType = TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT
        )
        keygen("P-256", P256, CURVE_P256, 3)
        val gen = keygen("Wei25519", WEI, CURVE_WEI, if (xy) 6 else if (x) 3 else 0)
        val genK1 = if (xyK1) keygen("Wei25519, cofactor declared 1", WEI, CURVE_WEI or COFACTOR_ONE, 6) else false
        val aes = aes()
        memory()
        val rsa = listOf(2, 3, 65537).map { rsa(it) }
        val mul = mul()
        val verdict = Verdict(
            sha512 = digests.getValue("SHA-512"), aes256 = aes, ecdhXy = xy, ecdhX = x || xNoK,
            keygen = gen && (xy || x), rsaRaw = rsa[0] || rsa[1], mulMillis = mul,
            ecdhXyCofactorOne = !xy && (xyK1 || xyNoK), keygenCofactorOne = genK1
        )
        return findings.toList() to verdict
    }

    private fun info() {
        val a = send(0x50)
        if (!a.ok || a.data.size < 10) {
            note("card", "platform", false, a.failure(), a.millis)
            return
        }
        val d = a.data
        fun u16(i: Int) = ((d[i].toInt() and 0xFF) shl 8) or (d[i + 1].toInt() and 0xFF)
        // getAvailableMemory answers a short: 32767 means "that much or more".
        fun mem(i: Int) = u16(i).let { if (it >= 32767) ">= 32767" else it.toString() }
        note("card", "JavaCard API version (JCSystem.getVersion)", null, "${d[0].toInt()}.${d[1].toInt()}", a.millis)
        note(
            "card", "free memory, bytes", null,
            "persistent ${mem(2)}, transient-reset ${mem(4)}, transient-deselect ${mem(6)}", a.millis
        )
        note("card", "object deletion", null, if (d[8].toInt() == 1) "supported" else "not supported", a.millis)
        note("card", "protocol", null, "T=${d[9].toInt() and 0x0F}", a.millis)
    }

    private fun digest(name: String, alg: Int): Boolean {
        val msg = "abc".toByteArray()
        val a = send(0x51, alg, 0, msg)
        val want = MessageDigest.getInstance(name).digest(msg)
        val detail = when {
            !a.ok -> a.failure(listOf("getInstance", "doFinal"))
            a.data.contentEquals(want) -> "right"
            else -> "WRONG digest ${hex(a.data)}"
        }
        return note("digest", name, a.ok && a.data.contentEquals(want), detail, a.millis)
    }

    private fun ecdh(label: String, c: Curve, alg: Int, curveByte: Int, wantXy: Boolean, keyType: Int = TYPE_EC_FP_PRIVATE): Boolean {
        val a = send(0x54, alg, curveByte, byteArrayOf(keyType.toByte()) + fixed(SCALAR) + c.encode(c.g))
        val q = c.mul(SCALAR, c.g)!!
        val wantX = fixed(q.first)
        val wantBoth = fixed(q.first) + fixed(q.second)
        val name = if (alg == 6) "ALG_EC_SVDP_DH_PLAIN_XY" else "ALG_EC_SVDP_DH_PLAIN"
        val (ok, detail) = when {
            !a.ok -> false to a.failure(ECDH_STAGES)
            wantXy && (a.data.contentEquals(byteArrayOf(4) + wantBoth) || a.data.contentEquals(wantBoth)) ->
                true to "right, both coordinates (${a.data.size} bytes)"
            !wantXy && a.data.contentEquals(wantX) -> true to "right, X coordinate"
            else -> false to "WRONG result (${a.data.size} bytes): ${hex(a.data)}"
        }
        return note("scalar multiplication", "$label: $name", ok, detail, a.millis)
    }

    /** ALG_EC_SVDP_DH answers SHA-1 of the X coordinate: it shows the curve arithmetic where the plain ones are missing. */
    private fun ecdhHashed(label: String, c: Curve, curveByte: Int) {
        val a = send(0x54, 1, curveByte, byteArrayOf(TYPE_EC_FP_PRIVATE.toByte()) + fixed(SCALAR) + c.encode(c.g))
        val want = MessageDigest.getInstance("SHA-1").digest(fixed(c.mul(SCALAR, c.g)!!.first))
        val (ok, detail) = when {
            !a.ok -> false to a.failure(ECDH_STAGES)
            a.data.contentEquals(want) -> true to "right (SHA-1 of the X coordinate)"
            else -> false to "WRONG result: ${hex(a.data)}"
        }
        note("scalar multiplication", "$label: ALG_EC_SVDP_DH", ok, detail, a.millis)
    }

    private fun keygen(label: String, c: Curve, curveByte: Int, checkAlg: Int): Boolean {
        val a = send(0x55, checkAlg, curveByte)
        if (!a.ok) return note("key generation", label, false, a.failure(KEYGEN_STAGES), a.millis)
        val d = a.data
        if (d.size < 65 || d[0].toInt() != 4) return note("key generation", label, false, "public point: ${hex(d)}", a.millis)
        val w = BigInteger(1, d.copyOfRange(1, 33)) to BigInteger(1, d.copyOfRange(33, 65))
        val problems = buildList {
            if (!c.onCurve(w)) add("the public point is NOT on the curve")
            else if (c.mul(c.r, w) != null) add("the public point is NOT in the base point's subgroup")
            val rest = d.copyOfRange(65, d.size)
            when (checkAlg) {
                6 -> if (!(rest.contentEquals(d.copyOfRange(0, 65)) || rest.contentEquals(d.copyOfRange(1, 65)))) {
                    add("its own ECDH with the base point gives another point")
                }
                3 -> if (!rest.contentEquals(d.copyOfRange(1, 33))) add("its own ECDH with the base point gives another X")
            }
        }
        val checked = if (checkAlg == 0) "public point on the curve" else "public point on the curve, and the card's ECDH agrees"
        return note("key generation", label, problems.isEmpty(), problems.joinToString("; ").ifEmpty { checked }, a.millis)
    }

    private fun aes(): Boolean {
        val key = ByteArray(32) { (it * 7 + 1).toByte() }
        val a = send(0x56, 0, 0, key)
        val ok = a.ok && a.data.contentEquals(key)
        val detail = if (ok) "built, set and read back" else if (a.ok) "read back differs" else a.failure(listOf("buildKey", "setKey", "getKey"))
        return note("key objects", "AES-256 key round trip", ok, detail, a.millis)
    }

    /**
     * The Impala applet's transient memory, allocated the way its constructor does: can this
     * card hold all of it at once? The probe's own arrays ([PROBE_DESELECT] bytes cleared on
     * deselect) are already there and count towards the applet's deselect total.
     */
    private fun memory() {
        fun alloc(kind: Int, size: Int) = byteArrayOf(kind.toByte()) + short(size)
        val base = alloc(1, APPLET_RESET)
        val engine = base + alloc(2, APPLET_DESELECT + ENGINE_WORK - PROBE_DESELECT) + alloc(3, 0)
        val steps = listOf(
            "nothing more" to byteArrayOf(),
            "the applet's reset-transient buffers ($APPLET_RESET)" to base,
            "+ its deselect buffers and the Ed25519 engine ($APPLET_DESELECT + $ENGINE_WORK, a transient key)" to engine,
            "+ the SEP-10 challenge stage ($SEP10_STAGE)" to engine + alloc(2, SEP10_STAGE)
        )
        for ((what, data) in steps) {
            val a = send(0x59, 0, 0, data)
            val detail = if (a.ok && a.data.size == 4) {
                fun u16(i: Int) = ((a.data[i].toInt() and 0xFF) shl 8) or (a.data[i + 1].toInt() and 0xFF)
                "fits; left: transient-reset ${u16(0)}, transient-deselect ${u16(2)}"
            } else {
                a.failure() + " (allocation ${a.stage} of ${data.size / 3})"
            }
            note("transient memory", what, if (data.isEmpty()) null else a.ok, detail, a.millis)
        }
    }

    private fun rsa(exponent: Int): Boolean {
        val n = RSA_MODULUS
        val m = BigInteger(1, ByteArray(64) { (it + 3).toByte() }).mod(n)
        val e = BigInteger.valueOf(exponent.toLong()).toByteArray().dropWhile { it.toInt() == 0 }.toByteArray()
        val a = send(0x57, ALG_RSA_NOPAD, 0, short(512) + byteArrayOf(e.size.toByte()) + e + fixed(n, 64) + fixed(m, 64))
        val want = fixed(m.modPow(BigInteger.valueOf(exponent.toLong()), n), 64)
        val (ok, detail) = when {
            !a.ok -> false to a.failure(listOf("buildKey", "setModulus", "setExponent", "getInstance", "init", "doFinal"))
            a.data.contentEquals(want) -> true to "right"
            else -> false to "WRONG result"
        }
        return note("raw RSA (512 bits)", "exponent $exponent", ok, detail, a.millis)
    }

    private fun mul(): Double? {
        val x = fixed(SCALAR)
        val y = ByteArray(32) { (0xF1 - it * 5).toByte() }
        val want = fixed(BigInteger(1, x) * BigInteger(1, y), 64)
        val one = send(0x58, 1, 0, x + y)
        if (!one.ok || !one.data.contentEquals(want)) {
            note("bytecode speed", "256-bit multiplication", false, if (one.ok) "WRONG product" else one.failure(), one.millis)
            return null
        }
        val many = send(0x58, 1 + MUL_REPEAT, 0, x + y)
        if (!many.ok || !many.data.contentEquals(want)) {
            note("bytecode speed", "256-bit multiplication", false, "failed when repeated", many.millis)
            return null
        }
        val each = (many.millis - one.millis).coerceAtLeast(0).toDouble() / MUL_REPEAT
        note("bytecode speed", "256-bit multiplication", null, "%.1f ms each (%d of them)".format(each, MUL_REPEAT), many.millis)
        return each
    }

    /** A short Weierstrass curve over a prime field, in affine coordinates; null is the point at infinity. */
    class Curve(val p: BigInteger, val a: BigInteger, val b: BigInteger, val g: Pair<BigInteger, BigInteger>, val r: BigInteger) {
        fun onCurve(q: Pair<BigInteger, BigInteger>): Boolean =
            q.first < p && q.second < p && (q.second.pow(2) - (q.first.pow(3) + a * q.first + b)).mod(p).signum() == 0

        fun add(s: Pair<BigInteger, BigInteger>?, t: Pair<BigInteger, BigInteger>?): Pair<BigInteger, BigInteger>? {
            if (s == null) return t
            if (t == null) return s
            val lambda = if (s.first == t.first) {
                if ((s.second + t.second).mod(p).signum() == 0) return null
                (THREE * s.first.pow(2) + a) * (TWO * s.second).modInverse(p)
            } else {
                (t.second - s.second) * (t.first - s.first).mod(p).modInverse(p)
            }
            val x = (lambda.pow(2) - s.first - t.first).mod(p)
            return x to (lambda * (s.first - x) - s.second).mod(p)
        }

        fun mul(k: BigInteger, q: Pair<BigInteger, BigInteger>): Pair<BigInteger, BigInteger>? {
            var acc: Pair<BigInteger, BigInteger>? = null
            for (i in k.bitLength() - 1 downTo 0) {
                acc = add(acc, acc)
                if (k.testBit(i)) acc = add(acc, q)
            }
            return acc
        }

        fun encode(q: Pair<BigInteger, BigInteger>): ByteArray = byteArrayOf(4) + fixed(q.first) + fixed(q.second)
    }

    companion object {
        const val APPLET_AID = "F0494D5050524F424501"
        const val MUL_REPEAT = 20
        // ImpalaApplet's constructor: buffers cleared on reset (its own 443 and the secure channel's 115),
        // buffers cleared on deselect (179), the engine's work area, the SEP-10 stage (32 + 640).
        const val APPLET_RESET = 558
        const val APPLET_DESELECT = 179
        const val ENGINE_WORK = 481
        const val SEP10_STAGE = 672
        /** ProbeApplet's own transient arrays (160 + 140 + 1). */
        const val PROBE_DESELECT = 301

        private const val CURVE_P256 = 0
        private const val CURVE_WEI = 1
        private const val NO_COFACTOR = 0x10
        private const val COFACTOR_ONE = 0x20
        // javacard.security.KeyBuilder and javacardx.crypto.Cipher values (checked against the API by ProbeTest).
        const val TYPE_RSA_PUBLIC = 4
        const val TYPE_EC_FP_PUBLIC = 11
        const val TYPE_EC_FP_PRIVATE = 12
        const val TYPE_AES_TRANSIENT_DESELECT = 14
        const val TYPE_AES = 15
        const val TYPE_EC_FP_PRIVATE_TRANSIENT_RESET = 30
        const val TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT = 31
        const val ALG_RSA_NOPAD = 12

        private val TWO = BigInteger.valueOf(2)
        private val THREE = BigInteger.valueOf(3)
        private fun h(s: String) = BigInteger(s.replace(" ", ""), 16)

        private val KEY_AGREEMENTS = listOf(
            "ALG_EC_SVDP_DH" to 1, "ALG_EC_SVDP_DHC" to 2, "ALG_EC_SVDP_DH_PLAIN" to 3,
            "ALG_EC_SVDP_DHC_PLAIN" to 4, "ALG_EC_PACE_GM" to 5, "ALG_EC_SVDP_DH_PLAIN_XY" to 6
        )
        private val KEYS = listOf(
            Triple("EC private key", TYPE_EC_FP_PRIVATE, 256),
            Triple("EC public key", TYPE_EC_FP_PUBLIC, 256),
            Triple("EC private key, transient (reset)", TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, 256),
            Triple("EC private key, transient (deselect)", TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, 256),
            Triple("AES key", TYPE_AES, 256),
            Triple("AES key, transient (deselect)", TYPE_AES_TRANSIENT_DESELECT, 256),
            Triple("RSA public key", TYPE_RSA_PUBLIC, 512),
            Triple("RSA public key", TYPE_RSA_PUBLIC, 1024),
            Triple("RSA public key", TYPE_RSA_PUBLIC, 2048)
        )
        private val ECDH_STAGES = listOf(
            "buildKey", "setFieldFP", "setA", "setB", "setG", "setR", "setK", "setS", "getInstance", "init", "generateSecret"
        )
        private val CURVE_STAGES = listOf("setFieldFP", "setA", "setB", "setG", "setR", "setK")
        private val KEYGEN_STAGES = listOf("buildKey (public)", "buildKey (private)") +
            CURVE_STAGES.map { "$it (public key)" } + CURVE_STAGES.map { "$it (private key)" } +
            listOf("new KeyPair", "genKeyPair", "getW", "getS", "getInstance", "init", "generateSecret")

        private val CRYPTO_REASONS = mapOf(
            1 to "ILLEGAL_VALUE", 2 to "UNINITIALIZED_KEY", 3 to "NO_SUCH_ALGORITHM", 4 to "INVALID_INIT", 5 to "ILLEGAL_USE"
        )
        private val SYSTEM_REASONS = mapOf(
            1 to "ILLEGAL_VALUE", 2 to "NO_TRANSIENT_SPACE", 3 to "ILLEGAL_TRANSIENT", 4 to "ILLEGAL_AID", 5 to "NO_RESOURCE", 6 to "ILLEGAL_USE"
        )
        private val RUNTIME = mapOf(1 to "NullPointerException", 2 to "IndexOutOfBoundsException", 3 to "SecurityException", 4 to "ArithmeticException")

        /** Wei25519, written out here independently of the applet's tables. */
        val WEI: Curve = run {
            val p = TWO.pow(255) - BigInteger.valueOf(19)
            val bigA = BigInteger.valueOf(486662)
            val a = ((THREE - bigA.pow(2)) * THREE.modInverse(p)).mod(p)
            val b = ((TWO * bigA.pow(3) - BigInteger.valueOf(9) * bigA) * BigInteger.valueOf(27).modInverse(p)).mod(p)
            val gx = (BigInteger.valueOf(9) + bigA * THREE.modInverse(p)).mod(p)
            // The Y that maps to the RFC 8032 base point (the other root is its negative).
            val gy = h("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9")
            Curve(p, a, b, gx to gy, TWO.pow(252) + BigInteger("27742317777372353535851937790883648493"))
        }
        val P256: Curve = Curve(
            h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            h("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            h("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296") to
                h("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            h("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        )

        /** A fixed test scalar below both group orders (the RFC 8032 TEST 1 scalar, reduced). Not a card secret. */
        val SCALAR: BigInteger = h("0FE94D9006F020A5A3C080D96827FFFCE8852346655006E96AE99BE612AC2C7C")

        /**
         * A 512-bit modulus for the raw-RSA probe: the product of two primes drawn from a fixed
         * seed (an engine may refuse a modulus with small factors). Nothing is secret here.
         */
        val RSA_MODULUS: BigInteger = java.util.Random(25519).let { seed ->
            generateSequence { BigInteger.probablePrime(256, seed) * BigInteger.probablePrime(256, seed) }
                .first { it.bitLength() == 512 }
        }

        fun fixed(v: BigInteger, size: Int = 32): ByteArray {
            val raw = v.toByteArray().dropWhile { it.toInt() == 0 }.toByteArray()
            require(raw.size <= size)
            return ByteArray(size - raw.size) + raw
        }

        fun short(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
        fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }
        fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

        fun render(findings: List<Finding>, verdict: Verdict): String = buildString {
            var group = ""
            for (f in findings) {
                if (f.group != group) {
                    group = f.group
                    appendLine()
                    appendLine(group)
                }
                val mark = when (f.ok) { true -> "ok  "; false -> "NO  "; null -> "    " }
                appendLine("  $mark %-44s %s  [%d ms]".format(f.what, f.detail, f.millis))
            }
            appendLine()
            appendLine("verdict")
            verdict.lines().forEach { appendLine("  $it") }
        }
    }
}

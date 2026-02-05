package com.impala.sdk.scp03

/**
 * AES-CMAC implementation per NIST SP 800-38B.
 * Uses a pure-Kotlin AES-128 implementation for cross-platform (JVM, iOS, Android) compatibility.
 */
object AESCMAC {

    private const val BLOCK_SIZE = 16
    private const val CONST_RB: Int = 0x87

    /**
     * Computes the full 16-byte AES-CMAC.
     *
     * @param key  16-byte AES key
     * @param data input data
     * @return 16-byte MAC
     */
    fun sign(key: ByteArray, data: ByteArray): ByteArray {
        require(key.size == BLOCK_SIZE) { "Key must be 16 bytes" }

        // Generate subkeys
        val (k1, k2) = generateSubkeys(key)

        val n = if (data.isEmpty()) 1 else (data.size + BLOCK_SIZE - 1) / BLOCK_SIZE
        val lastBlockComplete = data.isNotEmpty() && (data.size % BLOCK_SIZE == 0)

        // Process all blocks except the last
        var state = ByteArray(BLOCK_SIZE)
        for (i in 0 until n - 1) {
            val block = data.copyOfRange(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
            state = AES128.encryptBlock(key, xorBlocks(state, block))
        }

        // Process last block
        val lastBlock: ByteArray
        if (lastBlockComplete) {
            val block = data.copyOfRange((n - 1) * BLOCK_SIZE, n * BLOCK_SIZE)
            lastBlock = xorBlocks(block, k1)
        } else {
            val remaining = if (data.isEmpty()) ByteArray(0) else data.copyOfRange((n - 1) * BLOCK_SIZE, data.size)
            val padded = padISO9797(remaining)
            lastBlock = xorBlocks(padded, k2)
        }

        return AES128.encryptBlock(key, xorBlocks(state, lastBlock))
    }

    private fun generateSubkeys(key: ByteArray): Pair<ByteArray, ByteArray> {
        val l = AES128.encryptBlock(key, ByteArray(BLOCK_SIZE))

        val k1 = shiftLeft(l)
        if (l[0].toInt() and 0x80 != 0) {
            k1[BLOCK_SIZE - 1] = (k1[BLOCK_SIZE - 1].toInt() xor CONST_RB).toByte()
        }

        val k2 = shiftLeft(k1)
        if (k1[0].toInt() and 0x80 != 0) {
            k2[BLOCK_SIZE - 1] = (k2[BLOCK_SIZE - 1].toInt() xor CONST_RB).toByte()
        }

        return Pair(k1, k2)
    }

    private fun shiftLeft(block: ByteArray): ByteArray {
        val result = ByteArray(BLOCK_SIZE)
        var carry = 0
        for (i in BLOCK_SIZE - 1 downTo 0) {
            val b = block[i].toInt() and 0xFF
            result[i] = ((b shl 1) or carry).toByte()
            carry = (b shr 7) and 1
        }
        return result
    }

    private fun padISO9797(data: ByteArray): ByteArray {
        val padded = ByteArray(BLOCK_SIZE)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        // Rest is already zero
        return padded
    }

    internal fun xorBlocks(a: ByteArray, b: ByteArray): ByteArray {
        val result = ByteArray(a.size)
        for (i in result.indices) {
            result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return result
    }
}

/**
 * Minimal AES-128 ECB implementation (single-block encrypt only).
 * Pure Kotlin — no platform dependencies.
 */
internal object AES128 {

    private val SBOX = intArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )

    private val INV_SBOX = intArrayOf(
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

    private val RCON = intArrayOf(
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    )

    /**
     * Encrypts a single 16-byte block with AES-128 ECB.
     */
    fun encryptBlock(key: ByteArray, block: ByteArray): ByteArray {
        require(key.size == 16) { "Key must be 16 bytes" }
        require(block.size == 16) { "Block must be 16 bytes" }

        val roundKeys = expandKey(key)
        val state = block.copyOf()

        addRoundKey(state, roundKeys, 0)

        for (round in 1..9) {
            subBytes(state)
            shiftRows(state)
            mixColumns(state)
            addRoundKey(state, roundKeys, round)
        }

        subBytes(state)
        shiftRows(state)
        addRoundKey(state, roundKeys, 10)

        return state
    }

    /**
     * Decrypts a single 16-byte block with AES-128 ECB.
     */
    fun decryptBlock(key: ByteArray, block: ByteArray): ByteArray {
        require(key.size == 16) { "Key must be 16 bytes" }
        require(block.size == 16) { "Block must be 16 bytes" }

        val roundKeys = expandKey(key)
        val state = block.copyOf()

        addRoundKey(state, roundKeys, 10)

        for (round in 9 downTo 1) {
            invShiftRows(state)
            invSubBytes(state)
            addRoundKey(state, roundKeys, round)
            invMixColumns(state)
        }

        invShiftRows(state)
        invSubBytes(state)
        addRoundKey(state, roundKeys, 0)

        return state
    }

    /**
     * Encrypts data using AES-128-CBC with the given IV.
     */
    fun encryptCBC(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        require(data.size % 16 == 0) { "Data must be a multiple of 16 bytes" }
        val result = ByteArray(data.size)
        var prev = iv.copyOf()
        for (i in data.indices step 16) {
            val block = ByteArray(16)
            for (j in 0 until 16) {
                block[j] = (data[i + j].toInt() xor prev[j].toInt()).toByte()
            }
            val encrypted = encryptBlock(key, block)
            encrypted.copyInto(result, i)
            prev = encrypted
        }
        return result
    }

    /**
     * Decrypts data using AES-128-CBC with the given IV.
     */
    fun decryptCBC(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        require(data.size % 16 == 0) { "Data must be a multiple of 16 bytes" }
        val result = ByteArray(data.size)
        var prev = iv.copyOf()
        for (i in data.indices step 16) {
            val block = data.copyOfRange(i, i + 16)
            val decrypted = decryptBlock(key, block)
            for (j in 0 until 16) {
                result[i + j] = (decrypted[j].toInt() xor prev[j].toInt()).toByte()
            }
            prev = block
        }
        return result
    }

    private fun expandKey(key: ByteArray): Array<ByteArray> {
        val nk = 4  // Number of 32-bit words in key (AES-128)
        val nr = 10 // Number of rounds
        val w = Array(4 * (nr + 1)) { ByteArray(4) }

        for (i in 0 until nk) {
            w[i][0] = key[4 * i]
            w[i][1] = key[4 * i + 1]
            w[i][2] = key[4 * i + 2]
            w[i][3] = key[4 * i + 3]
        }

        for (i in nk until 4 * (nr + 1)) {
            val temp = w[i - 1].copyOf()
            if (i % nk == 0) {
                // RotWord
                val t = temp[0]
                temp[0] = temp[1]
                temp[1] = temp[2]
                temp[2] = temp[3]
                temp[3] = t
                // SubWord
                for (j in 0 until 4) {
                    temp[j] = SBOX[temp[j].toInt() and 0xFF].toByte()
                }
                temp[0] = (temp[0].toInt() xor RCON[i / nk - 1]).toByte()
            }
            for (j in 0 until 4) {
                w[i][j] = (w[i - nk][j].toInt() xor temp[j].toInt()).toByte()
            }
        }

        return w
    }

    private fun addRoundKey(state: ByteArray, roundKeys: Array<ByteArray>, round: Int) {
        for (c in 0 until 4) {
            for (r in 0 until 4) {
                state[r + 4 * c] = (state[r + 4 * c].toInt() xor roundKeys[4 * round + c][r].toInt()).toByte()
            }
        }
    }

    private fun subBytes(state: ByteArray) {
        for (i in state.indices) {
            state[i] = SBOX[state[i].toInt() and 0xFF].toByte()
        }
    }

    private fun invSubBytes(state: ByteArray) {
        for (i in state.indices) {
            state[i] = INV_SBOX[state[i].toInt() and 0xFF].toByte()
        }
    }

    private fun shiftRows(state: ByteArray) {
        // Row 1: shift left by 1
        var t = state[1]
        state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t
        // Row 2: shift left by 2
        t = state[2]; state[2] = state[10]; state[10] = t
        t = state[6]; state[6] = state[14]; state[14] = t
        // Row 3: shift left by 3 (= right by 1)
        t = state[15]
        state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t
    }

    private fun invShiftRows(state: ByteArray) {
        // Row 1: shift right by 1
        var t = state[13]
        state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t
        // Row 2: shift right by 2
        t = state[2]; state[2] = state[10]; state[10] = t
        t = state[6]; state[6] = state[14]; state[14] = t
        // Row 3: shift right by 3 (= left by 1)
        t = state[3]
        state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t
    }

    private fun mixColumns(state: ByteArray) {
        for (c in 0 until 4) {
            val i = c * 4
            val s0 = state[i].toInt() and 0xFF
            val s1 = state[i + 1].toInt() and 0xFF
            val s2 = state[i + 2].toInt() and 0xFF
            val s3 = state[i + 3].toInt() and 0xFF

            state[i] = (gmul(2, s0) xor gmul(3, s1) xor s2 xor s3).toByte()
            state[i + 1] = (s0 xor gmul(2, s1) xor gmul(3, s2) xor s3).toByte()
            state[i + 2] = (s0 xor s1 xor gmul(2, s2) xor gmul(3, s3)).toByte()
            state[i + 3] = (gmul(3, s0) xor s1 xor s2 xor gmul(2, s3)).toByte()
        }
    }

    private fun invMixColumns(state: ByteArray) {
        for (c in 0 until 4) {
            val i = c * 4
            val s0 = state[i].toInt() and 0xFF
            val s1 = state[i + 1].toInt() and 0xFF
            val s2 = state[i + 2].toInt() and 0xFF
            val s3 = state[i + 3].toInt() and 0xFF

            state[i] = (gmul(14, s0) xor gmul(11, s1) xor gmul(13, s2) xor gmul(9, s3)).toByte()
            state[i + 1] = (gmul(9, s0) xor gmul(14, s1) xor gmul(11, s2) xor gmul(13, s3)).toByte()
            state[i + 2] = (gmul(13, s0) xor gmul(9, s1) xor gmul(14, s2) xor gmul(11, s3)).toByte()
            state[i + 3] = (gmul(11, s0) xor gmul(13, s1) xor gmul(9, s2) xor gmul(14, s3)).toByte()
        }
    }

    private fun gmul(a: Int, b: Int): Int {
        var p = 0
        var aa = a
        var bb = b
        for (i in 0 until 8) {
            if (bb and 1 != 0) p = p xor aa
            val hiBit = aa and 0x80
            aa = (aa shl 1) and 0xFF
            if (hiBit != 0) aa = aa xor 0x1B
            bb = bb shr 1
        }
        return p
    }
}

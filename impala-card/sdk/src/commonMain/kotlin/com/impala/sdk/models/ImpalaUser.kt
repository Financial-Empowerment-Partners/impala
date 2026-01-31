package com.impala.sdk.models

import com.benasher44.uuid.Uuid
import com.impala.sdk.Constants
import okio.Buffer
import okio.internal.commonToUtf8String

class ImpalaUser(cardData: ImpalaCardUser) {
    val accountId: String = cardData.accountId
    var cardId: String = cardData.cardId
    var fullName: String = cardData.fullName
    var gender: String = "unspecified"
    var role: String = "unspecified"

    constructor(data: ByteArray) : this(ImpalaCardUser(data))
}

class ImpalaCardUser(data: ByteArray){
    val accountId: String
    val cardId: String
    val fullName: String
    init {
        val uuidLen: Int = Constants.UUID_LENGTH.toInt()
        val uuidLen2: Int = Constants.UUID_LENGTH.toInt() * 2
        accountId = data.sliceArray(IntRange(0, uuidLen - 1)).toUuid().toString()
        cardId = data.sliceArray(IntRange(uuidLen, uuidLen2 - 1)).toUuid().toString()
        fullName = data.commonToUtf8String(uuidLen2, data.size)
    }
}

fun ByteArray.toUuid(): Uuid {
    // UUID is stored in big-endian format (2 sets of 8 bytes)
    val byteBuffer = Buffer()
    byteBuffer.write(this)
    val mostSigBits = byteBuffer.readLong() // longs are 8 bytes
    val leastSigBits = byteBuffer.readLong()
    return Uuid(mostSigBits, leastSigBits)
}


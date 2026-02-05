package com.impala.sdk.scp03

/**
 * SCP03 protocol constants per GlobalPlatform 2.3 Amendment D.
 */
object SCP03Constants {
    // GlobalPlatform CLA bytes
    const val CLA_GP: Byte = 0x80.toByte()
    const val CLA_GP_SECURED: Byte = 0x84.toByte()

    // GP instruction codes
    const val INS_INITIALIZE_UPDATE: Byte = 0x50
    const val INS_EXTERNAL_AUTHENTICATE: Byte = 0x82.toByte()

    // Applet-specific SCP03 instructions
    const val INS_PROVISION_PIN: Byte = 0x70
    const val INS_APPLET_UPDATE: Byte = 0x71

    // Derivation constants (GP 2.3 Amd D, Table 4-1)
    const val S_ENC: Byte = 0x04
    const val S_MAC: Byte = 0x06
    const val S_RMAC: Byte = 0x07
    const val CARD_CRYPTO: Byte = 0x00
    const val HOST_CRYPTO: Byte = 0x01

    // Security level flags
    const val C_MAC: Byte = 0x01
    const val C_DEC: Byte = 0x02
    const val R_MAC: Byte = 0x10
    const val R_ENC: Byte = 0x20

    // Sizes
    const val CHALLENGE_LENGTH: Int = 8
    const val CRYPTOGRAM_LENGTH: Int = 8
    const val BLOCK_SIZE: Int = 16
    const val KEY_LENGTH: Int = 16
    const val DERIVATION_DATA_LENGTH: Int = 32
}

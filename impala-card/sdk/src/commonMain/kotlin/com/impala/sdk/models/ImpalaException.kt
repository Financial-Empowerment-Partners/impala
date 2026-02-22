package com.impala.sdk.models

import com.impala.sdk.apdu4j.BIBOException

/**
 * Exception thrown when the response APDU from the card contains unexpected SW
 * or data.
 *
 * @copyright Financial Empowerment Partners
 * @version 1.0
 * @since 01.01.2026
 */
open class ImpalaException : BIBOException {
    val code: Int

    /**
     * Creates an exception with SW and message.
     *
     * @param code    the error code
     * @param message a descriptive message of the error
     */
    constructor(code: Int, message: String) : super("$message, $code") {
        this.code = code
    }

    /**
     * Creates an exception with a message.
     *
     * @param message a descriptive message of the error
     */
    constructor(message: String?) : super(message) {
        this.code = 0
    }
    /**
     * Creates an exception based on parent.
     *
     * @param BIBOException
     */
    constructor(message: String = "", e: BIBOException) : super(message, e) {
        this.code = 0
    }

    companion object {
        /**
         * Maps a 2-byte status word to the appropriate ImpalaException subclass.
         *
         * @param sw the status word from the card response (e.g. 0x9000, 0x69C3)
         * @return an ImpalaException subclass matching the error condition
         */
        fun fromStatusWord(sw: Int): ImpalaException {
            // PIN failure range 0x69C0-0x69C9: low nibble = tries remaining
            if (sw in 0x69C0..0x69C9) {
                val tries = sw and 0x0F
                return ImpalaPinException("PIN verification failed, $tries tries remaining", tries)
            }

            return when (sw) {
                // Card terminated
                0x6687 -> ImpalaCardTerminatedException("Card has been terminated (0x6687)")

                // Security / access control
                0x6982 -> ImpalaSecurityException("Security status not satisfied (0x6982)")
                0x6985 -> ImpalaSecurityException("Conditions not satisfied (0x6985)")
                0x6690 -> ImpalaSecurityException("PIN required (0x6690)")
                0x6691 -> ImpalaSecurityException("PIN rejected (0x6691)")

                // Wrong length
                0x6700 -> ImpalaWrongLengthException("Wrong length (0x6700)")

                // INS not supported
                0x6D00 -> ImpalaInstructionNotSupportedException("Instruction not supported (0x6D00)")

                // Insufficient funds
                0x6224 -> ImpalaInsufficientFundsException("Insufficient funds (0x6224)")

                // Crypto errors
                0x6683 -> ImpalaCryptoException("Crypto exception (0x6683)")
                0x6684 -> ImpalaCryptoException("Invalid AES key (0x6684)")
                0x0022 -> ImpalaCryptoException("Key verification failed (0x0022)")
                0x0023 -> ImpalaCryptoException("Signature verification failed (0x0023)")
                0x6227 -> ImpalaCryptoException("Error initializing signer (0x6227)")
                0x6230 -> ImpalaCryptoException("EC card key missing (0x6230)")

                // Transfer errors
                0x6231 -> ImpalaTransferException("Wrong sender (0x6231)")
                0x6232 -> ImpalaTransferException("Wrong recipient (0x6232)")
                0x6226 -> ImpalaTransferException("Error parsing recipient (0x6226)")
                0x6229 -> ImpalaTransferException("Wrong currency (0x6229)")

                // Card data errors
                0x6677 -> ImpalaCardDataException("Card data signature invalid (0x6677)")
                0x6678 -> ImpalaCardDataException("Card data nonce invalid (0x6678)")
                0x6679 -> ImpalaCardDataException("Wrong card ID (0x6679)")
                0x6688 -> ImpalaCardDataException("Null pointer exception on card (0x6688)")
                0x6689 -> ImpalaCardDataException("Array index out of bounds on card (0x6689)")

                // Set failures
                0x6C01 -> ImpalaCardDataException("Set account ID failed (0x6C01)")
                0x6C02 -> ImpalaCardDataException("Set balance failed (0x6C02)")

                // Already initialized / key already set
                0x6685 -> ImpalaSecurityException("Public key already set (0x6685)")
                0x6686 -> ImpalaSecurityException("PRNG already seeded (0x6686)")

                // Incorrect parameters
                0x6A86 -> ImpalaException("Incorrect P1/P2 (0x6A86)")

                // SCP03 auth failed
                0x6300 -> ImpalaSecurityException("SCP03 authentication failed (0x6300)")

                // Tag lost
                0x0000 -> ImpalaTagLostException("Tag lost (0x0000)")

                // Status broken
                0x0001 -> ImpalaCardDataException("Card status broken (0x0001)")

                // Unknown codes
                0x6F00 -> ImpalaException("Unknown error (0x6F00)")
                0x4469 -> ImpalaException("Unknown error (0x4469)")
                0x6F15 -> ImpalaException("Unknown error (0x6F15)")

                else -> {
                    val hex = "0x" + sw.toString(16).uppercase().padStart(4, '0')
                    ImpalaException("Unknown status word: $hex")
                }
            }
        }
    }
}

/**
 * PIN verification failed. [triesRemaining] indicates how many attempts are left
 * before the PIN is blocked.
 */
class ImpalaPinException(message: String, val triesRemaining: Int) : ImpalaException(message)

/** Security or access control violation on the card. */
class ImpalaSecurityException(message: String) : ImpalaException(message)

/** The card balance is insufficient for the requested operation. */
class ImpalaInsufficientFundsException(message: String) : ImpalaException(message)

/** The card has been permanently terminated and is no longer usable. */
class ImpalaCardTerminatedException(message: String) : ImpalaException(message)

/** The APDU data length did not match what the card expected. */
class ImpalaWrongLengthException(message: String) : ImpalaException(message)

/** The instruction byte (INS) is not recognized by the card applet. */
class ImpalaInstructionNotSupportedException(message: String) : ImpalaException(message)

/** A cryptographic operation on the card failed. */
class ImpalaCryptoException(message: String) : ImpalaException(message)

/** A transfer operation failed due to invalid sender, recipient, or currency. */
class ImpalaTransferException(message: String) : ImpalaException(message)

/** Card data is corrupt or could not be read/written correctly. */
class ImpalaCardDataException(message: String) : ImpalaException(message)

/** Communication with the card was lost (NFC tag removed). */
class ImpalaTagLostException(message: String) : ImpalaException(message)

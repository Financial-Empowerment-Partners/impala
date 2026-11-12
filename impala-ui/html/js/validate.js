/**
 * Input validation module providing reusable validators for form fields.
 *
 * Each validator returns {valid: boolean, message: string}.
 * Use firstError() to check an array of validations and get the first failure.
 *
 * @module Validate
 */
var Validate = (function () {
    /**
     * Validate a Stellar account ID (starts with 'G', 56 alphanumeric chars).
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function stellarId(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Stellar ID is required' };
        }
        value = value.trim();
        if (value.charAt(0) !== 'G') {
            return { valid: false, message: 'Stellar ID must start with G' };
        }
        if (value.length !== 56) {
            return { valid: false, message: 'Stellar ID must be 56 characters' };
        }
        if (!/^[A-Za-z0-9]+$/.test(value)) {
            return { valid: false, message: 'Stellar ID must be alphanumeric' };
        }
        return { valid: true, message: '' };
    }

    /** RFC 4648 base32 alphabet, the one StrKey uses (upper case only). */
    var BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** StrKey version byte of an ed25519 account id (6 << 3): encodes as 'G'. */
    var STRKEY_VERSION_ACCOUNT_ID = 0x30;

    /**
     * Decode an unpadded base32 string into bytes. Returns null when a
     * character is outside the alphabet or leftover bits are not zero.
     * @param {string} str
     * @returns {number[]|null}
     */
    function base32Decode(str) {
        var bytes = [];
        var buffer = 0;
        var bits = 0;
        for (var i = 0; i < str.length; i++) {
            var idx = BASE32_ALPHABET.indexOf(str.charAt(i));
            if (idx === -1) return null;
            buffer = ((buffer << 5) | idx) & 0xffff;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                bytes.push((buffer >> bits) & 0xff);
            }
        }
        if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null;
        return bytes;
    }

    /**
     * CRC16-XModem (poly 0x1021, init 0x0000, no reflection, no final xor)
     * over bytes[0..len).
     * @param {number[]} bytes
     * @param {number} len
     * @returns {number}
     */
    function crc16Xmodem(bytes, len) {
        var crc = 0;
        for (var i = 0; i < len; i++) {
            crc ^= bytes[i] << 8;
            for (var k = 0; k < 8; k++) {
                crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
            }
        }
        return crc;
    }

    /**
     * Validate a Stellar account id with the full StrKey check (SEP-23):
     * 56 characters of the upper-case base32 alphabet, decoding to
     * version byte 0x30 (account id) ‖ 32-byte ed25519 key ‖ CRC16-XModem of
     * the first 33 bytes, little-endian. Unlike `stellarId` (a shape check),
     * this rejects a single mistyped character.
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function stellarAccountId(value) {
        if (!value || typeof value !== 'string' || value.trim() === '') {
            return { valid: false, message: 'Stellar address is required' };
        }
        value = value.trim();
        if (value.length !== 56) {
            return { valid: false, message: 'Stellar address must be 56 characters' };
        }
        if (!/^[A-Z2-7]+$/.test(value)) {
            return {
                valid: false,
                message: 'Stellar address may contain only upper-case letters A-Z and digits 2-7'
            };
        }
        var bytes = base32Decode(value);
        if (!bytes || bytes.length !== 35) {
            return { valid: false, message: 'Stellar address is not valid base32' };
        }
        if (bytes[0] !== STRKEY_VERSION_ACCOUNT_ID) {
            return {
                valid: false,
                message: 'Not a Stellar account address (G...): wrong version byte'
            };
        }
        var expected = crc16Xmodem(bytes, 33);
        var stored = bytes[33] | (bytes[34] << 8);
        if (expected !== stored) {
            return {
                valid: false,
                message: 'Stellar address checksum does not match (mistyped or truncated?)'
            };
        }
        return { valid: true, message: '' };
    }

    /**
     * Validate an E.164 phone number (starts with +, 8-15 digits).
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function phone(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Phone number is required' };
        }
        value = value.trim();
        // E.164 allows up to 15 digits total after the '+'; the old {7,14}
        // upper bound rejected valid 15-digit numbers.
        if (!/^\+[0-9]{7,15}$/.test(value)) {
            return { valid: false, message: 'Phone must be E.164 format (e.g. +1234567890)' };
        }
        return { valid: true, message: '' };
    }

    /**
     * Validate a basic email address.
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function email(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Email is required' };
        }
        value = value.trim();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
            return { valid: false, message: 'Invalid email address' };
        }
        return { valid: true, message: '' };
    }

    /**
     * Validate a hex string (even number of hex chars).
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function hexString(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'Hex string is required' };
        }
        value = value.trim();
        if (!/^[0-9a-fA-F]+$/.test(value)) {
            return { valid: false, message: 'Must contain only hex characters (0-9, a-f)' };
        }
        if (value.length % 2 !== 0) {
            return { valid: false, message: 'Hex string must have an even number of characters' };
        }
        return { valid: true, message: '' };
    }

    /**
     * Validate that a value is non-empty after trimming.
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function required(value) {
        if (value === null || value === undefined || String(value).trim() === '') {
            return { valid: false, message: 'This field is required' };
        }
        return { valid: true, message: '' };
    }

    /**
     * Validate that a value is a positive number (> 0).
     * @param {string|number} value
     * @returns {{valid: boolean, message: string}}
     */
    function positiveNumber(value) {
        var num = Number(value);
        if (isNaN(num) || num <= 0) {
            return { valid: false, message: 'Must be a positive number' };
        }
        return { valid: true, message: '' };
    }

    /**
     * Validate a TOTP code (exactly 6 digits).
     * @param {string} value
     * @returns {{valid: boolean, message: string}}
     */
    function totpCode(value) {
        if (!value || typeof value !== 'string') {
            return { valid: false, message: 'TOTP code is required' };
        }
        value = value.trim();
        if (!/^[0-9]{6}$/.test(value)) {
            return { valid: false, message: 'TOTP code must be exactly 6 digits' };
        }
        return { valid: true, message: '' };
    }

    /**
     * Check an array of validations and return the first error message, or null.
     * @param {Array<{valid: boolean, message: string}>} validations
     * @returns {string|null} First error message, or null if all valid.
     */
    function firstError(validations) {
        for (var i = 0; i < validations.length; i++) {
            if (!validations[i].valid) {
                return validations[i].message;
            }
        }
        return null;
    }

    return {
        stellarId: stellarId,
        stellarAccountId: stellarAccountId,
        crc16Xmodem: crc16Xmodem,
        phone: phone,
        email: email,
        hexString: hexString,
        required: required,
        positiveNumber: positiveNumber,
        totpCode: totpCode,
        firstError: firstError
    };
})();

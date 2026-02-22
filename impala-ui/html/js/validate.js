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
        if (!/^\+[0-9]{7,14}$/.test(value)) {
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
        phone: phone,
        email: email,
        hexString: hexString,
        required: required,
        positiveNumber: positiveNumber,
        totpCode: totpCode,
        firstError: firstError
    };
})();

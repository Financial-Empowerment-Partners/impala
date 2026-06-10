/**
 * Shared HTML-escaping utility.
 *
 * String-replace based (no DOM dependency) so it is safe to interpolate
 * untrusted values into innerHTML markup in both element content and
 * double-quoted attribute positions, and testable under node:vm.
 *
 * @module EscapeHtml
 */
var EscapeHtml = (function () {
    /**
     * Escape the five HTML metacharacters in a value.
     * @param {*} value - The value to escape; non-strings are stringified.
     * @returns {string} HTML-safe string ('' for null/undefined).
     */
    function escape(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    return {
        escape: escape
    };
})();

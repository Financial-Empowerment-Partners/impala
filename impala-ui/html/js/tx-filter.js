/**
 * Pure transaction-filter query builder (no DOM / globals at load time).
 *
 * Translates a filter object from the transactions page into the query string
 * accepted by `GET /transactions`. Empty / undefined values are omitted so the
 * server applies its defaults. Kept side-effect-free for unit testing via
 * tests/helpers/load-script.js.
 *
 * @module TxFilter
 */
var TxFilter = (function () {
    /**
     * Build a `GET /transactions` query string from a filter object.
     * Recognised keys: page, per_page, status, flagged (bool/'true'/'false'),
     * source_account, from, to, q. Whitespace is trimmed from text fields.
     * @param {Object} [filters]
     * @returns {string} URL query string without a leading '?'.
     */
    function buildQuery(filters) {
        filters = filters || {};
        var parts = [];

        function add(key, value) {
            if (value === undefined || value === null) return;
            var str = String(value).trim();
            if (str === '') return;
            parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(str));
        }

        add('page', filters.page);
        add('per_page', filters.per_page);
        add('status', filters.status);

        if (filters.flagged === true || filters.flagged === 'true') {
            add('flagged', 'true');
        } else if (filters.flagged === false || filters.flagged === 'false') {
            add('flagged', 'false');
        }

        add('source_account', filters.source_account);
        add('from', filters.from);
        add('to', filters.to);
        add('q', filters.q);

        return parts.join('&');
    }

    return {
        buildQuery: buildQuery
    };
})();

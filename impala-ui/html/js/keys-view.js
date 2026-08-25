/**
 * DOM-free logic for the bridge-keys console.
 *
 * Everything here is pure so the confirmation rules — the part that decides
 * whether an operator is about to replace a live money-moving credential — can
 * be unit-tested without a browser. `keys.js` does the rendering and nothing
 * else.
 *
 * One rule shapes the whole module: **this file never reconstructs a value the
 * server will compare against.** The confirmation phrase and the current
 * fingerprint both arrive in the payload; a client that built them itself
 * could drift from the bridge and hand operators a phrase that is always
 * rejected. Where a value is missing, the UI must refuse rather than guess.
 *
 * @module KeysView
 */
var KeysView = (function () {
    'use strict';

    /**
     * Badge describing where a running credential came from.
     * @param {Object} view - A KeyView from GET /admin/keys.
     * @returns {{label: string, cls: string, title: string}}
     */
    function sourceBadge(view) {
        if (!view) return { label: 'unknown', cls: 'neutral', title: '' };
        if (view.resolution_error) {
            return {
                label: 'failed',
                cls: 'error',
                title: 'A stored credential could not be used at startup, so this ' +
                    'provider is disabled for this instance: ' + view.resolution_error
            };
        }
        if (!view.active) {
            return {
                label: 'not configured',
                cls: 'neutral',
                title: 'No credential is in effect; this provider is disabled.'
            };
        }
        if (view.effective_source === 'db') {
            return {
                label: 'imported',
                cls: 'ok',
                title: 'Running a credential imported through this console.'
            };
        }
        if (view.effective_source === 'env') {
            return {
                label: 'environment',
                cls: 'info',
                title: 'Running a credential supplied by the deployment configuration.'
            };
        }
        return { label: view.effective_source || 'unknown', cls: 'neutral', title: '' };
    }

    /**
     * The one-line status an operator most needs: is what is stored actually
     * running? With restart-activated credentials this is the normal state
     * after an import, so it must read as informative rather than broken.
     * @param {Object} view
     * @returns {{text: string, cls: string}|null}
     */
    function pendingNotice(view) {
        if (!view || !view.pending_restart) return null;
        if (view.stored_fingerprint && !view.effective_fingerprint) {
            return {
                text: 'Stored but not running — this instance has no credential in effect. ' +
                    'Roll the deployment to activate it.',
                cls: 'pending'
            };
        }
        if (!view.stored_fingerprint && view.effective_fingerprint) {
            return {
                text: 'Running an environment credential; nothing is stored for this kind.',
                cls: 'info'
            };
        }
        return {
            text: 'Stored version ' + (view.stored_version || '?') +
                ' differs from the one running here. Roll the deployment to activate it.',
            cls: 'pending'
        };
    }

    /**
     * Shorten a fingerprint for display without ever showing a truncated value
     * where an exact one is required.
     * @param {string} fp
     * @returns {string}
     */
    function shortFingerprint(fp) {
        if (!fp) return '—';
        return fp.length > 12 ? fp.slice(0, 12) + '…' : fp;
    }

    /**
     * Whether this import would REPLACE something rather than add it.
     *
     * Keys off `replace_target_fingerprint`, which the bridge computes as "the
     * credential this would supersede": the stored one if there is one,
     * otherwise whatever the instance is running. Looking only at what is
     * RUNNING would call an import an addition whenever a stored credential
     * exists but has not been activated yet — and the server would then reject
     * it, with advice the operator cannot act on.
     * @param {Object} view
     * @returns {boolean}
     */
    function isReplacement(view) {
        return !!(view && view.replace_target_fingerprint);
    }

    /**
     * Build and validate the POST body for an import.
     *
     * @param {Object} view - The KeyView being acted on.
     * @param {Object} input - { parts: {name: value}, note, confirmTyped,
     *                           strandInFlight, skipVerify }
     * @returns {{ok: boolean, error?: string, body?: Object}}
     */
    function buildImport(view, input) {
        input = input || {};
        var parts = {};
        var names = Object.keys(input.parts || {});
        for (var i = 0; i < names.length; i++) {
            var value = (input.parts[names[i]] || '').trim();
            if (value) parts[names[i]] = value;
        }

        var required = (view && view.required_parts) || [];
        for (var r = 0; r < required.length; r++) {
            if (!parts[required[r]]) {
                return { ok: false, error: 'Missing required part: ' + required[r] };
            }
        }
        if (Object.keys(parts).length === 0) {
            return { ok: false, error: 'Provide at least one part' };
        }

        var body = {
            parts: parts,
            strand_in_flight: !!input.strandInFlight,
            skip_verify: !!input.skipVerify
        };
        if (input.note) body.note = input.note;

        if (!isReplacement(view)) {
            // Adding. No confirmation is required, and deliberately none is
            // sent: `replace: true` on an add would be a lie in the audit log.
            return { ok: true, body: body };
        }

        // Replacing. The server checks all of this again; the point of
        // checking here is to fail before the secret leaves the browser.
        if (!view.confirm_phrase) {
            return {
                ok: false,
                error: 'The bridge did not supply a confirmation phrase for this ' +
                    'credential; refresh before replacing it.'
            };
        }
        if ((input.confirmTyped || '') !== view.confirm_phrase) {
            return {
                ok: false,
                error: 'Type exactly: ' + view.confirm_phrase
            };
        }
        body.replace = true;
        body.expected_fingerprint = view.replace_target_fingerprint;
        body.confirm_phrase = view.confirm_phrase;
        return { ok: true, body: body };
    }

    /**
     * Build and validate the POST body for a revoke.
     * @param {Object} view
     * @param {Object} input - { confirmTyped, acknowledgedNextSource }
     * @returns {{ok: boolean, error?: string, body?: Object}}
     */
    function buildRevoke(view, input) {
        input = input || {};
        if (!view || !view.stored_fingerprint) {
            return { ok: false, error: 'There is no stored credential to revoke' };
        }
        if (!view.confirm_phrase || (input.confirmTyped || '') !== view.confirm_phrase) {
            return { ok: false, error: 'Type exactly: ' + (view.confirm_phrase || '—') };
        }
        if (!input.acknowledgedNextSource) {
            return {
                ok: false,
                error: 'Acknowledge what this provider falls back to after the next restart'
            };
        }
        if (view.in_flight_count && !input.strandInFlight) {
            return {
                ok: false,
                error: 'Orders are still running against this provider; acknowledge that ' +
                    'nothing will be able to reconcile them'
            };
        }
        return {
            ok: true,
            body: {
                expected_fingerprint: view.stored_fingerprint,
                confirm_phrase: view.confirm_phrase,
                confirm_next_source: true,
                strand_in_flight: !!input.strandInFlight
            }
        };
    }

    /**
     * Plain-language description of what a revoke leaves behind. Revocation
     * silently handing the provider back to an older environment credential is
     * the surprise worth spelling out before it happens.
     * @param {Object} view
     * @returns {string}
     */
    function revokeFallback(view) {
        var vars = (view && view.env_vars_set) || [];
        if (vars.length === 0) {
            return 'After the next restart this provider will be UNCONFIGURED and its ' +
                'endpoints will stop working.';
        }
        return 'After the next restart this provider falls back to the environment ' +
            'credential (' + vars.join(', ') + ') — a DIFFERENT key will take over.';
    }

    /**
     * Build and validate the POST body for a merge (rotating part of a set).
     *
     * A merge is always a replacement, and carries the same acknowledgements
     * as one: omitting them means the server rejects every merge whenever any
     * order is in flight, with no way to say so from the UI.
     * @param {Object} view
     * @param {Object} input - { setParts, dropPart, confirmTyped,
     *                           strandInFlight, skipVerify }
     * @returns {{ok: boolean, error?: string, body?: Object}}
     */
    function buildMerge(view, input) {
        input = input || {};
        var setParts = {};
        var names = Object.keys(input.setParts || {});
        for (var i = 0; i < names.length; i++) {
            var value = (input.setParts[names[i]] || '').trim();
            if (value) setParts[names[i]] = value;
        }
        var drop = input.dropPart ? [input.dropPart] : [];
        if (Object.keys(setParts).length === 0 && drop.length === 0) {
            return { ok: false, error: 'Change at least one part' };
        }
        if (!view.confirm_phrase || (input.confirmTyped || '') !== view.confirm_phrase) {
            return { ok: false, error: 'Type exactly: ' + (view.confirm_phrase || '—') };
        }
        return {
            ok: true,
            body: {
                set_parts: setParts,
                drop_parts: drop,
                expected_fingerprint: view.replace_target_fingerprint,
                confirm_phrase: view.confirm_phrase,
                strand_in_flight: !!input.strandInFlight,
                skip_verify: !!input.skipVerify
            }
        };
    }

    /**
     * Warning shown before replacing a credential with orders still running.
     * @param {Object} view
     * @returns {string|null}
     */
    function inFlightWarning(view) {
        if (!view || !view.in_flight_count) return null;
        return view.in_flight_count + ' order(s)/cycle(s) are still running against this ' +
            'provider. If the new credential belongs to a different provider account, ' +
            'their references become unreachable and anything already sent is stranded.';
    }

    return {
        sourceBadge: sourceBadge,
        pendingNotice: pendingNotice,
        shortFingerprint: shortFingerprint,
        isReplacement: isReplacement,
        buildImport: buildImport,
        buildMerge: buildMerge,
        buildRevoke: buildRevoke,
        revokeFallback: revokeFallback,
        inFlightWarning: inFlightWarning
    };
})();

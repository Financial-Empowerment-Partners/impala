/**
 * DOM-free logic for the MFA panels on the MFA page: the operator's own
 * session assurance and TOTP step-up, and the admin per-account MFA summary,
 * mandate toggle and device-key recovery.
 *
 * `mfa.js` renders; every decision lives here so it is unit-tested. Contract:
 * docs/mfa-card-pin-biometrics.md §5. Two rules, as elsewhere in this UI:
 *
 *  - **Tolerate deploy skew.** A missing or unexpected field renders as a
 *    neutral "not reported"; an unknown `amr` token shows its raw name on a
 *    neutral badge. Gating here is display convenience; the bridge enforces
 *    the mandate and every capability itself.
 *  - **Never interpolate into an attribute context.** The caller escapes text
 *    nodes through `EscapeHtml.escape`; this module returns data, not HTML.
 *
 * @module MfaAdminView
 */
var MfaAdminView = (function () {
    'use strict';

    /** Badge classes this module may emit (CSS-class whitelist). */
    var BADGE_CLASSES = ['ok', 'error', 'pending', 'info', 'neutral', 'warning'];

    /** The `amr` tokens this build knows, with display labels. `mfa` is the
     *  derived multi-factor marker and is not shown as a factor chip. */
    var AMR_LABELS = {
        pwd: 'Password',
        fed: 'Federated',
        sc: 'Card',
        pin: 'Card PIN',
        otp: 'TOTP',
        dev: 'Device key',
        bio: 'Biometric'
    };

    function isObject(v) {
        return v !== null && typeof v === 'object' && !Array.isArray(v);
    }

    function str(v) {
        return typeof v === 'string' && v !== '' ? v : null;
    }

    function tri(v) {
        return v === true ? true : (v === false ? false : null);
    }

    function nonNegativeInt(v) {
        return typeof v === 'number' && isFinite(v) && v >= 0 && Math.floor(v) === v ? v : null;
    }

    function badge(label, cls) {
        return { label: label, cls: BADGE_CLASSES.indexOf(cls) !== -1 ? cls : 'neutral' };
    }

    /**
     * Normalise `GET /mfa/status` (the caller's own session). Never throws.
     * @param {*} payload
     * @returns {Object}
     */
    function normalizeStatus(payload) {
        var p = isObject(payload) ? payload : {};
        var amr = Array.isArray(p.amr)
            ? p.amr.filter(function (m) { return typeof m === 'string'; })
            : [];
        return {
            amr: amr,
            authTime: nonNegativeInt(p.auth_time),
            mfa: tri(p.mfa),
            required: tri(p.required),
            requiredByRole: tri(p.required_by_role),
            satisfied: tri(p.satisfied),
            maxAgeSecs: nonNegativeInt(p.max_age_secs)
        };
    }

    /**
     * The factor chips for a session's `amr`: a label + whitelisted badge
     * class per known token, the raw name on a neutral badge for an unknown
     * one. The derived `mfa` marker is dropped (it is summarised separately).
     * @param {string[]} amr
     * @returns {Array<{label: string, cls: string}>}
     */
    function factorChips(amr) {
        var list = Array.isArray(amr) ? amr : [];
        var chips = [];
        list.forEach(function (m) {
            if (m === 'mfa') return;
            if (Object.prototype.hasOwnProperty.call(AMR_LABELS, m)) {
                chips.push(badge(AMR_LABELS[m], m === 'bio' ? 'info' : 'ok'));
            } else {
                chips.push(badge(m, 'neutral'));
            }
        });
        return chips;
    }

    /**
     * One-line summary of a session's MFA standing and whether a step-up is
     * needed to use the API.
     * @param {Object} status - Normalised status.
     * @returns {{badge: Object, text: string, needsStepUp: boolean}}
     */
    function sessionSummary(status) {
        if (!status.required) {
            return {
                badge: status.mfa === true ? badge('multi-factor', 'ok') : badge('single-factor', 'neutral'),
                text: 'This account is not required to be multi-factor.',
                needsStepUp: false
            };
        }
        if (status.satisfied === true) {
            return {
                badge: badge('multi-factor', 'ok'),
                text: 'Multi-factor requirement satisfied' +
                    (status.requiredByRole === true ? ' (required for this role).' : '.'),
                needsStepUp: false
            };
        }
        return {
            badge: badge('step-up required', 'warning'),
            text: 'This account must complete multi-factor authentication before it can ' +
                'use the API. Add a factor below.' +
                (status.requiredByRole === true ? ' (Required for this role.)' : ''),
            needsStepUp: true
        };
    }

    /**
     * Normalise `GET /admin/accounts/{id}/mfa`.
     * @param {*} payload
     * @returns {Object}
     */
    function normalizeAccountMfa(payload) {
        var p = isObject(payload) ? payload : {};
        var keys = Array.isArray(p.device_keys) ? p.device_keys.map(normalizeDeviceKey) : [];
        return {
            accountId: str(p.account_id),
            mfaRequired: tri(p.mfa_required),
            totpEnrolled: tri(p.totp_enrolled),
            cards: nonNegativeInt(p.cards),
            deviceKeys: keys,
            deviceKeysMalformed: !Array.isArray(p.device_keys)
        };
    }

    function normalizeDeviceKey(raw) {
        raw = isObject(raw) ? raw : {};
        return {
            keyId: str(raw.key_id),
            label: str(raw.label),
            platform: str(raw.platform),
            userVerification: str(raw.user_verification) || 'none',
            createdAtUnix: nonNegativeInt(raw.created_at_unix)
        };
    }

    /**
     * The factor summary for the admin view: which factor kinds the account
     * has enrolled, as chips, plus whether it can actually be multi-factor.
     * @param {Object} acct - Normalised account MFA.
     * @returns {{chips: Array, factorKinds: number, canBeMfa: boolean}}
     */
    function accountFactorSummary(acct) {
        var chips = [];
        var kinds = 0;
        if (acct.totpEnrolled === true) { chips.push(badge('TOTP', 'ok')); kinds++; }
        if (acct.cards !== null && acct.cards > 0) {
            chips.push(badge(acct.cards + (acct.cards === 1 ? ' card' : ' cards'), 'ok'));
            kinds++;
        }
        if (acct.deviceKeys.length > 0) {
            chips.push(badge(acct.deviceKeys.length +
                (acct.deviceKeys.length === 1 ? ' device key' : ' device keys'), 'ok'));
            kinds++;
        }
        if (chips.length === 0) chips.push(badge('no factors enrolled', 'neutral'));
        return { chips: chips, factorKinds: kinds, canBeMfa: kinds >= 2 };
    }

    /** @returns {{mfa_type: string, code: string}} step-up body for a TOTP code. */
    function totpStepUpBody(code) {
        return { mfa_type: 'totp', code: typeof code === 'string' ? code.trim() : '' };
    }

    /** @returns {{required: boolean}} policy body. */
    function policyBody(required) {
        return { required: required === true };
    }

    /**
     * The token pair a step-up answered with. For a bearer session the bridge
     * issues a new token family and revokes the one that asked, so the caller
     * must store these before its next request, or that request is refused. A
     * cookie session is upgraded in place and the answer carries no tokens.
     * @param {Object} res - POST /mfa/step-up response
     * @returns {{temporal: string, refresh: (string|null)}|null} null: nothing to store
     */
    function stepUpTokens(res) {
        var r = res || {};
        if (typeof r.temporal_token !== 'string' || r.temporal_token === '') return null;
        return {
            temporal: r.temporal_token,
            refresh: (typeof r.refresh_token === 'string' && r.refresh_token !== '') ? r.refresh_token : null
        };
    }

    /**
     * What to say when a step-up was not accepted. The bridge answers a
     * refused code with a generic 401 (never why), and a code is good once.
     * @param {Error} err - rejection of POST /mfa/step-up
     * @returns {string}
     */
    function stepUpErrorMessage(err) {
        var status = err && err.status;
        if (status === 401) {
            return 'That code was not accepted. A code works once: use the next one your authenticator shows.';
        }
        if (status === 429) return 'Too many attempts. Wait a few minutes before trying again.';
        return actionErrorMessage(err);
    }

    /**
     * The confirmation an admin sees before the mandate changes. Either way
     * the account is signed out everywhere (its auth epoch moves), so both
     * directions ask; requiring MFA of an account that cannot yet be
     * multi-factor says what that means.
     * @param {boolean} want - true: require MFA; false: lift the requirement
     * @param {boolean} canBeMfa - the account has two factor kinds enrolled
     * @returns {{title: string, message: string}}
     */
    function mandateConfirm(want, canBeMfa) {
        if (want !== true) {
            return {
                title: 'Lift the MFA requirement?',
                message: 'The account will be able to work with a single factor again. It is signed out ' +
                    'everywhere and signs in again.'
            };
        }
        return {
            title: 'Require MFA?',
            message: 'The account is signed out everywhere, and every session it opens is refused until ' +
                'it has two factors.' + (canBeMfa === true ? '' :
                ' This account has fewer than two factor kinds enrolled, and cannot enrol one while the ' +
                'requirement is on: it stays locked out until you lift the requirement again.')
        };
    }

    /**
     * How a failed status / admin load should render. 403 is a role problem;
     * 404 (admin route) is an account that does not exist.
     * @param {Error} err
     * @returns {{kind: string, message: string}} kind: forbidden | notfound | error
     */
    function classifyLoadError(err) {
        var status = err && err.status;
        if (status === 403) return { kind: 'forbidden', message: 'Your role cannot read this.' };
        if (status === 404) return { kind: 'notfound', message: 'No such account.' };
        return { kind: 'error', message: (err && err.message) || 'Could not load MFA status.' };
    }

    /**
     * Operator-facing message for a failed step-up or policy change.
     * @param {Error} err
     * @returns {string}
     */
    function actionErrorMessage(err) {
        var code = err && err.code;
        if (code === 'mfa_required' || code === 'mfa_reauth_required') {
            return 'This change needs a fresh multi-factor session. Step up first.';
        }
        if (err && err.status === 401) return 'The code was not accepted. Try again.';
        return (err && err.message) || 'Request failed.';
    }

    /** True when an error is the bridge asking the caller to step up first. */
    function isMfaRequired(err) {
        return !!err && (err.code === 'mfa_required' ||
            (err.status === 403 && typeof err.message === 'string' &&
                err.message.indexOf('mfa_required') !== -1));
    }

    return {
        AMR_LABELS: AMR_LABELS,
        normalizeStatus: normalizeStatus,
        factorChips: factorChips,
        sessionSummary: sessionSummary,
        normalizeAccountMfa: normalizeAccountMfa,
        normalizeDeviceKey: normalizeDeviceKey,
        accountFactorSummary: accountFactorSummary,
        totpStepUpBody: totpStepUpBody,
        stepUpTokens: stepUpTokens,
        stepUpErrorMessage: stepUpErrorMessage,
        mandateConfirm: mandateConfirm,
        policyBody: policyBody,
        classifyLoadError: classifyLoadError,
        actionErrorMessage: actionErrorMessage,
        isMfaRequired: isMfaRequired
    };
})();

/**
 * DOM-free logic for the SEP-10 signing-key panel on the Keys page.
 *
 * `sep10.js` renders; every decision lives here so it is unit-tested:
 * normalising `GET /admin/sep10/signing-keys`, the status summary and badges,
 * which actions each key offers, the exact confirmation phrases, checking what
 * the operator typed, and the request bodies.
 *
 * Contract: docs/sep10-card-keys.md section 6.1. Two rules shape the module:
 *
 *  - **Tolerate deploy skew, fail closed on actions.** A missing or
 *    unexpected field renders as "not reported"; an unknown key state renders
 *    as its raw name on a neutral badge and offers no action. A value the
 *    request depends on (the version, the network word of the phrase, the
 *    fingerprint being superseded) that is missing or ambiguous disables the
 *    action instead of being guessed.
 *  - **`opened` is one instance's answer.** Each key row says whether the
 *    bridge instance that answered holds the key open in its key ring
 *    (`true` / `false`, `null` when it runs none or an older bridge does not
 *    say). Activation is held while a pending key reads `false`: the bridge
 *    would refuse it (409 `sep10_key_not_opened`), and a key no instance can
 *    open must never be scheduled, because the key it supersedes cannot come
 *    back.
 *  - **Phrases are built from the payload's `network` only.** Unlike the
 *    provider-credential console (KeysView), this contract does not ship the
 *    phrase in the payload; it fixes the template (`activate sep10-signing
 *    {network}`, `revoke sep10-signing {network} v{version}`) and states
 *    that `network` is "the same word the confirm phrases use". The UI never
 *    substitutes its own network selection.
 *
 * @module Sep10View
 */
var Sep10View = (function () {
    'use strict';

    var BASE_PATH = '/admin/sep10/signing-keys';
    /** Why a freshly generated key cannot be activated yet. */
    var NOT_OPENED_YET = 'This bridge instance has not opened it yet: its key ring reads new ' +
        'keys every 30 seconds, so reload shortly. If it stays this way, the bridge cannot ' +
        'unseal the key (check its seed protector).';
    var KNOWN_STATES = ['pending', 'active', 'superseded', 'revoked'];
    /** Badge classes this module may emit (CSS-class whitelist). */
    var BADGE_CLASSES = ['ok', 'error', 'pending', 'info', 'neutral', 'warning'];
    /** The phrase's network word: a plain lowercase token, nothing else. */
    var NETWORK_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

    function isObject(v) {
        return v !== null && typeof v === 'object' && !Array.isArray(v);
    }

    function str(v) {
        return typeof v === 'string' && v !== '' ? v : null;
    }

    function nonNegativeInt(v) {
        return typeof v === 'number' && isFinite(v) && v >= 0 && Math.floor(v) === v ? v : null;
    }

    function positiveVersion(v) {
        return typeof v === 'number' && isFinite(v) && v > 0 && Math.floor(v) === v &&
            v <= 9007199254740991 ? v : null;
    }

    /** true / false as reported, anything else (absent, older bridge) null. */
    function tri(v) {
        return v === true ? true : (v === false ? false : null);
    }

    function badge(label, cls) {
        return { label: label, cls: BADGE_CLASSES.indexOf(cls) !== -1 ? cls : 'neutral' };
    }

    /**
     * One key row, normalised. `state` is the raw string the bridge sent
     * (for display); `knownState` is set only for the four states this build
     * understands.
     * @param {*} raw
     * @returns {Object}
     */
    function normalizeKey(raw) {
        raw = isObject(raw) ? raw : {};
        var state = typeof raw.state === 'string' ? raw.state : null;
        return {
            version: positiveVersion(raw.version),
            state: state,
            knownState: state !== null && KNOWN_STATES.indexOf(state) !== -1 ? state : null,
            publicAddress: str(raw.public_address),
            fingerprint: str(raw.fingerprint),
            generatedBy: str(raw.generated_by),
            generatedAt: str(raw.generated_at),
            activateAt: str(raw.activate_at),
            supersededAt: str(raw.superseded_at),
            revokedAt: str(raw.revoked_at),
            opened: tri(raw.opened)
        };
    }

    /**
     * Normalise the status payload. Never throws; anything unreadable
     * becomes null (scalars) or an empty list (keys, with `keysMalformed`).
     * @param {*} payload - Body of GET /admin/sep10/signing-keys.
     * @returns {Object}
     */
    function normalizeStatus(payload) {
        var p = isObject(payload) ? payload : {};
        var network = str(p.network);
        var keys = Array.isArray(p.keys) ? p.keys.map(normalizeKey) : [];
        return {
            enabled: tri(p.enabled),
            keyRingLive: tri(p.key_ring_live),
            homeDomain: str(p.home_domain),
            webAuthEndpoint: str(p.web_auth_endpoint),
            network: network,
            networkValid: network !== null && NETWORK_RE.test(network),
            networkPassphrase: str(p.network_passphrase),
            challengeTtlSecs: nonNegativeInt(p.challenge_ttl_secs),
            registeredCardKeys: nonNegativeInt(p.registered_card_keys),
            keys: keys,
            keysMalformed: !Array.isArray(p.keys)
        };
    }

    function keysIn(status, state) {
        return ((status && status.keys) || []).filter(function (k) {
            return k.knownState === state;
        });
    }

    function parseTime(value) {
        if (!value) return NaN;
        return Date.parse(value);
    }

    /**
     * Lifecycle phase of a key. A pending row with `activate_at` set has been
     * activated and is waiting out the activation delay ('scheduled'); once
     * that instant has passed the bridge instances switch to it by the
     * database clock, even before the row itself reads 'active' ('due').
     * @param {Object} key - A normalised key.
     * @param {number} [nowMs] - Current time in ms (Date.now() if omitted).
     * @returns {string} pending | scheduled | due | active | superseded | revoked | unknown
     */
    function phase(key, nowMs) {
        if (!key || !key.knownState) return 'unknown';
        if (key.knownState !== 'pending') return key.knownState;
        if (!key.activateAt) return 'pending';
        var at = parseTime(key.activateAt);
        var now = typeof nowMs === 'number' ? nowMs : Date.now();
        return !isNaN(at) && at <= now ? 'due' : 'scheduled';
    }

    /**
     * Badge for a key row: label + whitelisted CSS class. An unknown state
     * shows its raw name on a neutral badge.
     * @param {Object} key
     * @param {number} [nowMs]
     * @returns {{label: string, cls: string}}
     */
    function keyBadge(key, nowMs) {
        switch (phase(key, nowMs)) {
        case 'pending': return badge('pending', 'pending');
        case 'scheduled': return badge('activation scheduled', 'info');
        case 'due': return badge('activating', 'info');
        case 'active': return badge('active', 'ok');
        case 'superseded': return badge('superseded', 'neutral');
        case 'revoked': return badge('revoked', 'error');
        default: return badge((key && key.state) || 'unknown', 'neutral');
        }
    }

    /**
     * One-sentence explanation of what a key's phase means for sign-in.
     * The swap at `activate_at` is applied by the bridge's key rings, which
     * run only while SEP-10 is enabled: on a bridge with SEP-10 off (the
     * documented first roll-out activates the key before enabling), a
     * scheduled key takes over when SEP-10 is turned on, not at that time.
     * @param {Object} key
     * @param {number} [nowMs]
     * @param {boolean|null} [enabled] - The status payload's `enabled`.
     * @returns {string}
     */
    function keyExplanation(key, nowMs, enabled) {
        var ph = phase(key, nowMs);
        if (enabled === false && (ph === 'scheduled' || ph === 'due')) {
            return 'Activated (for ' + key.activateAt + '). SEP-10 is off on this bridge, ' +
                'so nothing signs with it yet; it goes into service when SEP-10 is ' +
                'enabled, and the list shows it active after the first poll.';
        }
        switch (ph) {
        case 'pending':
            return 'Generated, not in service. It signs nothing until it is activated.' +
                (key.opened === false ? ' ' + NOT_OPENED_YET : '');
        case 'scheduled':
            return 'Activated; it takes over at ' + key.activateAt +
                ', after the activation delay, on every bridge instance together.';
        case 'due':
            return 'Its activation time (' + key.activateAt + ') has passed; bridge ' +
                'instances sign with it now, and the list shows it active after the next poll.';
        case 'active':
            return 'Signs the SEP-10 challenges and is published in stellar.toml.';
        case 'superseded':
            return 'Replaced by a newer key. Challenges it signed are still accepted for ' +
                'a short overlap after it was superseded.';
        case 'revoked':
            return 'Revoked. Never accepted again.';
        default:
            return 'This dashboard does not know the state "' + ((key && key.state) || '') +
                '". It is shown as reported and offers no action; update the dashboard.';
        }
    }

    /**
     * Summary for the panel header and the notices an operator needs.
     * @param {Object} status - Normalised status.
     * @param {number} [nowMs]
     * @returns {{enabledBadge: Object, activeKey: Object|null, pendingKey: Object|null,
     *            activeCount: number, pendingCount: number,
     *            notices: Array<{cls: string, text: string}>}}
     */
    function summary(status, nowMs) {
        var active = keysIn(status, 'active');
        var pending = keysIn(status, 'pending');
        var notices = [];

        var enabledBadge;
        if (status.enabled === true) enabledBadge = badge('enabled', 'ok');
        else if (status.enabled === false) enabledBadge = badge('disabled', 'neutral');
        else enabledBadge = badge('not reported', 'neutral');

        var due = pending.filter(function (k) { return phase(k, nowMs) === 'due'; });

        if (status.keysMalformed) {
            notices.push({
                cls: 'alert',
                text: 'The bridge returned no readable key list, so no key action is offered.'
            });
        }
        if (active.length > 1) {
            notices.push({
                cls: 'alert',
                text: 'The bridge reported ' + active.length + ' active keys. There should ' +
                    'never be more than one; activation is disabled until this is resolved.'
            });
        }
        if (status.enabled === true && status.keyRingLive === false) {
            notices.push({
                cls: 'alert',
                text: 'The key ring of the bridge instance that answered is stale (it has ' +
                    'not read the key table for five minutes), so that instance answers 503 ' +
                    'for SEP-10. Check its database connection.'
            });
        }
        if (status.enabled === true && active.length === 1 && active[0].opened === false) {
            notices.push({
                cls: 'alert',
                text: 'The bridge instance that answered could not open the active key (v' +
                    (active[0].version === null ? '?' : active[0].version) + '), so it ' +
                    'answers 503 for SEP-10. Check its seed protector; the bridge log lines ' +
                    'start with "sep10 ring:".'
            });
        }
        if (status.enabled === true && active.length === 0 && due.length === 0) {
            notices.push({
                cls: 'alert',
                text: 'SEP-10 is enabled but no signing key is active, so SEP-10 sign-in ' +
                    'answers 503 until a key is activated.'
            });
        }
        if (status.enabled === false) {
            notices.push({
                cls: 'primary',
                text: 'SEP-10 is off on this bridge. Turning it on is a bridge setting ' +
                    '(SEP10_ENABLED=true), not something this page does. Generate and ' +
                    'activate a key first, so sign-in works the moment it is enabled.'
            });
        }
        if (status.enabled === null) {
            notices.push({
                cls: 'warning',
                text: 'The bridge did not report whether SEP-10 is enabled.'
            });
        }
        if (status.enabled === true && (!status.homeDomain || !status.webAuthEndpoint)) {
            notices.push({
                cls: 'warning',
                text: 'The web-auth endpoint is not configured (home domain or endpoint ' +
                    'unset), so clients cannot discover SEP-10 from stellar.toml.'
            });
        }
        if (!status.networkValid) {
            notices.push({
                cls: 'warning',
                text: 'The bridge did not report a usable network name. The confirmation ' +
                    'phrases name the network, so activate and revoke are unavailable.'
            });
        }

        return {
            enabledBadge: enabledBadge,
            activeKey: active.length === 1 ? active[0] : null,
            pendingKey: pending.length === 1 ? pending[0] : null,
            activeCount: active.length,
            pendingCount: pending.length,
            notices: notices
        };
    }

    /**
     * What the bridge instance that answered can do with the keys right now,
     * in words (the panel's "This instance" line). `key_ring_live` and each
     * key's `opened` describe that one instance, not the deployment.
     * @param {Object} status - Normalised status.
     * @param {Object} sum - Its summary().
     * @returns {string}
     */
    function instanceLine(status, sum) {
        if (status.keyRingLive === null) {
            return status.enabled === false
                ? 'runs no key ring (SEP-10 is off): keys are stored, not served'
                : 'did not report its key ring';
        }
        if (status.keyRingLive === false) return 'key ring stale: answers 503 for SEP-10';
        if (!sum || !sum.activeKey) return 'key ring live; no active key to serve';
        if (sum.activeKey.opened === false) {
            return 'key ring live, but the active key is not open here: answers 503';
        }
        return 'key ring live; the active key is open: serving SEP-10';
    }

    /**
     * The `confirm_supersede` value activation must carry: the fingerprint
     * of the key in service, or "none" when there is none. Ambiguous (two
     * active rows, or an active row without a fingerprint) is refused.
     * @param {Object} status
     * @returns {{ok: boolean, value?: string, key?: Object|null, error?: string}}
     */
    function supersedeTarget(status) {
        if (!status || status.keysMalformed) {
            return { ok: false, error: 'The key list could not be read; refresh first.' };
        }
        var active = keysIn(status, 'active');
        if (active.length === 0) return { ok: true, value: 'none', key: null };
        if (active.length > 1) {
            return { ok: false, error: 'More than one key is reported active; refusing to guess which one this supersedes.' };
        }
        if (!active[0].fingerprint) {
            return { ok: false, error: 'The active key has no fingerprint in the payload; refresh before activating.' };
        }
        return { ok: true, value: active[0].fingerprint, key: active[0] };
    }

    /** @returns {string|null} "activate sep10-signing {network}" */
    function activatePhrase(status) {
        if (!status || !status.networkValid) return null;
        return 'activate sep10-signing ' + status.network;
    }

    /** @returns {string|null} "revoke sep10-signing {network} v{version}" */
    function revokePhrase(status, key) {
        if (!status || !status.networkValid || !key || key.version === null) return null;
        return 'revoke sep10-signing ' + status.network + ' v' + key.version;
    }

    /**
     * Which actions a key row offers. Display gating only: the bridge
     * enforces ManageKeys and the state rules itself.
     * @param {Object} key
     * @param {Object} status
     * @param {{canManage: boolean}} perms
     * @param {number} [nowMs]
     * @returns {{activate: boolean, revoke: boolean}}
     */
    function actionsFor(key, status, perms, nowMs) {
        var none = { activate: false, revoke: false };
        if (!perms || !perms.canManage) return none;
        if (!key || key.version === null || !status || !status.networkValid) return none;
        if (status.keysMalformed) return none;
        var ph = phase(key, nowMs);
        if (ph === 'pending') {
            return { activate: supersedeTarget(status).ok && !activationHold(key).held, revoke: true };
        }
        if (ph === 'scheduled' || ph === 'due' || ph === 'active' || ph === 'superseded') {
            return { activate: false, revoke: true };
        }
        return none;
    }

    /**
     * Whether activating a pending key must wait, and why. Held only on an
     * explicit `opened: false`; an instance without a key ring (`null`)
     * cannot tell, and the bridge does not refuse there either.
     * @param {Object} key
     * @returns {{held: boolean, reason: string}}
     */
    function activationHold(key) {
        if (key && key.knownState === 'pending' && !key.activateAt && key.opened === false) {
            return { held: true, reason: NOT_OPENED_YET };
        }
        return { held: false, reason: '' };
    }

    /**
     * Whether Generate is offered, and why not when it is not.
     * @param {Object} status
     * @param {{canManage: boolean}} perms
     * @returns {{allowed: boolean, reason: string}}
     */
    function canGenerate(status, perms) {
        if (!perms || !perms.canManage) {
            return { allowed: false, reason: 'Generating needs the admin or key-custodian role.' };
        }
        var pending = keysIn(status, 'pending');
        if (pending.length > 0) {
            return {
                allowed: false,
                reason: 'A pending key (v' + (pending[0].version === null ? '?' : pending[0].version) +
                    ') already exists. Activate or revoke it before generating another.'
            };
        }
        return { allowed: true, reason: '' };
    }

    function typedMatches(typed, phrase) {
        return typeof typed === 'string' && phrase !== null && typed.trim() === phrase;
    }

    /** @returns {{path: string, body: Object}} */
    function buildGenerate() {
        return { path: BASE_PATH + '/generate', body: {} };
    }

    /**
     * Validate an activation and build its request.
     * @param {Object} status
     * @param {Object} key - The pending key to activate.
     * @param {string} typed - What the operator typed.
     * @returns {{ok: boolean, error?: string, path?: string, body?: Object}}
     */
    function buildActivate(status, key, typed) {
        if (!key || key.version === null) return { ok: false, error: 'This key has no usable version number.' };
        if (phase(key) !== 'pending') return { ok: false, error: 'Only a pending key that has not been activated can be activated.' };
        var hold = activationHold(key);
        if (hold.held) return { ok: false, error: hold.reason };
        var phrase = activatePhrase(status);
        if (phrase === null) return { ok: false, error: 'The bridge did not report its network; refresh first.' };
        var target = supersedeTarget(status);
        if (!target.ok) return { ok: false, error: target.error };
        if (!typedMatches(typed, phrase)) return { ok: false, error: 'Type exactly: ' + phrase };
        return {
            ok: true,
            path: BASE_PATH + '/' + key.version + '/activate',
            body: { confirm_supersede: target.value, confirm_phrase: phrase }
        };
    }

    /**
     * Validate a revocation and build its request.
     * @param {Object} status
     * @param {Object} key
     * @param {string} typed
     * @returns {{ok: boolean, error?: string, path?: string, body?: Object}}
     */
    function buildRevoke(status, key, typed) {
        if (!key || key.version === null) return { ok: false, error: 'This key has no usable version number.' };
        if (!key.knownState || key.knownState === 'revoked') {
            return { ok: false, error: 'This key cannot be revoked from here.' };
        }
        var phrase = revokePhrase(status, key);
        if (phrase === null) return { ok: false, error: 'The bridge did not report its network; refresh first.' };
        if (!typedMatches(typed, phrase)) return { ok: false, error: 'Type exactly: ' + phrase };
        return {
            ok: true,
            path: BASE_PATH + '/' + key.version + '/revoke',
            body: { confirm_phrase: phrase }
        };
    }

    /**
     * What revoking this key does, in the operator's terms.
     * @param {Object} key
     * @param {number} [nowMs]
     * @returns {{severity: string, text: string}}
     */
    function revokeWarning(key, nowMs) {
        switch (phase(key, nowMs)) {
        case 'active':
        case 'due':
            return {
                severity: 'alert',
                text: 'This is the key the bridge signs challenges with. Revoking it stops ' +
                    'SEP-10 sign-in (the endpoint answers 503) until another key is ' +
                    'activated and its activation delay has passed. Card sign-in through ' +
                    'SEP-10 fails until then; the Android app falls back to SIGN_AUTH on 503.'
            };
        case 'scheduled':
            return {
                severity: 'warning',
                text: 'This key is scheduled to take over at ' + key.activateAt + '. Revoking ' +
                    'it cancels that; the key in service now stays in service.'
            };
        case 'superseded':
            return {
                severity: 'warning',
                text: 'This key no longer signs challenges. Revoking it ends the short ' +
                    'overlap during which challenges it signed are still accepted.'
            };
        default:
            return {
                severity: 'warning',
                text: 'This key is not in service. Revoking it discards it for good; ' +
                    'generate a new one to rotate.'
            };
        }
    }

    /**
     * How a failed status load should render. A 404 means a bridge older
     * than the route (it is always mounted on bridges that have it), which
     * is a neutral "not offered" state, not an error.
     * @param {Error} err
     * @returns {{kind: string, message: string}} kind: unsupported | forbidden | error
     */
    function classifyLoadError(err) {
        var status = err && err.status;
        if (status === 404) {
            return { kind: 'unsupported', message: 'This bridge does not offer SEP-10.' };
        }
        if (status === 403) {
            return { kind: 'forbidden', message: 'Your role cannot read the SEP-10 signing keys.' };
        }
        return { kind: 'error', message: (err && err.message) || 'Could not load the SEP-10 signing keys.' };
    }

    /**
     * Operator-facing message for a failed generate / activate / revoke.
     * @param {Error} err - From API.post (carries status and code).
     * @returns {string}
     */
    function actionErrorMessage(err) {
        var code = err && err.code;
        var message = (err && err.message) || 'Request failed';
        if (code === 'pending_key_exists' ||
            (err && err.status === 409 && message.indexOf('pending_key_exists') !== -1)) {
            return 'A pending key already exists. Activate or revoke it before generating another.';
        }
        if (code === 'sep10_key_not_opened' ||
            (err && err.status === 409 && message.indexOf('sep10_key_not_opened') !== -1)) {
            return 'The bridge has not opened this key yet, so it was not activated. ' +
                NOT_OPENED_YET;
        }
        return message;
    }

    /** Toast text after a successful generate. */
    function describeGenerated(res) {
        var r = isObject(res) ? res : {};
        var version = positiveVersion(r.version);
        var address = str(r.public_address);
        return 'Generated signing key ' + (version === null ? '' : 'v' + version + ' ') +
            '(pending)' + (address ? ': ' + address : '') +
            '. It signs nothing until you activate it.';
    }

    /** Toast text after a successful activation. */
    function describeActivated(res) {
        var r = isObject(res) ? res : {};
        var version = positiveVersion(r.version);
        var at = str(r.activate_at);
        return 'Signing key ' + (version === null ? '' : 'v' + version + ' ') +
            (at ? 'takes over at ' + at : 'is scheduled to take over after the activation delay') +
            '.';
    }

    /** Toast text after a successful revocation. */
    function describeRevoked(res) {
        var r = isObject(res) ? res : {};
        var version = positiveVersion(r.version);
        return 'Signing key ' + (version === null ? '' : 'v' + version + ' ') + 'revoked.';
    }

    /**
     * Challenge lifetime for display.
     * @param {number|null} secs
     * @returns {string}
     */
    function formatTtl(secs) {
        if (secs === null || secs === undefined) return 'not reported';
        if (secs >= 60 && secs % 60 === 0) return secs + ' s (' + (secs / 60) + ' min)';
        return secs + ' s';
    }

    return {
        KNOWN_STATES: KNOWN_STATES,
        normalizeStatus: normalizeStatus,
        normalizeKey: normalizeKey,
        phase: phase,
        keyBadge: keyBadge,
        keyExplanation: keyExplanation,
        summary: summary,
        instanceLine: instanceLine,
        supersedeTarget: supersedeTarget,
        activatePhrase: activatePhrase,
        revokePhrase: revokePhrase,
        actionsFor: actionsFor,
        activationHold: activationHold,
        canGenerate: canGenerate,
        buildGenerate: buildGenerate,
        buildActivate: buildActivate,
        buildRevoke: buildRevoke,
        revokeWarning: revokeWarning,
        classifyLoadError: classifyLoadError,
        actionErrorMessage: actionErrorMessage,
        describeGenerated: describeGenerated,
        describeActivated: describeActivated,
        describeRevoked: describeRevoked,
        formatTtl: formatTtl
    };
})();

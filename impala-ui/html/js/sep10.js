/**
 * SEP-10 signing-key panel on the Keys page (thin DOM controller).
 *
 * Renders `GET /admin/sep10/signing-keys` and drives generate / activate /
 * revoke. Every decision (normalisation, badges, which actions a key offers,
 * confirmation phrases, request bodies) is made by the DOM-free `Sep10View`;
 * this file only turns its answers into markup and wires buttons.
 *
 * Rendering rules: every dynamic value goes through EscapeHtml.escape and
 * only into element content, never into an attribute. Row buttons carry the
 * row's index in this page's own list, not a server value. Badge classes
 * come from Sep10View's whitelist.
 *
 * Loaded after keys.js, which runs Router.init() and the view_keys page guard.
 *
 * @module Sep10Panel
 */
(function () {
    'use strict';

    var panel = document.getElementById('sep10-panel');
    // keys.js replaced the page with the in-page denial: nothing to do.
    if (!panel) return;
    if (!Roles.currentUserHasPermission('view_keys')) return;

    var canManage = Roles.currentUserHasPermission('manage_keys');
    var perms = { canManage: canManage };
    var esc = EscapeHtml.escape;
    var CALLOUT_CLASSES = ['alert', 'warning', 'primary'];

    var statusEl = document.getElementById('sep10-status');
    var noticesEl = document.getElementById('sep10-notices');
    var generateEl = document.getElementById('sep10-generate');
    var keysEl = document.getElementById('sep10-keys');

    var state = { status: null };

    /* ---- small renderers --------------------------------------------------- */

    function badgeHtml(b) {
        return '<span class="badge ' + b.cls + '">' + esc(b.label) + '</span>';
    }

    function muted(text) {
        return '<span class="text-muted">' + esc(text) + '</span>';
    }

    /** A full identifier (address, fingerprint, URL), never truncated. */
    function ident(value, fallback) {
        return value ? '<code class="ident">' + esc(value) + '</code>' : muted(fallback || 'not reported');
    }

    function plain(value, fallback) {
        return value !== null && value !== undefined && value !== ''
            ? esc(String(value)) : muted(fallback || 'not reported');
    }

    function callout(notice) {
        var cls = CALLOUT_CLASSES.indexOf(notice.cls) !== -1 ? notice.cls : 'primary';
        return '<div class="callout ' + cls + '"><p>' + esc(notice.text) + '</p></div>';
    }

    /* ---- load ---------------------------------------------------------------- */

    function load() {
        statusEl.innerHTML = '<p class="text-muted">Loading&hellip;</p>';
        return API.get('/admin/sep10/signing-keys').then(function (res) {
            state.status = Sep10View.normalizeStatus(res);
            render();
        }).catch(function (err) {
            state.status = null;
            renderUnavailable(Sep10View.classifyLoadError(err));
        });
    }

    function renderUnavailable(c) {
        noticesEl.innerHTML = '';
        generateEl.innerHTML = '';
        keysEl.innerHTML = '';
        if (c.kind === 'unsupported') {
            statusEl.innerHTML = '<p>' + badgeHtml({ cls: 'neutral', label: 'not offered' }) +
                ' ' + esc(c.message) + ' ' + muted('It predates the SEP-10 signing-key ' +
                'routes; cards on it sign in with SIGN_AUTH only.') + '</p>';
            return;
        }
        statusEl.innerHTML = '<div class="callout ' + (c.kind === 'forbidden' ? 'warning' : 'alert') +
            '"><p>' + esc(c.message) + '</p></div>';
    }

    /* ---- render -------------------------------------------------------------- */

    function render() {
        var s = state.status;
        var now = Date.now();
        var sum = Sep10View.summary(s, now);

        var inService = sum.activeKey
            ? 'v' + esc(String(sum.activeKey.version === null ? '?' : sum.activeKey.version)) +
              ' ' + ident(sum.activeKey.publicAddress) + '<br>fingerprint ' +
              ident(sum.activeKey.fingerprint)
            : muted(sum.activeCount > 1 ? 'ambiguous (see below)' : 'no active key');

        statusEl.innerHTML = '<dl class="kv">' +
            '<dt>SEP-10</dt><dd>' + badgeHtml(sum.enabledBadge) + '</dd>' +
            '<dt>Network</dt><dd>' + plain(s.network) +
            (s.networkPassphrase ? ' ' + muted('(passphrase:') + ' <code class="ident">' +
                esc(s.networkPassphrase) + '</code>' + muted(')') : '') + '</dd>' +
            '<dt>Home domain</dt><dd>' + ident(s.homeDomain, 'not configured') + '</dd>' +
            '<dt>Web-auth endpoint</dt><dd>' + ident(s.webAuthEndpoint, 'not configured') + '</dd>' +
            '<dt>Challenge lifetime</dt><dd>' + esc(Sep10View.formatTtl(s.challengeTtlSecs)) + '</dd>' +
            '<dt>Cards with a Stellar key</dt><dd>' + plain(s.registeredCardKeys) +
            ' ' + muted('active cards that can sign in with SEP-10') + '</dd>' +
            '<dt>In service</dt><dd>' + inService + '</dd>' +
            '<dt>This instance</dt><dd>' + esc(Sep10View.instanceLine(s, sum)) + '</dd>' +
            '</dl>';

        noticesEl.innerHTML = sum.notices.map(callout).join('');
        renderGenerate();
        renderKeys(now);
    }

    function renderGenerate() {
        if (!canManage) {
            generateEl.innerHTML = '';
            return;
        }
        var gen = Sep10View.canGenerate(state.status, perms);
        generateEl.innerHTML = '<p><button type="button" class="button" id="sep10-generate-btn"' +
            (gen.allowed ? '' : ' disabled') + '>Generate a signing key&hellip;</button>' +
            (gen.allowed ? '' : ' ' + muted(gen.reason)) + '</p>';
        var btn = document.getElementById('sep10-generate-btn');
        if (btn && gen.allowed) btn.addEventListener('click', openGenerateModal);
    }

    function renderKeys(now) {
        var s = state.status;
        if (s.keysMalformed) {
            keysEl.innerHTML = '';
            return;
        }
        if (s.keys.length === 0) {
            keysEl.innerHTML = '<p class="text-muted">No SEP-10 signing key has been generated on this bridge.</p>';
            return;
        }
        var anyActions = false;
        var rows = s.keys.map(function (k, idx) {
            var acts = Sep10View.actionsFor(k, s, perms, now);
            var buttons = '';
            if (acts.activate) {
                buttons += '<button type="button" class="button tiny" data-sep10-activate="' +
                    idx + '">Activate&hellip;</button> ';
            } else if (canManage && Sep10View.activationHold(k).held) {
                // The reason is already in the State column; the button stays
                // visible so the operator sees what will become available.
                buttons += '<button type="button" class="button tiny" disabled>Activate&hellip;</button> ';
            }
            if (acts.revoke) {
                buttons += '<button type="button" class="button tiny alert" data-sep10-revoke="' +
                    idx + '">Revoke&hellip;</button>';
            }
            if (buttons) anyActions = true;
            return '<tr>' +
                '<td>' + plain(k.version === null ? null : 'v' + k.version) + '</td>' +
                '<td>' + badgeHtml(Sep10View.keyBadge(k, now)) +
                '<br><small class="text-muted">' + esc(Sep10View.keyExplanation(k, now, s.enabled)) + '</small></td>' +
                '<td>' + ident(k.publicAddress) + '</td>' +
                '<td>' + ident(k.fingerprint) + '</td>' +
                '<td>' + plain(k.generatedAt, '—') + '<br>' + muted('by') + ' ' + plain(k.generatedBy, '?') + '</td>' +
                '<td>' + plain(k.activateAt, '—') + '</td>' +
                '<td>' + plain(k.supersededAt, '—') + '</td>' +
                '<td>' + plain(k.revokedAt, '—') + '</td>' +
                (canManage ? '<td><div class="row-actions">' + buttons + '</div></td>' : '') +
                '</tr>';
        }).join('');

        keysEl.innerHTML = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Version</th><th>State</th><th>Public address</th><th>Fingerprint</th>' +
            '<th>Generated</th><th>Activate at</th><th>Superseded</th><th>Revoked</th>' +
            (canManage ? '<th>Actions</th>' : '') +
            '</tr></thead><tbody>' + rows + '</tbody></table></div>' +
            (canManage && !anyActions
                ? '<p class="text-muted">No action is available on the listed keys.</p>' : '');

        bindRows('data-sep10-activate', openActivateModal);
        bindRows('data-sep10-revoke', openRevokeModal);
    }

    function bindRows(attr, handler) {
        var nodes = keysEl.querySelectorAll('[' + attr + ']');
        Array.prototype.forEach.call(nodes, function (btn) {
            btn.addEventListener('click', function () {
                var idx = parseInt(btn.getAttribute(attr), 10);
                var s = state.status;
                var key = s && s.keys[idx];
                // Snapshot what the operator is looking at: the request is
                // built from this view, so a concurrent change is caught by
                // the bridge's compare-and-set rather than silently retargeted.
                if (key) handler(s, key);
            });
        });
    }

    /* ---- actions ------------------------------------------------------------- */

    function confirmField(phrase) {
        return '<label>Type <code>' + esc(phrase || '') + '</code> to confirm' +
            '<input type="text" id="sep10-confirm" autocomplete="off" spellcheck="false"></label>' +
            '<p class="form-error" id="sep10-error" hidden></p>';
    }

    function showError(dialog, message) {
        var el = dialog.querySelector('#sep10-error');
        el.textContent = message;
        el.hidden = false;
    }

    function submit(dialog, helpers, req, describe) {
        dialog.querySelector('#sep10-error').hidden = true;
        API.setButtonLoading(helpers.button, true);
        API.post(req.path, req.body)
            .then(function (res) {
                Router.showToast(describe(res), 'success');
                helpers.close();
                load();
            })
            .catch(function (err) {
                showError(dialog, Sep10View.actionErrorMessage(err));
            })
            .then(function () { API.setButtonLoading(helpers.button, false); });
    }

    function openGenerateModal() {
        var body =
            '<p>The bridge creates a new Ed25519 signing key, seals it with its ' +
            'seed-protection backend and stores it as <strong>pending</strong>. The secret ' +
            'never leaves the bridge; this page only ever sees the public address and the ' +
            'fingerprint.</p>' +
            '<p>A pending key signs nothing. To put it in service, <strong>activate</strong> it; ' +
            'it then takes over after the activation delay.</p>' +
            '<p class="form-error" id="sep10-error" hidden></p>';
        Modal.open({
            title: 'Generate a SEP-10 signing key',
            bodyHtml: body,
            confirmLabel: 'Generate',
            onConfirm: function (dialog, helpers) {
                submit(dialog, helpers, Sep10View.buildGenerate(), Sep10View.describeGenerated);
            }
        });
    }

    function openActivateModal(s, key) {
        var target = Sep10View.supersedeTarget(s);
        var phrase = Sep10View.activatePhrase(s);
        var supersedes = target.ok && target.key
            ? '<p>It supersedes v' + esc(String(target.key.version === null ? '?' : target.key.version)) +
              ', fingerprint ' + ident(target.key.fingerprint) + '. The request carries that ' +
              'fingerprint, so the bridge refuses it if the key in service changed since this ' +
              'page loaded.</p>'
            : '<p>No key is in service, so this supersedes <code>none</code>.</p>';
        var body =
            '<p>Activate v' + esc(String(key.version)) + ' ' + ident(key.publicAddress) +
            ', fingerprint ' + ident(key.fingerprint) + '.</p>' +
            supersedes +
            '<p>It takes over after the activation delay, on every bridge instance at the same ' +
            'instant; the key it replaces becomes superseded.</p>' +
            confirmField(phrase);
        Modal.open({
            title: 'Activate SEP-10 signing key v' + key.version,
            bodyHtml: body,
            confirmLabel: 'Activate',
            onConfirm: function (dialog, helpers) {
                var built = Sep10View.buildActivate(s, key, dialog.querySelector('#sep10-confirm').value);
                if (!built.ok) {
                    showError(dialog, built.error);
                    return;
                }
                submit(dialog, helpers, built, Sep10View.describeActivated);
            }
        });
    }

    function openRevokeModal(s, key) {
        var warning = Sep10View.revokeWarning(key, Date.now());
        var phrase = Sep10View.revokePhrase(s, key);
        var body =
            '<div class="callout ' + (warning.severity === 'alert' ? 'alert' : 'warning') + '"><p>' +
            esc(warning.text) + '</p></div>' +
            '<p>Revoke v' + esc(String(key.version)) + ' ' + ident(key.publicAddress) +
            ', fingerprint ' + ident(key.fingerprint) + '. A revoked key is never accepted ' +
            'again and cannot be restored.</p>' +
            confirmField(phrase);
        Modal.open({
            title: 'Revoke SEP-10 signing key v' + key.version,
            bodyHtml: body,
            confirmLabel: 'Revoke key',
            confirmClass: 'alert',
            onConfirm: function (dialog, helpers) {
                var built = Sep10View.buildRevoke(s, key, dialog.querySelector('#sep10-confirm').value);
                if (!built.ok) {
                    showError(dialog, built.error);
                    return;
                }
                submit(dialog, helpers, built, Sep10View.describeRevoked);
            }
        });
    }

    load();
})();

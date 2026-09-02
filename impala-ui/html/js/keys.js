/**
 * Bridge key management console.
 *
 * Renders `GET /admin/keys`: for each provider credential, what this bridge
 * instance is actually running, what is stored, and whether the two differ.
 * Drives import / merge / revoke, and the two custodial-seed endpoints.
 *
 * Two rules govern everything here:
 *
 *  1. **No secret is ever rendered.** The API never returns key material, and
 *     this module never echoes a value out of an input back into the DOM. Every
 *     secret field is `type="password"` with autocomplete off, and its value is
 *     overwritten before the modal closes — a browser is a hostile place to
 *     hold a private key, and this narrows (it cannot close) the window.
 *  2. **No value the server will compare against is reconstructed here.** The
 *     confirmation phrase and the current fingerprint both arrive in the
 *     payload. All decision logic lives in the DOM-free `KeysView` module so it
 *     is unit-tested.
 *
 * @module KeysPage
 */
(function () {
    'use strict';

    Router.init();
    if (!Router.requirePermission('view_keys', 'Bridge Keys')) return;

    // One flag, applied at every action-injection point: viewers without it
    // (the auditor) get the same inventory, read-only. The bridge enforces
    // the same boundary server-side regardless — which is also why the
    // injection points carry no unit tests (DOM rendering, outside the
    // DOM-free test style): a missed gate shows a button that 403s, never an
    // unauthorized mutation.
    var canManage = Roles.currentUserHasPermission('manage_keys');

    var escapeHtml = EscapeHtml.escape;

    var state = { payload: null };

    /** Overwrite an input's value before it is torn out of the DOM. */
    function scrub(dialog) {
        var inputs = dialog.querySelectorAll('input[type="password"], textarea');
        Array.prototype.forEach.call(inputs, function (el) {
            el.value = '';
        });
    }

    function viewFor(kind) {
        var list = (state.payload && state.payload.keys) || [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].kind === kind) return list[i];
        }
        return null;
    }

    /* ---- rendering ------------------------------------------------------- */

    function load() {
        return API.get('/admin/keys').then(function (res) {
            state.payload = res;
            document.getElementById('keys-disabled').hidden = !!res.enabled;
            document.getElementById('keys-degraded').hidden = !res.degraded;
            renderList();
            renderHistory();
        }).catch(function (err) {
            document.getElementById('keys-list').innerHTML =
                '<p class="text-muted">' + escapeHtml(err.message) + '</p>';
        });
    }

    function badge(b) {
        return '<span class="badge ' + escapeHtml(b.cls) + '" title="' +
            escapeHtml(b.title || '') + '">' + escapeHtml(b.label) + '</span>';
    }

    function partFingerprints(view) {
        var fps = view.per_part_fingerprints || {};
        var names = Object.keys(fps);
        if (names.length === 0) return '';
        return '<dl class="kv">' + names.map(function (n) {
            return '<dt>' + escapeHtml(n) + '</dt><dd><code>' +
                escapeHtml(KeysView.shortFingerprint(fps[n])) + '</code></dd>';
        }).join('') + '</dl>';
    }

    function renderList() {
        var el = document.getElementById('keys-list');
        var keys = (state.payload && state.payload.keys) || [];
        if (keys.length === 0) {
            el.innerHTML = '<p class="text-muted">No credential kinds.</p>';
            return;
        }
        var enabled = state.payload.enabled;

        el.innerHTML = keys.map(function (v) {
            var notice = KeysView.pendingNotice(v);
            var warn = KeysView.inFlightWarning(v);
            var rows = [];

            rows.push('<dt>Running here</dt><dd>' + badge(KeysView.sourceBadge(v)) +
                ' <code>' + escapeHtml(KeysView.shortFingerprint(v.effective_fingerprint)) +
                '</code>' + (v.effective_version ? ' (v' + v.effective_version + ')' : '') +
                '</dd>');

            rows.push('<dt>Stored</dt><dd>' + (v.stored_fingerprint
                ? '<code>' + escapeHtml(KeysView.shortFingerprint(v.stored_fingerprint)) +
                  '</code> (v' + escapeHtml(String(v.stored_version)) + ', ' +
                  escapeHtml(v.stored_state || '') + ')'
                : '<span class="text-muted">nothing stored</span>') + '</dd>');

            if (v.env_vars_set && v.env_vars_set.length) {
                rows.push('<dt>Environment</dt><dd><code>' +
                    v.env_vars_set.map(escapeHtml).join('</code> <code>') + '</code>' +
                    (v.shadowed_env_fingerprint
                        ? ' <span class="text-muted">— shadowed by the stored credential; ' +
                          'remove these to finish the rotation</span>'
                        : '') +
                    '</dd>');
            }

            rows.push('<dt>Parts</dt><dd>' + v.parts.map(function (p) {
                var required = v.required_parts.indexOf(p) !== -1;
                return escapeHtml(p) + (required ? '' : ' <span class="text-muted">(optional)</span>');
            }).join(', ') + '</dd>');

            if (v.imported_at) {
                rows.push('<dt>Imported</dt><dd>' + escapeHtml(v.imported_at) + ' by ' +
                    escapeHtml(v.imported_by || '?') + '</dd>');
            }
            if (v.note) {
                rows.push('<dt>Note</dt><dd>' + escapeHtml(v.note) + '</dd>');
            }

            var actions = '';
            if (enabled && canManage) {
                actions =
                    '<button class="button small" data-import="' + escapeHtml(v.kind) + '">' +
                    (KeysView.isReplacement(v) ? 'Replace&hellip;' : 'Import&hellip;') +
                    '</button>' +
                    (v.stored_fingerprint
                        ? ' <button class="button small secondary" data-merge="' +
                          escapeHtml(v.kind) + '">Rotate one part&hellip;</button>' +
                          ' <button class="button small alert" data-revoke="' +
                          escapeHtml(v.kind) + '">Revoke&hellip;</button>'
                        : '');
            }

            return '<div class="card"><div class="card-section">' +
                '<h6>' + escapeHtml(v.kind) + '</h6>' +
                (v.resolution_error
                    ? '<p class="form-error">This instance could not use the stored ' +
                      'credential (' + escapeHtml(v.resolution_error) + '), so the provider ' +
                      'is disabled here. It deliberately did not fall back to the ' +
                      'environment.</p>'
                    : '') +
                (notice ? '<p>' + badge({ cls: notice.cls, label: 'pending', title: '' }) +
                    ' ' + escapeHtml(notice.text) + '</p>' : '') +
                (warn ? '<p class="text-muted">' + escapeHtml(warn) + '</p>' : '') +
                '<dl class="kv">' + rows.join('') + '</dl>' +
                partFingerprints(v) +
                '<p>' + actions + '</p>' +
                '</div></div>';
        }).join('');

        bind('data-import', openImportModal);
        bind('data-merge', openMergeModal);
        bind('data-revoke', openRevokeModal);
    }

    function bind(attr, handler) {
        var nodes = document.querySelectorAll('[' + attr + ']');
        Array.prototype.forEach.call(nodes, function (btn) {
            btn.addEventListener('click', function () {
                handler(btn.getAttribute(attr));
            });
        });
    }

    function renderHistory() {
        var el = document.getElementById('keys-history');
        var rows = [];
        ((state.payload && state.payload.keys) || []).forEach(function (v) {
            (v.history || []).forEach(function (h) {
                rows.push(h);
            });
        });
        if (rows.length === 0) {
            el.innerHTML = '<p class="text-muted">Nothing has been imported on this bridge.</p>';
            return;
        }
        el.innerHTML = '<table class="table"><thead><tr>' +
            '<th>Kind</th><th>Version</th><th>State</th><th>Fingerprint</th>' +
            '<th>Imported</th><th>By</th><th>Scrubbed</th><th>Note</th>' +
            '</tr></thead><tbody>' +
            rows.map(function (h) {
                return '<tr>' +
                    '<td>' + escapeHtml(h.kind) + '</td>' +
                    '<td>' + escapeHtml(String(h.version)) + '</td>' +
                    '<td>' + escapeHtml(h.state) + '</td>' +
                    '<td><code>' + escapeHtml(KeysView.shortFingerprint(h.set_fingerprint)) +
                    '</code></td>' +
                    '<td>' + escapeHtml(h.imported_at || '') + '</td>' +
                    '<td>' + escapeHtml(h.imported_by || '') + '</td>' +
                    '<td>' + escapeHtml(h.scrubbed_at || '—') + '</td>' +
                    '<td>' + escapeHtml(h.note || '') + '</td>' +
                    '</tr>';
            }).join('') + '</tbody></table>';
    }

    /* ---- import / replace ------------------------------------------------ */

    function secretField(name, required) {
        return '<label>' + escapeHtml(name) +
            (required ? '' : ' <span class="text-muted">(optional)</span>') +
            '<input type="password" autocomplete="off" spellcheck="false" ' +
            'data-part="' + escapeHtml(name) + '"></label>';
    }

    function openImportModal(kind) {
        var view = viewFor(kind);
        if (!view) return;
        var replacing = KeysView.isReplacement(view);
        var warn = KeysView.inFlightWarning(view);

        var body =
            '<p class="text-muted">Values are sent to the bridge and sealed with its ' +
            'protection backend. They are never returned, and there is no way to read ' +
            'one back.</p>' +
            (replacing
                ? '<div class="callout alert"><p>This <strong>replaces</strong> the ' +
                  'credential this would supersede (<code>' +
                  escapeHtml(KeysView.shortFingerprint(view.replace_target_fingerprint)) +
                  '</code>). It takes effect at the next rolling restart.</p>' +
                  (warn ? '<p>' + escapeHtml(warn) + '</p>' : '') + '</div>'
                : '<p class="text-muted">Nothing is in effect for this kind, so this is an ' +
                  '<strong>addition</strong>.</p>') +
            view.parts.map(function (p) {
                return secretField(p, view.required_parts.indexOf(p) !== -1);
            }).join('') +
            '<label>Note <span class="text-muted">(stored in plaintext, shown in listings)</span>' +
            '<input type="text" id="key-note" maxlength="256"></label>' +
            (replacing
                ? '<label>Type <code>' + escapeHtml(view.confirm_phrase || '') +
                  '</code> to confirm<input type="text" id="key-confirm" ' +
                  'autocomplete="off"></label>'
                : '') +
            (warn
                ? '<label><input type="checkbox" id="key-strand"> The new credential is for ' +
                  'the same provider account (or I accept stranding the in-flight work)</label>'
                : '') +
            '<label><input type="checkbox" id="key-skip-verify"> Skip the provider check ' +
            '(store without proving the credential works)</label>' +
            '<p class="form-error" id="key-error" hidden></p>';

        var handle = Modal.open({
            title: (replacing ? 'Replace ' : 'Import ') + kind,
            bodyHtml: body,
            confirmLabel: replacing ? 'Replace credential' : 'Import credential',
            onConfirm: function (dialog, helpers) {
                var parts = {};
                Array.prototype.forEach.call(
                    dialog.querySelectorAll('[data-part]'),
                    function (el) { parts[el.getAttribute('data-part')] = el.value; }
                );
                var checked = function (id) {
                    var el = dialog.querySelector(id);
                    return !!(el && el.checked);
                };
                var typed = dialog.querySelector('#key-confirm');
                var built = KeysView.buildImport(view, {
                    parts: parts,
                    note: dialog.querySelector('#key-note').value.trim(),
                    confirmTyped: typed ? typed.value : '',
                    strandInFlight: checked('#key-strand'),
                    skipVerify: checked('#key-skip-verify')
                });
                var errEl = dialog.querySelector('#key-error');
                if (!built.ok) {
                    errEl.textContent = built.error;
                    errEl.hidden = false;
                    return;
                }
                errEl.hidden = true;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/keys/' + encodeURIComponent(kind), built.body)
                    .then(function (res) {
                        // Scrub before the modal is torn down, not after.
                        scrub(dialog);
                        Router.showToast((res && res.message) || 'Credential stored', 'success');
                        if (res && res.verify_note) Router.showToast(res.verify_note, 'warning');
                        if (res && res.env_shadow_note) {
                            Router.showToast(res.env_shadow_note, 'warning');
                        }
                        helpers.close();
                        load();
                    })
                    .catch(function (err) {
                        errEl.textContent = err.message;
                        errEl.hidden = false;
                    })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            },
            // Fired after the dialog is detached, but the node is still in
            // memory — overwriting the inputs is the last chance to drop the
            // plaintext this page ever held.
            onClose: function () { if (handle && handle.dialog) scrub(handle.dialog); }
        });
    }

    /* ---- merge ----------------------------------------------------------- */

    function openMergeModal(kind) {
        var view = viewFor(kind);
        if (!view) return;
        var stored = Object.keys(view.per_part_fingerprints || {});

        var body =
            '<p class="text-muted">Replaces only the parts you fill in, keeping the rest of ' +
            'the stored set. Use this to rotate one part without re-entering keys you ' +
            'cannot read back.</p>' +
            view.parts.map(function (p) { return secretField(p, false); }).join('') +
            (stored.length
                ? '<label>Remove a part<select id="key-drop">' +
                  '<option value="">— none —</option>' +
                  stored.filter(function (p) {
                      return view.required_parts.indexOf(p) === -1;
                  }).map(function (p) {
                      return '<option value="' + escapeHtml(p) + '">' + escapeHtml(p) +
                          '</option>';
                  }).join('') + '</select></label>'
                : '') +
            '<label>Type <code>' + escapeHtml(view.confirm_phrase || '') +
            '</code> to confirm<input type="text" id="key-confirm" autocomplete="off"></label>' +
            '<p class="form-error" id="key-error" hidden></p>';

        var handle = Modal.open({
            title: 'Rotate part of ' + kind,
            bodyHtml: body,
            confirmLabel: 'Store new version',
            onConfirm: function (dialog, helpers) {
                var setParts = {};
                Array.prototype.forEach.call(
                    dialog.querySelectorAll('[data-part]'),
                    function (el) {
                        var v = el.value.trim();
                        if (v) setParts[el.getAttribute('data-part')] = v;
                    }
                );
                var dropEl = dialog.querySelector('#key-drop');
                var drop = dropEl && dropEl.value ? [dropEl.value] : [];
                var errEl = dialog.querySelector('#key-error');
                if (Object.keys(setParts).length === 0 && drop.length === 0) {
                    errEl.textContent = 'Change at least one part';
                    errEl.hidden = false;
                    return;
                }
                if (dialog.querySelector('#key-confirm').value !== view.confirm_phrase) {
                    errEl.textContent = 'Type exactly: ' + view.confirm_phrase;
                    errEl.hidden = false;
                    return;
                }
                errEl.hidden = true;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/keys/' + encodeURIComponent(kind) + '/merge', {
                    set_parts: setParts,
                    drop_parts: drop,
                    expected_fingerprint: view.effective_fingerprint,
                    confirm_phrase: view.confirm_phrase
                })
                    .then(function (res) {
                        scrub(dialog);
                        Router.showToast((res && res.message) || 'New version stored', 'success');
                        helpers.close();
                        load();
                    })
                    .catch(function (err) {
                        errEl.textContent = err.message;
                        errEl.hidden = false;
                    })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            },
            // Fired after the dialog is detached, but the node is still in
            // memory — overwriting the inputs is the last chance to drop the
            // plaintext this page ever held.
            onClose: function () { if (handle && handle.dialog) scrub(handle.dialog); }
        });
    }

    /* ---- revoke ---------------------------------------------------------- */

    function openRevokeModal(kind) {
        var view = viewFor(kind);
        if (!view) return;

        var body =
            '<div class="callout alert"><p>' + escapeHtml(KeysView.revokeFallback(view)) +
            '</p><p>Revoking here does <strong>not</strong> invalidate the key at the ' +
            'provider. If it is compromised, revoke it there first.</p></div>' +
            '<label><input type="checkbox" id="key-ack"> I understand what this provider ' +
            'falls back to</label>' +
            '<label>Type <code>' + escapeHtml(view.confirm_phrase || '') +
            '</code> to confirm<input type="text" id="key-confirm" autocomplete="off"></label>' +
            '<p class="form-error" id="key-error" hidden></p>';

        Modal.open({
            title: 'Revoke ' + kind,
            bodyHtml: body,
            confirmLabel: 'Revoke credential',
            onConfirm: function (dialog, helpers) {
                var built = KeysView.buildRevoke(view, {
                    confirmTyped: dialog.querySelector('#key-confirm').value,
                    acknowledgedNextSource: dialog.querySelector('#key-ack').checked
                });
                var errEl = dialog.querySelector('#key-error');
                if (!built.ok) {
                    errEl.textContent = built.error;
                    errEl.hidden = false;
                    return;
                }
                errEl.hidden = true;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/keys/' + encodeURIComponent(kind) + '/revoke', built.body)
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Credential revoked', 'success');
                        helpers.close();
                        load();
                    })
                    .catch(function (err) {
                        errEl.textContent = err.message;
                        errEl.hidden = false;
                    })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    /* ---- custodial seeds -------------------------------------------------- */

    function openGenerateSeedModal() {
        var body =
            '<p class="text-muted">The bridge creates the key itself. It never exists ' +
            'outside the process in plaintext and cannot be exported — which is why this ' +
            'is the only way to provision the conversion-reserve account.</p>' +
            '<label>Payala account id<input type="text" id="seed-account" maxlength="64"></label>' +
            '<label>Label <span class="text-muted">(for the account record)</span>' +
            '<input type="text" id="seed-label" maxlength="32"></label>' +
            '<p class="form-error" id="seed-error" hidden></p>';

        Modal.open({
            title: 'Generate a custodial seed',
            bodyHtml: body,
            confirmLabel: 'Generate',
            onConfirm: function (dialog, helpers) {
                var account = dialog.querySelector('#seed-account').value.trim();
                var errEl = dialog.querySelector('#seed-error');
                if (!account) {
                    errEl.textContent = 'Account id is required';
                    errEl.hidden = false;
                    return;
                }
                errEl.hidden = true;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/stellar-seeds/generate', {
                    payala_account_id: account,
                    label: dialog.querySelector('#seed-label').value.trim() || undefined
                })
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Seed generated', 'success');
                        helpers.close();
                    })
                    .catch(function (err) {
                        errEl.textContent = err.message;
                        errEl.hidden = false;
                    })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    function openImportSeedModal() {
        var body =
            '<div class="callout alert"><p>The key you paste also exists wherever you ' +
            'copied it from, and passing through a browser exposes it to that browser. ' +
            'Prefer <code>impalactl stellar-seed import</code>, which reads it from a file, ' +
            'stdin, or a no-echo prompt.</p></div>' +
            '<label>Payala account id<input type="text" id="seed-account" maxlength="64"></label>' +
            '<label>Secret seed (S&hellip;)<input type="password" id="seed-secret" ' +
            'autocomplete="off" spellcheck="false"></label>' +
            '<label><input type="checkbox" id="seed-replace"> Replace the existing seed ' +
            '(must derive the same address)</label>' +
            '<label>Current address, if replacing<input type="text" id="seed-expected" ' +
            'autocomplete="off"></label>' +
            '<label>Confirmation phrase, if replacing ' +
            '<span class="text-muted">(<code>replace seed &lt;last 6 of the address&gt;</code>)</span>' +
            '<input type="text" id="seed-confirm" autocomplete="off"></label>' +
            '<p class="form-error" id="seed-error" hidden></p>';

        var handle = Modal.open({
            title: 'Import a custodial seed',
            bodyHtml: body,
            confirmLabel: 'Import seed',
            onConfirm: function (dialog, helpers) {
                var account = dialog.querySelector('#seed-account').value.trim();
                var secret = dialog.querySelector('#seed-secret').value.trim();
                var errEl = dialog.querySelector('#seed-error');
                if (!account || !secret) {
                    errEl.textContent = 'Account id and secret seed are required';
                    errEl.hidden = false;
                    return;
                }
                var replace = dialog.querySelector('#seed-replace').checked;
                var payload = { payala_account_id: account, secret_seed: secret };
                if (replace) {
                    payload.replace = true;
                    payload.expected_stellar_account_id =
                        dialog.querySelector('#seed-expected').value.trim();
                    payload.confirm_phrase = dialog.querySelector('#seed-confirm').value.trim();
                }
                errEl.hidden = true;
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/stellar-seeds/import', payload)
                    .then(function (res) {
                        scrub(dialog);
                        Router.showToast((res && res.message) || 'Seed imported', 'success');
                        helpers.close();
                    })
                    .catch(function (err) {
                        errEl.textContent = err.message;
                        errEl.hidden = false;
                    })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            },
            // Fired after the dialog is detached, but the node is still in
            // memory — overwriting the inputs is the last chance to drop the
            // plaintext this page ever held.
            onClose: function () { if (handle && handle.dialog) scrub(handle.dialog); }
        });
    }

    // Static action buttons carry data-permission="manage_keys" in the HTML
    // (hidden for read-only viewers by Router.enforcePermissions), so wire
    // them null-safely and only when the role can act.
    var seedGen = document.getElementById('seed-generate');
    var seedImp = document.getElementById('seed-import');
    if (canManage && seedGen) seedGen.addEventListener('click', openGenerateSeedModal);
    if (canManage && seedImp) seedImp.addEventListener('click', openImportSeedModal);

    if (!canManage) {
        Router.showReadOnlyBanner('Key operations', 'the admin or key-custodian role');
    }

    load();
})();

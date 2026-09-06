/**
 * Custody console.
 *
 * Renders the bridge's /admin/custody/* and /admin/reconciliation/* APIs:
 * the custodial policy (pause + caps), every payment intent, the custodial
 * accounts with their per-account overrides, and the reconciliation
 * snapshots. All decision logic lives in the DOM-free CustodyView module;
 * every dynamic value rendered here is escaped, and no dynamic string is
 * ever interpolated into an attribute (row actions key off numeric indices
 * into the cached payloads instead).
 *
 * Two rules: (1) no value the bridge compares against is reconstructed here
 * (the resume phrase arrives in the policy payload); (2) viewers without
 * manage_custody get the same live page, read-only — the bridge enforces
 * the same boundary server-side, and `resume` additionally needs admin.
 *
 * @module CustodyPage
 */
(function () {
    'use strict';

    Router.init();
    if (!Router.requirePermission('view_custody', 'Custody')) return;

    var canManage = Roles.currentUserHasPermission('manage_custody');
    var isAdmin = Roles.isAdmin();
    var escapeHtml = EscapeHtml.escape;
    var PER_PAGE = 10;

    var state = {
        policy: null,
        intents: null,
        intentsPage: 1,
        intentStatus: '',
        accounts: null,
        accountsPage: 1,
        snapshots: null,
        snapshotsPage: 1
    };

    function showError(err) {
        Router.showToast((err && err.message) || 'Request failed', 'alert');
    }

    /** Machine-readable refusals carry `error.code`; explain them by code. */
    function explain(err) {
        var code = err && err.code;
        if (code && CustodyView.REFUSAL_CODES.indexOf(code) !== -1) {
            return CustodyView.refusalText(code) + ' (' + code + ')';
        }
        return (err && err.message) || 'Request failed';
    }

    function badge(cls, text) {
        return '<span class="badge ' + cls + '">' + escapeHtml(text) + '</span>';
    }

    function pager(res, containerId, onPage) {
        var totalPages = Math.max(1, Math.ceil((res.total || 0) / (res.per_page || PER_PAGE)));
        Paginate.renderControls({ page: res.page || 1, totalPages: totalPages, totalItems: res.total || 0 },
            containerId, onPage);
    }

    /* ---- policy ---------------------------------------------------------- */

    function loadPolicy() {
        return API.get('/admin/custody/policy').then(function (res) {
            state.policy = res;
            renderPolicy();
        });
    }

    function renderPolicy() {
        var view = state.policy;
        if (!view) return;
        var html = '<dl class="detail-grid">';
        CustodyView.policyRows(view).forEach(function (row) {
            html += '<dt>' + escapeHtml(row.label) + '</dt><dd>' + badge(row.cls, row.value) + '</dd>';
        });
        html += '</dl>';
        document.getElementById('custody-policy').innerHTML = html;
        var pause = document.getElementById('policy-pause');
        var resume = document.getElementById('policy-resume');
        if (pause) pause.disabled = !!view.paused;
        if (resume) resume.disabled = !view.paused;
    }

    function openCapsModal() {
        var view = state.policy || {};
        var handle = Modal.open({
            title: 'Set custodial caps',
            bodyHtml:
                '<p class="text-muted">Integer stroops (1 XLM = 10,000,000). A cap of 0 leaves signing refused. Leave a field blank to keep its current value.</p>' +
                '<label>Per-transaction cap (stroops)<input type="text" id="cap-tx" inputmode="numeric" autocomplete="off"></label>' +
                '<label>Per-account daily cap (stroops)<input type="text" id="cap-daily" inputmode="numeric" autocomplete="off"></label>' +
                '<label><input type="checkbox" id="cap-require-key"> Require a client idempotency key</label>' +
                '<p class="text-muted" id="cap-error" role="alert"></p>',
            confirmLabel: 'Save caps',
            onConfirm: function (dialog, helpers) {
                var body = {};
                var txIn = dialog.querySelector('#cap-tx').value;
                var dailyIn = dialog.querySelector('#cap-daily').value;
                var errEl = dialog.querySelector('#cap-error');
                if (txIn.trim() !== '') {
                    var tx = CustodyView.validateStroops(txIn);
                    if (!tx.ok) { errEl.textContent = 'Per-transaction: ' + tx.error; return; }
                    body.per_tx_max_stroops = tx.value;
                }
                if (dailyIn.trim() !== '') {
                    var daily = CustodyView.validateStroops(dailyIn);
                    if (!daily.ok) { errEl.textContent = 'Daily: ' + daily.error; return; }
                    body.per_account_daily_max_stroops = daily.value;
                }
                var requireKey = dialog.querySelector('#cap-require-key').checked;
                if (requireKey !== !!view.require_idempotency_key) {
                    body.require_idempotency_key = requireKey;
                }
                if (Object.keys(body).length === 0) { errEl.textContent = 'Nothing to change.'; return; }
                API.setButtonLoading(helpers.button, true);
                API.put('/admin/custody/policy', body).then(function () {
                    helpers.close();
                    Router.showToast('Custodial caps updated', 'success');
                    return loadPolicy();
                }).catch(function (err) {
                    API.setButtonLoading(helpers.button, false);
                    errEl.textContent = explain(err);
                });
            }
        });
        handle.dialog.querySelector('#cap-tx').value = view.per_tx_max_stroops > 0 ? String(view.per_tx_max_stroops) : '';
        handle.dialog.querySelector('#cap-daily').value = view.per_account_daily_max_stroops > 0 ? String(view.per_account_daily_max_stroops) : '';
        handle.dialog.querySelector('#cap-require-key').checked = !!view.require_idempotency_key;
    }

    function openPauseModal() {
        Modal.open({
            title: 'Pause custodial payments',
            bodyHtml:
                '<p>Every <code>POST /managed-account/sign</code> answers <code>503 custodial_paused</code> until an admin resumes. Reserve payouts, refunds and replenishment are NOT affected by this switch.</p>' +
                '<label>Reason (recorded in the audit feed)<input type="text" id="pause-reason" maxlength="200" autocomplete="off"></label>' +
                '<p class="text-muted" id="pause-error" role="alert"></p>',
            confirmLabel: 'Pause now',
            confirmClass: 'alert',
            onConfirm: function (dialog, helpers) {
                var reason = dialog.querySelector('#pause-reason').value.trim();
                var errEl = dialog.querySelector('#pause-error');
                if (!reason) { errEl.textContent = 'A reason is required.'; return; }
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/custody/pause', { reason: reason }).then(function (res) {
                    helpers.close();
                    Router.showToast(res && res.changed === false ? 'Already paused' : 'Custodial payments paused', 'warning');
                    return loadPolicy();
                }).catch(function (err) {
                    API.setButtonLoading(helpers.button, false);
                    errEl.textContent = explain(err);
                });
            }
        });
    }

    function openResumeModal() {
        var view = state.policy || {};
        var needsForce = CustodyView.resumeNeedsForce(view);
        var handle = Modal.open({
            title: 'Resume custodial payments',
            bodyHtml:
                '<p>Type the confirmation phrase exactly as the bridge serves it:</p>' +
                '<p><code id="resume-phrase-shown"></code></p>' +
                '<label>Confirmation phrase<input type="text" id="resume-phrase" autocomplete="off"></label>' +
                (needsForce
                    ? '<p class="badge error">' + escapeHtml(String(view.open_intents.ambiguous)) + ' intent(s) have an unknown on-chain outcome</p>' +
                      '<label><input type="checkbox" id="resume-force"> Resume anyway (force) — resolve them first if at all possible</label>'
                    : '') +
                '<p class="text-muted" id="resume-error" role="alert"></p>',
            confirmLabel: 'Resume',
            onConfirm: function (dialog, helpers) {
                var errEl = dialog.querySelector('#resume-error');
                var body = { confirm_phrase: dialog.querySelector('#resume-phrase').value.trim() };
                var forceEl = dialog.querySelector('#resume-force');
                if (forceEl && forceEl.checked) body.force = true;
                if (!body.confirm_phrase) { errEl.textContent = 'The confirmation phrase is required.'; return; }
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/custody/resume', body).then(function (res) {
                    helpers.close();
                    Router.showToast(res && res.changed === false ? 'Was not paused' : 'Custodial payments resumed', 'success');
                    return loadPolicy();
                }).catch(function (err) {
                    API.setButtonLoading(helpers.button, false);
                    errEl.textContent = explain(err);
                });
            }
        });
        // The phrase is server-supplied; it is displayed as text, never rebuilt.
        handle.dialog.querySelector('#resume-phrase-shown').textContent = view.resume_phrase || '(phrase unavailable — reload the policy)';
    }

    /* ---- intents --------------------------------------------------------- */

    function loadIntents() {
        var q = '?page=' + state.intentsPage + '&per_page=' + PER_PAGE +
            (state.intentStatus ? '&status=' + encodeURIComponent(state.intentStatus) : '');
        return API.get('/admin/custody/intents' + q).then(function (res) {
            state.intents = res;
            renderIntents();
        });
    }

    function renderIntents() {
        var res = state.intents;
        if (!res) return;
        var rows = res.data || [];
        var container = document.getElementById('custody-intents');
        if (!rows.length) {
            container.innerHTML = '<p class="text-muted">No intents' + (state.intentStatus ? ' with this status' : '') + '.</p>';
            pager(res, 'intents-pagination', function (p) { state.intentsPage = p; loadIntents().catch(showError); });
            return;
        }
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Created</th><th>Account</th><th>Status</th><th>Amount (XLM)</th><th>Key</th><th>Hash</th><th>Resolution</th><th></th>' +
            '</tr></thead><tbody>';
        rows.forEach(function (it, i) {
            html += '<tr>' +
                '<td>' + escapeHtml(it.created_at || '') + '</td>' +
                '<td class="mono">' + escapeHtml(it.payala_account_id) + '</td>' +
                '<td>' + badge(CustodyView.intentBadge(it.status), it.status) + '</td>' +
                '<td class="mono">' + escapeHtml(it.amount || String(it.amount_minor)) + '</td>' +
                '<td class="mono">' + escapeHtml(it.idempotency_key) + ' <span class="text-muted">(' + escapeHtml(it.key_source) + ')</span></td>' +
                '<td class="mono">' + escapeHtml(it.stellar_hash || '—') + '</td>' +
                '<td>' + escapeHtml(it.resolution || '') + (it.last_error ? ' <span class="text-muted">' + escapeHtml(it.last_error) + '</span>' : '') + '</td>' +
                '<td>' + (canManage && CustodyView.isResolvable(it.status)
                    ? '<button type="button" class="button tiny secondary intent-resolve" data-idx="' + i + '">Resolve</button>'
                    : '') + '</td></tr>';
        });
        html += '</tbody></table></div>';
        container.innerHTML = html;
        container.querySelectorAll('.intent-resolve').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openResolveModal(rows[parseInt(btn.getAttribute('data-idx'), 10)]);
            });
        });
        pager(res, 'intents-pagination', function (p) { state.intentsPage = p; loadIntents().catch(showError); });
    }

    function openResolveModal(intent) {
        Modal.open({
            title: 'Resolve intent',
            bodyHtml:
                '<p class="mono" id="resolve-id"></p>' +
                '<p><strong>complete</strong>: the bridge verifies the signed hash settled on Horizon (optionally a different settling hash) and records the ledger row. ' +
                '<strong>fail</strong>: allowed only 600s after arming AND when a fresh Horizon proves the hash failed or never landed.</p>' +
                '<label><input type="radio" name="resolve-action" value="complete" checked> complete</label>' +
                '<label><input type="radio" name="resolve-action" value="fail"> fail</label>' +
                '<label>Settling transaction hash (optional, complete only)<input type="text" id="resolve-hash" autocomplete="off"></label>' +
                '<p class="text-muted" id="resolve-error" role="alert"></p>',
            confirmLabel: 'Resolve',
            confirmClass: 'alert',
            onConfirm: function (dialog, helpers) {
                var action = dialog.querySelector('input[name="resolve-action"]:checked').value;
                var hash = dialog.querySelector('#resolve-hash').value.trim();
                var body = { action: action };
                if (hash && action === 'complete') body.stellar_hash = hash;
                var errEl = dialog.querySelector('#resolve-error');
                API.setButtonLoading(helpers.button, true);
                API.post('/admin/custody/intents/' + encodeURIComponent(intent.intent_id) + '/resolve', body).then(function (res) {
                    helpers.close();
                    Router.showToast('Intent ' + ((res && res.status) || 'resolved'), 'success');
                    return Promise.all([loadIntents(), loadPolicy()]);
                }).catch(function (err) {
                    API.setButtonLoading(helpers.button, false);
                    errEl.textContent = explain(err);
                });
            }
        }).dialog.querySelector('#resolve-id').textContent = intent.intent_id + ' — ' + intent.status + ' — ' + (intent.stellar_hash || '');
    }

    /* ---- accounts -------------------------------------------------------- */

    function loadAccounts() {
        return API.get('/admin/custody/accounts?page=' + state.accountsPage + '&per_page=' + PER_PAGE).then(function (res) {
            state.accounts = res;
            renderAccounts();
        });
    }

    function renderAccounts() {
        var res = state.accounts;
        if (!res) return;
        var rows = res.data || [];
        var container = document.getElementById('custody-accounts');
        if (!rows.length) {
            container.innerHTML = '<p class="text-muted">No custodial accounts.</p>';
            return;
        }
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Account</th><th>Stellar address</th><th>Origin</th><th>Daily override</th><th></th>' +
            '</tr></thead><tbody>';
        rows.forEach(function (a, i) {
            var override = a.custodial_daily_max_stroops;
            var overrideText = override === null || override === undefined
                ? badge('neutral', 'global cap')
                : (override === 0 ? badge('error', 'frozen (0)') : badge('ok', String(override) + ' stroops'));
            html += '<tr>' +
                '<td class="mono">' + escapeHtml(a.payala_account_id) + '</td>' +
                '<td class="mono">' + escapeHtml(a.stellar_account_id) + '</td>' +
                '<td>' + escapeHtml(a.origin) + '</td>' +
                '<td>' + overrideText + '</td>' +
                '<td>' + (canManage ? '<button type="button" class="button tiny secondary account-limit" data-idx="' + i + '">Set limit</button>' : '') + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div>';
        container.innerHTML = html;
        container.querySelectorAll('.account-limit').forEach(function (btn) {
            btn.addEventListener('click', function () {
                openLimitModal(rows[parseInt(btn.getAttribute('data-idx'), 10)]);
            });
        });
        pager(res, 'accounts-pagination', function (p) { state.accountsPage = p; loadAccounts().catch(showError); });
    }

    function openLimitModal(account) {
        var handle = Modal.open({
            title: 'Per-account daily limit',
            bodyHtml:
                '<p class="mono" id="limit-account"></p>' +
                '<p class="text-muted">Integer stroops. 0 freezes the account; clear the field to remove the override (global cap applies).</p>' +
                '<label>Daily cap (stroops)<input type="text" id="limit-value" inputmode="numeric" autocomplete="off"></label>' +
                '<p class="text-muted" id="limit-error" role="alert"></p>',
            confirmLabel: 'Save limit',
            onConfirm: function (dialog, helpers) {
                var raw = dialog.querySelector('#limit-value').value;
                var errEl = dialog.querySelector('#limit-error');
                var body = { custodial_daily_max_stroops: null };
                if (raw.trim() !== '') {
                    var v = CustodyView.validateStroops(raw);
                    if (!v.ok) { errEl.textContent = v.error; return; }
                    body.custodial_daily_max_stroops = v.value;
                }
                API.setButtonLoading(helpers.button, true);
                API.put('/admin/custody/accounts/' + encodeURIComponent(account.payala_account_id) + '/limit', body).then(function () {
                    helpers.close();
                    Router.showToast('Account limit updated', 'success');
                    return loadAccounts();
                }).catch(function (err) {
                    API.setButtonLoading(helpers.button, false);
                    errEl.textContent = explain(err);
                });
            }
        });
        handle.dialog.querySelector('#limit-account').textContent = account.payala_account_id;
        var current = account.custodial_daily_max_stroops;
        handle.dialog.querySelector('#limit-value').value = (current === null || current === undefined) ? '' : String(current);
    }

    /* ---- snapshots ------------------------------------------------------- */

    function loadSnapshots() {
        return API.get('/admin/reconciliation/snapshots?page=' + state.snapshotsPage + '&per_page=' + PER_PAGE).then(function (res) {
            state.snapshots = res;
            renderSnapshots();
        });
    }

    function renderSnapshots() {
        var res = state.snapshots;
        if (!res) return;
        var rows = res.data || [];
        var container = document.getElementById('custody-snapshots');
        if (!rows.length) {
            container.innerHTML = '<p class="text-muted">No snapshots yet. The daily job records one per UTC date.</p>';
            return;
        }
        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Date</th><th>Kind</th><th>As of</th><th>Verdict</th><th>Horizon</th><th>Complete</th><th>By</th><th>Id</th>' +
            '</tr></thead><tbody>';
        rows.forEach(function (s) {
            var b = CustodyView.snapshotBadge(s);
            html += '<tr>' +
                '<td>' + escapeHtml(s.snapshot_date) + '</td>' +
                '<td>' + escapeHtml(s.kind) + '</td>' +
                '<td>' + escapeHtml(s.as_of || '') + '</td>' +
                '<td>' + badge(b.cls, b.label) + '</td>' +
                '<td>' + (s.horizon_fresh ? badge('ok', 'fresh') : badge('pending', 'lagging')) + '</td>' +
                '<td>' + (s.complete ? badge('ok', 'yes') : badge('pending', 'partial')) + '</td>' +
                '<td>' + escapeHtml(s.created_by || 'job') + '</td>' +
                '<td class="mono">' + escapeHtml(s.snapshot_id) + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div>';
        container.innerHTML = html;
        pager(res, 'snapshots-pagination', function (p) { state.snapshotsPage = p; loadSnapshots().catch(showError); });
    }

    function runSnapshot() {
        var btn = document.getElementById('snapshot-run');
        API.setButtonLoading(btn, true);
        API.post('/admin/reconciliation/snapshots', {}).then(function (res) {
            API.setButtonLoading(btn, false);
            Router.showToast('Snapshot recorded' + (res && res.attested ? ' (attested)' : ' (unattested — see the row)'),
                res && res.attested ? 'success' : 'warning');
            state.snapshotsPage = 1;
            return loadSnapshots();
        }).catch(function (err) {
            API.setButtonLoading(btn, false);
            showError(err);
        });
    }

    /* ---- wiring ---------------------------------------------------------- */

    var statusSelect = document.getElementById('intent-status');
    ['prepared', 'submitted', 'ambiguous', 'settled', 'rejected'].forEach(function (s) {
        var opt = document.createElement('option');
        opt.value = s;
        opt.textContent = s;
        statusSelect.appendChild(opt);
    });
    statusSelect.addEventListener('change', function () {
        state.intentStatus = statusSelect.value;
        state.intentsPage = 1;
        loadIntents().catch(showError);
    });

    if (canManage) {
        document.getElementById('policy-edit').addEventListener('click', openCapsModal);
        document.getElementById('policy-pause').addEventListener('click', openPauseModal);
        document.getElementById('snapshot-run').addEventListener('click', runSnapshot);
    }
    if (isAdmin) {
        document.getElementById('policy-resume').addEventListener('click', openResumeModal);
    }
    if (!canManage) {
        Router.showReadOnlyBanner('Custody actions', 'the admin or treasurer role');
    }

    loadPolicy().catch(showError);
    loadIntents().catch(showError);
    loadAccounts().catch(showError);
    loadSnapshots().catch(showError);
})();

/**
 * Accounts console — server-paged account list with a detail drawer.
 *
 * Lists accounts via GET /accounts (admin), opens a per-account drawer
 * (GET /account) showing the full profile, a role-grant control
 * (PUT /admin/accounts/:id/role), directory force-sync
 * (POST /admin/accounts/:id/sync-profile) and on-chain details
 * (GET /account/onchain). Create / edit use a modal against the real bridge
 * fields; delete uses a confirm modal against DELETE /admin/accounts/:id.
 *
 * All actions are permission-gated: view_accounts (view), manage_accounts
 * (create/edit), delete_accounts (delete), manage_roles (grant role),
 * sync_profile (force-sync).
 */
(function () {
    Router.init();

    var PAGE_SIZE = 10;
    var currentPage = 1;
    var currentSearch = '';

    var listContainer = document.getElementById('accounts-list');
    var paginationContainer = 'accounts-pagination';
    var searchInput = document.getElementById('accounts-search');
    var searchBtn = document.getElementById('accounts-search-btn');
    var newBtn = document.getElementById('new-account-btn');

    var GENDERS = ['', 'male', 'female', 'other', 'unspecified'];

    if (searchBtn) {
        searchBtn.addEventListener('click', function () {
            currentSearch = searchInput.value.trim();
            currentPage = 1;
            loadList();
        });
    }
    if (searchInput) {
        searchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                currentSearch = searchInput.value.trim();
                currentPage = 1;
                loadList();
            }
        });
    }
    if (newBtn) {
        newBtn.addEventListener('click', function () { openCreateModal(); });
    }

    loadList();

    /* ---- list ------------------------------------------------------------ */

    function loadList() {
        renderSkeleton();
        var qs = 'page=' + currentPage + '&per_page=' + PAGE_SIZE;
        if (currentSearch) qs += '&search=' + encodeURIComponent(currentSearch);

        API.get('/accounts?' + qs)
            .then(function (resp) {
                renderTable(resp);
            })
            .catch(function (err) {
                if (err && err.status === 403) {
                    listContainer.innerHTML = emptyState('🔒', 'Your role cannot list accounts',
                        'The accounts list requires the admin, auditor, or key-custodian role. If you need it, an admin can change your role from this page.');
                } else {
                    listContainer.innerHTML = '<div class="callout alert">' + escapeHtml(err.message) + '</div>';
                }
                document.getElementById(paginationContainer).innerHTML = '';
            });
    }

    function renderSkeleton() {
        var rows = '';
        for (var i = 0; i < 5; i++) rows += '<div class="skeleton skeleton-row"></div>';
        listContainer.innerHTML = rows;
        var pag = document.getElementById(paginationContainer);
        if (pag) pag.innerHTML = '';
    }

    function renderTable(resp) {
        var items = (resp && resp.data) || [];
        var total = (resp && typeof resp.total === 'number') ? resp.total : items.length;

        if (items.length === 0) {
            listContainer.innerHTML = emptyState('👤', 'No accounts found',
                currentSearch ? 'No accounts match your search.' : 'No accounts have been created yet.');
            document.getElementById(paginationContainer).innerHTML = '';
            return;
        }

        var canEdit = Roles.currentUserHasPermission('manage_accounts');
        var canDelete = Roles.currentUserHasPermission('delete_accounts');

        var html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Name</th><th>Payala ID</th><th>Stellar ID</th><th>Role</th><th>Source</th><th>Created</th><th>Actions</th>' +
            '</tr></thead><tbody>';

        items.forEach(function (a, idx) {
            html += '<tr>' +
                '<td>' + escapeHtml(displayName(a)) + '</td>' +
                '<td class="mono">' + escapeHtml(a.payala_account_id || '') + '</td>' +
                '<td class="mono nowrap" title="' + escapeHtml(a.stellar_account_id || '') + '">' + escapeHtml(truncate(a.stellar_account_id, 14)) + '</td>' +
                '<td>' + roleBadge(a.role, a.allowlisted) + '</td>' +
                '<td>' + sourceBadge(a.profile_source) + '</td>' +
                '<td class="nowrap">' + escapeHtml(formatDate(a.created_at)) + '</td>' +
                '<td><div class="row-actions">' +
                '<button class="button ghost tiny view-btn" data-idx="' + idx + '">View</button>' +
                (canEdit ? '<button class="button ghost tiny edit-btn" data-idx="' + idx + '">Edit</button>' : '') +
                (canDelete ? '<button class="button alert tiny delete-btn" data-idx="' + idx + '">Delete</button>' : '') +
                '</div></td>' +
                '</tr>';
        });

        html += '</tbody></table></div>';
        listContainer.innerHTML = html;

        bindRowButtons('.view-btn', items, function (a) { openDrawer(a); });
        bindRowButtons('.edit-btn', items, function (a) { openEditModal(a); });
        bindRowButtons('.delete-btn', items, function (a) { confirmDelete(a); });

        var totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        var info = { page: currentPage, pageSize: PAGE_SIZE, totalPages: totalPages, totalItems: total };
        Paginate.renderControls(info, paginationContainer, function (newPage) {
            currentPage = newPage;
            loadList();
        });
    }

    function bindRowButtons(selector, items, fn) {
        var btns = listContainer.querySelectorAll(selector);
        for (var i = 0; i < btns.length; i++) {
            btns[i].addEventListener('click', function () {
                var a = items[parseInt(this.getAttribute('data-idx'), 10)];
                if (a) fn(a);
            });
        }
    }

    /* ---- drawer (detail) ------------------------------------------------- */

    function openDrawer(listItem) {
        var drawer = Drawer.open({
            title: displayName(listItem),
            bodyHtml: '<div class="skeleton skeleton-line"></div><div class="skeleton skeleton-line"></div>' +
                '<div class="skeleton skeleton-line short"></div>'
        });
        fetchDetail(listItem.stellar_account_id, drawer);
    }

    function fetchDetail(stellarId, drawer) {
        API.get('/account?stellar_account_id=' + encodeURIComponent(stellarId))
            .then(function (acct) {
                renderDetail(acct, drawer);
            })
            .catch(function (err) {
                drawer.setBody('<div class="callout alert">' + escapeHtml(err.message) + '</div>');
            });
    }

    function renderDetail(acct, drawer) {
        drawer.setTitle(displayName(acct));

        var html = '<dl class="detail-grid">' +
            field('Payala ID', acct.payala_account_id, true) +
            field('Stellar ID', acct.stellar_account_id, true) +
            field('First name', acct.first_name) +
            field('Middle name', acct.middle_name) +
            field('Last name', acct.last_name) +
            field('Nickname', acct.nickname) +
            field('Affiliation', acct.affiliation) +
            field('Gender', acct.gender) +
            '<dt>Role</dt><dd>' + roleBadge(acct.role, acct.allowlisted) + '</dd>' +
            '</dl>';

        // Role grant
        if (Roles.currentUserHasPermission('manage_roles')) {
            var isSelf = acct.payala_account_id && acct.payala_account_id === Auth.getUsername();
            html += '<div class="detail-section"><h6>Role grant</h6>';
            html += '<div class="grid-x grid-margin-x"><div class="cell auto">' +
                '<select id="drawer-role"' + (isSelf ? ' disabled title="You cannot change your own role"' : '') + '>';
            var roleKnown = Roles.isKnownRole(acct.role);
            if (!roleKnown) {
                html += '<option value="" selected disabled>Unknown role: ' +
                    escapeHtml(String(acct.role)) + ' (update the UI before changing it)</option>';
            }
            Object.keys(Roles.DEFINITIONS).forEach(function (r) {
                html += '<option value="' + r + '"' + (roleKnown && r === acct.role ? ' selected' : '') + '>' +
                    escapeHtml(Roles.DEFINITIONS[r].label) + '</option>';
            });
            html += '</select></div><div class="cell shrink">' +
                '<button class="button" id="drawer-role-btn"' + (isSelf ? ' disabled' : '') + '>Update role</button>' +
                '</div></div>';
            if (isSelf) html += '<p class="text-muted" style="font-size:0.8rem;">Changing your own role is disabled to prevent self-lockout.</p>';
            html += '</div>';
        }

        // Directory profile + force-sync
        html += '<div class="detail-section"><h6>Directory profile</h6>' +
            '<dl class="detail-grid">' +
            '<dt>Source</dt><dd>' + sourceBadge(acct.profile_source) + '</dd>' +
            '<dt>Synced</dt><dd>' + escapeHtml(acct.profile_synced_at ? formatDate(acct.profile_synced_at) : 'Never') + '</dd>' +
            '</dl>';
        if (Roles.currentUserHasPermission('sync_profile')) {
            html += '<button class="button ghost" id="drawer-sync-btn">Force directory sync</button>';
        }
        html += '</div>';

        // On-chain panel
        html += '<div class="detail-section"><h6>On-chain details</h6>' +
            '<div id="onchain-panel"><p class="text-muted">Not loaded yet.</p></div>' +
            '<button class="button ghost" id="drawer-onchain-btn">Refresh on-chain details</button>' +
            '</div>';

        drawer.setBody(html);

        wireDrawer(acct, drawer);
    }

    function wireDrawer(acct, drawer) {
        var roleBtn = drawer.body.querySelector('#drawer-role-btn');
        if (roleBtn) {
            roleBtn.addEventListener('click', function () {
                var sel = drawer.body.querySelector('#drawer-role');
                var newRole = sel.value;
                if (!newRole) {
                    Router.showToast('Pick a role first — this account holds a role this UI build does not know.', 'warning');
                    return;
                }
                if (acct.payala_account_id === Auth.getUsername() && newRole !== 'admin') {
                    Router.showToast('You cannot demote your own admin role', 'warning');
                    return;
                }
                API.setButtonLoading(roleBtn, true);
                API.put('/admin/accounts/' + encodeURIComponent(acct.payala_account_id) + '/role', { role: newRole })
                    .then(function (res) {
                        // An allowlisted target keeps issuing admin tokens no
                        // matter what was stored — that warning must persist,
                        // not vanish in a 4-second success toast.
                        var severity = (res && res.allowlisted && newRole !== 'admin') ? 'alert' : 'success';
                        Router.showToast(res.message || 'Role updated', severity);
                        acct.role = (res && res.role) || newRole;
                        loadList();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(roleBtn, false); });
            });
        }

        var syncBtn = drawer.body.querySelector('#drawer-sync-btn');
        if (syncBtn) {
            syncBtn.addEventListener('click', function () {
                API.setButtonLoading(syncBtn, true);
                API.post('/admin/accounts/' + encodeURIComponent(acct.payala_account_id) + '/sync-profile')
                    .then(function (res) {
                        Router.showToast(res.message || 'Profile synced', 'success');
                        fetchDetail(acct.stellar_account_id, drawer);
                        loadList();
                    })
                    .catch(function (err) { Router.showToast('Sync failed: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(syncBtn, false); });
            });
        }

        var onchainBtn = drawer.body.querySelector('#drawer-onchain-btn');
        if (onchainBtn) {
            onchainBtn.addEventListener('click', function () {
                var panel = drawer.body.querySelector('#onchain-panel');
                panel.innerHTML = '<div class="skeleton skeleton-line"></div><div class="skeleton skeleton-line short"></div>';
                API.setButtonLoading(onchainBtn, true);
                API.get('/account/onchain?stellar_account_id=' + encodeURIComponent(acct.stellar_account_id))
                    .then(function (data) { panel.innerHTML = renderOnchain(data); })
                    .catch(function (err) { panel.innerHTML = '<div class="callout alert">' + escapeHtml(err.message) + '</div>'; })
                    .then(function () { API.setButtonLoading(onchainBtn, false); });
            });
        }
    }

    function renderOnchain(data) {
        if (!data || data.exists === false) {
            return '<p>' + '<span class="badge error">Not funded</span> ' +
                'This account does not exist on-chain yet.</p>';
        }
        var balances = data.balances || [];
        var html = '<dl class="detail-grid">' +
            '<dt>Status</dt><dd><span class="badge ok">Exists</span></dd>' +
            '<dt>Sequence</dt><dd class="mono">' + escapeHtml(String(data.sequence == null ? '' : data.sequence)) + '</dd>' +
            '<dt>Native (XLM)</dt><dd class="mono">' + escapeHtml(String(data.native_balance == null ? '' : data.native_balance)) + '</dd>' +
            '<dt>Subentries</dt><dd>' + escapeHtml(String(data.subentry_count == null ? '' : data.subentry_count)) + '</dd>' +
            '</dl>';
        if (balances.length) {
            html += '<div class="table-wrap"><table><thead><tr><th>Asset</th><th>Balance</th></tr></thead><tbody>';
            balances.forEach(function (b) {
                var asset = b.asset_type === 'native' ? 'XLM (native)' : (b.asset_code || b.asset_type || '');
                html += '<tr><td>' + escapeHtml(asset) + '</td><td class="mono">' + escapeHtml(String(b.balance == null ? '' : b.balance)) + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        if ((data.signers || []).length) {
            html += '<h6 style="margin-top:0.75rem;">Signers</h6><div class="table-wrap"><table><thead><tr><th>Key</th><th>Weight</th></tr></thead><tbody>';
            data.signers.forEach(function (s) {
                html += '<tr><td class="mono" title="' + escapeHtml(s.key || '') + '">' + escapeHtml(truncate(s.key, 16)) + '</td><td>' + escapeHtml(String(s.weight == null ? '' : s.weight)) + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }
        return html;
    }

    /* ---- create / edit modals ------------------------------------------- */

    function accountFormHtml(prefix, a, lockStellar) {
        a = a || {};
        function input(name, label, value, attrs) {
            return '<label>' + escapeHtml(label) +
                '<input type="text" id="' + prefix + '-' + name + '" value="' + escapeHtml(value || '') + '"' + (attrs || '') + '></label>';
        }
        var genderOpts = GENDERS.map(function (g) {
            return '<option value="' + g + '"' + (g === (a.gender || '') ? ' selected' : '') + '>' + (g === '' ? '—' : escapeHtml(g)) + '</option>';
        }).join('');

        return input('stellar', 'Stellar Account ID', a.stellar_account_id, lockStellar ? ' readonly' : '') +
            input('payala', 'Payala Account ID', a.payala_account_id, lockStellar ? ' readonly' : '') +
            input('first', 'First name', a.first_name) +
            input('middle', 'Middle name', a.middle_name) +
            input('last', 'Last name', a.last_name) +
            input('nickname', 'Nickname', a.nickname) +
            input('affiliation', 'Affiliation', a.affiliation) +
            '<label>Gender<select id="' + prefix + '-gender">' + genderOpts + '</select></label>';
    }

    function readForm(prefix) {
        function val(name) {
            var el = document.getElementById(prefix + '-' + name);
            return el ? el.value.trim() : '';
        }
        return {
            stellar_account_id: val('stellar'),
            payala_account_id: val('payala'),
            first_name: val('first'),
            middle_name: val('middle'),
            last_name: val('last'),
            nickname: val('nickname'),
            affiliation: val('affiliation'),
            gender: val('gender')
        };
    }

    function openCreateModal() {
        Modal.open({
            title: 'Create account',
            bodyHtml: accountFormHtml('create', {}, false),
            confirmLabel: 'Create',
            onConfirm: function (dialog, helpers) {
                var form = readForm('create');
                var error = Validate.firstError([
                    Validate.stellarId(form.stellar_account_id),
                    Validate.required(form.payala_account_id),
                    Validate.required(form.first_name),
                    Validate.required(form.last_name)
                ]);
                if (error) { Router.showToast(error, 'warning'); return; }

                var body = {
                    stellar_account_id: form.stellar_account_id,
                    payala_account_id: form.payala_account_id,
                    first_name: form.first_name,
                    last_name: form.last_name,
                    middle_name: form.middle_name || undefined,
                    nickname: form.nickname || undefined,
                    affiliation: form.affiliation || undefined,
                    gender: form.gender || undefined
                };
                API.setButtonLoading(helpers.button, true);
                API.post('/account', body)
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Account created', 'success');
                        helpers.close();
                        loadList();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    function openEditModal(a) {
        Modal.open({
            title: 'Edit account',
            bodyHtml: accountFormHtml('edit', a, true),
            confirmLabel: 'Save',
            onConfirm: function (dialog, helpers) {
                var form = readForm('edit');
                var error = Validate.firstError([
                    Validate.stellarId(form.stellar_account_id),
                    Validate.required(form.first_name),
                    Validate.required(form.last_name)
                ]);
                if (error) { Router.showToast(error, 'warning'); return; }

                var body = {
                    stellar_account_id: form.stellar_account_id,
                    first_name: form.first_name,
                    last_name: form.last_name,
                    middle_name: form.middle_name || undefined,
                    nickname: form.nickname || undefined,
                    affiliation: form.affiliation || undefined,
                    gender: form.gender || undefined
                };
                API.setButtonLoading(helpers.button, true);
                API.put('/account', body)
                    .then(function (res) {
                        Router.showToast((res && res.message) || 'Account updated', 'success');
                        helpers.close();
                        loadList();
                    })
                    .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); })
                    .then(function () { API.setButtonLoading(helpers.button, false); });
            }
        });
    }

    function confirmDelete(a) {
        Modal.confirm({
            title: 'Delete account',
            message: 'Permanently delete ' + displayName(a) + ' (' + (a.payala_account_id || a.stellar_account_id) + ')? This cannot be undone.',
            confirmLabel: 'Delete',
            confirmClass: 'alert'
        }).then(function (ok) {
            if (!ok) return;
            API.del('/admin/accounts/' + encodeURIComponent(a.payala_account_id))
                .then(function (res) {
                    Router.showToast((res && res.message) || 'Account deleted', 'success');
                    loadList();
                })
                .catch(function (err) { Router.showToast('Error: ' + err.message, 'alert'); });
        });
    }

    /* ---- helpers --------------------------------------------------------- */

    function displayName(a) {
        if (a.nickname) return a.nickname;
        var full = [a.first_name, a.last_name].filter(Boolean).join(' ').trim();
        return full || a.payala_account_id || a.stellar_account_id || 'Account';
    }

    function field(label, value, mono) {
        if (value == null || value === '') return '';
        return '<dt>' + escapeHtml(label) + '</dt><dd' + (mono ? ' class="mono"' : '') + '>' + escapeHtml(value) + '</dd>';
    }

    function roleBadge(role, allowlisted) {
        // An unknown role (bridge deployed ahead of this UI) must NEVER wear
        // another role's badge: an admin verifying a grant would read a
        // treasurer as "View Only" and might "fix" it — an accidental
        // demotion. Show the raw name on a neutral badge instead.
        var known = Roles.isKnownRole(role);
        var label = known ? Roles.getDefinition(role).label : String(role || 'unknown');
        var html = '<span class="role-badge ' + (known ? escapeHtml(role) : 'unknown') + '">' +
            escapeHtml(label) + '</span>';
        if (allowlisted) {
            // The env allowlist overrides the DB role to admin at issuance —
            // the badge must show effective privilege, not a comfortable lie.
            html += ' <span class="badge warning" title="On the ADMIN_ACCOUNT_IDS allowlist: ' +
                'this account receives admin tokens regardless of its stored role.">effective admin</span>';
        }
        return html;
    }

    function sourceBadge(source) {
        source = source || 'local';
        return '<span class="badge neutral">' + escapeHtml(source) + '</span>';
    }

    function emptyState(icon, title, msg) {
        return '<div class="empty-state"><span class="empty-icon" aria-hidden="true">' + icon + '</span>' +
            '<h6>' + escapeHtml(title) + '</h6><p>' + escapeHtml(msg) + '</p></div>';
    }

    function truncate(str, len) {
        if (!str) return '';
        return str.length > len ? str.substring(0, len) + '…' : str;
    }

    function formatDate(value) {
        if (!value) return '';
        var d = new Date(value);
        return isNaN(d.getTime()) ? String(value) : d.toLocaleString();
    }

    // Delegates to the shared escaper: a text-node round trip escapes & < >
    // but NOT quotes, so values interpolated into double-quoted attributes
    // (value="...", title="...") could break out and inject attributes.
    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }
})();

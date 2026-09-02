/**
 * Roles page — read-only Roles & Permissions reference (any view_roles
 * holder: every privileged role).
 *
 * Authorization is server-driven now; role grants happen in the Accounts drawer
 * (PUT /admin/accounts/:id/role). This page just documents the role → permission
 * matrix from Roles.DEFINITIONS so operators can see what each role can do.
 */
(function () {
    Router.init();
    // The roles reference is documentation: every privileged role may read
    // it (the nav shows it to view_roles holders — the guard must match).
    if (!Router.requirePermission('view_roles', 'Roles & Permissions')) return;

    renderRoleDefinitions();
    renderPermissionMatrix();

    /**
     * One-line "who should hold this" guidance for the ladder roles, which
     * carry no description in DEFINITIONS (the lateral roles and admin do).
     */
    var LADDER_GUIDANCE = {
        'view-only': 'Default least privilege: read-only dashboards and support lookups.',
        'device': 'Transaction-creating devices — terminals and kiosks that also manage cards.',
        'token': 'Account and MFA management tokens for provisioning integrations.',
        'admin': 'Full governance: role grants, account deletion, and every privileged surface.'
    };

    /**
     * Render a card per role — badge and "who should hold this" guidance
     * (the role's description from DEFINITIONS where present). The exact
     * permission sets live in the matrix below, so the cards stay prose.
     */
    function renderRoleDefinitions() {
        var defs = Roles.DEFINITIONS;
        var html = '<div class="grid-x grid-margin-x">';
        Object.keys(defs).forEach(function (key) {
            var def = defs[key];
            var guidance = def.description || LADDER_GUIDANCE[key] || '';
            html += '<div class="cell medium-6 large-4">' +
                '<div class="card"><div class="card-section">' +
                '<span class="role-badge ' + escapeHtml(key) + '">' + escapeHtml(def.label) + '</span>' +
                '<p class="text-muted" style="margin:0.5rem 0 0;font-size:0.9rem;">' + escapeHtml(guidance) + '</p>' +
                '</div></div></div>';
        });
        html += '</div>';
        document.getElementById('role-definitions').innerHTML = html;
    }

    function renderPermissionMatrix() {
        var el = document.getElementById('permission-matrix');
        if (!el) return;

        var defs = Roles.DEFINITIONS;
        var roleKeys = Object.keys(defs);

        // Collect the union of all permissions, preserving first-seen order.
        var perms = [];
        roleKeys.forEach(function (rk) {
            defs[rk].permissions.forEach(function (p) {
                if (perms.indexOf(p) === -1) perms.push(p);
            });
        });
        perms.sort();

        var html = '<p class="text-muted">UI gating only — the bridge enforces capabilities server-side on every request.</p>';
        html += '<div class="table-wrap"><table><thead><tr><th>Permission</th>';
        roleKeys.forEach(function (rk) {
            html += '<th>' + escapeHtml(defs[rk].label) + '</th>';
        });
        html += '</tr></thead><tbody>';

        perms.forEach(function (perm) {
            html += '<tr><td class="mono">' + escapeHtml(perm) + '</td>';
            roleKeys.forEach(function (rk) {
                var has = Roles.roleHasPermission(rk, perm);
                html += '<td>' + (has ? '<span class="badge ok">✓</span>' : '<span class="text-muted">—</span>') + '</td>';
            });
            html += '</tr>';
        });

        html += '</tbody></table></div>';
        el.innerHTML = html;
    }

    // Delegates to the shared escaper: a text-node round trip escapes & < >
    // but NOT quotes, so values interpolated into double-quoted attributes
    // (value="...", title="...") could break out and inject attributes.
    function escapeHtml(str) {
        return EscapeHtml.escape(str);
    }
})();

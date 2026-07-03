/**
 * Admin page — read-only Roles & Permissions reference (admin-only).
 *
 * Authorization is server-driven now; role grants happen in the Accounts drawer
 * (PUT /admin/accounts/:id/role). This page just documents the role → permission
 * matrix from Roles.DEFINITIONS so operators can see what each role can do.
 */
(function () {
    Router.init();
    if (!Router.requireAdmin()) return;

    renderRoleDefinitions();
    renderPermissionMatrix();

    function renderRoleDefinitions() {
        var defs = Roles.DEFINITIONS;
        var html = '<div class="table-wrap"><table><thead><tr><th>Role</th><th>Permissions</th></tr></thead><tbody>';
        Object.keys(defs).forEach(function (key) {
            var def = defs[key];
            html += '<tr>' +
                '<td><span class="role-badge ' + escapeHtml(key) + '">' + escapeHtml(def.label) + '</span></td>' +
                '<td>' + def.permissions.map(function (p) { return '<span class="badge neutral">' + escapeHtml(p) + '</span>'; }).join(' ') + '</td>' +
                '</tr>';
        });
        html += '</tbody></table></div>';
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

        var html = '<div class="table-wrap"><table><thead><tr><th>Permission</th>';
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

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str == null ? '' : str));
        return div.innerHTML;
    }
})();

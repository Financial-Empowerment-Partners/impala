/**
 * Admin page module — manage role assignments (admin-only).
 *
 * Displays role definitions with their permission sets, lists all current
 * role assignments with pagination, and allows assigning/removing roles.
 * The current user cannot modify their own role (self-demotion prevention).
 * Role changes and removals require confirmation.
 */
(function () {
    Router.init();
    if (!Router.requireAdmin()) return;

    var PAGE_SIZE = 10;
    var currentPage = 1;

    renderRoleDefinitions();
    renderAssignments();

    var assignForm = document.getElementById('assign-form');

    assignForm.addEventListener('submit', function (e) {
        e.preventDefault();

        var accountId = document.getElementById('assign-account-id').value.trim();
        var role = document.getElementById('assign-role').value;

        var error = Validate.firstError([
            Validate.required(accountId)
        ]);
        if (error) {
            Router.showToast('Please enter an account ID', 'warning');
            return;
        }

        if (!confirm('Are you sure you want to assign role "' + role + '" to ' + accountId + '?')) {
            return;
        }

        Roles.setRole(accountId, role);
        Router.showToast('Role assigned: ' + accountId + ' \u2192 ' + role, 'success');
        assignForm.reset();
        renderAssignments();
    });

    function renderRoleDefinitions() {
        var defs = Roles.DEFINITIONS;
        var html = '<table><thead><tr><th>Role</th><th>Permissions</th></tr></thead><tbody>';

        Object.keys(defs).forEach(function (key) {
            var def = defs[key];
            html += '<tr>' +
                '<td><span class="role-badge ' + key + '">' + escapeHtml(def.label) + '</span></td>' +
                '<td>' + def.permissions.join(', ') + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        document.getElementById('role-definitions').innerHTML = html;
    }

    function renderAssignments() {
        var assignments = Roles.getAllAssignments();
        var keys = Object.keys(assignments);

        if (keys.length === 0) {
            document.getElementById('role-assignments').innerHTML =
                '<div class="callout primary">No role assignments yet.</div>';
            return;
        }

        var info = Paginate.paginate(keys, currentPage, PAGE_SIZE);

        var html = '<table><thead><tr><th>Account ID</th><th>Role</th><th>Actions</th></tr></thead><tbody>';

        info.items.forEach(function (accountId) {
            var role = assignments[accountId];
            var currentUser = Auth.getUsername();
            var isSelf = accountId === currentUser;

            html += '<tr>' +
                '<td>' + escapeHtml(accountId) + (isSelf ? ' <em>(you)</em>' : '') + '</td>' +
                '<td>' +
                '<select class="role-select" data-account="' + escapeHtml(accountId) + '"' +
                (isSelf ? ' disabled title="Cannot change your own role"' : '') + '>';

            Object.keys(Roles.DEFINITIONS).forEach(function (r) {
                html += '<option value="' + r + '"' + (r === role ? ' selected' : '') + '>' +
                    Roles.DEFINITIONS[r].label + '</option>';
            });

            html += '</select></td>' +
                '<td>';
            if (!isSelf) {
                html += '<button class="button small alert remove-role-btn" data-account="' +
                    escapeHtml(accountId) + '">Remove</button>';
            }
            html += '</td></tr>';
        });

        html += '</tbody></table>';
        html += '<div id="admin-pagination"></div>';
        document.getElementById('role-assignments').innerHTML = html;

        Paginate.renderControls(info, 'admin-pagination', function (newPage) {
            currentPage = newPage;
            renderAssignments();
        });

        // Bind change handlers with confirmation
        var selects = document.querySelectorAll('.role-select');
        for (var i = 0; i < selects.length; i++) {
            selects[i].addEventListener('change', function () {
                var acct = this.getAttribute('data-account');
                var newRole = this.value;
                if (!confirm('Are you sure you want to change this user\'s role?')) {
                    // Revert to previous value
                    this.value = Roles.getRole(acct);
                    return;
                }
                Roles.setRole(acct, newRole);
                Router.showToast('Role updated: ' + acct + ' \u2192 ' + newRole, 'success');
            });
        }

        // Bind remove handlers with confirmation
        var removeBtns = document.querySelectorAll('.remove-role-btn');
        for (var j = 0; j < removeBtns.length; j++) {
            removeBtns[j].addEventListener('click', function () {
                var acct = this.getAttribute('data-account');
                if (!confirm('Are you sure you want to remove the role for ' + acct + '?')) {
                    return;
                }
                Roles.removeRole(acct);
                Router.showToast('Role removed: ' + acct, 'info');
                renderAssignments();
            });
        }
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();

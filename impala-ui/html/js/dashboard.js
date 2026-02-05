(function () {
    Router.init();

    // Version info
    API.get('/version')
        .then(function (data) {
            var html = '<table>' +
                '<tbody>';
            if (data.build_date) html += '<tr><td><strong>Build Date</strong></td><td>' + escapeHtml(data.build_date) + '</td></tr>';
            if (data.rustc_version) html += '<tr><td><strong>Rust Version</strong></td><td>' + escapeHtml(data.rustc_version) + '</td></tr>';
            if (data.schema_version !== undefined) html += '<tr><td><strong>Schema Version</strong></td><td>' + escapeHtml(String(data.schema_version)) + '</td></tr>';
            // Show any other fields
            Object.keys(data).forEach(function (key) {
                if (['build_date', 'rustc_version', 'schema_version'].indexOf(key) === -1) {
                    html += '<tr><td><strong>' + escapeHtml(key) + '</strong></td><td>' + escapeHtml(String(data[key])) + '</td></tr>';
                }
            });
            html += '</tbody></table>';
            document.getElementById('version-info').innerHTML = html;
        })
        .catch(function (err) {
            document.getElementById('version-info').innerHTML =
                '<span class="badge error">Error</span> ' + escapeHtml(err.message);
        });

    // Health check
    fetch('/api/version')
        .then(function (res) {
            var status = res.ok ? 'ok' : 'error';
            var label = res.ok ? 'Healthy' : 'Unhealthy';
            document.getElementById('health-info').innerHTML =
                '<span class="badge ' + status + '">' + label + '</span>' +
                '<p style="margin-top:0.5rem">API endpoint responding (HTTP ' + res.status + ')</p>';
        })
        .catch(function () {
            document.getElementById('health-info').innerHTML =
                '<span class="badge error">Unreachable</span>' +
                '<p style="margin-top:0.5rem">Cannot reach the API server.</p>';
        });

    // Session info
    var username = Auth.getUsername() || 'Unknown';
    var role = Roles.currentUserRole();
    var roleDef = Roles.DEFINITIONS[role] || {};
    var expiry = Auth.getTokenExpiry();
    var expiryStr = expiry ? expiry.toLocaleString() : 'Unknown';

    document.getElementById('session-info').innerHTML =
        '<table><tbody>' +
        '<tr><td><strong>User</strong></td><td>' + escapeHtml(username) + '</td></tr>' +
        '<tr><td><strong>Role</strong></td><td><span class="role-badge ' + role + '">' + escapeHtml(roleDef.label || role) + '</span></td></tr>' +
        '<tr><td><strong>Token Expires</strong></td><td>' + escapeHtml(expiryStr) + '</td></tr>' +
        '<tr><td><strong>Permissions</strong></td><td>' + (roleDef.permissions || []).join(', ') + '</td></tr>' +
        '</tbody></table>';

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }
})();
